from mailcheck.dkim import check_dkim
from mailcheck.dmarc import check_dmarc, parse_tags
from mailcheck.mx import check_mta_sts, check_mx


def ids(findings):
    return {f.check for f in findings}


def test_parse_tags_tolerates_whitespace():
    assert parse_tags("v=DMARC1 ; p = reject;rua=mailto:a@b.c;") == {
        "v": "DMARC1",
        "p": "reject",
        "rua": "mailto:a@b.c",
    }


def test_dmarc_missing(make_resolver):
    assert ids(check_dmarc(make_resolver(), "d")) == {"dmarc.missing"}


def test_dmarc_reject_with_rua_is_clean(make_resolver):
    r = make_resolver(txt={"_dmarc.d": ["v=DMARC1; p=reject; rua=mailto:r@d"]})
    assert all(f.ok for f in check_dmarc(r, "d"))


def test_dmarc_none_is_medium(make_resolver):
    r = make_resolver(txt={"_dmarc.d": ["v=DMARC1; p=none; rua=mailto:r@d"]})
    f = next(f for f in check_dmarc(r, "d") if f.check == "dmarc.monitor_only")
    assert f.severity.label == "medium"


def test_dmarc_invalid_policy_and_no_rua(make_resolver):
    r = make_resolver(txt={"_dmarc.d": ["v=DMARC1; p=bogus"]})
    assert {"dmarc.invalid_policy", "dmarc.no_rua"} <= ids(check_dmarc(r, "d"))


def test_dmarc_partial_and_weak_subdomain(make_resolver):
    r = make_resolver(txt={"_dmarc.d": ["v=DMARC1; p=reject; pct=50; sp=none; rua=mailto:r@d"]})
    assert {"dmarc.partial", "dmarc.weak_subdomain_policy"} <= ids(check_dmarc(r, "d"))


def test_dkim_found_extra_selector_and_revoked(make_resolver):
    r = make_resolver(
        txt={
            "custom._domainkey.d": ["v=DKIM1; k=rsa; p=MIGf"],
            "old._domainkey.d": ["v=DKIM1; p="],
        }
    )
    result = check_dkim(r, "d", extra_selectors=("custom", "old"))
    assert ids(result) == {"dkim.found", "dkim.revoked"}


def test_dkim_not_found(make_resolver):
    assert ids(check_dkim(make_resolver(), "d")) == {"dkim.not_found"}


def test_mx_missing_and_null(make_resolver):
    assert ids(check_mx(make_resolver(), "d")) == {"mx.missing"}
    assert ids(check_mx(make_resolver(mx={"d": [(0, "")]}), "d")) == {"mx.null"}


def test_mx_unresolvable_and_single(make_resolver):
    r = make_resolver(mx={"d": [(10, "mail.d")]})
    assert {"mx.unresolvable", "mx.single"} <= ids(check_mx(r, "d"))


def test_mx_healthy(make_resolver):
    r = make_resolver(mx={"d": [(10, "a.d"), (20, "b.d")]}, addresses={"a.d", "b.d"})
    assert all(f.ok for f in check_mx(r, "d"))


def test_mta_sts(make_resolver):
    assert {"mta_sts.missing", "tls_rpt.missing"} == ids(check_mta_sts(make_resolver(), "d"))
    r = make_resolver(
        txt={"_mta-sts.d": ["v=STSv1; id=1"], "_smtp._tls.d": ["v=TLSRPTv1; rua=mailto:x@d"]}
    )
    assert all(f.ok for f in check_mta_sts(r, "d"))
