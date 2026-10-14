from mailcheck.spf import check_spf, count_lookups


def ids(findings):
    return {f.check for f in findings}


def test_missing(make_resolver):
    assert ids(check_spf(make_resolver(), "example.com")) == {"spf.missing"}


def test_multiple_records(make_resolver):
    r = make_resolver(txt={"example.com": ["v=spf1 -all", "v=spf1 ~all"]})
    assert ids(check_spf(r, "example.com")) == {"spf.multiple"}


def test_hardfail_is_clean(make_resolver):
    r = make_resolver(txt={"example.com": ["v=spf1 ip4:192.0.2.1 -all"]})
    result = check_spf(r, "example.com")
    assert all(f.ok for f in result)
    assert "spf.hardfail" in ids(result)


def test_plus_all_is_high(make_resolver):
    r = make_resolver(txt={"example.com": ["v=spf1 +all"]})
    bad = [f for f in check_spf(r, "example.com") if f.check == "spf.pass_all"]
    assert bad and bad[0].severity.label == "high"


def test_no_all_and_softfail_and_neutral(make_resolver):
    assert "spf.no_all" in ids(check_spf(make_resolver(txt={"d": ["v=spf1 mx"]}), "d"))
    assert "spf.softfail" in ids(check_spf(make_resolver(txt={"d": ["v=spf1 ~all"]}), "d"))
    assert "spf.neutral_all" in ids(check_spf(make_resolver(txt={"d": ["v=spf1 ?all"]}), "d"))


def test_ptr_flagged(make_resolver):
    assert "spf.ptr" in ids(check_spf(make_resolver(txt={"d": ["v=spf1 ptr -all"]}), "d"))


def test_lookup_counting_follows_includes(make_resolver):
    r = make_resolver(
        txt={
            "d": ["v=spf1 include:a.test mx -all"],
            "a.test": ["v=spf1 include:b.test a -all"],
            "b.test": ["v=spf1 ip4:192.0.2.0/24 -all"],
        }
    )
    assert count_lookups(r, "v=spf1 include:a.test mx -all") == 4


def test_include_loop_does_not_hang(make_resolver):
    r = make_resolver(
        txt={"a.test": ["v=spf1 include:b.test -all"], "b.test": ["v=spf1 include:a.test -all"]}
    )
    assert count_lookups(r, "v=spf1 include:a.test -all") == 3


def test_too_many_lookups(make_resolver):
    record = "v=spf1 " + " ".join(f"include:i{n}.test" for n in range(11)) + " -all"
    result = check_spf(make_resolver(txt={"d": [record]}), "d")
    assert "spf.too_many_lookups" in ids(result)


def test_redirect_counts_and_replaces_all(make_resolver):
    r = make_resolver(txt={"d": ["v=spf1 redirect=_spf.test"], "_spf.test": ["v=spf1 -all"]})
    result = check_spf(r, "d")
    assert "spf.no_all" not in ids(result)
    assert "spf.lookups" in ids(result)
