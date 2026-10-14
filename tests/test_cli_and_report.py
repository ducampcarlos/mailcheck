import json

import pytest

from mailcheck import cli
from mailcheck.models import Finding, Report, Severity
from mailcheck.runner import normalise_domain, run_checks


@pytest.mark.parametrize(
    "raw",
    ["Example.COM", "user@example.com", "https://example.com/some/path", "example.com."],
)
def test_normalise_domain(raw):
    assert normalise_domain(raw) == "example.com"


def good_resolver(make_resolver):
    return make_resolver(
        txt={
            "example.com": ["v=spf1 ip4:192.0.2.1 -all"],
            "_dmarc.example.com": ["v=DMARC1; p=reject; rua=mailto:r@example.com"],
            "google._domainkey.example.com": ["v=DKIM1; p=ABC"],
            "_mta-sts.example.com": ["v=STSv1; id=1"],
            "_smtp._tls.example.com": ["v=TLSRPTv1; rua=mailto:t@example.com"],
        },
        mx={"example.com": [(10, "a.example.com"), (20, "b.example.com")]},
        addresses={"a.example.com", "b.example.com"},
    )


def test_perfect_domain_scores_100(make_resolver):
    report = run_checks(good_resolver(make_resolver), "example.com")
    assert report.score == 100 and report.grade == "A"
    assert report.worst() is None


def test_empty_domain_fails(make_resolver):
    report = run_checks(make_resolver(), "nothing.test")
    assert report.grade in ("D", "F")
    assert report.worst() == Severity.HIGH


def test_score_never_negative():
    report = Report("d", [Finding(f"x{i}", Severity.HIGH, "bad") for i in range(10)])
    assert report.score == 0 and report.grade == "F"


def run_cli(monkeypatch, make_resolver, argv, resolver=None):
    monkeypatch.setattr(cli, "DnsResolver", lambda **_: resolver or make_resolver())
    return cli.main(argv)


def test_cli_json_and_exit_codes(monkeypatch, make_resolver, capsys):
    code = run_cli(monkeypatch, make_resolver, ["x.test", "-f", "json"])
    data = json.loads(capsys.readouterr().out)
    assert data["domain"] == "x.test" and code == cli.EXIT_FINDINGS


def test_cli_fail_on_none(monkeypatch, make_resolver, capsys):
    assert run_cli(monkeypatch, make_resolver, ["x.test", "--fail-on", "none"]) == cli.EXIT_OK
    assert "score" in capsys.readouterr().out


def test_cli_clean_domain_exits_zero(monkeypatch, make_resolver, capsys):
    code = run_cli(
        monkeypatch, make_resolver, ["example.com"], resolver=good_resolver(make_resolver)
    )
    assert code == cli.EXIT_OK
    assert "grade A" in capsys.readouterr().out


def test_text_output_shows_fix_hint(make_resolver):
    report = run_checks(make_resolver(), "x.test")
    out = cli.render_text(report, colour=False)
    assert "fix:" in out and "\033[" not in out
