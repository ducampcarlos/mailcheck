# mailcheck

[![CI](https://github.com/ducampcarlos/mailcheck/actions/workflows/ci.yml/badge.svg)](https://github.com/ducampcarlos/mailcheck/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)

**A fast, passive command-line check of a domain's email authentication: SPF, DKIM, DMARC, MX and MTA-STS.**
It only reads public DNS records. It never connects to a mail server and never sends an email.

Built for the moment after a mail-server migration or a "why does my mail land in spam?" ticket: one command, a score, and a concrete fix for every problem.

```text
$ mailcheck example.com
mailcheck report for example.com
score 84/100  grade B

[ ok   ] mx.present: 2 MX record(s) published.
[ ok   ] spf.present: A single SPF record is published.
[low   ] spf.softfail: `~all` (softfail) is acceptable while rolling out but weaker than `-all`.
         fix: Move to `-all` when all legitimate senders are covered.
[ ok   ] spf.lookups: SPF uses 1 of 10 allowed DNS lookups.
[ ok   ] dkim.found: DKIM key found for selector(s): google.
[ ok   ] dmarc.present: A DMARC record is published.
[medium] dmarc.monitor_only: Policy is `p=none`: spoofed mail is still delivered.
         fix: Use the aggregate reports to fix senders, then move to quarantine/reject.
[low   ] mta_sts.missing: No MTA-STS record, so inbound SMTP TLS can be downgraded.
         fix: Publish `_mta-sts` TXT and host the policy at `https://mta-sts.<domain>/.well-known/mta-sts.txt`.
[info  ] tls_rpt.missing: No TLS-RPT record, so you get no reports about TLS delivery failures.
         fix: Publish `_smtp._tls` TXT `v=TLSRPTv1; rua=mailto:<mailbox>`.
```

(Sample output for a made-up domain, produced from the test fixtures. `example.com` is not actually queried.)

## Install

```bash
pip install git+https://github.com/ducampcarlos/mailcheck.git
```

Requires Python 3.10+. The only dependency is [dnspython](https://www.dnspython.org/).

## Usage

```bash
mailcheck example.com                       # human-readable report
mailcheck example.com -f json | jq .score   # machine-readable
mailcheck example.com --dkim-selector s1024 # probe your own DKIM selector
mailcheck example.com --fail-on medium      # CI gate: exit 1 on medium or worse
mailcheck example.com --nameserver 1.1.1.1  # bypass the local resolver / DNS cache
```

You can also pass an email address or a URL; the domain is extracted.

### Exit codes

| Code | Meaning |
| ---: | --- |
| 0 | No finding at or above `--fail-on` (default `high`) |
| 1 | At least one finding at or above `--fail-on` |
| 2 | Usage error |

## What it checks

| Area | Checks |
| --- | --- |
| **MX** | records exist, null MX, MX hosts resolve, single point of failure |
| **SPF** | present, single record, `+all` / `?all` / `~all` / `-all`, deprecated `ptr`, the 10-DNS-lookup limit (follows `include:` and `redirect=`, safe against loops) |
| **DKIM** | probes common selectors plus any you pass, detects revoked keys. Selectors can't be enumerated through DNS, so a "not found" means "not found among the probed names" |
| **DMARC** | present, single record, policy strength, `pct`, `rua`, weak `sp=` |
| **MTA-STS / TLS-RPT** | records published |

Every finding has a stable ID (`spf.too_many_lookups`, `dmarc.monitor_only`, ...), a severity (`info|low|medium|high`) and a remediation. The score starts at 100 and loses 3, 10 or 25 points for each low, medium or high finding. Grades: A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, F below.

## Limits

* It does not validate that the MTA-STS policy file is reachable, or the TLS certificate of your MX hosts; it only looks at DNS.
* It cannot tell whether *your* sending services are all covered by SPF. It checks that the record is well formed and safe, not that it is complete.
* DNS answers can differ by resolver; use `--nameserver` to compare.

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
ruff check . && ruff format --check .
pytest
```

Tests never touch the network: DNS goes through a small `Resolver` interface and the tests use an in-memory fake.

## License

MIT, see [LICENSE](LICENSE). Copyright (c) 2026 Carlos Ducamp.
