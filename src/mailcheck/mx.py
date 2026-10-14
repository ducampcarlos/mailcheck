"""MX, MTA-STS and TLS-RPT checks (DNS side only; nothing connects to a mail server)."""

from __future__ import annotations

from .models import Finding, Severity
from .resolver import Resolver


def check_mx(resolver: Resolver, domain: str) -> list[Finding]:
    records = resolver.mx(domain)
    if not records:
        return [
            Finding(
                "mx.missing",
                Severity.MEDIUM,
                "No MX records: the domain cannot receive email.",
                "Add MX records pointing at your mail provider (ignore if it is a send-only domain "
                "and you publish a null MX: `0 .`).",
            )
        ]
    if len(records) == 1 and records[0][1] == "":
        return [
            Finding(
                "mx.null", Severity.INFO, "Null MX published (domain accepts no mail).", ok=True
            )
        ]

    findings = [
        Finding("mx.present", Severity.INFO, f"{len(records)} MX record(s) published.", ok=True)
    ]
    broken = [host for _, host in records if not resolver.has_address(host)]
    if broken:
        findings.append(
            Finding(
                "mx.unresolvable",
                Severity.HIGH,
                f"MX host(s) without A/AAAA records: {', '.join(broken)}.",
                "Fix or remove those MX entries; senders will retry and eventually bounce.",
            )
        )
    if len(records) == 1:
        findings.append(
            Finding(
                "mx.single",
                Severity.LOW,
                "Only one MX host; mail queues up if it is down.",
                "Add a secondary MX (or confirm your provider already load-balances).",
            )
        )
    return findings


def check_mta_sts(resolver: Resolver, domain: str) -> list[Finding]:
    findings: list[Finding] = []
    if any(t.lower().startswith("v=stsv1") for t in resolver.txt(f"_mta-sts.{domain}")):
        findings.append(Finding("mta_sts.present", Severity.INFO, "MTA-STS is published.", ok=True))
    else:
        findings.append(
            Finding(
                "mta_sts.missing",
                Severity.LOW,
                "No MTA-STS record, so inbound SMTP TLS can be downgraded.",
                "Publish `_mta-sts` TXT and host the policy at "
                "`https://mta-sts.<domain>/.well-known/mta-sts.txt`.",
            )
        )
    if any(t.lower().startswith("v=tlsrptv1") for t in resolver.txt(f"_smtp._tls.{domain}")):
        findings.append(Finding("tls_rpt.present", Severity.INFO, "TLS-RPT is published.", ok=True))
    else:
        findings.append(
            Finding(
                "tls_rpt.missing",
                Severity.INFO,
                "No TLS-RPT record, so you get no reports about TLS delivery failures.",
                "Publish `_smtp._tls` TXT `v=TLSRPTv1; rua=mailto:<mailbox>`.",
            )
        )
    return findings
