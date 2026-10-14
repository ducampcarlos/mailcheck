"""DMARC (RFC 7489) checks."""

from __future__ import annotations

from .models import Finding, Severity
from .resolver import Resolver


def parse_tags(record: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for part in record.split(";"):
        key, sep, value = part.strip().partition("=")
        if sep:
            tags[key.strip().lower()] = value.strip()
    return tags


def check_dmarc(resolver: Resolver, domain: str) -> list[Finding]:
    records = [t for t in resolver.txt(f"_dmarc.{domain}") if t.lower().startswith("v=dmarc1")]
    if not records:
        return [
            Finding(
                "dmarc.missing",
                Severity.HIGH,
                "No DMARC record published.",
                "Publish `_dmarc` TXT `v=DMARC1; p=none; rua=mailto:dmarc@<domain>` and tighten "
                "the policy as reports come in.",
            )
        ]
    if len(records) > 1:
        return [
            Finding(
                "dmarc.multiple",
                Severity.HIGH,
                "Multiple DMARC records found; receivers ignore all of them.",
                "Keep exactly one `v=DMARC1` TXT record.",
            )
        ]

    tags = parse_tags(records[0])
    findings = [Finding("dmarc.present", Severity.INFO, "A DMARC record is published.", ok=True)]

    policy = tags.get("p", "").lower()
    if policy == "reject":
        findings.append(Finding("dmarc.reject", Severity.INFO, "Policy is `p=reject`.", ok=True))
    elif policy == "quarantine":
        findings.append(
            Finding(
                "dmarc.quarantine",
                Severity.LOW,
                "Policy is `p=quarantine`.",
                "Consider `p=reject` once reports show no legitimate failures.",
            )
        )
    elif policy == "none":
        findings.append(
            Finding(
                "dmarc.monitor_only",
                Severity.MEDIUM,
                "Policy is `p=none`: spoofed mail is still delivered.",
                "Use the aggregate reports to fix senders, then move to quarantine/reject.",
            )
        )
    else:
        findings.append(
            Finding(
                "dmarc.invalid_policy",
                Severity.HIGH,
                f"Missing or invalid `p=` tag ({policy!r}).",
                "Set `p=none`, `p=quarantine` or `p=reject`.",
            )
        )

    pct = tags.get("pct")
    if pct is not None and pct.isdigit() and int(pct) < 100 and policy in ("quarantine", "reject"):
        findings.append(
            Finding(
                "dmarc.partial",
                Severity.LOW,
                f"Policy applies to only {pct}% of messages.",
                "Raise `pct` to 100 once you are confident.",
            )
        )

    if "rua" not in tags:
        findings.append(
            Finding(
                "dmarc.no_rua",
                Severity.LOW,
                "No `rua=` address, so you receive no aggregate reports.",
                "Add `rua=mailto:<mailbox>` to see who sends as your domain.",
            )
        )
    sp = tags.get("sp", "").lower()
    if sp == "none" and policy in ("quarantine", "reject"):
        findings.append(
            Finding(
                "dmarc.weak_subdomain_policy",
                Severity.MEDIUM,
                "Subdomain policy `sp=none` undermines the main policy.",
                "Remove `sp=` or match it to `p=`.",
            )
        )
    return findings
