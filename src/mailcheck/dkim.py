"""DKIM (RFC 6376) discovery. DKIM selectors can't be listed, so we probe common ones."""

from __future__ import annotations

from .models import Finding, Severity
from .resolver import Resolver

COMMON_SELECTORS = (
    "default", "google", "selector1", "selector2", "k1", "k2", "s1", "s2",
    "mail", "dkim", "smtp", "mandrill", "mxvault", "everlytickey1", "cm", "zoho",
)  # fmt: skip


def check_dkim(
    resolver: Resolver, domain: str, extra_selectors: tuple[str, ...] = ()
) -> list[Finding]:
    selectors = tuple(dict.fromkeys((*extra_selectors, *COMMON_SELECTORS)))
    valid: list[str] = []
    revoked: list[str] = []
    for selector in selectors:
        for record in resolver.txt(f"{selector}._domainkey.{domain}"):
            tags = {
                k.strip().lower(): v.strip()
                for k, _, v in (p.partition("=") for p in record.split(";"))
            }
            if "p" not in tags:
                continue
            (valid if tags["p"] else revoked).append(selector)
            break

    findings: list[Finding] = []
    if valid:
        findings.append(
            Finding(
                "dkim.found",
                Severity.INFO,
                f"DKIM key found for selector(s): {', '.join(valid)}.",
                ok=True,
            )
        )
    else:
        findings.append(
            Finding(
                "dkim.not_found",
                Severity.MEDIUM,
                f"No DKIM key found among {len(selectors)} common selectors.",
                "Enable DKIM signing at your mail provider. If you already did, rerun with "
                "`--dkim-selector <name>` (see the `DKIM-Signature` header of a real email).",
            )
        )
    if revoked:
        findings.append(
            Finding(
                "dkim.revoked",
                Severity.LOW,
                f"Revoked (empty `p=`) key for selector(s): {', '.join(revoked)}.",
                "Delete DNS records for selectors you no longer use.",
            )
        )
    return findings
