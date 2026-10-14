"""SPF (RFC 7208) checks: presence, single record, qualifier and the 10-lookup limit."""

from __future__ import annotations

from .models import Finding, Severity
from .resolver import Resolver

MAX_LOOKUPS = 10
_LOOKUP_MECHANISMS = ("include", "a", "mx", "ptr", "exists")


def _spf_records(resolver: Resolver, domain: str) -> list[str]:
    return [t for t in resolver.txt(domain) if t.lower().startswith("v=spf1")]


def count_lookups(resolver: Resolver, record: str, _seen: set[str] | None = None) -> int:
    """Count DNS-querying terms, following ``include:`` and ``redirect=`` recursively."""
    seen = _seen if _seen is not None else set()
    total = 0
    for term in record.split()[1:]:
        term = term.lstrip("+-~?")
        name, _, value = term.partition(":")
        name = name.split("/")[0].lower()
        if name.startswith("redirect="):
            name, value = "redirect", term.split("=", 1)[1]
        if name in _LOOKUP_MECHANISMS or name == "redirect":
            total += 1
        if name in ("include", "redirect") and value and value.lower() not in seen:
            seen.add(value.lower())
            for child in _spf_records(resolver, value):
                total += count_lookups(resolver, child, seen)
    return total


def check_spf(resolver: Resolver, domain: str) -> list[Finding]:
    records = _spf_records(resolver, domain)
    if not records:
        return [
            Finding(
                "spf.missing",
                Severity.HIGH,
                "No SPF record published.",
                "Publish a TXT record such as `v=spf1 include:<your-provider> -all`.",
            )
        ]
    if len(records) > 1:
        return [
            Finding(
                "spf.multiple",
                Severity.HIGH,
                f"{len(records)} SPF records found; receivers treat this as a permanent error.",
                "Merge them into a single `v=spf1` TXT record.",
            )
        ]

    record = records[0]
    findings = [Finding("spf.present", Severity.INFO, "A single SPF record is published.", ok=True)]

    terms = [t.lower() for t in record.split()[1:]]
    all_term = next((t for t in terms if t.lstrip("+-~?") == "all"), None)
    if all_term is None and not any(t.startswith("redirect=") for t in terms):
        findings.append(
            Finding(
                "spf.no_all",
                Severity.MEDIUM,
                "SPF record has no terminating `all` mechanism.",
                "End the record with `-all` (or `~all` while you are still rolling out).",
            )
        )
    elif all_term in ("all", "+all"):
        findings.append(
            Finding(
                "spf.pass_all",
                Severity.HIGH,
                "`+all` authorises every server on the internet to send as this domain.",
                "Replace it with `-all` or `~all`.",
            )
        )
    elif all_term == "?all":
        findings.append(
            Finding(
                "spf.neutral_all",
                Severity.MEDIUM,
                "`?all` says nothing about unlisted senders.",
                "Use `~all`, then `-all` once you are sure every sender is listed.",
            )
        )
    elif all_term == "~all":
        findings.append(
            Finding(
                "spf.softfail",
                Severity.LOW,
                "`~all` (softfail) is acceptable while rolling out but weaker than `-all`.",
                "Move to `-all` when all legitimate senders are covered.",
            )
        )
    elif all_term == "-all":
        findings.append(Finding("spf.hardfail", Severity.INFO, "SPF ends in `-all`.", ok=True))

    if any(t.lstrip("+-~?").startswith("ptr") for t in terms):
        findings.append(
            Finding(
                "spf.ptr",
                Severity.LOW,
                "The `ptr` mechanism is deprecated (RFC 7208 §5.5).",
                "Replace it with explicit `ip4:`/`ip6:`/`include:` terms.",
            )
        )

    lookups = count_lookups(resolver, record)
    if lookups > MAX_LOOKUPS:
        findings.append(
            Finding(
                "spf.too_many_lookups",
                Severity.HIGH,
                f"SPF needs {lookups} DNS lookups; the limit is {MAX_LOOKUPS}.",
                "Flatten includes or drop providers you no longer use.",
            )
        )
    else:
        findings.append(
            Finding(
                "spf.lookups",
                Severity.INFO,
                f"SPF uses {lookups} of {MAX_LOOKUPS} allowed DNS lookups.",
                ok=True,
            )
        )
    return findings
