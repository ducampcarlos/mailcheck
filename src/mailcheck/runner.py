"""Run every check and assemble a report."""

from __future__ import annotations

from .dkim import check_dkim
from .dmarc import check_dmarc
from .models import Report
from .mx import check_mta_sts, check_mx
from .resolver import Resolver
from .spf import check_spf


def normalise_domain(value: str) -> str:
    """Accept ``Example.COM``, ``user@example.com`` or ``https://example.com/path``."""
    value = value.strip().lower()
    value = value.split("://", 1)[-1].split("/", 1)[0]
    value = value.rsplit("@", 1)[-1]
    return value.rstrip(".")


def run_checks(resolver: Resolver, domain: str, dkim_selectors: tuple[str, ...] = ()) -> Report:
    domain = normalise_domain(domain)
    report = Report(domain=domain)
    report.extend(check_mx(resolver, domain))
    report.extend(check_spf(resolver, domain))
    report.extend(check_dkim(resolver, domain, dkim_selectors))
    report.extend(check_dmarc(resolver, domain))
    report.extend(check_mta_sts(resolver, domain))
    return report
