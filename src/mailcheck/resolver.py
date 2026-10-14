"""DNS access behind a tiny interface, so checks can be tested without a network."""

from __future__ import annotations

from typing import Protocol

import dns.exception
import dns.resolver


class Resolver(Protocol):
    def txt(self, name: str) -> list[str]:
        """Return TXT records for ``name`` as joined strings (empty if none)."""

    def mx(self, name: str) -> list[tuple[int, str]]:
        """Return ``(preference, host)`` pairs, hosts without trailing dot."""

    def has_address(self, name: str) -> bool:
        """True when ``name`` resolves to at least one A or AAAA record."""


class DnsResolver:
    """Resolver backed by dnspython. Lookup failures are treated as 'no records'."""

    def __init__(self, timeout: float = 5.0, nameserver: str | None = None) -> None:
        self._resolver = dns.resolver.Resolver()
        self._resolver.lifetime = timeout
        self._resolver.timeout = timeout
        if nameserver:
            self._resolver.nameservers = [nameserver]

    def _query(self, name: str, rtype: str):
        try:
            return self._resolver.resolve(name, rtype)
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
            dns.name.EmptyLabel,
        ):
            return []

    def txt(self, name: str) -> list[str]:
        return [
            b"".join(rdata.strings).decode("utf-8", errors="replace")
            for rdata in self._query(name, "TXT")
        ]

    def mx(self, name: str) -> list[tuple[int, str]]:
        return sorted(
            (int(r.preference), str(r.exchange).rstrip(".").lower())
            for r in self._query(name, "MX")
        )

    def has_address(self, name: str) -> bool:
        return bool(self._query(name, "A") or self._query(name, "AAAA"))
