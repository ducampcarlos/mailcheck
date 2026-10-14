"""A fake resolver so no test touches the network."""

from __future__ import annotations

import pytest


class FakeResolver:
    def __init__(self, txt=None, mx=None, addresses=()):
        self._txt = txt or {}
        self._mx = mx or {}
        self._addresses = set(addresses)

    def txt(self, name):
        return list(self._txt.get(name, []))

    def mx(self, name):
        return list(self._mx.get(name, []))

    def has_address(self, name):
        return name in self._addresses


@pytest.fixture
def make_resolver():
    return FakeResolver
