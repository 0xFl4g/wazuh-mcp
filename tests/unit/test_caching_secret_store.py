"""CachingSecretStore — TTL + single-flight + explicit invalidation."""

from __future__ import annotations

import asyncio

import pytest

from wazuh_mcp.secrets.caching import CachingSecretStore
from wazuh_mcp.secrets.value import SecretValue


class _FakeStore:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []
        self._data: dict[tuple[str, str], str] = {("t1", "k1"): "v1", ("t1", "k2"): "v2"}

    async def get(self, tenant_id: str, key: str) -> SecretValue:
        self.calls.append((tenant_id, key))
        await asyncio.sleep(0)  # yield, to expose races
        if (tenant_id, key) not in self._data:
            raise KeyError(key)
        return SecretValue(self._data[(tenant_id, key)])


@pytest.mark.asyncio
async def test_hit_caches_within_ttl() -> None:
    inner = _FakeStore()
    cache = CachingSecretStore(inner, ttl_seconds=60)
    v1 = await cache.get("t1", "k1")
    v2 = await cache.get("t1", "k1")
    assert v1.expose() == v2.expose() == "v1"
    assert inner.calls == [("t1", "k1")]


@pytest.mark.asyncio
async def test_miss_across_keys() -> None:
    inner = _FakeStore()
    cache = CachingSecretStore(inner, ttl_seconds=60)
    await cache.get("t1", "k1")
    await cache.get("t1", "k2")
    assert inner.calls == [("t1", "k1"), ("t1", "k2")]


@pytest.mark.asyncio
async def test_ttl_expiry_refetches(monkeypatch: pytest.MonkeyPatch) -> None:
    inner = _FakeStore()
    fake_now = [1000.0]

    def _now() -> float:
        return fake_now[0]

    cache = CachingSecretStore(inner, ttl_seconds=10, clock=_now)
    await cache.get("t1", "k1")
    fake_now[0] += 5
    await cache.get("t1", "k1")  # still cached
    fake_now[0] += 6  # now 1011 — past TTL
    await cache.get("t1", "k1")  # refetch
    assert inner.calls == [("t1", "k1"), ("t1", "k1")]


@pytest.mark.asyncio
async def test_explicit_invalidate() -> None:
    inner = _FakeStore()
    cache = CachingSecretStore(inner, ttl_seconds=60)
    await cache.get("t1", "k1")
    cache.invalidate("t1", "k1")
    await cache.get("t1", "k1")
    assert inner.calls == [("t1", "k1"), ("t1", "k1")]


@pytest.mark.asyncio
async def test_single_flight_concurrent_gets() -> None:
    inner = _FakeStore()
    cache = CachingSecretStore(inner, ttl_seconds=60)
    results = await asyncio.gather(*[cache.get("t1", "k1") for _ in range(20)])
    assert all(r.expose() == "v1" for r in results)
    assert inner.calls == [("t1", "k1")]  # exactly one inner call despite 20 concurrent


@pytest.mark.asyncio
async def test_missing_secret_not_cached() -> None:
    inner = _FakeStore()
    cache = CachingSecretStore(inner, ttl_seconds=60)
    with pytest.raises(KeyError):
        await cache.get("t1", "missing")
    # Second call still hits inner — negative results must not be cached
    with pytest.raises(KeyError):
        await cache.get("t1", "missing")
    assert inner.calls == [("t1", "missing"), ("t1", "missing")]
