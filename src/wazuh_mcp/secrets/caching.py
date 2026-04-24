"""TTL + single-flight cache wrapping any SecretStore.

Design notes:
 - Positive results only: KeyError and other failures bypass the cache so
   transient misses don't get pinned for TTL seconds.
 - Single-flight via an asyncio.Future keyed on (tenant, key): concurrent
   gets for the same key share one inner call.
 - `clock` is injectable for tests (real code uses time.monotonic).
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable

from wazuh_mcp.secrets.store import SecretStore
from wazuh_mcp.secrets.value import SecretValue


class CachingSecretStore:
    def __init__(
        self,
        inner: SecretStore,
        *,
        ttl_seconds: float = 300.0,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._inner = inner
        self._ttl = float(ttl_seconds)
        self._clock = clock or time.monotonic
        self._cache: dict[tuple[str, str], tuple[float, SecretValue]] = {}
        self._inflight: dict[tuple[str, str], asyncio.Future[SecretValue]] = {}
        self._lock = asyncio.Lock()

    async def get(self, tenant_id: str, key: str) -> SecretValue:
        cache_key = (tenant_id, key)
        now = self._clock()
        # Fast path: return cached if live.
        entry = self._cache.get(cache_key)
        if entry is not None and entry[0] > now:
            return entry[1]

        # Single-flight: coalesce concurrent refetches.
        async with self._lock:
            # Re-check under lock in case another caller just populated.
            entry = self._cache.get(cache_key)
            if entry is not None and entry[0] > self._clock():
                return entry[1]
            fut = self._inflight.get(cache_key)
            if fut is None:
                fut = asyncio.get_running_loop().create_future()
                self._inflight[cache_key] = fut
                owner = True
            else:
                owner = False

        if owner:
            try:
                value = await self._inner.get(tenant_id, key)
            except BaseException as exc:  # propagate, do not cache negatives
                async with self._lock:
                    self._inflight.pop(cache_key, None)
                    fut.set_exception(exc)
                # Retrieve the exception on the future so Python doesn't
                # warn about an unretrieved future exception when no
                # other coroutines were waiting on it.
                fut.exception()
                raise
            async with self._lock:
                self._cache[cache_key] = (self._clock() + self._ttl, value)
                self._inflight.pop(cache_key, None)
                fut.set_result(value)
            return value
        # Non-owner: await the flight started by another caller.
        return await fut

    def invalidate(self, tenant_id: str, key: str) -> None:
        self._cache.pop((tenant_id, key), None)
