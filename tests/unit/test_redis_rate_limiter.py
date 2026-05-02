"""RedisRateLimiter unit tests via fakeredis.aioredis.

End-to-end limiter behavior: Protocol conformance, two-bucket math,
WazuhError emission with correct scope, fallback routing on Redis
failure, per-tenant config overrides, NOSCRIPT recovery.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import fakeredis.aioredis
import pytest
from redis.exceptions import ConnectionError as RedisConnectionError

from wazuh_mcp.rate_limit.redis_limiter import (
    BreakerState,
    RedisRateLimiter,
    _RedisCircuitBreaker,
)
from wazuh_mcp.tenancy.m4_config import BucketConfig, RateLimitConfig
from wazuh_mcp.wazuh.errors import WazuhError


def _cfg(tenant_cap: int = 5, session_cap: int = 3, refill: float = 0.0001) -> RateLimitConfig:
    return RateLimitConfig(
        tenant=BucketConfig(capacity=tenant_cap, refill_per_sec=refill),
        session=BucketConfig(capacity=session_cap, refill_per_sec=refill),
    )


def _breaker() -> _RedisCircuitBreaker:
    return _RedisCircuitBreaker(
        error_threshold=3,
        open_duration_sec=0.05,
        half_open_max_calls=1,
        call_timeout_ms=200,
    )


@pytest.fixture
async def redis_client() -> AsyncIterator[fakeredis.aioredis.FakeRedis]:
    client = fakeredis.aioredis.FakeRedis()
    yield client
    await client.aclose()


@pytest.mark.asyncio
async def test_acquires_under_budget(redis_client: fakeredis.aioredis.FakeRedis) -> None:
    limiter = RedisRateLimiter(
        redis_client=redis_client,
        default=_cfg(),
        key_prefix="t",
        breaker=_breaker(),
    )
    await limiter.acquire("ten1", "sess1")
    await limiter.acquire("ten1", "sess1")
    await limiter.acquire("ten1", "sess1")


@pytest.mark.asyncio
async def test_session_exhaustion_raises_session_scope(
    redis_client: fakeredis.aioredis.FakeRedis,
) -> None:
    limiter = RedisRateLimiter(
        redis_client=redis_client,
        default=_cfg(tenant_cap=100, session_cap=2),
        key_prefix="t",
        breaker=_breaker(),
    )
    await limiter.acquire("ten1", "sess1")
    await limiter.acquire("ten1", "sess1")
    with pytest.raises(WazuhError) as exc:
        await limiter.acquire("ten1", "sess1")
    assert exc.value.code == "rate_limited"
    assert exc.value.scope == "rate_limit:session"


@pytest.mark.asyncio
async def test_tenant_exhaustion_raises_tenant_scope(
    redis_client: fakeredis.aioredis.FakeRedis,
) -> None:
    limiter = RedisRateLimiter(
        redis_client=redis_client,
        default=_cfg(tenant_cap=2, session_cap=100),
        key_prefix="t",
        breaker=_breaker(),
    )
    await limiter.acquire("ten1", "sess1")
    await limiter.acquire("ten1", "sess2")
    with pytest.raises(WazuhError) as exc:
        await limiter.acquire("ten1", "sess3")
    assert exc.value.scope == "rate_limit:tenant"


@pytest.mark.asyncio
async def test_distinct_tenants_distinct_budgets(
    redis_client: fakeredis.aioredis.FakeRedis,
) -> None:
    limiter = RedisRateLimiter(
        redis_client=redis_client,
        default=_cfg(tenant_cap=2),
        key_prefix="t",
        breaker=_breaker(),
    )
    await limiter.acquire("a", "s")
    await limiter.acquire("a", "s")
    await limiter.acquire("b", "s")
    await limiter.acquire("b", "s")


@pytest.mark.asyncio
async def test_per_tenant_override(redis_client: fakeredis.aioredis.FakeRedis) -> None:
    default = _cfg(tenant_cap=2)
    big = RateLimitConfig(
        tenant=BucketConfig(capacity=10, refill_per_sec=0.0001),
        session=BucketConfig(capacity=10, refill_per_sec=0.0001),
    )
    limiter = RedisRateLimiter(
        redis_client=redis_client,
        default=default,
        per_tenant={"vip": big},
        key_prefix="t",
        breaker=_breaker(),
    )
    for _ in range(10):
        await limiter.acquire("vip", "s")
    await limiter.acquire("plebs", "s")
    await limiter.acquire("plebs", "s")
    with pytest.raises(WazuhError):
        await limiter.acquire("plebs", "s")


@pytest.mark.asyncio
async def test_redis_connection_error_routes_to_fallback(
    redis_client: fakeredis.aioredis.FakeRedis,
) -> None:
    """Simulate Redis going away mid-call; first call should still succeed via fallback."""

    class FlakeyRedis:
        def __init__(self, real: fakeredis.aioredis.FakeRedis) -> None:
            self._real = real
            self.fail_next = True

        async def script_load(self, script: str) -> str:
            return await self._real.script_load(script)

        async def evalsha(self, *args, **kwargs):
            if self.fail_next:
                raise RedisConnectionError("simulated redis down")
            return await self._real.evalsha(*args, **kwargs)  # ty: ignore[invalid-await]

    flakey = FlakeyRedis(redis_client)
    limiter = RedisRateLimiter(
        redis_client=flakey,
        default=_cfg(),
        key_prefix="t",
        breaker=_breaker(),
    )
    await limiter.acquire("ten1", "sess1")
    assert limiter._fallback is not None


@pytest.mark.asyncio
async def test_breaker_open_after_threshold_failures() -> None:
    class AlwaysFailRedis:
        async def script_load(self, script: str) -> str:
            return "fakesha"

        async def evalsha(self, *args, **kwargs):
            raise RedisConnectionError("nope")

    breaker = _RedisCircuitBreaker(
        error_threshold=3,
        open_duration_sec=10.0,
        half_open_max_calls=1,
        call_timeout_ms=200,
    )
    limiter = RedisRateLimiter(
        redis_client=AlwaysFailRedis(),
        default=_cfg(),
        key_prefix="t",
        breaker=breaker,
    )
    for _ in range(3):
        await limiter.acquire("ten1", "sess1")
    assert breaker.state == BreakerState.OPEN


@pytest.mark.asyncio
async def test_noscript_triggers_reload_and_succeeds(
    redis_client: fakeredis.aioredis.FakeRedis,
) -> None:
    limiter = RedisRateLimiter(
        redis_client=redis_client,
        default=_cfg(),
        key_prefix="t",
        breaker=_breaker(),
    )
    await limiter.acquire("ten1", "sess1")
    await redis_client.script_flush()
    await limiter.acquire("ten1", "sess1")


@pytest.mark.asyncio
async def test_key_prefix_isolation(redis_client: fakeredis.aioredis.FakeRedis) -> None:
    limiter_a = RedisRateLimiter(
        redis_client=redis_client,
        default=_cfg(tenant_cap=2),
        key_prefix="depA",
        breaker=_breaker(),
    )
    limiter_b = RedisRateLimiter(
        redis_client=redis_client,
        default=_cfg(tenant_cap=2),
        key_prefix="depB",
        breaker=_breaker(),
    )
    await limiter_a.acquire("ten", "s")
    await limiter_a.acquire("ten", "s")
    await limiter_b.acquire("ten", "s")
    await limiter_b.acquire("ten", "s")
