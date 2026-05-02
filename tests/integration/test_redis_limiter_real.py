"""Real-Redis integration test for RedisRateLimiter.

Marked @pytest.mark.integration. Spun up via docker/bootstrap.sh which
starts the redis service from integration-compose.yml.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
from collections.abc import AsyncIterator

import pytest
from redis.asyncio import Redis as AsyncRedis

from wazuh_mcp.rate_limit.redis_limiter import (
    BreakerState,
    RedisRateLimiter,
    _RedisCircuitBreaker,
)
from wazuh_mcp.tenancy.m4_config import BucketConfig, RateLimitConfig
from wazuh_mcp.wazuh.errors import WazuhError

pytestmark = pytest.mark.integration

REDIS_URL = os.environ.get("WAZUH_MCP_REDIS_URL", "redis://localhost:6379/0")


def _cfg(tenant_cap: int = 5, session_cap: int = 5) -> RateLimitConfig:
    return RateLimitConfig(
        tenant=BucketConfig(capacity=tenant_cap, refill_per_sec=0.1),
        session=BucketConfig(capacity=session_cap, refill_per_sec=0.1),
    )


def _breaker() -> _RedisCircuitBreaker:
    return _RedisCircuitBreaker(
        error_threshold=3,
        open_duration_sec=2.0,
        half_open_max_calls=1,
        call_timeout_ms=500,
    )


@pytest.fixture
async def redis_clean() -> AsyncIterator[AsyncRedis]:
    client = AsyncRedis.from_url(REDIS_URL, decode_responses=False)
    await client.flushdb()
    yield client
    await client.flushdb()
    await client.aclose()


@pytest.mark.asyncio
async def test_real_redis_basic_acquire(redis_clean: AsyncRedis) -> None:
    limiter = RedisRateLimiter(
        redis_client=redis_clean,
        default=_cfg(tenant_cap=3, session_cap=3),
        key_prefix="itest:basic",
        breaker=_breaker(),
    )
    for _ in range(3):
        await limiter.acquire("ten1", "sess1")
    with pytest.raises(WazuhError):
        await limiter.acquire("ten1", "sess1")


@pytest.mark.asyncio
async def test_two_replicas_share_budget(redis_clean: AsyncRedis) -> None:
    """Two RedisRateLimiter instances against the same Redis enforce one global budget."""
    a = RedisRateLimiter(
        redis_client=redis_clean,
        default=_cfg(tenant_cap=4),
        key_prefix="itest:share",
        breaker=_breaker(),
    )
    b = RedisRateLimiter(
        redis_client=redis_clean,
        default=_cfg(tenant_cap=4),
        key_prefix="itest:share",
        breaker=_breaker(),
    )
    await a.acquire("ten", "s1")
    await b.acquire("ten", "s2")
    await a.acquire("ten", "s3")
    await b.acquire("ten", "s4")
    with pytest.raises(WazuhError):
        await a.acquire("ten", "s5")


@pytest.mark.asyncio
async def test_redis_stop_triggers_fallback(redis_clean: AsyncRedis) -> None:
    """docker stop redis mid-load -> breaker opens -> fallback serves; restart -> breaker closes."""
    if shutil.which("docker") is None:
        pytest.skip("docker CLI not available")

    container_name = f"wazuhmcp-redis-{os.environ.get('COMPOSE_PROJECT_NAME', 'test')}"

    limiter = RedisRateLimiter(
        redis_client=redis_clean,
        default=_cfg(tenant_cap=1000),
        key_prefix="itest:stop",
        breaker=_breaker(),
    )

    await limiter.acquire("ten", "sess")
    subprocess.run(["docker", "stop", container_name], check=True, timeout=15)  # noqa: ASYNC221
    try:
        for _ in range(5):
            await limiter.acquire("ten", "sess")
        assert limiter._breaker.state == BreakerState.OPEN  # deliberate access
    finally:
        subprocess.run(["docker", "start", container_name], check=True, timeout=15)  # noqa: ASYNC221
        for _ in range(30):
            try:
                await redis_clean.ping()
                break
            except Exception:
                await asyncio.sleep(0.5)

    await asyncio.sleep(2.5)
    await limiter.acquire("ten", "sess")
    assert limiter._breaker.state == BreakerState.CLOSED  # deliberate access


@pytest.mark.asyncio
async def test_real_redis_noscript_recovery(redis_clean: AsyncRedis) -> None:
    """SCRIPT FLUSH mid-run; next acquire reloads via NOSCRIPT path."""
    limiter = RedisRateLimiter(
        redis_client=redis_clean,
        default=_cfg(),
        key_prefix="itest:noscript",
        breaker=_breaker(),
    )
    await limiter.acquire("ten", "sess")
    await redis_clean.script_flush()
    await limiter.acquire("ten", "sess")
