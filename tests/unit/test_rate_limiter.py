"""InProcessRateLimiter: tenant + session scope, fail-closed."""

from __future__ import annotations

import asyncio

import pytest

from wazuh_mcp.rate_limit.limiter import InProcessRateLimiter
from wazuh_mcp.tenancy.m4_config import BucketConfig, RateLimitConfig
from wazuh_mcp.wazuh.errors import WazuhError


def _cfg(tenant_cap: int = 3, session_cap: int = 2) -> RateLimitConfig:
    return RateLimitConfig(
        tenant=BucketConfig(capacity=tenant_cap, refill_per_sec=1.0),
        session=BucketConfig(capacity=session_cap, refill_per_sec=1.0),
    )


@pytest.mark.asyncio
async def test_tenant_and_session_both_succeed_under_budget() -> None:
    limiter = InProcessRateLimiter(default=_cfg())
    await limiter.acquire("t1", "s1")
    await limiter.acquire("t1", "s1")  # 2 within session budget


@pytest.mark.asyncio
async def test_session_bucket_exhaustion() -> None:
    limiter = InProcessRateLimiter(default=_cfg(tenant_cap=100, session_cap=2))
    await limiter.acquire("t1", "s1")
    await limiter.acquire("t1", "s1")
    with pytest.raises(WazuhError) as exc:
        await limiter.acquire("t1", "s1")
    assert exc.value.code == "rate_limited"


@pytest.mark.asyncio
async def test_tenant_bucket_exhaustion_across_sessions() -> None:
    limiter = InProcessRateLimiter(default=_cfg(tenant_cap=2, session_cap=100))
    await limiter.acquire("t1", "s1")
    await limiter.acquire("t1", "s2")
    with pytest.raises(WazuhError) as exc:
        await limiter.acquire("t1", "s3")
    assert exc.value.code == "rate_limited"


@pytest.mark.asyncio
async def test_per_tenant_override() -> None:
    default = _cfg(tenant_cap=1)
    override = RateLimitConfig(
        tenant=BucketConfig(capacity=10, refill_per_sec=1.0),
        session=BucketConfig(capacity=10, refill_per_sec=1.0),
    )
    limiter = InProcessRateLimiter(default=default, per_tenant={"t1": override})
    # t1 is allowed 10; t2 falls back to default (1) and is exhausted after 1
    for _ in range(5):
        await limiter.acquire("t1", "sa")
    await limiter.acquire("t2", "sb")
    with pytest.raises(WazuhError):
        await limiter.acquire("t2", "sc")


@pytest.mark.asyncio
async def test_concurrent_acquire_race_safety() -> None:
    limiter = InProcessRateLimiter(default=_cfg(tenant_cap=100, session_cap=10))

    async def try_one() -> bool:
        try:
            await limiter.acquire("t1", "s1")
            return True
        except WazuhError:
            return False

    results = await asyncio.gather(*[try_one() for _ in range(50)])
    # Session bucket capped at 10, so exactly 10 succeed.
    assert sum(results) == 10
