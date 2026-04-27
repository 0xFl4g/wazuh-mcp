"""Per-tenant rate-limiter behavior pinning (M4d T2).

Verifies InProcessRateLimiter.per_tenant works as advertised: tenant_a's
bucket exhaustion does not affect tenant_b; per-tenant cfg overrides
default; absent tenant_id falls through to default.
"""

from __future__ import annotations

import pytest

from wazuh_mcp.rate_limit.limiter import InProcessRateLimiter
from wazuh_mcp.tenancy.m4_config import BucketConfig, RateLimitConfig
from wazuh_mcp.wazuh.errors import WazuhError


def _cfg(tenant_capacity: int = 10, session_capacity: int = 10) -> RateLimitConfig:
    """Build a RateLimitConfig with refill so slow it's effectively a fixed cap.

    BucketConfig requires refill_per_sec > 0; 0.001 tokens/sec means a sub-second
    test never gains a whole token back, so capacity behaves as a hard cap.
    """
    return RateLimitConfig(
        tenant=BucketConfig(capacity=tenant_capacity, refill_per_sec=0.001),
        session=BucketConfig(capacity=session_capacity, refill_per_sec=0.001),
    )


@pytest.mark.asyncio
async def test_per_tenant_capacity_overrides_default() -> None:
    """tenant_a configured with capacity=2; default capacity=100. tenant_a
    hits its cap after 2 calls; default-only tenants do not."""
    limiter = InProcessRateLimiter(
        default=_cfg(tenant_capacity=100, session_capacity=100),
        per_tenant={"tenant_a": _cfg(tenant_capacity=2, session_capacity=100)},
    )

    # tenant_a: 2 succeed, 3rd raises rate_limited.
    await limiter.acquire("tenant_a", "alice")
    await limiter.acquire("tenant_a", "alice")
    with pytest.raises(WazuhError) as exc_info:
        await limiter.acquire("tenant_a", "alice")
    assert exc_info.value.code == "rate_limited"


@pytest.mark.asyncio
async def test_tenant_a_exhaustion_does_not_block_tenant_b() -> None:
    """The headline M4d invariant: per-tenant token-bucket isolation."""
    limiter = InProcessRateLimiter(
        default=_cfg(tenant_capacity=2, session_capacity=100),
        per_tenant={
            "tenant_a": _cfg(tenant_capacity=2, session_capacity=100),
            "tenant_b": _cfg(tenant_capacity=2, session_capacity=100),
        },
    )

    # Burn tenant_a's bucket entirely.
    await limiter.acquire("tenant_a", "alice")
    await limiter.acquire("tenant_a", "alice")
    with pytest.raises(WazuhError):
        await limiter.acquire("tenant_a", "alice")

    # tenant_b is unaffected.
    await limiter.acquire("tenant_b", "bob")
    await limiter.acquire("tenant_b", "bob")


@pytest.mark.asyncio
async def test_unknown_tenant_falls_through_to_default() -> None:
    """When per_tenant doesn't have an entry, default cfg applies."""
    limiter = InProcessRateLimiter(
        default=_cfg(tenant_capacity=3, session_capacity=100),
        per_tenant={"tenant_a": _cfg(tenant_capacity=1, session_capacity=100)},
    )

    # tenant_unknown uses default (capacity=3): 3 succeed.
    await limiter.acquire("tenant_unknown", "alice")
    await limiter.acquire("tenant_unknown", "alice")
    await limiter.acquire("tenant_unknown", "alice")
    with pytest.raises(WazuhError):
        await limiter.acquire("tenant_unknown", "alice")


@pytest.mark.asyncio
async def test_session_buckets_are_per_tenant_session_pair() -> None:
    """Two sessions on same tenant share tenant bucket but have independent
    session buckets. Two sessions across tenants share neither."""
    limiter = InProcessRateLimiter(
        default=_cfg(tenant_capacity=100, session_capacity=2),
    )

    # session_a on tenant_a: burn its session bucket.
    await limiter.acquire("tenant_a", "session_a")
    await limiter.acquire("tenant_a", "session_a")
    with pytest.raises(WazuhError):
        await limiter.acquire("tenant_a", "session_a")

    # session_b on tenant_a: independent session bucket; succeeds.
    await limiter.acquire("tenant_a", "session_b")
    await limiter.acquire("tenant_a", "session_b")


@pytest.mark.asyncio
async def test_no_per_tenant_arg_falls_through_to_default() -> None:
    """Backwards-compat: limiter constructed with only default kwarg works
    identically to today's behavior — every tenant gets default cfg."""
    limiter = InProcessRateLimiter(default=_cfg(tenant_capacity=2, session_capacity=100))

    await limiter.acquire("tenant_a", "alice")
    await limiter.acquire("tenant_a", "alice")
    with pytest.raises(WazuhError):
        await limiter.acquire("tenant_a", "alice")
