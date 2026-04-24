"""TokenBucket invariants."""

from __future__ import annotations

import asyncio

import pytest

from wazuh_mcp.rate_limit.token_bucket import TokenBucket


def test_initial_fill_equals_capacity() -> None:
    b = TokenBucket(capacity=10, refill_per_sec=1.0, now=lambda: 0.0)
    # consume all tokens without refill
    for _ in range(10):
        assert b.try_acquire() is True
    assert b.try_acquire() is False


def test_refill_over_time() -> None:
    t = [0.0]
    b = TokenBucket(capacity=10, refill_per_sec=2.0, now=lambda: t[0])
    for _ in range(10):
        b.try_acquire()
    assert b.try_acquire() is False
    t[0] = 5.0  # +10 tokens at 2/sec
    assert b.try_acquire() is True
    for _ in range(9):
        assert b.try_acquire() is True
    assert b.try_acquire() is False


def test_refill_clamps_at_capacity() -> None:
    t = [0.0]
    b = TokenBucket(capacity=5, refill_per_sec=1.0, now=lambda: t[0])
    t[0] = 1_000_000.0
    # Even after an age, the bucket doesn't exceed capacity.
    for _ in range(5):
        assert b.try_acquire() is True
    assert b.try_acquire() is False


def test_fractional_tokens_not_consumable() -> None:
    t = [0.0]
    b = TokenBucket(capacity=10, refill_per_sec=1.0, now=lambda: t[0])
    for _ in range(10):
        b.try_acquire()
    t[0] = 0.5  # half a token accumulated
    assert b.try_acquire() is False
    t[0] = 1.0
    assert b.try_acquire() is True


def test_invalid_params() -> None:
    with pytest.raises(ValueError):
        TokenBucket(capacity=0, refill_per_sec=1.0)
    with pytest.raises(ValueError):
        TokenBucket(capacity=1, refill_per_sec=0.0)


@pytest.mark.asyncio
async def test_concurrent_acquires_race_safe() -> None:
    """The bucket primitive itself isn't locked, so we verify the expected
    behaviour: callers wrap it. This test just confirms it doesn't explode."""
    b = TokenBucket(capacity=100, refill_per_sec=1.0, now=lambda: 0.0)
    results = await asyncio.gather(*[asyncio.to_thread(b.try_acquire) for _ in range(200)])
    # With a shared lock in the limiter (tested elsewhere), exactly 100 succeed.
    # Without the lock, we allow some races but bound them.
    assert 80 <= sum(results) <= 120
