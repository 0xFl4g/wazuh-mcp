"""_RedisCircuitBreaker state machine unit tests.

Pure asyncio state machine — no Redis. Tests inject an async callable
that can be flipped to succeed / fail / hang to drive transitions.
"""

from __future__ import annotations

import asyncio

import pytest
from wazuh_mcp.rate_limit.redis_limiter import (  # ty: ignore  (until T-B2)
    BreakerState,
    CircuitBreakerOpenError,
    _RedisCircuitBreaker,
)


def _bcfg(
    *,
    error_threshold: int = 3,
    open_duration_sec: float = 0.05,
    half_open_max_calls: int = 1,
    call_timeout_ms: int = 50,
) -> dict[str, object]:
    return {
        "error_threshold": error_threshold,
        "open_duration_sec": open_duration_sec,
        "half_open_max_calls": half_open_max_calls,
        "call_timeout_ms": call_timeout_ms,
    }


class _Counter:
    """Stateful test fixture: caller flips .should_fail to control behavior."""

    def __init__(self) -> None:
        self.calls = 0
        self.should_fail = False
        self.should_hang = False

    async def __call__(self) -> int:
        self.calls += 1
        if self.should_hang:
            await asyncio.sleep(10)
        if self.should_fail:
            raise RuntimeError("simulated failure")
        return 42


@pytest.mark.asyncio
async def test_closed_passes_call_through() -> None:
    breaker = _RedisCircuitBreaker(**_bcfg())  # ty: ignore
    counter = _Counter()
    assert await breaker.call(counter) == 42
    assert counter.calls == 1
    assert breaker.state == BreakerState.CLOSED


@pytest.mark.asyncio
async def test_closed_to_open_after_threshold_consecutive_failures() -> None:
    breaker = _RedisCircuitBreaker(**_bcfg(error_threshold=3))  # ty: ignore
    counter = _Counter()
    counter.should_fail = True
    for _ in range(3):
        with pytest.raises(RuntimeError):
            await breaker.call(counter)
    assert breaker.state == BreakerState.OPEN


@pytest.mark.asyncio
async def test_success_resets_failure_counter() -> None:
    breaker = _RedisCircuitBreaker(**_bcfg(error_threshold=3))  # ty: ignore
    counter = _Counter()
    counter.should_fail = True
    for _ in range(2):
        with pytest.raises(RuntimeError):
            await breaker.call(counter)
    counter.should_fail = False
    await breaker.call(counter)  # success resets counter
    counter.should_fail = True
    for _ in range(2):
        with pytest.raises(RuntimeError):
            await breaker.call(counter)
    assert breaker.state == BreakerState.CLOSED


@pytest.mark.asyncio
async def test_open_raises_circuit_open_without_calling() -> None:
    breaker = _RedisCircuitBreaker(**_bcfg(error_threshold=2))  # ty: ignore
    counter = _Counter()
    counter.should_fail = True
    for _ in range(2):
        with pytest.raises(RuntimeError):
            await breaker.call(counter)
    assert breaker.state == BreakerState.OPEN
    counter.calls = 0
    counter.should_fail = False
    with pytest.raises(CircuitBreakerOpenError):
        await breaker.call(counter)
    assert counter.calls == 0


@pytest.mark.asyncio
async def test_open_to_half_open_after_open_duration() -> None:
    breaker = _RedisCircuitBreaker(**_bcfg(error_threshold=2, open_duration_sec=0.05))  # ty: ignore
    counter = _Counter()
    counter.should_fail = True
    for _ in range(2):
        with pytest.raises(RuntimeError):
            await breaker.call(counter)
    assert breaker.state == BreakerState.OPEN
    await asyncio.sleep(0.06)
    counter.should_fail = False
    assert await breaker.call(counter) == 42
    assert breaker.state == BreakerState.CLOSED


@pytest.mark.asyncio
async def test_half_open_failure_reopens_breaker() -> None:
    breaker = _RedisCircuitBreaker(**_bcfg(error_threshold=2, open_duration_sec=0.05))  # ty: ignore
    counter = _Counter()
    counter.should_fail = True
    for _ in range(2):
        with pytest.raises(RuntimeError):
            await breaker.call(counter)
    await asyncio.sleep(0.06)
    with pytest.raises(RuntimeError):
        await breaker.call(counter)
    assert breaker.state == BreakerState.OPEN


@pytest.mark.asyncio
async def test_call_timeout_counts_as_failure() -> None:
    breaker = _RedisCircuitBreaker(**_bcfg(error_threshold=2, call_timeout_ms=20))  # ty: ignore
    counter = _Counter()
    counter.should_hang = True
    for _ in range(2):
        with pytest.raises(asyncio.TimeoutError):
            await breaker.call(counter)
    assert breaker.state == BreakerState.OPEN


@pytest.mark.asyncio
async def test_concurrent_calls_under_closed_state() -> None:
    breaker = _RedisCircuitBreaker(**_bcfg())  # ty: ignore
    counter = _Counter()
    results = await asyncio.gather(*(breaker.call(counter) for _ in range(10)))
    assert results == [42] * 10
    assert counter.calls == 10
    assert breaker.state == BreakerState.CLOSED


@pytest.mark.asyncio
async def test_state_transitions_recorded_for_observability() -> None:
    breaker = _RedisCircuitBreaker(**_bcfg(error_threshold=2))  # ty: ignore
    counter = _Counter()
    counter.should_fail = True
    for _ in range(2):
        with pytest.raises(RuntimeError):
            await breaker.call(counter)
    assert breaker.last_transition is not None
    from_state, to_state = breaker.last_transition
    assert from_state == BreakerState.CLOSED
    assert to_state == BreakerState.OPEN
