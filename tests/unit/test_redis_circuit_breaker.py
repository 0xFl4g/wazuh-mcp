"""_RedisCircuitBreaker state machine unit tests.

Pure asyncio state machine — no Redis. Tests inject an async callable
that can be flipped to succeed / fail / hang to drive transitions.
"""

from __future__ import annotations

import asyncio

import pytest

from wazuh_mcp.rate_limit.redis_limiter import (
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
    breaker = _RedisCircuitBreaker(**_bcfg())
    counter = _Counter()
    assert await breaker.call(counter) == 42
    assert counter.calls == 1
    assert breaker.state == BreakerState.CLOSED


@pytest.mark.asyncio
async def test_closed_to_open_after_threshold_consecutive_failures() -> None:
    breaker = _RedisCircuitBreaker(**_bcfg(error_threshold=3))
    counter = _Counter()
    counter.should_fail = True
    for _ in range(3):
        with pytest.raises(RuntimeError):
            await breaker.call(counter)
    assert breaker.state == BreakerState.OPEN


@pytest.mark.asyncio
async def test_success_resets_failure_counter() -> None:
    breaker = _RedisCircuitBreaker(**_bcfg(error_threshold=3))
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
    breaker = _RedisCircuitBreaker(**_bcfg(error_threshold=2))
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
    breaker = _RedisCircuitBreaker(**_bcfg(error_threshold=2, open_duration_sec=0.05))
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
    breaker = _RedisCircuitBreaker(**_bcfg(error_threshold=2, open_duration_sec=0.05))
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
    breaker = _RedisCircuitBreaker(**_bcfg(error_threshold=2, call_timeout_ms=20))
    counter = _Counter()
    counter.should_hang = True
    for _ in range(2):
        with pytest.raises(asyncio.TimeoutError):
            await breaker.call(counter)
    assert breaker.state == BreakerState.OPEN


@pytest.mark.asyncio
async def test_concurrent_calls_under_closed_state() -> None:
    breaker = _RedisCircuitBreaker(**_bcfg())
    counter = _Counter()
    results = await asyncio.gather(*(breaker.call(counter) for _ in range(10)))
    assert results == [42] * 10
    assert counter.calls == 10
    assert breaker.state == BreakerState.CLOSED


@pytest.mark.asyncio
async def test_state_transitions_recorded_for_observability() -> None:
    breaker = _RedisCircuitBreaker(**_bcfg(error_threshold=2))
    counter = _Counter()
    counter.should_fail = True
    for _ in range(2):
        with pytest.raises(RuntimeError):
            await breaker.call(counter)
    assert breaker.last_transition is not None
    from_state, to_state = breaker.last_transition
    assert from_state == BreakerState.CLOSED
    assert to_state == BreakerState.OPEN


@pytest.mark.asyncio
async def test_half_open_admits_up_to_max_calls_then_rejects() -> None:
    """With half_open_max_calls=2, exactly 2 concurrent probes get admitted; the third is rejected."""
    breaker = _RedisCircuitBreaker(
        **_bcfg(
            error_threshold=2, open_duration_sec=0.05, half_open_max_calls=2, call_timeout_ms=200
        )
    )
    counter = _Counter()
    counter.should_fail = True
    for _ in range(2):
        with pytest.raises(RuntimeError):
            await breaker.call(counter)
    assert breaker.state == BreakerState.OPEN
    await asyncio.sleep(0.06)

    # Block the probe so we can observe HALF_OPEN admission counting.
    counter.should_fail = False
    block_event = asyncio.Event()

    async def slow_probe() -> int:
        await block_event.wait()
        return 1

    # Admit two probes (the budget). They both proceed to wait on block_event.
    t1 = asyncio.create_task(breaker.call(slow_probe))
    t2 = asyncio.create_task(breaker.call(slow_probe))
    await asyncio.sleep(0.01)  # let them grab the budget

    # Third concurrent call should be rejected with CircuitBreakerOpenError —
    # budget exhausted in HALF_OPEN.
    with pytest.raises(CircuitBreakerOpenError):
        await breaker.call(slow_probe)

    # Release the two probes; on success both → CLOSED.
    block_event.set()
    await t1
    await t2
    assert breaker.state == BreakerState.CLOSED


@pytest.mark.asyncio
async def test_half_open_concurrent_failures_refresh_opened_at() -> None:
    """Reviewer-fix path (a1100f0): a stale probe failure landing in OPEN refreshes _opened_at.

    Drives two concurrent probes in HALF_OPEN, both fail. The second
    failure arrives after the first already transitioned to OPEN; the
    second's _record_failure must refresh _opened_at instead of being
    a no-op.
    """
    clock = [0.0]

    def fake_now() -> float:
        return clock[0]

    breaker = _RedisCircuitBreaker(
        error_threshold=2,
        open_duration_sec=0.05,
        half_open_max_calls=2,
        call_timeout_ms=200,
        now=fake_now,
    )
    counter = _Counter()
    counter.should_fail = True
    # Trip the breaker.
    for _ in range(2):
        with pytest.raises(RuntimeError):
            await breaker.call(counter)
    assert breaker.state == BreakerState.OPEN

    # Advance clock past open_duration so next call promotes to HALF_OPEN.
    clock[0] = 1.0
    # First HALF_OPEN failure transitions to OPEN at clock=1.0.
    with pytest.raises(RuntimeError):
        await breaker.call(counter)
    assert breaker.state == BreakerState.OPEN
    first_opened = breaker._opened_at

    # Advance clock; force a stale probe failure to land while OPEN.
    clock[0] = 2.0
    # The breaker is OPEN with _opened_at=1.0; calling now would raise CircuitBreakerOpenError
    # before reaching fn. Drive _record_failure directly to simulate the stale-probe race.
    await breaker._record_failure()

    # _opened_at must be refreshed to clock=2.0, not stuck at 1.0.
    assert breaker._opened_at == 2.0
    assert breaker._opened_at != first_opened
