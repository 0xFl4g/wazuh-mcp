"""RedisRateLimiter and supporting circuit breaker.

The breaker is a per-process asyncio state machine that wraps every
Redis call. When OPEN, RedisRateLimiter.acquire() delegates to a
per-replica InProcessRateLimiter without touching Redis. T-C1 fills
out RedisRateLimiter; this file currently ships only the breaker.
"""

from __future__ import annotations

import asyncio
import enum
import logging
import time
from collections.abc import Awaitable, Callable
from typing import TypeVar

T = TypeVar("T")
_LOG = logging.getLogger(__name__)


class BreakerState(enum.IntEnum):
    CLOSED = 0
    HALF_OPEN = 1
    OPEN = 2


class CircuitBreakerOpenError(Exception):
    """Raised by _RedisCircuitBreaker.call() when the breaker is OPEN.

    Caller (RedisRateLimiter.acquire in T-C1) catches this and routes
    to the per-replica InProcessRateLimiter fallback.
    """


class _RedisCircuitBreaker:
    """Asyncio circuit breaker. Counts consecutive failures; opens on
    threshold; probes after open_duration_sec; closes on probe success.

    Per-process. One instance per RedisRateLimiter (one per replica).
    """

    def __init__(
        self,
        *,
        error_threshold: int,
        open_duration_sec: float,
        half_open_max_calls: int,
        call_timeout_ms: int,
        now: Callable[[], float] | None = None,
    ) -> None:
        if error_threshold < 1:
            raise ValueError("error_threshold must be >= 1")
        if open_duration_sec <= 0:
            raise ValueError("open_duration_sec must be > 0")
        if half_open_max_calls < 1:
            raise ValueError("half_open_max_calls must be >= 1")
        if call_timeout_ms <= 0:
            raise ValueError("call_timeout_ms must be > 0")
        self._error_threshold = error_threshold
        self._open_duration_sec = open_duration_sec
        self._half_open_max_calls = half_open_max_calls
        self._call_timeout = call_timeout_ms / 1000.0
        self._now = now or time.monotonic

        self._state: BreakerState = BreakerState.CLOSED
        self._consecutive_failures: int = 0
        self._opened_at: float | None = None
        self._half_open_in_flight: int = 0
        self._lock = asyncio.Lock()
        self.last_transition: tuple[BreakerState, BreakerState] | None = None

    @property
    def state(self) -> BreakerState:
        return self._state

    async def _transition(self, new_state: BreakerState) -> None:
        # Caller must hold self._lock.
        if new_state == self._state:
            return
        self.last_transition = (self._state, new_state)
        self._state = new_state
        if new_state == BreakerState.OPEN:
            self._opened_at = self._now()
            self._half_open_in_flight = 0
        elif new_state == BreakerState.CLOSED:
            self._consecutive_failures = 0
            self._opened_at = None
            self._half_open_in_flight = 0
        elif new_state == BreakerState.HALF_OPEN:
            self._half_open_in_flight = 0

    async def _maybe_promote_to_half_open(self) -> None:
        # Caller must hold self._lock.
        if self._state != BreakerState.OPEN:
            return
        if self._opened_at is None:
            return
        if self._now() - self._opened_at >= self._open_duration_sec:
            await self._transition(BreakerState.HALF_OPEN)

    async def call(self, fn: Callable[[], Awaitable[T]]) -> T:
        async with self._lock:
            await self._maybe_promote_to_half_open()
            current = self._state
            if current == BreakerState.OPEN:
                raise CircuitBreakerOpenError("breaker is OPEN")
            if current == BreakerState.HALF_OPEN:
                if self._half_open_in_flight >= self._half_open_max_calls:
                    raise CircuitBreakerOpenError("HALF_OPEN probe budget exhausted")
                self._half_open_in_flight += 1

        # Execute outside the lock so concurrent callers don't serialize on Redis I/O.
        try:
            result = await asyncio.wait_for(fn(), timeout=self._call_timeout)
        except Exception:  # every exception counts as a breaker failure
            await self._record_failure()
            raise

        await self._record_success()
        return result

    async def _record_success(self) -> None:
        async with self._lock:
            if self._state == BreakerState.HALF_OPEN:
                await self._transition(BreakerState.CLOSED)
            elif self._state == BreakerState.CLOSED:
                self._consecutive_failures = 0

    async def _record_failure(self) -> None:
        async with self._lock:
            if self._state == BreakerState.HALF_OPEN:
                await self._transition(BreakerState.OPEN)
                return
            if self._state == BreakerState.CLOSED:
                self._consecutive_failures += 1
                if self._consecutive_failures >= self._error_threshold:
                    await self._transition(BreakerState.OPEN)
