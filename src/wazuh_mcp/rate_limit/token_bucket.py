"""TokenBucket primitive — pure, unlocked, time-injectable for tests.

Consumers (RateLimiter) wrap it under a lock for thread/async safety.
"""

from __future__ import annotations

import time
from collections.abc import Callable


class TokenBucket:
    __slots__ = ("_capacity", "_last", "_now", "_refill", "_tokens")

    def __init__(
        self,
        *,
        capacity: int,
        refill_per_sec: float,
        now: Callable[[], float] | None = None,
    ) -> None:
        if capacity <= 0:
            raise ValueError("capacity must be > 0")
        if refill_per_sec <= 0:
            raise ValueError("refill_per_sec must be > 0")
        self._capacity = capacity
        self._refill = refill_per_sec
        self._now = now or time.monotonic
        self._tokens: float = float(capacity)
        self._last: float = self._now()

    def _refresh(self) -> None:
        now = self._now()
        elapsed = now - self._last
        if elapsed > 0:
            self._tokens = min(
                float(self._capacity), self._tokens + elapsed * self._refill
            )
        self._last = now

    def try_acquire(self, n: int = 1) -> bool:
        self._refresh()
        if self._tokens >= n:
            self._tokens -= n
            return True
        return False
