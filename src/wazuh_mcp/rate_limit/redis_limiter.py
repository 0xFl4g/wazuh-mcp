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
import math
import socket
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import TypeVar

from redis.asyncio import Redis as AsyncRedis
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import NoScriptError
from redis.exceptions import TimeoutError as RedisTimeoutError

from wazuh_mcp.rate_limit.limiter import InProcessRateLimiter
from wazuh_mcp.tenancy.m4_config import BucketConfig, RateLimitConfig
from wazuh_mcp.wazuh.errors import WazuhError

T = TypeVar("T")
_LOG = logging.getLogger(__name__)
_LUA_PATH = Path(__file__).parent / "lua" / "token_bucket.lua"


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
        try:
            from wazuh_mcp.observability.metrics import m4_counters

            m4_counters()["rate_limit_redis_state"].set(
                int(new_state), {"replica": socket.gethostname()}
            )
        except Exception:
            # Metrics never break business logic.
            _LOG.debug("rate_limit_redis_state metric emission failed", exc_info=True)
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
                return
            # OPEN: a stale in-flight probe from the previous HALF_OPEN window
            # failed after a concurrent failure already re-opened. Refresh
            # _opened_at so the cooling period restarts from the latest signal
            # rather than the first one.
            self._opened_at = self._now()


def _ttl_for(cfg: RateLimitConfig) -> int:
    """TTL seconds = max(2 * full_refill_window, 60).

    full_refill_window = capacity / refill_per_sec. Use the longer of
    tenant and session refill windows so both buckets get a survivable TTL.
    """
    windows = [
        cfg.tenant.capacity / cfg.tenant.refill_per_sec,
        cfg.session.capacity / cfg.session.refill_per_sec,
    ]
    return max(math.ceil(2 * max(windows)), 60)


class RedisRateLimiter:
    """Two-tier token-bucket limiter backed by Redis with breaker fallback.

    Implements the RateLimiter Protocol. acquire() runs the Lua script
    against tenant + session bucket keys; raises WazuhError(rate_limited)
    on budget exhaustion (same behavior as InProcessRateLimiter).

    On Redis call failure (timeout, ConnectionError, server error), the
    circuit breaker counts the failure and routes the call to a
    per-process InProcessRateLimiter fallback that is lazy-constructed
    on first OPEN transition and kept warm.
    """

    def __init__(
        self,
        *,
        redis_client: AsyncRedis,
        default: RateLimitConfig,
        per_tenant: dict[str, RateLimitConfig] | None = None,
        key_prefix: str,
        breaker: _RedisCircuitBreaker,
        now_ms: Callable[[], int] | None = None,
    ) -> None:
        self._redis = redis_client
        self._default = default
        self._per_tenant = per_tenant or {}
        self._key_prefix = key_prefix
        self._breaker = breaker
        self._now_ms = now_ms or (lambda: int(time.time() * 1000))
        self._script_text = _LUA_PATH.read_text(encoding="utf-8")
        self._script_sha: str | None = None
        self._fallback: InProcessRateLimiter | None = None

    def _cfg(self, tenant_id: str) -> RateLimitConfig:
        return self._per_tenant.get(tenant_id, self._default)

    def _tenant_key(self, tenant_id: str) -> str:
        return f"{self._key_prefix}:tenant:{tenant_id}"

    def _session_key(self, tenant_id: str, session_id: str) -> str:
        return f"{self._key_prefix}:session:{tenant_id}:{session_id}"

    def _ensure_fallback(self) -> InProcessRateLimiter:
        if self._fallback is None:
            self._fallback = InProcessRateLimiter(
                default=self._default,
                per_tenant=self._per_tenant,
            )
        return self._fallback

    async def _load_script(self) -> str:
        # redis-py stubs annotate script_load as returning Awaitable[str] | str
        sha = await self._redis.script_load(self._script_text)
        self._script_sha = sha
        return sha

    async def _evalsha(
        self, sha: str, key: str, capacity: int, refill: float, n: int, ttl: int
    ) -> int:
        # redis-py stubs return Awaitable[str] | str; evalsha args are str on the wire
        result = await self._redis.evalsha(  # ty:ignore[invalid-await]
            sha, 1, key, str(capacity), str(refill), str(self._now_ms()), str(n), str(ttl)
        )
        return int(result)

    async def _run_script(self, key: str, capacity: int, refill: float, n: int, ttl: int) -> int:
        sha = self._script_sha if self._script_sha is not None else await self._load_script()
        try:
            return await self._evalsha(sha, key, capacity, refill, n, ttl)
        except NoScriptError:
            sha = await self._load_script()
            return await self._evalsha(sha, key, capacity, refill, n, ttl)

    async def _try_redis_acquire(self, key: str, cfg_bucket: BucketConfig, ttl: int) -> bool:
        from wazuh_mcp.observability.metrics import m4_counters

        counters = m4_counters()
        try:
            result = await self._run_script(
                key=key,
                capacity=cfg_bucket.capacity,
                refill=cfg_bucket.refill_per_sec,
                n=1,
                ttl=ttl,
            )
            counters["rate_limit_redis_call_total"].add(1, {"outcome": "ok"})
            return result == 1
        except (RedisTimeoutError, TimeoutError):
            counters["rate_limit_redis_call_total"].add(1, {"outcome": "timeout"})
            raise
        except Exception:
            counters["rate_limit_redis_call_total"].add(1, {"outcome": "error"})
            raise

    async def acquire(self, tenant_id: str, session_id: str) -> None:
        cfg = self._cfg(tenant_id)
        ttl = _ttl_for(cfg)
        tenant_key = self._tenant_key(tenant_id)
        session_key = self._session_key(tenant_id, session_id)

        try:
            granted = await self._breaker.call(
                lambda: self._try_redis_acquire(tenant_key, cfg.tenant, ttl)
            )
        except CircuitBreakerOpenError:
            from wazuh_mcp.observability.metrics import m4_counters

            m4_counters()["rate_limit_fallback_total"].add(
                1, {"tenant_id": tenant_id, "scope": "tenant"}
            )
            await self._ensure_fallback().acquire(tenant_id, session_id)
            return
        except (RedisConnectionError, RedisTimeoutError, TimeoutError):
            from wazuh_mcp.observability.metrics import m4_counters

            m4_counters()["rate_limit_fallback_total"].add(
                1, {"tenant_id": tenant_id, "scope": "tenant"}
            )
            _LOG.debug("rate_limit_redis_call_failed", exc_info=True)
            await self._ensure_fallback().acquire(tenant_id, session_id)
            return

        if not granted:
            raise WazuhError(
                "rate_limited",
                "tenant rate limit exceeded",
                429,
                scope="rate_limit:tenant",
            )

        try:
            granted = await self._breaker.call(
                lambda: self._try_redis_acquire(session_key, cfg.session, ttl)
            )
        except CircuitBreakerOpenError:
            from wazuh_mcp.observability.metrics import m4_counters

            m4_counters()["rate_limit_fallback_total"].add(
                1, {"tenant_id": tenant_id, "scope": "session"}
            )
            await self._ensure_fallback().acquire(tenant_id, session_id)
            return
        except (RedisConnectionError, RedisTimeoutError, TimeoutError):
            from wazuh_mcp.observability.metrics import m4_counters

            m4_counters()["rate_limit_fallback_total"].add(
                1, {"tenant_id": tenant_id, "scope": "session"}
            )
            _LOG.debug("rate_limit_redis_call_failed", exc_info=True)
            await self._ensure_fallback().acquire(tenant_id, session_id)
            return

        if not granted:
            raise WazuhError(
                "rate_limited",
                "session rate limit exceeded",
                429,
                scope="rate_limit:session",
            )
