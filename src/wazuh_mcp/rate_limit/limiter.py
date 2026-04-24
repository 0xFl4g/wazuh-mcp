"""RateLimiter protocol and in-process implementation.

Scope: tenant bucket protects Wazuh's 300/min Server API cap;
session bucket isolates one rogue session from starving siblings.
Every tool call consumes exactly 1 token from both buckets.

Failure mode: fail-closed — raise WazuhError(code="rate_limited").
Caller (@instrumented_tool) emits the rate_limited_total metric with
scope label.

Single-process today. External (Redis) implementation can slot in as a
different class implementing the same protocol.
"""

from __future__ import annotations

import asyncio
from typing import Protocol

from wazuh_mcp.rate_limit.token_bucket import TokenBucket
from wazuh_mcp.tenancy.m4_config import BucketConfig, RateLimitConfig
from wazuh_mcp.wazuh.errors import WazuhError


class RateLimiter(Protocol):
    async def acquire(self, tenant_id: str, session_id: str) -> None: ...


def _mk_bucket(cfg: BucketConfig) -> TokenBucket:
    return TokenBucket(capacity=cfg.capacity, refill_per_sec=cfg.refill_per_sec)


class InProcessRateLimiter:
    def __init__(
        self,
        *,
        default: RateLimitConfig,
        per_tenant: dict[str, RateLimitConfig] | None = None,
    ) -> None:
        self._default = default
        self._per_tenant = per_tenant or {}
        self._tenant_buckets: dict[str, TokenBucket] = {}
        self._session_buckets: dict[tuple[str, str], TokenBucket] = {}
        self._lock = asyncio.Lock()

    def _cfg(self, tenant_id: str) -> RateLimitConfig:
        return self._per_tenant.get(tenant_id, self._default)

    async def acquire(self, tenant_id: str, session_id: str) -> None:
        async with self._lock:
            cfg = self._cfg(tenant_id)
            tbucket = self._tenant_buckets.setdefault(tenant_id, _mk_bucket(cfg.tenant))
            if not tbucket.try_acquire():
                raise WazuhError("rate_limited", "tenant rate limit exceeded", 429)
            skey = (tenant_id, session_id)
            sbucket = self._session_buckets.setdefault(skey, _mk_bucket(cfg.session))
            if not sbucket.try_acquire():
                raise WazuhError("rate_limited", "session rate limit exceeded", 429)
