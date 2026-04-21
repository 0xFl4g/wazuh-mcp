"""JWKS cache with discovery + refresh-on-unknown-kid.

One cache per MCP deployment (single IdP). TTL-bounded (10 min), refresh
happens on first miss. Further unknown-kid hits within the same TTL window
do NOT retrigger refresh - cost-capped at once per TTL.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx

DEFAULT_TTL_SECONDS = 600  # 10 minutes
DEFAULT_TIMEOUT = httpx.Timeout(connect=5.0, read=5.0, write=5.0, pool=5.0)


class JwksCache:
    __slots__ = (
        "_client",
        "_fetched_at",
        "_issuer",
        "_jwks_uri",
        "_keys",
        "_last_refresh_on_miss",
        "_lock",
        "_ttl",
    )

    def __init__(
        self,
        *,
        issuer: str,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        timeout: httpx.Timeout = DEFAULT_TIMEOUT,
    ) -> None:
        self._issuer: str = issuer.rstrip("/")
        self._jwks_uri: str | None = None
        self._keys: dict[str, dict[str, Any]] = {}
        self._fetched_at: float = 0.0
        self._ttl: int = ttl_seconds
        self._client: httpx.AsyncClient = httpx.AsyncClient(timeout=timeout)
        self._lock: asyncio.Lock = asyncio.Lock()
        self._last_refresh_on_miss: float = 0.0

    async def get_key(self, kid: str) -> dict[str, Any] | None:
        await self._ensure_discovered()
        if kid in self._keys:
            return self._keys[kid]
        # Unknown kid: allow at most one refresh per TTL window.
        now = time.monotonic()
        if now - self._last_refresh_on_miss >= self._ttl:
            self._last_refresh_on_miss = now
            await self._refresh()
        return self._keys.get(kid)

    async def _ensure_discovered(self) -> None:
        if self._jwks_uri is not None:
            return
        async with self._lock:
            if self._jwks_uri is not None:
                return
            disco_url = f"{self._issuer}/.well-known/openid-configuration"
            resp = await self._client.get(disco_url)
            if resp.status_code != 200:
                raise RuntimeError(f"OIDC discovery failed: {resp.status_code}")
            body = resp.json()
            jwks_uri = body.get("jwks_uri")
            if not jwks_uri:
                raise RuntimeError("OIDC discovery response missing jwks_uri")
            self._jwks_uri = jwks_uri
        await self._refresh()

    async def _refresh(self) -> None:
        async with self._lock:
            if self._jwks_uri is None:
                return
            resp = await self._client.get(self._jwks_uri)
            if resp.status_code != 200:
                return  # keep stale cache
            body = resp.json()
            new_keys = {k["kid"]: k for k in body.get("keys", []) if "kid" in k}
            self._keys = new_keys
            self._fetched_at = time.monotonic()

    async def aclose(self) -> None:
        await self._client.aclose()
