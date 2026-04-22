"""Async HTTPX client for the Wazuh Server API (port 55000).

Responsibilities:
- Mint JWT via POST /security/user/authenticate with basic auth.
- Decode `exp` client-side (no signature check) to compute refresh timing.
- Proactively refresh at 80% of token lifetime.
- Retry-once on 401: mint a fresh JWT, replay the request. Second 401 is fatal.
- Per-request run_as attribution (URL query parameter).
- Scrub upstream errors via map_http_error / map_timeout.

Credential hygiene: basic-auth credentials live only on this instance. They
flow to Wazuh once per mint and never appear in logs, error paths, or
__repr__ output.

Concurrency: mint/refresh is serialised via an asyncio.Lock to prevent
mint stampedes when multiple callers race through token-expiry.
"""

from __future__ import annotations

import asyncio
import base64
import json
import time
from pathlib import Path
from typing import Any

import httpx

from wazuh_mcp.secrets.value import SecretValue
from wazuh_mcp.wazuh.errors import map_http_error, map_timeout

DEFAULT_TIMEOUT = httpx.Timeout(connect=5.0, read=30.0, write=10.0, pool=5.0)
REFRESH_AT_FRACTION = 0.80  # mint a new JWT once we've consumed 80% of lifetime
_AUTH_PATH = "/security/user/authenticate"


class ServerApiClient:
    def __init__(
        self,
        *,
        base_url: str,
        user: SecretValue,
        password: SecretValue,
        verify_tls: bool = True,
        ca_bundle_path: Path | None = None,
        timeout: httpx.Timeout = DEFAULT_TIMEOUT,
    ) -> None:
        verify: bool | str = str(ca_bundle_path) if ca_bundle_path else verify_tls
        # The mint call uses basic auth; subsequent calls use Authorization: Bearer.
        # Keep a single httpx.AsyncClient and swap the header per-request.
        self._client = httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            verify=verify,
            timeout=timeout,
            headers={"Content-Type": "application/json"},
        )
        self._user = user
        self._password = password
        self._token: str | None = None
        self._token_exp: float | None = None  # wall-clock seconds
        self._token_issued_at: float | None = None
        self._lock = asyncio.Lock()
        self._closed = False

    def __repr__(self) -> str:  # pragma: no cover — inspected only in error paths
        # Never leak the token or basic-auth credentials via repr.
        return f"ServerApiClient(base_url={self._client.base_url!r}, token=<redacted>)"

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True
        await self._client.aclose()

    # ---- Public HTTP methods ----

    async def get(
        self,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        run_as: str | None = None,
    ) -> dict[str, Any]:
        return await self._request("GET", path, params=params, run_as=run_as)

    async def post(
        self,
        path: str,
        *,
        json: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        run_as: str | None = None,
    ) -> dict[str, Any]:
        return await self._request("POST", path, json=json, params=params, run_as=run_as)

    # ---- Internal ----

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
        run_as: str | None = None,
    ) -> dict[str, Any]:
        token = await self._ensure_jwt()
        effective_params = dict(params or {})
        if run_as is not None:
            effective_params["run_as"] = run_as

        def _do(jwt: str) -> httpx.Request:
            return self._client.build_request(
                method,
                path,
                params=effective_params or None,
                json=json,
                headers={"Authorization": f"Bearer {jwt}"},
            )

        try:
            resp = await self._client.send(_do(token))
        except httpx.TimeoutException as e:
            raise map_timeout() from e

        if resp.status_code == 401:
            # Retry-once: mint fresh, replay. Second 401 surfaces auth_expired.
            token = await self._refresh_jwt_force()
            try:
                resp = await self._client.send(_do(token))
            except httpx.TimeoutException as e:
                raise map_timeout() from e

        if resp.status_code >= 400:
            raise map_http_error(resp)
        return resp.json()

    async def _ensure_jwt(self) -> str:
        async with self._lock:
            now = time.monotonic()
            if self._token and self._token_issued_at and self._token_exp:
                lifetime = self._token_exp - self._token_issued_at
                consumed = now - self._token_issued_at
                if consumed < lifetime * REFRESH_AT_FRACTION:
                    return self._token
            return await self._mint_locked()

    async def _refresh_jwt_force(self) -> str:
        async with self._lock:
            return await self._mint_locked()

    async def _mint_locked(self) -> str:
        try:
            resp = await self._client.post(
                _AUTH_PATH,
                auth=(self._user.expose(), self._password.expose()),
            )
        except httpx.TimeoutException as e:
            raise map_timeout() from e
        if resp.status_code >= 400:
            raise map_http_error(resp)

        body = resp.json()
        token = body.get("data", {}).get("token")
        if not isinstance(token, str) or not token:
            # Upstream returned 200 but malformed body; surface as upstream_error
            # rather than leaking the body.
            raise map_http_error(httpx.Response(500))

        self._token = token
        self._token_issued_at = time.monotonic()
        self._token_exp = self._token_issued_at + self._parse_exp_seconds(token)
        return token

    @staticmethod
    def _parse_exp_seconds(token: str) -> float:
        """Decode JWT exp claim client-side. Returns seconds-from-issuance
        (i.e. the token's nominal lifetime). Signature is not verified — we
        only use this to schedule refresh, never for access decisions.

        Falls back to 15 minutes on any parse failure: matches Wazuh's
        documented default and is safer than assuming no expiry.
        """
        try:
            _header_b64, payload_b64, _sig_b64 = token.split(".", 2)
            pad = "=" * (-len(payload_b64) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64 + pad))
            exp = payload.get("exp")
            iat = payload.get("iat", time.time())
            if not isinstance(exp, int | float):
                return 900.0
            lifetime = float(exp) - float(iat)
            if lifetime <= 0:
                return 900.0
            return lifetime
        except Exception:
            return 900.0
