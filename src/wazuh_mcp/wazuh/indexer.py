"""Async HTTPX client for the Wazuh Indexer (OpenSearch REST, port 9200).

Responsibilities in M1:
- Basic auth from SecretValue (never logged)
- TLS verification (with optional CA bundle)
- POST _search
- Map upstream errors to safe codes
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx

from wazuh_mcp.secrets.value import SecretValue
from wazuh_mcp.wazuh.errors import map_http_error

DEFAULT_TIMEOUT = httpx.Timeout(connect=5.0, read=30.0, write=10.0, pool=5.0)


class IndexerClient:
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
        self._client = httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            auth=(user.expose(), password.expose()),
            verify=verify,
            timeout=timeout,
            headers={"Content-Type": "application/json"},
        )
        self._closed = False

    async def search(self, *, index: str, query: dict[str, Any]) -> dict[str, Any]:
        # Defense in depth: reject path-traversal or slash injection. httpx
        # normalises "/../_nodes" into "/_nodes" before sending, so even a
        # well-meaning caller handing a raw user string could silently hit a
        # different endpoint.
        if not index or "/" in index or ".." in index:
            raise ValueError("invalid index name")
        resp = await self._client.post(f"/{index}/_search", json=query)
        if resp.status_code >= 400:
            raise map_http_error(resp)
        return resp.json()

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True
        await self._client.aclose()
