"""Per-tenant pool for ServerApiClient. Mirrors IndexerClientPool.

Lazy, server-lifetime, idempotent close. Pool entries are keyed by
tenant_id and shared across concurrent requests for the same tenant.
"""

from __future__ import annotations

import asyncio

from wazuh_mcp.secrets.store import SecretStore
from wazuh_mcp.tenancy.config import TenantConfig
from wazuh_mcp.tenancy.registry import TenantRegistry
from wazuh_mcp.wazuh.server_api import ServerApiClient


class ServerApiClientPool:
    def __init__(self, *, registry: TenantRegistry, secrets: SecretStore) -> None:
        self._registry = registry
        self._secrets = secrets
        self._clients: dict[str, ServerApiClient] = {}
        self._lock = asyncio.Lock()
        self._closed = False

    async def acquire(self, tenant_id: str) -> ServerApiClient:
        async with self._lock:
            if self._closed:
                raise RuntimeError("ServerApiClientPool closed")
            existing = self._clients.get(tenant_id)
            if existing is not None:
                return existing
            tenant: TenantConfig = self._registry.get(tenant_id)
            user = await self._secrets.get(tenant_id, "server_api_user")
            password = await self._secrets.get(tenant_id, "server_api_password")
            # Server API lives alongside the indexer in practice. TenantConfig
            # carries indexer_url; Server API base defaults to the same host
            # on port 55000 unless overridden via server_api_url (future).
            base_url = self._derive_server_api_url(tenant)
            client = ServerApiClient(
                base_url=base_url,
                user=user,
                password=password,
                verify_tls=tenant.verify_tls,
                ca_bundle_path=tenant.ca_bundle_path,
            )
            self._clients[tenant_id] = client
            return client

    async def aclose(self) -> None:
        async with self._lock:
            if self._closed:
                return
            self._closed = True
            for client in self._clients.values():
                await client.aclose()
            self._clients.clear()

    @staticmethod
    def _derive_server_api_url(tenant: TenantConfig) -> str:
        # Derive Server API base from indexer_url by swapping port 9200 -> 55000.
        # Operators with a non-standard deployment can override via a future
        # TenantConfig.server_api_url field (out of scope for M3).
        u = str(tenant.indexer_url).rstrip("/")
        # Simple substring swap is safe because the indexer always uses 9200.
        if ":9200" in u:
            return u.replace(":9200", ":55000")
        # No explicit port - append 55000 on the same host.
        return u + ":55000"
