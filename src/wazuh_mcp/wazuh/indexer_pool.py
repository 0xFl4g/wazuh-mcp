"""Per-tenant IndexerClient pool.

Lazy-initialises one client per tenant_id on first acquire, shares that
client for every subsequent acquire of the same tenant, and closes them
all on shutdown. Credentials are fetched once per tenant via SecretStore.
"""

from __future__ import annotations

import asyncio

from wazuh_mcp.secrets.store import SecretStore
from wazuh_mcp.tenancy.registry import TenantRegistry
from wazuh_mcp.wazuh.indexer import IndexerClient


class IndexerClientPool:
    __slots__ = ("_clients", "_lock", "_registry", "_secrets")
    _clients: dict[str, IndexerClient]
    _lock: asyncio.Lock
    _registry: TenantRegistry
    _secrets: SecretStore

    def __init__(self, *, registry: TenantRegistry, secrets: SecretStore) -> None:
        self._registry = registry
        self._secrets = secrets
        self._clients = {}
        self._lock = asyncio.Lock()

    async def acquire(self, tenant_id: str) -> IndexerClient:
        if tenant_id in self._clients:
            return self._clients[tenant_id]
        async with self._lock:
            if tenant_id in self._clients:
                return self._clients[tenant_id]
            tenant = self._registry.get(tenant_id)  # KeyError if unknown
            user = await self._secrets.get(tenant_id, "indexer_user")
            password = await self._secrets.get(tenant_id, "indexer_password")
            client = IndexerClient(
                base_url=str(tenant.indexer_url),
                user=user,
                password=password,
                verify_tls=tenant.verify_tls,
                ca_bundle_path=tenant.ca_bundle_path,
            )
            self._clients[tenant_id] = client
            return client

    async def aclose_all(self) -> None:
        clients = list(self._clients.values())
        self._clients.clear()
        for c in clients:
            await c.aclose()
