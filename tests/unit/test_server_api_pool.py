"""ServerApiClientPool - per-tenant lazy-init and close semantics."""

import pytest

from wazuh_mcp.secrets.value import SecretValue
from wazuh_mcp.tenancy.config import TenantConfig
from wazuh_mcp.wazuh.server_api_pool import ServerApiClientPool


class _FakeRegistry:
    def __init__(self, tenants: dict[str, TenantConfig]) -> None:
        self._tenants = tenants

    def get(self, tenant_id: str) -> TenantConfig:
        return self._tenants[tenant_id]


class _FakeSecrets:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    async def get(self, tenant_id: str, key: str) -> SecretValue:
        self.calls.append((tenant_id, key))
        return SecretValue(f"{tenant_id}:{key}")


def _tenant(tenant_id: str, url: str = "https://wazuh.example:9200") -> TenantConfig:
    return TenantConfig.model_validate(
        {
            "tenant_id": tenant_id,
            "indexer_url": url,
            "default_rbac_role": "soc_analyst",
        }
    )


@pytest.mark.asyncio
async def test_acquire_is_lazy_and_idempotent():
    registry = _FakeRegistry({"a": _tenant("a")})
    secrets = _FakeSecrets()
    pool = ServerApiClientPool(registry=registry, secrets=secrets)
    try:
        c1 = await pool.acquire("a")
        c2 = await pool.acquire("a")
    finally:
        await pool.aclose_all()

    assert c1 is c2
    assert secrets.calls == [
        ("a", "server_api_user"),
        ("a", "server_api_password"),
    ]


@pytest.mark.asyncio
async def test_acquire_raises_after_close():
    pool = ServerApiClientPool(
        registry=_FakeRegistry({"a": _tenant("a")}),
        secrets=_FakeSecrets(),
    )
    await pool.aclose_all()
    with pytest.raises(RuntimeError, match="closed"):
        await pool.acquire("a")


@pytest.mark.asyncio
async def test_aclose_is_idempotent():
    pool = ServerApiClientPool(
        registry=_FakeRegistry({"a": _tenant("a")}),
        secrets=_FakeSecrets(),
    )
    await pool.aclose_all()
    await pool.aclose_all()  # must not raise


@pytest.mark.asyncio
async def test_derive_server_api_url_swaps_9200_to_55000():
    pool = ServerApiClientPool(
        registry=_FakeRegistry({}),
        secrets=_FakeSecrets(),
    )
    tenant = _tenant("t", url="https://wazuh.example:9200")
    assert pool._derive_server_api_url(tenant) == "https://wazuh.example:55000"
