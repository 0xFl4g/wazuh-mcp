from pathlib import Path

import pytest

from wazuh_mcp.secrets.yaml_driver import YamlSecretStore
from wazuh_mcp.tenancy.registry import YamlTenantRegistry
from wazuh_mcp.wazuh.indexer import IndexerClient
from wazuh_mcp.wazuh.indexer_pool import IndexerClientPool


@pytest.fixture
def registry_and_secrets(tmp_path: Path) -> tuple[YamlTenantRegistry, YamlSecretStore]:
    (tmp_path / "tenants.yaml").write_text(
        """
tenants:
  - tenant_id: acme
    indexer_url: https://wazuh.acme:9200
    verify_tls: false
    ca_bundle_path: null
    default_rbac_role: soc_analyst
  - tenant_id: beta
    indexer_url: https://wazuh.beta:9200
    verify_tls: false
    ca_bundle_path: null
    default_rbac_role: soc_analyst
""".strip()
    )
    (tmp_path / "secrets.yaml").write_text(
        """
acme:
  indexer_user: admin
  indexer_password: a
beta:
  indexer_user: admin
  indexer_password: b
""".strip()
    )
    return (
        YamlTenantRegistry(tmp_path / "tenants.yaml"),
        YamlSecretStore(tmp_path / "secrets.yaml"),
    )


async def test_same_tenant_returns_same_client(registry_and_secrets):
    registry, secrets = registry_and_secrets
    pool = IndexerClientPool(registry=registry, secrets=secrets)
    try:
        c1 = await pool.acquire("acme")
        c2 = await pool.acquire("acme")
    finally:
        await pool.aclose_all()
    assert c1 is c2


async def test_different_tenants_get_distinct_clients(registry_and_secrets):
    registry, secrets = registry_and_secrets
    pool = IndexerClientPool(registry=registry, secrets=secrets)
    try:
        a = await pool.acquire("acme")
        b = await pool.acquire("beta")
    finally:
        await pool.aclose_all()
    assert a is not b
    assert isinstance(a, IndexerClient)
    assert isinstance(b, IndexerClient)


async def test_unknown_tenant_raises(registry_and_secrets):
    registry, secrets = registry_and_secrets
    pool = IndexerClientPool(registry=registry, secrets=secrets)
    try:
        with pytest.raises(KeyError, match="ghost"):
            await pool.acquire("ghost")
    finally:
        await pool.aclose_all()


async def test_aclose_all_is_idempotent(registry_and_secrets):
    registry, secrets = registry_and_secrets
    pool = IndexerClientPool(registry=registry, secrets=secrets)
    await pool.acquire("acme")
    await pool.aclose_all()
    await pool.aclose_all()  # must not raise
