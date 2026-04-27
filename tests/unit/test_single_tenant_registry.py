"""SingleTenantRegistry — stdio adapter for one-config registries (M4c T2)."""

from __future__ import annotations

import pytest

from wazuh_mcp.tenancy.config import TenantConfig
from wazuh_mcp.tenancy.registry import SingleTenantRegistry


def _cfg(tenant_id: str = "tenant_a") -> TenantConfig:
    return TenantConfig(
        tenant_id=tenant_id,
        indexer_url="https://indexer.example.com:9200",
        verify_tls=False,
        default_rbac_role="readonly",
        oauth_issuer="https://issuer.example.com",
        oauth_audience="aud",
    )


def test_returns_config_for_own_tenant_id() -> None:
    cfg = _cfg("tenant_a")
    registry = SingleTenantRegistry(cfg)
    assert registry.get("tenant_a") is cfg


def test_raises_keyerror_for_other_tenant_id() -> None:
    registry = SingleTenantRegistry(_cfg("tenant_a"))
    with pytest.raises(KeyError, match="unknown tenant: tenant_b"):
        registry.get("tenant_b")


def test_implements_tenant_registry_protocol() -> None:
    """The adapter is structurally a TenantRegistry."""
    from wazuh_mcp.tenancy.registry import TenantRegistry

    cfg = _cfg("tenant_a")
    registry: TenantRegistry = SingleTenantRegistry(cfg)
    assert registry.get("tenant_a") is cfg


def test_single_tenant_registry_all_tenants_returns_one_entry() -> None:
    cfg = _cfg("tenant_a")
    registry = SingleTenantRegistry(cfg)
    result = list(registry.all_tenants())
    assert len(result) == 1
    assert result[0] is cfg


def test_yaml_tenant_registry_all_tenants_returns_all(tmp_path) -> None:
    from wazuh_mcp.tenancy.registry import YamlTenantRegistry

    yaml_path = tmp_path / "tenants.yaml"
    yaml_path.write_text(
        """
tenants:
  - tenant_id: tenant_a
    indexer_url: https://indexer.example.com:9200
    verify_tls: false
    default_rbac_role: readonly
    oauth_issuer: https://issuer-a.example.com
    oauth_audience: aud
  - tenant_id: tenant_b
    indexer_url: https://indexer.example.com:9200
    verify_tls: false
    default_rbac_role: analyst
    oauth_issuer: https://issuer-b.example.com
    oauth_audience: aud
""".strip()
    )
    registry = YamlTenantRegistry(yaml_path)
    result = list(registry.all_tenants())
    tenant_ids = {t.tenant_id for t in result}
    assert tenant_ids == {"tenant_a", "tenant_b"}
