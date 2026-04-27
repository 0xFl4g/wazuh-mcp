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
