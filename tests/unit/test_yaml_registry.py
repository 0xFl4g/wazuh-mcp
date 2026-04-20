from pathlib import Path

import pytest

from wazuh_mcp.tenancy.registry import YamlTenantRegistry


@pytest.fixture
def tenants_file(tmp_path: Path) -> Path:
    p = tmp_path / "tenants.yaml"
    p.write_text(
        """
tenants:
  - tenant_id: acme
    indexer_url: https://wazuh.acme.example:9200
    verify_tls: true
    ca_bundle_path: null
    default_rbac_role: soc_analyst
  - tenant_id: beta
    indexer_url: https://wazuh.beta.example:9200
    verify_tls: false
    ca_bundle_path: null
    default_rbac_role: soc_analyst
""".strip()
    )
    return p


def test_registry_loads_multiple_tenants(tenants_file):
    reg = YamlTenantRegistry(tenants_file)
    acme = reg.get("acme")
    assert acme.tenant_id == "acme"
    assert str(acme.indexer_url).startswith("https://wazuh.acme.example")


def test_registry_unknown_tenant_raises(tenants_file):
    reg = YamlTenantRegistry(tenants_file)
    with pytest.raises(KeyError, match="ghost"):
        reg.get("ghost")


def test_registry_rejects_duplicate_tenant_ids(tmp_path):
    p = tmp_path / "dup.yaml"
    p.write_text(
        """
tenants:
  - tenant_id: acme
    indexer_url: https://a:9200
    verify_tls: true
    ca_bundle_path: null
    default_rbac_role: soc_analyst
  - tenant_id: acme
    indexer_url: https://b:9200
    verify_tls: true
    ca_bundle_path: null
    default_rbac_role: soc_analyst
""".strip()
    )
    with pytest.raises(ValueError, match="duplicate"):
        YamlTenantRegistry(p)
