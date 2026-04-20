import pytest
from pydantic import ValidationError

from wazuh_mcp.tenancy.config import TenantConfig


def test_valid_config():
    cfg = TenantConfig(
        tenant_id="acme",
        indexer_url="https://wazuh.acme.example:9200",
        verify_tls=True,
        ca_bundle_path=None,
        default_rbac_role="soc_analyst",
    )
    assert cfg.tenant_id == "acme"


def test_rejects_unknown_fields():
    with pytest.raises(ValidationError):
        TenantConfig(
            tenant_id="acme",
            indexer_url="https://x:9200",
            verify_tls=True,
            ca_bundle_path=None,
            default_rbac_role="soc_analyst",
            extra_field="nope",
        )


def test_rejects_invalid_url():
    with pytest.raises(ValidationError):
        TenantConfig(
            tenant_id="acme",
            indexer_url="not-a-url",
            verify_tls=True,
            ca_bundle_path=None,
            default_rbac_role="soc_analyst",
        )


def test_tenant_id_charset():
    with pytest.raises(ValidationError):
        TenantConfig(
            tenant_id="acme/../etc",
            indexer_url="https://x:9200",
            verify_tls=True,
            ca_bundle_path=None,
            default_rbac_role="soc_analyst",
        )
