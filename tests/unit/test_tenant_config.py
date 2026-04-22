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


def test_oauth_fields_optional():
    cfg = TenantConfig(
        tenant_id="acme",
        indexer_url="https://wazuh.acme.example:9200",
        verify_tls=True,
        ca_bundle_path=None,
        default_rbac_role="soc_analyst",
    )
    assert cfg.oauth_issuer is None
    assert cfg.oauth_audience is None


def test_oauth_fields_accepted():
    cfg = TenantConfig(
        tenant_id="acme",
        indexer_url="https://wazuh.acme.example:9200",
        verify_tls=True,
        ca_bundle_path=None,
        default_rbac_role="soc_analyst",
        oauth_issuer="https://idp.example.com/realms/msp",
        oauth_audience="wazuh-mcp-api",
    )
    assert str(cfg.oauth_issuer).startswith("https://idp.example.com")
    assert cfg.oauth_audience == "wazuh-mcp-api"


def test_oauth_issuer_must_be_url():
    with pytest.raises(ValidationError):
        TenantConfig(
            tenant_id="acme",
            indexer_url="https://x:9200",
            verify_tls=True,
            ca_bundle_path=None,
            default_rbac_role="soc_analyst",
            oauth_issuer="not-a-url",
        )


def _base_cfg() -> dict:
    return {
        "tenant_id": "t1",
        "indexer_url": "https://indexer.example",
        "default_rbac_role": "soc_analyst",
    }


def test_wazuh_user_claim_defaults_to_wazuh_user():
    cfg = TenantConfig.model_validate(_base_cfg())
    assert cfg.wazuh_user_claim == "wazuh_user"


def test_wazuh_user_claim_custom():
    cfg = TenantConfig.model_validate({**_base_cfg(), "wazuh_user_claim": "uid"})
    assert cfg.wazuh_user_claim == "uid"


def test_tenant_config_rejects_unknown_fields():
    with pytest.raises(ValidationError):
        TenantConfig.model_validate({**_base_cfg(), "not_a_field": True})
