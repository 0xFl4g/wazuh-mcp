import pytest

from wazuh_mcp.tenancy.config import TenantConfig
from wazuh_mcp.tenancy.issuer_index import IssuerIndex


def _tenant(tid: str, issuer: str | None) -> TenantConfig:
    return TenantConfig(
        tenant_id=tid,
        indexer_url="https://x:9200",
        verify_tls=False,
        ca_bundle_path=None,
        default_rbac_role="soc_analyst",
        oauth_issuer=issuer,
        oauth_audience="api" if issuer else None,
    )


def test_lookup_returns_tenant_config():
    a = _tenant("acme", "https://idp.example.com/realms/acme")
    b = _tenant("beta", "https://idp.example.com/realms/beta")
    idx = IssuerIndex([a, b])
    got_a = idx.get("https://idp.example.com/realms/acme")
    got_b = idx.get("https://idp.example.com/realms/beta")
    assert got_a is not None and got_a.tenant_id == "acme"
    assert got_b is not None and got_b.tenant_id == "beta"


def test_unknown_issuer_returns_none():
    idx = IssuerIndex([_tenant("acme", "https://idp.example.com/realms/acme")])
    assert idx.get("https://elsewhere") is None


def test_tenants_without_issuer_are_skipped():
    idx = IssuerIndex([_tenant("acme", None)])
    assert idx.get("anything") is None


def test_duplicate_issuers_rejected():
    a = _tenant("acme", "https://idp.example.com/realms/shared")
    b = _tenant("beta", "https://idp.example.com/realms/shared")
    with pytest.raises(ValueError, match="duplicate"):
        IssuerIndex([a, b])


def test_issuer_trailing_slash_ignored():
    a = _tenant("acme", "https://idp.example.com/realms/acme/")
    idx = IssuerIndex([a])
    got_plain = idx.get("https://idp.example.com/realms/acme")
    got_slash = idx.get("https://idp.example.com/realms/acme/")
    assert got_plain is not None and got_plain.tenant_id == "acme"
    assert got_slash is not None and got_slash.tenant_id == "acme"
