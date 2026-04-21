import pytest
from pytest_httpx import HTTPXMock

from tests.fixtures.jwt_factory import JwtFactory
from wazuh_mcp.auth.errors import (
    ExpiredToken,
    InvalidToken,
    MissingClaim,
)
from wazuh_mcp.auth.oauth import OAuthSessionFactory
from wazuh_mcp.tenancy.config import TenantConfig
from wazuh_mcp.tenancy.issuer_index import IssuerIndex

ISS = "https://idp.test"
AUD = "wazuh-mcp-api"
DISCO = f"{ISS}/.well-known/openid-configuration"
JWKS = f"{ISS}/jwks"


def _tenant(tid: str, issuer: str | None = ISS) -> TenantConfig:
    return TenantConfig(
        tenant_id=tid,
        indexer_url="https://x:9200",
        verify_tls=False,
        ca_bundle_path=None,
        default_rbac_role="soc_analyst",
        oauth_issuer=issuer,
        oauth_audience=AUD if issuer else None,
    )


@pytest.fixture
def jwt_factory() -> JwtFactory:
    return JwtFactory(issuer=ISS, audience=AUD)


@pytest.fixture
def index() -> IssuerIndex:
    return IssuerIndex([_tenant("acme")])


@pytest.fixture
def seed_oidc(httpx_mock: HTTPXMock, jwt_factory: JwtFactory) -> None:
    httpx_mock.add_response(url=DISCO, json=jwt_factory.oidc_discovery(JWKS))
    httpx_mock.add_response(url=JWKS, json=jwt_factory.jwks())


async def test_valid_token_with_tenant_claim(seed_oidc, jwt_factory, index):
    factory = OAuthSessionFactory(
        issuer=ISS,
        audience=AUD,
        algorithms=["RS256"],
        rbac_claims=["wazuh_mcp_role"],
        issuer_index=index,
    )
    try:
        token = jwt_factory.make(
            sub="alice", extra={"tenant_id": "acme", "wazuh_mcp_role": "soc_analyst"}
        )
        session = await factory.build({"headers": {"Authorization": f"Bearer {token}"}})
    finally:
        await factory.aclose()
    assert session.user_id == "alice"
    assert session.tenant_id == "acme"
    assert session.rbac_role == "soc_analyst"
    assert session.auth_method == "oauth"


async def test_valid_token_falls_back_to_iss_when_no_tenant_claim(seed_oidc, jwt_factory, index):
    factory = OAuthSessionFactory(
        issuer=ISS,
        audience=AUD,
        algorithms=["RS256"],
        rbac_claims=["groups"],
        issuer_index=index,
    )
    try:
        token = jwt_factory.make(sub="alice", extra={"groups": ["admin"]})
        session = await factory.build({"headers": {"Authorization": f"Bearer {token}"}})
    finally:
        await factory.aclose()
    assert session.tenant_id == "acme"  # from iss fallback
    assert session.rbac_role == "admin"


async def test_claim_and_iss_mismatch_rejected(seed_oidc, jwt_factory, index):
    factory = OAuthSessionFactory(
        issuer=ISS,
        audience=AUD,
        algorithms=["RS256"],
        rbac_claims=["wazuh_mcp_role"],
        issuer_index=index,
    )
    try:
        token = jwt_factory.make(
            sub="alice", extra={"tenant_id": "ghost", "wazuh_mcp_role": "soc_analyst"}
        )
        with pytest.raises(InvalidToken):
            await factory.build({"headers": {"Authorization": f"Bearer {token}"}})
    finally:
        await factory.aclose()


async def test_missing_authorization_header_raises(index):
    factory = OAuthSessionFactory(
        issuer=ISS,
        audience=AUD,
        algorithms=["RS256"],
        rbac_claims=["wazuh_mcp_role"],
        issuer_index=index,
    )
    try:
        with pytest.raises(InvalidToken):
            await factory.build({"headers": {}})
    finally:
        await factory.aclose()


async def test_expired_token_raises_expired(seed_oidc, jwt_factory, index):
    factory = OAuthSessionFactory(
        issuer=ISS,
        audience=AUD,
        algorithms=["RS256"],
        rbac_claims=["wazuh_mcp_role"],
        issuer_index=index,
    )
    try:
        token = jwt_factory.make_expired(sub="alice", extra={"tenant_id": "acme"})
        with pytest.raises(ExpiredToken):
            await factory.build({"headers": {"Authorization": f"Bearer {token}"}})
    finally:
        await factory.aclose()


async def test_wrong_issuer_rejected(seed_oidc, jwt_factory, index):
    wrong = JwtFactory(issuer="https://attacker.example", audience=AUD)
    factory = OAuthSessionFactory(
        issuer=ISS,
        audience=AUD,
        algorithms=["RS256"],
        rbac_claims=["wazuh_mcp_role"],
        issuer_index=index,
    )
    try:
        token = wrong.make(sub="alice", extra={"tenant_id": "acme"})
        with pytest.raises(InvalidToken):
            await factory.build({"headers": {"Authorization": f"Bearer {token}"}})
    finally:
        await factory.aclose()


async def test_wrong_audience_rejected(seed_oidc, jwt_factory, index):
    factory = OAuthSessionFactory(
        issuer=ISS,
        audience="different-aud",
        algorithms=["RS256"],
        rbac_claims=["wazuh_mcp_role"],
        issuer_index=index,
    )
    try:
        token = jwt_factory.make(sub="alice", extra={"tenant_id": "acme"})
        with pytest.raises(InvalidToken):
            await factory.build({"headers": {"Authorization": f"Bearer {token}"}})
    finally:
        await factory.aclose()


async def test_no_tenant_resolution_raises_missing_claim(seed_oidc, jwt_factory):
    empty_index = IssuerIndex([])
    factory = OAuthSessionFactory(
        issuer=ISS,
        audience=AUD,
        algorithms=["RS256"],
        rbac_claims=["wazuh_mcp_role"],
        issuer_index=empty_index,
    )
    try:
        token = jwt_factory.make(sub="alice")
        with pytest.raises(MissingClaim):
            await factory.build({"headers": {"Authorization": f"Bearer {token}"}})
    finally:
        await factory.aclose()


async def test_rbac_claims_priority(seed_oidc, jwt_factory, index):
    factory = OAuthSessionFactory(
        issuer=ISS,
        audience=AUD,
        algorithms=["RS256"],
        rbac_claims=["wazuh_mcp_role", "roles", "groups"],
        issuer_index=index,
    )
    try:
        token = jwt_factory.make(
            sub="alice",
            extra={"tenant_id": "acme", "wazuh_mcp_role": "first", "groups": ["third"]},
        )
        session = await factory.build({"headers": {"Authorization": f"Bearer {token}"}})
    finally:
        await factory.aclose()
    assert session.rbac_role == "first"


async def test_aud_as_list_accepted(seed_oidc, jwt_factory, index):
    factory = OAuthSessionFactory(
        issuer=ISS,
        audience=AUD,
        algorithms=["RS256"],
        rbac_claims=["wazuh_mcp_role"],
        issuer_index=index,
    )
    try:
        token = jwt_factory.make(
            sub="alice",
            extra={
                "tenant_id": "acme",
                "wazuh_mcp_role": "soc_analyst",
                "aud": [AUD, "other-aud"],
            },
        )
        session = await factory.build({"headers": {"Authorization": f"Bearer {token}"}})
    finally:
        await factory.aclose()
    assert session.user_id == "alice"
    assert session.auth_method == "oauth"


async def test_missing_sub_raises_missing_claim(seed_oidc, jwt_factory, index):
    factory = OAuthSessionFactory(
        issuer=ISS,
        audience=AUD,
        algorithms=["RS256"],
        rbac_claims=["wazuh_mcp_role"],
        issuer_index=index,
    )
    try:
        token = jwt_factory.make(sub="", extra={"tenant_id": "acme", "wazuh_mcp_role": "x"})
        with pytest.raises(MissingClaim) as excinfo:
            await factory.build({"headers": {"Authorization": f"Bearer {token}"}})
    finally:
        await factory.aclose()
    assert excinfo.value.claim_name == "sub"


def test_none_algorithm_rejected_at_construction(index):
    with pytest.raises(ValueError, match="none"):
        OAuthSessionFactory(
            issuer=ISS,
            audience=AUD,
            algorithms=["RS256", "none"],
            rbac_claims=["wazuh_mcp_role"],
            issuer_index=index,
        )


def test_empty_algorithms_rejected_at_construction(index):
    with pytest.raises(ValueError, match="at least one"):
        OAuthSessionFactory(
            issuer=ISS,
            audience=AUD,
            algorithms=[],
            rbac_claims=["wazuh_mcp_role"],
            issuer_index=index,
        )
