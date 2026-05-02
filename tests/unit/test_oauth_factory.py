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


def _tenant(
    tid: str,
    issuer: str | None = ISS,
    *,
    wazuh_user_claim: str = "wazuh_user",
) -> TenantConfig:
    return TenantConfig(
        tenant_id=tid,
        indexer_url="https://x:9200",
        verify_tls=False,
        ca_bundle_path=None,
        default_rbac_role="soc_analyst",
        oauth_issuer=issuer,
        oauth_audience=AUD if issuer else None,
        wazuh_user_claim=wazuh_user_claim,
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


async def test_wrong_issuer_rejected(jwt_factory, index):
    # v1.0.4 (failure A): wrong issuer is now rejected at the unverified-iss
    # peek BEFORE any JWKS fetch — no seed_oidc fixture needed because the
    # JWKS cache for the global issuer is never consulted.
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


async def test_oauth_factory_extracts_wazuh_user_default_claim(seed_oidc, jwt_factory):
    index = IssuerIndex([_tenant("acme", wazuh_user_claim="wazuh_user")])
    factory = OAuthSessionFactory(
        issuer=ISS,
        audience=AUD,
        algorithms=["RS256"],
        rbac_claims=["wazuh_mcp_role"],
        issuer_index=index,
    )
    try:
        token = jwt_factory.make(
            sub="abc",
            extra={
                "tenant_id": "acme",
                "wazuh_mcp_role": "soc_analyst",
                "wazuh_user": "alice",
            },
        )
        session = await factory.build({"headers": {"Authorization": f"Bearer {token}"}})
    finally:
        await factory.aclose()
    assert session.wazuh_user == "alice"


async def test_oauth_factory_extracts_wazuh_user_custom_claim(seed_oidc, jwt_factory):
    index = IssuerIndex([_tenant("acme", wazuh_user_claim="uid")])
    factory = OAuthSessionFactory(
        issuer=ISS,
        audience=AUD,
        algorithms=["RS256"],
        rbac_claims=["wazuh_mcp_role"],
        issuer_index=index,
    )
    try:
        token = jwt_factory.make(
            sub="abc",
            extra={
                "tenant_id": "acme",
                "wazuh_mcp_role": "soc_analyst",
                "uid": "bob",
            },
        )
        session = await factory.build({"headers": {"Authorization": f"Bearer {token}"}})
    finally:
        await factory.aclose()
    assert session.wazuh_user == "bob"


async def test_oauth_factory_wazuh_user_absent_yields_none(seed_oidc, jwt_factory, index):
    factory = OAuthSessionFactory(
        issuer=ISS,
        audience=AUD,
        algorithms=["RS256"],
        rbac_claims=["wazuh_mcp_role"],
        issuer_index=index,
    )
    try:
        token = jwt_factory.make(
            sub="abc",
            extra={"tenant_id": "acme", "wazuh_mcp_role": "soc_analyst"},
        )
        session = await factory.build({"headers": {"Authorization": f"Bearer {token}"}})
    finally:
        await factory.aclose()
    assert session.wazuh_user is None


async def test_oauth_factory_wazuh_user_list_takes_first(seed_oidc, jwt_factory, index):
    factory = OAuthSessionFactory(
        issuer=ISS,
        audience=AUD,
        algorithms=["RS256"],
        rbac_claims=["wazuh_mcp_role"],
        issuer_index=index,
    )
    try:
        token = jwt_factory.make(
            sub="abc",
            extra={
                "tenant_id": "acme",
                "wazuh_mcp_role": "soc_analyst",
                "wazuh_user": ["alice", "backup"],
            },
        )
        session = await factory.build({"headers": {"Authorization": f"Bearer {token}"}})
    finally:
        await factory.aclose()
    assert session.wazuh_user == "alice"


async def test_shared_issuer_falls_back_to_claim_tenants_default_rbac_role(seed_oidc, jwt_factory):
    """Two tenants share an issuer; the JWT carries a ``tenant_id`` claim
    but NO rbac claim (typical for service-account / client_credentials
    tokens). The factory must use the *claim-resolved* tenant's
    ``default_rbac_role`` — not iss_tenant_cfg, which is None for
    shared issuers."""

    tenant_b = TenantConfig(
        tenant_id="beta",
        indexer_url="https://x:9200",
        verify_tls=False,
        ca_bundle_path=None,
        default_rbac_role="analyst",  # distinct from acme's "soc_analyst"
        oauth_issuer=ISS,
        oauth_audience=AUD,
    )
    shared_index = IssuerIndex([_tenant("acme"), tenant_b])
    factory = OAuthSessionFactory(
        issuer=ISS,
        audience=AUD,
        algorithms=["RS256"],
        rbac_claims=["wazuh_mcp_role"],
        issuer_index=shared_index,
    )
    try:
        # No wazuh_mcp_role claim — fallback to tenant_b's default_rbac_role.
        token = jwt_factory.make(sub="svc-account", extra={"tenant_id": "beta"})
        session = await factory.build({"headers": {"Authorization": f"Bearer {token}"}})
    finally:
        await factory.aclose()
    assert session.tenant_id == "beta"
    assert session.rbac_role == "analyst"


async def test_shared_issuer_resolves_wazuh_user_via_tenant_id_claim(seed_oidc, jwt_factory):
    """Two tenants share an issuer; tenant_b configures a custom
    ``wazuh_user_claim``. The factory must resolve wazuh_user via the
    *claim-resolved* tenant's config, not iss_tenant_cfg (which is None
    for the shared issuer)."""

    tenant_b = TenantConfig(
        tenant_id="beta",
        indexer_url="https://x:9200",
        verify_tls=False,
        ca_bundle_path=None,
        default_rbac_role="soc_analyst",
        oauth_issuer=ISS,
        oauth_audience=AUD,
        wazuh_user_claim="preferred_username",
    )
    shared_index = IssuerIndex([_tenant("acme"), tenant_b])
    factory = OAuthSessionFactory(
        issuer=ISS,
        audience=AUD,
        algorithms=["RS256"],
        rbac_claims=["wazuh_mcp_role"],
        issuer_index=shared_index,
    )
    try:
        token = jwt_factory.make(
            sub="user-1",
            extra={
                "tenant_id": "beta",
                "wazuh_mcp_role": "soc_analyst",
                "preferred_username": "alice",
            },
        )
        session = await factory.build({"headers": {"Authorization": f"Bearer {token}"}})
    finally:
        await factory.aclose()
    assert session.tenant_id == "beta"
    assert session.wazuh_user == "alice"


async def test_shared_issuer_routes_by_tenant_id_claim(seed_oidc, jwt_factory):
    """Two tenants sharing an oauth_issuer (e.g. multi-tenant Keycloak realm
    with claim-mapper routing) must be resolved by the ``tenant_id`` claim.
    IssuerIndex returns None for the shared key; OAuthSessionFactory's
    claim-only path (oauth.py:125-126) routes the session correctly. A
    token without a ``tenant_id`` claim hitting the shared issuer fails
    closed with MissingClaim."""

    shared_index = IssuerIndex([_tenant("acme"), _tenant("beta")])
    factory = OAuthSessionFactory(
        issuer=ISS,
        audience=AUD,
        algorithms=["RS256"],
        rbac_claims=["wazuh_mcp_role"],
        issuer_index=shared_index,
    )
    try:
        token_beta = jwt_factory.make(
            sub="alice", extra={"tenant_id": "beta", "wazuh_mcp_role": "analyst"}
        )
        session_beta = await factory.build({"headers": {"Authorization": f"Bearer {token_beta}"}})
        assert session_beta.tenant_id == "beta"
        assert session_beta.rbac_role == "analyst"

        token_acme = jwt_factory.make(
            sub="bob", extra={"tenant_id": "acme", "wazuh_mcp_role": "soc_analyst"}
        )
        session_acme = await factory.build({"headers": {"Authorization": f"Bearer {token_acme}"}})
        assert session_acme.tenant_id == "acme"
        assert session_acme.rbac_role == "soc_analyst"

        token_no_claim = jwt_factory.make(sub="carol", extra={"wazuh_mcp_role": "analyst"})
        with pytest.raises(MissingClaim):
            await factory.build({"headers": {"Authorization": f"Bearer {token_no_claim}"}})
    finally:
        await factory.aclose()


async def test_v104_tenant_configured_issuer_accepted(httpx_mock: HTTPXMock):
    """v1.0.4 (failure A) — A tenant in tenants.yaml may declare an
    oauth_issuer distinct from the global oauth.issuer. JWTs minted by
    that tenant's issuer must validate against the per-issuer JWKS,
    NOT be rejected with "issuer mismatch" against the global issuer.
    """

    sidecar_iss = "https://sidecar.test"
    sidecar_disco = f"{sidecar_iss}/.well-known/openid-configuration"
    sidecar_jwks = f"{sidecar_iss}/jwks"
    sidecar_factory = JwtFactory(issuer=sidecar_iss, audience=AUD)

    httpx_mock.add_response(url=sidecar_disco, json=sidecar_factory.oidc_discovery(sidecar_jwks))
    httpx_mock.add_response(url=sidecar_jwks, json=sidecar_factory.jwks())

    # Index has a tenant with the side-car's issuer. Global oauth issuer
    # is the unrelated ISS — but tokens from sidecar_iss MUST be accepted.
    index = IssuerIndex([_tenant("trusted-sidecar", issuer=sidecar_iss)])
    factory = OAuthSessionFactory(
        issuer=ISS,
        audience=AUD,
        algorithms=["RS256"],
        rbac_claims=["wazuh_mcp_role"],
        issuer_index=index,
    )
    try:
        token = sidecar_factory.make(
            sub="phantom-user",
            extra={"tenant_id": "trusted-sidecar", "wazuh_mcp_role": "analyst"},
        )
        session = await factory.build({"headers": {"Authorization": f"Bearer {token}"}})
        assert session.tenant_id == "trusted-sidecar"
        assert session.rbac_role == "analyst"
    finally:
        await factory.aclose()


async def test_v104_unknown_issuer_rejected_before_jwks_fetch(jwt_factory, index):
    """v1.0.4 (failure A) — An issuer NEITHER global NOR in IssuerIndex
    must fail at the unverified-iss peek, before any JWKS fetch fires.
    No httpx_mock seeded; if a JWKS request escapes, pytest_httpx errors.
    """

    attacker = JwtFactory(issuer="https://attacker.example", audience=AUD)
    factory = OAuthSessionFactory(
        issuer=ISS,
        audience=AUD,
        algorithms=["RS256"],
        rbac_claims=["wazuh_mcp_role"],
        issuer_index=index,
    )
    try:
        token = attacker.make(sub="alice", extra={"tenant_id": "acme"})
        with pytest.raises(InvalidToken) as excinfo:
            await factory.build({"headers": {"Authorization": f"Bearer {token}"}})
        assert "not trusted" in str(excinfo.value._detail or "")
    finally:
        await factory.aclose()
