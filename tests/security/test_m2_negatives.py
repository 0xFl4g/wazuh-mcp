"""M2 auth layer — targeted negative security tests.

No Keycloak required; uses JwtFactory + a pytest-httpx fake JWKS endpoint.
Each test pins ONE specific attack we must reject.
"""

from __future__ import annotations

import base64
import json

import pytest
from pytest_httpx import HTTPXMock

from tests.fixtures.jwt_factory import JwtFactory
from wazuh_mcp.auth.errors import AuthError, InvalidToken
from wazuh_mcp.auth.oauth import OAuthSessionFactory
from wazuh_mcp.tenancy.config import TenantConfig
from wazuh_mcp.tenancy.issuer_index import IssuerIndex

ISS = "https://idp.test"
AUD = "wazuh-mcp-api"
DISCO = f"{ISS}/.well-known/openid-configuration"
JWKS = f"{ISS}/jwks"


def _tenant(tid: str) -> TenantConfig:
    return TenantConfig(
        tenant_id=tid,
        indexer_url="https://x:9200",
        verify_tls=False,
        ca_bundle_path=None,
        default_rbac_role="soc_analyst",
        oauth_issuer=ISS,
        oauth_audience=AUD,
    )


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


@pytest.fixture
def jf() -> JwtFactory:
    return JwtFactory(issuer=ISS, audience=AUD)


@pytest.fixture
def factory(httpx_mock: HTTPXMock, jf: JwtFactory) -> OAuthSessionFactory:
    # Marked optional so tests that reject tokens before JWKS fetch don't fail
    # the "all mocks consumed" assertion.
    httpx_mock.add_response(url=DISCO, json=jf.oidc_discovery(JWKS), is_optional=True)
    httpx_mock.add_response(url=JWKS, json=jf.jwks(), is_optional=True)
    return OAuthSessionFactory(
        issuer=ISS,
        audience=AUD,
        algorithms=["RS256"],
        rbac_claims=["wazuh_mcp_role"],
        issuer_index=IssuerIndex([_tenant("acme")]),
    )


async def test_alg_none_rejected(factory, jf):
    """A JWT signed with alg=none tries to skip signature verification.

    joserfc refuses to even encode ``alg=none``, so we craft the wire form
    by hand. The factory must reject this before ever consulting a key.
    """
    header = {"alg": "none", "kid": jf.kid, "typ": "JWT"}
    payload = {
        "iss": ISS,
        "sub": "alice",
        "aud": AUD,
        "iat": 0,
        "exp": 9999999999,
        "nbf": 0,
        "tenant_id": "acme",
        "wazuh_mcp_role": "soc_analyst",
    }
    tampered = (
        _b64u(json.dumps(header).encode())
        + "."
        + _b64u(json.dumps(payload).encode())
        + "."  # empty signature — the "none" attack
    )
    try:
        with pytest.raises(AuthError):
            await factory.build({"headers": {"Authorization": f"Bearer {tampered}"}})
    finally:
        await factory.aclose()


async def test_signature_tampered_rejected(factory, jf):
    token = jf.make(sub="alice", extra={"tenant_id": "acme"})
    head, body, sig = token.rsplit(".", 2)
    bad = head + "." + body + "." + ("A" if sig[0] != "A" else "B") + sig[1:]
    try:
        with pytest.raises(AuthError):
            await factory.build({"headers": {"Authorization": f"Bearer {bad}"}})
    finally:
        await factory.aclose()


async def test_algorithm_allowlist_enforced(httpx_mock: HTTPXMock):
    """Factory only accepts ES256 but token is RS256."""
    jf = JwtFactory(issuer=ISS, audience=AUD)
    httpx_mock.add_response(url=DISCO, json=jf.oidc_discovery(JWKS), is_optional=True)
    httpx_mock.add_response(url=JWKS, json=jf.jwks(), is_optional=True)
    factory = OAuthSessionFactory(
        issuer=ISS,
        audience=AUD,
        algorithms=["ES256"],
        rbac_claims=["wazuh_mcp_role"],
        issuer_index=IssuerIndex([_tenant("acme")]),
    )
    token = jf.make(sub="alice", extra={"tenant_id": "acme", "wazuh_mcp_role": "a"})
    try:
        with pytest.raises(AuthError):
            await factory.build({"headers": {"Authorization": f"Bearer {token}"}})
    finally:
        await factory.aclose()


async def test_malformed_jwt_rejected(factory):
    try:
        for bad in ["not.a.jwt", "aaa.bbb", "aaa..ccc", "."]:
            with pytest.raises(InvalidToken):
                await factory.build({"headers": {"Authorization": f"Bearer {bad}"}})
    finally:
        await factory.aclose()


async def test_log_poisoning_in_sub(factory, jf):
    """sub may contain newlines/ANSI; factory must still build, audit layer
    handles sanitisation downstream."""
    evil_sub = "alice\x1b[31m\nHIJACK"
    token = jf.make(
        sub=evil_sub,
        extra={"tenant_id": "acme", "wazuh_mcp_role": "a"},
    )
    try:
        session = await factory.build({"headers": {"Authorization": f"Bearer {token}"}})
    finally:
        await factory.aclose()
    assert session.user_id == evil_sub
