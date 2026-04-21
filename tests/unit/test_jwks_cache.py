import pytest
from pytest_httpx import HTTPXMock

from wazuh_mcp.auth.jwks_cache import JwksCache

DISCOVERY_URL = "https://idp.example.com/.well-known/openid-configuration"
JWKS_URL = "https://idp.example.com/protocol/openid-connect/certs"

JWKS_V1 = {
    "keys": [
        {"kty": "RSA", "kid": "key-a", "alg": "RS256", "use": "sig", "n": "abc", "e": "AQAB"},
    ]
}
JWKS_V2 = {
    "keys": [
        {"kty": "RSA", "kid": "key-b", "alg": "RS256", "use": "sig", "n": "xyz", "e": "AQAB"},
    ]
}


async def test_discovers_jwks_uri_from_openid_configuration(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url=DISCOVERY_URL,
        json={"jwks_uri": JWKS_URL, "issuer": "https://idp.example.com"},
    )
    httpx_mock.add_response(url=JWKS_URL, json=JWKS_V1)

    cache = JwksCache(issuer="https://idp.example.com")
    try:
        key = await cache.get_key("key-a")
    finally:
        await cache.aclose()
    assert key is not None
    assert key["kid"] == "key-a"


async def test_refresh_on_unknown_kid_happens_once(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url=DISCOVERY_URL, json={"jwks_uri": JWKS_URL, "issuer": "x"}
    )
    httpx_mock.add_response(url=JWKS_URL, json=JWKS_V1)
    httpx_mock.add_response(url=JWKS_URL, json=JWKS_V2)

    cache = JwksCache(issuer="https://idp.example.com")
    try:
        key = await cache.get_key("key-b")  # triggers refresh
    finally:
        await cache.aclose()
    assert key is not None
    assert key["kid"] == "key-b"
    # Discovery once + JWKS twice = 3 requests total.
    assert len(httpx_mock.get_requests()) == 3


async def test_still_unknown_after_refresh_returns_none(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url=DISCOVERY_URL, json={"jwks_uri": JWKS_URL, "issuer": "x"}
    )
    httpx_mock.add_response(url=JWKS_URL, json=JWKS_V1)
    httpx_mock.add_response(url=JWKS_URL, json=JWKS_V1)

    cache = JwksCache(issuer="https://idp.example.com")
    try:
        key = await cache.get_key("key-missing")
    finally:
        await cache.aclose()
    assert key is None


async def test_known_kid_uses_cache_no_refresh(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url=DISCOVERY_URL, json={"jwks_uri": JWKS_URL, "issuer": "x"}
    )
    httpx_mock.add_response(url=JWKS_URL, json=JWKS_V1)

    cache = JwksCache(issuer="https://idp.example.com")
    try:
        k1 = await cache.get_key("key-a")
        k2 = await cache.get_key("key-a")
    finally:
        await cache.aclose()
    assert k1 is k2
    assert len(httpx_mock.get_requests()) == 2  # discovery + JWKS only


async def test_discovery_failure_raises(httpx_mock: HTTPXMock):
    httpx_mock.add_response(url=DISCOVERY_URL, status_code=500)
    cache = JwksCache(issuer="https://idp.example.com")
    try:
        with pytest.raises(RuntimeError, match="discovery"):
            await cache.get_key("key-a")
    finally:
        await cache.aclose()
