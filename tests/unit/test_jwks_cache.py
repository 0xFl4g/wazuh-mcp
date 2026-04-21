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


async def test_discovery_missing_jwks_uri_raises(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url=DISCOVERY_URL, json={"issuer": "https://idp.example.com"}
    )
    cache = JwksCache(issuer="https://idp.example.com")
    try:
        with pytest.raises(RuntimeError, match="jwks_uri"):
            await cache.get_key("key-a")
    finally:
        await cache.aclose()


async def test_refresh_non_200_keeps_stale_cache(httpx_mock: HTTPXMock):
    # Initial fetch ok, subsequent refresh fails → we keep the old keys.
    httpx_mock.add_response(
        url=DISCOVERY_URL, json={"jwks_uri": JWKS_URL, "issuer": "x"}
    )
    httpx_mock.add_response(url=JWKS_URL, json=JWKS_V1)      # initial populate
    httpx_mock.add_response(url=JWKS_URL, status_code=500)   # refresh fails

    cache = JwksCache(issuer="https://idp.example.com")
    try:
        k1 = await cache.get_key("key-a")
        assert k1 is not None
        # Trigger refresh via unknown-kid; the 500 is swallowed.
        miss = await cache.get_key("unknown")
        assert miss is None
        # Old kid still served from stale cache.
        k2 = await cache.get_key("key-a")
    finally:
        await cache.aclose()
    assert k2 is not None
    assert k2["kid"] == "key-a"


async def test_second_unknown_kid_within_ttl_does_not_refresh(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url=DISCOVERY_URL, json={"jwks_uri": JWKS_URL, "issuer": "x"}
    )
    httpx_mock.add_response(url=JWKS_URL, json=JWKS_V1)  # initial populate
    httpx_mock.add_response(url=JWKS_URL, json=JWKS_V1)  # first refresh on miss

    cache = JwksCache(issuer="https://idp.example.com")
    try:
        await cache.get_key("missing-1")   # triggers refresh
        await cache.get_key("missing-2")   # within TTL, does NOT refresh
    finally:
        await cache.aclose()
    # Discovery + initial JWKS + exactly one refresh = 3 total.
    assert len(httpx_mock.get_requests()) == 3
