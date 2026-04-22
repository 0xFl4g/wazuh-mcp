"""ServerApiClient security-negatives — paths that should never leak or loop."""

import asyncio
import base64
import json
import time

import httpx
import pytest

from wazuh_mcp.secrets.value import SecretValue
from wazuh_mcp.wazuh.errors import WazuhError
from wazuh_mcp.wazuh.server_api import ServerApiClient


def _jwt(exp_offset_s: int = 900) -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=")
    payload = base64.urlsafe_b64encode(
        json.dumps(
            {
                "exp": int(time.time()) + exp_offset_s,
                "iat": int(time.time()),
                "sub": "mcp",
            }
        ).encode()
    ).rstrip(b"=")
    return f"{header.decode()}.{payload.decode()}.signature"


def _build_client() -> ServerApiClient:
    return ServerApiClient(
        base_url="https://manager.example:55000",
        user=SecretValue("wazuh-wui"),
        password=SecretValue("hunter2"),
        verify_tls=False,
    )


@pytest.mark.asyncio
async def test_401_twice_raises_auth_expired_not_loop(httpx_mock):
    """Both the initial request and the retry return 401: surface auth_expired,
    do NOT enter an infinite mint/retry loop.
    """
    # First mint (before the initial request)
    httpx_mock.add_response(
        url="https://manager.example:55000/security/user/authenticate",
        method="POST",
        json={"data": {"token": _jwt()}},
    )
    # Initial request — 401
    httpx_mock.add_response(
        url="https://manager.example:55000/agents",
        method="GET",
        status_code=401,
    )
    # Second mint (after the 401 on /agents)
    httpx_mock.add_response(
        url="https://manager.example:55000/security/user/authenticate",
        method="POST",
        json={"data": {"token": _jwt()}},
    )
    # Replay — also 401
    httpx_mock.add_response(
        url="https://manager.example:55000/agents",
        method="GET",
        status_code=401,
    )

    client = _build_client()
    try:
        with pytest.raises(WazuhError) as exc_info:
            await client.get("/agents")
    finally:
        await client.aclose()
    assert exc_info.value.code == "auth_expired"


@pytest.mark.asyncio
async def test_429_is_rate_limited(httpx_mock):
    httpx_mock.add_response(
        url="https://manager.example:55000/security/user/authenticate",
        method="POST",
        json={"data": {"token": _jwt()}},
    )
    httpx_mock.add_response(
        url="https://manager.example:55000/agents",
        method="GET",
        status_code=429,
        headers={"Retry-After": "30"},
    )

    client = _build_client()
    try:
        with pytest.raises(WazuhError) as exc_info:
            await client.get("/agents")
    finally:
        await client.aclose()
    assert exc_info.value.code == "rate_limited"


@pytest.mark.asyncio
async def test_concurrent_mint_is_serialised(httpx_mock):
    """Two concurrent requests on a client with no token trigger exactly one mint —
    the asyncio.Lock prevents a mint stampede.
    """
    httpx_mock.add_response(
        url="https://manager.example:55000/security/user/authenticate",
        method="POST",
        json={"data": {"token": _jwt()}},
    )
    # Two distinct responses on the same /agents URL so pytest-httpx hands them out in order
    httpx_mock.add_response(
        url="https://manager.example:55000/agents",
        method="GET",
        json={"data": {"affected_items": [{"id": "001"}]}},
    )
    httpx_mock.add_response(
        url="https://manager.example:55000/agents",
        method="GET",
        json={"data": {"affected_items": [{"id": "002"}]}},
    )

    client = _build_client()
    try:
        r1, r2 = await asyncio.gather(
            client.get("/agents"),
            client.get("/agents"),
        )
    finally:
        await client.aclose()

    assert {r1["data"]["affected_items"][0]["id"], r2["data"]["affected_items"][0]["id"]} == {
        "001",
        "002",
    }
    mint_calls = [
        r for r in httpx_mock.get_requests() if r.url.path == "/security/user/authenticate"
    ]
    assert len(mint_calls) == 1, "mint stampede — expected exactly one mint"


@pytest.mark.asyncio
async def test_mint_401_leaks_nothing(httpx_mock):
    """Bad basic-auth creds return 401 on mint. The raised error must not
    contain the credentials, the response body, or the Authorization header.
    """
    httpx_mock.add_response(
        url="https://manager.example:55000/security/user/authenticate",
        method="POST",
        status_code=401,
        text="bad credentials: wazuh-wui / hunter2",
    )

    client = _build_client()
    try:
        with pytest.raises(WazuhError) as exc_info:
            await client.get("/agents")
    finally:
        await client.aclose()
    err = exc_info.value
    assert err.code == "auth_expired"
    assert "hunter2" not in str(err)
    assert "hunter2" not in repr(err)
    assert "wazuh-wui" not in str(err)


@pytest.mark.asyncio
async def test_timeout_becomes_upstream_timeout(httpx_mock):
    # First mint succeeds
    httpx_mock.add_response(
        url="https://manager.example:55000/security/user/authenticate",
        method="POST",
        json={"data": {"token": _jwt()}},
    )
    # /agents times out
    httpx_mock.add_exception(httpx.TimeoutException("read timeout"))

    client = _build_client()
    try:
        with pytest.raises(WazuhError) as exc_info:
            await client.get("/agents")
    finally:
        await client.aclose()
    assert exc_info.value.code == "upstream_timeout"


@pytest.mark.asyncio
async def test_malformed_mint_response_is_upstream_error(httpx_mock):
    """Mint returns 200 but no token in body — surface upstream_error, not a
    KeyError or TypeError that would leak the response body.
    """
    httpx_mock.add_response(
        url="https://manager.example:55000/security/user/authenticate",
        method="POST",
        json={"data": {}},  # no token
    )

    client = _build_client()
    try:
        with pytest.raises(WazuhError) as exc_info:
            await client.get("/agents")
    finally:
        await client.aclose()
    assert exc_info.value.code == "upstream_error"
