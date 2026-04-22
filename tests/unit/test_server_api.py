"""ServerApiClient — JWT mint + basic request path tests."""

import base64
import json
import time

import httpx
import pytest

from wazuh_mcp.secrets.value import SecretValue
from wazuh_mcp.wazuh.server_api import ServerApiClient


def _jwt(exp_offset_s: int = 900) -> str:
    """Forge an RS-like JWT whose exp is decodable client-side (signature ignored)."""
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=")
    payload = base64.urlsafe_b64encode(
        json.dumps({"exp": int(time.time()) + exp_offset_s, "sub": "mcp"}).encode()
    ).rstrip(b"=")
    return f"{header.decode()}.{payload.decode()}.signature"


@pytest.fixture
def mint_response_ok():
    def _build(token: str) -> httpx.Response:
        return httpx.Response(200, json={"data": {"token": token}})

    return _build


@pytest.mark.asyncio
async def test_mint_on_first_call(httpx_mock, mint_response_ok):
    httpx_mock.add_response(
        url="https://manager.example:55000/security/user/authenticate",
        method="POST",
        json={"data": {"token": _jwt()}},
    )
    httpx_mock.add_response(
        url="https://manager.example:55000/agents",
        method="GET",
        json={"data": {"affected_items": []}},
    )

    client = ServerApiClient(
        base_url="https://manager.example:55000",
        user=SecretValue("wazuh-wui"),
        password=SecretValue("mcp-secret"),
        verify_tls=False,
    )
    try:
        result = await client.get("/agents")
    finally:
        await client.aclose()
    assert result["data"]["affected_items"] == []


@pytest.mark.asyncio
async def test_reuse_valid_token(httpx_mock):
    """A fresh token is reused for a second call made within lifetime budget."""
    httpx_mock.add_response(
        url="https://manager.example:55000/security/user/authenticate",
        method="POST",
        json={"data": {"token": _jwt()}},
    )
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

    client = ServerApiClient(
        base_url="https://manager.example:55000",
        user=SecretValue("wazuh-wui"),
        password=SecretValue("mcp-secret"),
        verify_tls=False,
    )
    try:
        a = await client.get("/agents")
        b = await client.get("/agents")
    finally:
        await client.aclose()
    assert a["data"]["affected_items"][0]["id"] == "001"
    assert b["data"]["affected_items"][0]["id"] == "002"

    # Only one mint for two calls
    mint_calls = [r for r in httpx_mock.get_requests() if r.url.path == "/security/user/authenticate"]
    assert len(mint_calls) == 1


@pytest.mark.asyncio
async def test_run_as_param_added_to_query(httpx_mock):
    httpx_mock.add_response(
        url="https://manager.example:55000/security/user/authenticate",
        method="POST",
        json={"data": {"token": _jwt()}},
    )
    # Register a response keyed on the URL with run_as — pytest-httpx matches by URL substring.
    httpx_mock.add_response(
        url="https://manager.example:55000/agents?run_as=alice",
        method="GET",
        json={"data": {"affected_items": []}},
    )

    client = ServerApiClient(
        base_url="https://manager.example:55000",
        user=SecretValue("wazuh-wui"),
        password=SecretValue("mcp-secret"),
        verify_tls=False,
    )
    try:
        await client.get("/agents", run_as="alice")
    finally:
        await client.aclose()

    # Confirm the request that was sent included run_as=alice
    request_urls = [r.url for r in httpx_mock.get_requests() if r.url.path == "/agents"]
    assert any("run_as=alice" in str(u) for u in request_urls)


@pytest.mark.asyncio
async def test_repr_redacts_token_and_credentials():
    client = ServerApiClient(
        base_url="https://manager.example:55000",
        user=SecretValue("wazuh-wui"),
        password=SecretValue("mcp-secret"),
        verify_tls=False,
    )
    try:
        r = repr(client)
        assert "mcp-secret" not in r
        assert "wazuh-wui" not in r
        assert "token=<redacted>" in r
    finally:
        await client.aclose()
