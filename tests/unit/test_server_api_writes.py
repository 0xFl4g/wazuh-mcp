"""ServerApiClient M4b write methods."""

from __future__ import annotations

import base64
import json
import time
from collections.abc import AsyncIterator

import httpx
import pytest
import pytest_asyncio

from wazuh_mcp.secrets.value import SecretValue
from wazuh_mcp.wazuh.server_api import ServerApiClient


def _jwt(exp_offset_s: int = 900) -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=")
    payload = base64.urlsafe_b64encode(
        json.dumps({"exp": int(time.time()) + exp_offset_s, "sub": "mcp"}).encode()
    ).rstrip(b"=")
    return f"{header.decode()}.{payload.decode()}.signature"


@pytest_asyncio.fixture
async def client(httpx_mock) -> AsyncIterator[ServerApiClient]:
    # Mint response is consumed on the first write call that needs a JWT.
    httpx_mock.add_response(
        url="https://wazuh.example:55000/security/user/authenticate",
        method="POST",
        json={"data": {"token": _jwt()}},
    )
    c = ServerApiClient(
        base_url="https://wazuh.example:55000",
        user=SecretValue("wazuh"),
        password=SecretValue("pass"),
        verify_tls=False,
    )
    try:
        yield c
    finally:
        await c.aclose()


@pytest.mark.asyncio
async def test_isolate_agent_posts_active_response(client, httpx_mock) -> None:
    httpx_mock.add_response(
        url=httpx.URL("https://wazuh.example:55000/active-response", params={"run_as": "alice"}),
        method="POST",
        json={"data": {"affected_items": ["003"]}},
    )
    resp = await client.isolate_agent(agent_id="003", run_as="alice")
    assert "data" in resp
    active_response_requests = [
        r for r in httpx_mock.get_requests() if r.url.path == "/active-response"
    ]
    assert active_response_requests, "expected a POST to /active-response"
    body = active_response_requests[-1].read()
    assert b'"command":"isolate"' in body or b'"command": "isolate"' in body
    assert b'"agents":["003"]' in body or b'"agents": ["003"]' in body


@pytest.mark.asyncio
async def test_restart_agent_puts(client, httpx_mock) -> None:
    httpx_mock.add_response(
        url=httpx.URL(
            "https://wazuh.example:55000/agents/003/restart",
            params={"run_as": "alice"},
        ),
        method="PUT",
        json={"data": {"affected_items": ["003"]}},
    )
    resp = await client.restart_agent(agent_id="003", run_as="alice")
    assert "data" in resp


@pytest.mark.asyncio
async def test_add_agent_to_group_puts(client, httpx_mock) -> None:
    httpx_mock.add_response(
        url=httpx.URL(
            "https://wazuh.example:55000/agents/003/group/linux",
            params={"run_as": "alice"},
        ),
        method="PUT",
        json={"data": {"affected_items": ["003"]}},
    )
    resp = await client.add_agent_to_group(agent_id="003", group_id="linux", run_as="alice")
    assert "data" in resp


@pytest.mark.asyncio
async def test_remove_agent_from_group_deletes(client, httpx_mock) -> None:
    httpx_mock.add_response(
        url=httpx.URL(
            "https://wazuh.example:55000/agents/003/group/linux",
            params={"run_as": "alice"},
        ),
        method="DELETE",
        json={"data": {"affected_items": ["003"]}},
    )
    resp = await client.remove_agent_from_group(
        agent_id="003", group_id="linux", run_as="alice"
    )
    assert "data" in resp


@pytest.mark.asyncio
async def test_upload_rule_file_puts_raw_xml(client, httpx_mock) -> None:
    httpx_mock.add_response(
        url=httpx.URL(
            "https://wazuh.example:55000/manager/files/rules/wazuh-mcp-100100.xml",
            params={"run_as": "alice", "overwrite": "true"},
        ),
        method="PUT",
        json={"data": {"affected_items": ["wazuh-mcp-100100.xml"]}},
    )
    xml = (
        b'<group name="test"><rule id="100100" level="5">'
        b"<description>d</description></rule></group>"
    )
    resp = await client.upload_rule_file(
        filename="wazuh-mcp-100100.xml", xml=xml, run_as="alice"
    )
    assert "data" in resp
    rule_upload_requests = [
        r
        for r in httpx_mock.get_requests()
        if r.url.path == "/manager/files/rules/wazuh-mcp-100100.xml"
    ]
    assert rule_upload_requests, "expected a PUT to the rule-file endpoint"
    ct = rule_upload_requests[-1].headers["content-type"]
    assert ct.startswith("application/xml") or ct == "application/octet-stream"


@pytest.mark.asyncio
async def test_run_active_response_posts_with_command_and_args(client, httpx_mock) -> None:
    httpx_mock.add_response(
        url=httpx.URL(
            "https://wazuh.example:55000/active-response",
            params={"run_as": "alice"},
        ),
        method="POST",
        json={"data": {"affected_items": ["003"]}},
    )
    resp = await client.run_active_response(
        agent_id="003",
        command="block-ip",
        custom_args={"srcip": "10.0.0.1"},
        run_as="alice",
    )
    assert "data" in resp
    active_response_requests = [
        r for r in httpx_mock.get_requests() if r.url.path == "/active-response"
    ]
    assert active_response_requests, "expected a POST to /active-response"
    body = active_response_requests[-1].read()
    assert b'"command":"block-ip"' in body or b'"command": "block-ip"' in body
    assert b'"srcip":"10.0.0.1"' in body or b'"srcip": "10.0.0.1"' in body
