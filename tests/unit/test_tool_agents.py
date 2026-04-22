"""Unit tests for agents.* tools."""

import io

import pytest

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import AuditEmitter
from wazuh_mcp.secrets.value import SecretValue
from wazuh_mcp.tools.agents import (
    AgentSubquery,
    GetAgentArgs,
    ListAgentsArgs,
    agent_packages,
    get_agent,
    list_agents,
)
from wazuh_mcp.wazuh.errors import WazuhError
from wazuh_mcp.wazuh.server_api import ServerApiClient


def _jwt() -> str:
    import base64
    import json
    import time as _t

    hdr = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=").decode()
    pl = (
        base64.urlsafe_b64encode(
            json.dumps({"exp": int(_t.time()) + 900, "iat": int(_t.time())}).encode()
        )
        .rstrip(b"=")
        .decode()
    )
    return f"{hdr}.{pl}.sig"


@pytest.fixture
def session() -> Session:
    return Session(
        user_id="u",
        tenant_id="t",
        rbac_role="soc_analyst",
        auth_method="oauth",
        wazuh_user="alice",
    )


@pytest.fixture
def audit() -> AuditEmitter:
    return AuditEmitter(stream=io.StringIO())


@pytest.fixture
async def server_api(httpx_mock):
    httpx_mock.add_response(
        url="https://manager.example:55000/security/user/authenticate",
        method="POST",
        json={"data": {"token": _jwt()}},
    )
    client = ServerApiClient(
        base_url="https://manager.example:55000",
        user=SecretValue("wazuh-wui"),
        password=SecretValue("x"),
        verify_tls=False,
    )
    try:
        yield client
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_list_agents_happy(session, audit, server_api, httpx_mock):
    httpx_mock.add_response(
        url="https://manager.example:55000/agents?status=active&limit=25&offset=0&run_as=alice",
        method="GET",
        json={
            "data": {
                "total_affected_items": 2,
                "affected_items": [
                    {"id": "001", "name": "a"},
                    {"id": "002", "name": "b"},
                ],
            }
        },
    )
    result = await list_agents(
        args=ListAgentsArgs(status="active", size=25),
        session=session,
        server_api=server_api,
        audit=audit,
    )
    assert result.total == 2
    assert [a.id for a in result.agents] == ["001", "002"]


@pytest.mark.asyncio
async def test_get_agent_not_found(session, audit, server_api, httpx_mock):
    httpx_mock.add_response(
        url="https://manager.example:55000/agents?agents_list=999&run_as=alice",
        method="GET",
        json={"data": {"affected_items": []}},
    )
    with pytest.raises(WazuhError) as exc_info:
        await get_agent(
            args=GetAgentArgs(agent_id="999"),
            session=session,
            server_api=server_api,
            audit=audit,
        )
    assert exc_info.value.code == "not_found"


@pytest.mark.asyncio
async def test_agent_packages_passes_run_as(session, audit, server_api, httpx_mock):
    httpx_mock.add_response(
        url="https://manager.example:55000/syscollector/001/packages?limit=10&offset=0&run_as=alice",
        method="GET",
        json={
            "data": {
                "total_affected_items": 1,
                "affected_items": [{"name": "openssl", "version": "3.0.0"}],
            }
        },
    )
    result = await agent_packages(
        args=AgentSubquery(agent_id="001", size=10),
        session=session,
        server_api=server_api,
        audit=audit,
    )
    assert result.agent_id == "001"
    assert result.items[0]["name"] == "openssl"
