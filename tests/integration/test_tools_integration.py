"""Per-tool integration smokes against the full fixture (manager + indexer + Keycloak)."""

from __future__ import annotations

import pytest

from tests.integration.conftest import MCP_URL


@pytest.mark.integration
async def test_alerts_tools_all_respond(mcp_http_server, keycloak_token):
    """Call each alerts.* tool; assert structured response even if results are empty."""
    import httpx as _httpx
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    token = keycloak_token()
    http_client = _httpx.AsyncClient(
        headers={"Authorization": f"Bearer {token}"},
        timeout=_httpx.Timeout(30.0),
    )
    try:
        async with (
            streamable_http_client(f"{MCP_URL}/mcp", http_client=http_client) as (
                read,
                write,
                _gsid,
            ),
            ClientSession(read, write) as session,
        ):
            await session.initialize()
            r = await session.call_tool("alerts.search_alerts", {"time_range": "24h", "size": 3})
            assert not r.isError
            r = await session.call_tool(
                "alerts.alerts_by_agent",
                {"agent_id": "000", "time_range": "24h", "size": 3},
            )
            assert not r.isError
            r = await session.call_tool(
                "alerts.alerts_by_mitre",
                {"technique_id": "T1110.001", "time_range": "24h", "size": 3},
            )
            assert not r.isError
    finally:
        await http_client.aclose()


@pytest.mark.integration
async def test_agents_tools_all_respond(mcp_http_server, keycloak_token):
    import httpx as _httpx
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    token = keycloak_token()
    http_client = _httpx.AsyncClient(
        headers={"Authorization": f"Bearer {token}"},
        timeout=_httpx.Timeout(30.0),
    )
    try:
        async with (
            streamable_http_client(f"{MCP_URL}/mcp", http_client=http_client) as (
                read,
                write,
                _gsid,
            ),
            ClientSession(read, write) as session,
        ):
            await session.initialize()
            r = await session.call_tool("agents.list_agents", {"size": 5})
            assert not r.isError
    finally:
        await http_client.aclose()


@pytest.mark.integration
async def test_hunt_query_rejects_off_allowlist_field(mcp_http_server, keycloak_token):
    """The hunt grammar's field allowlist must be enforced end-to-end."""
    import httpx as _httpx
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    token = keycloak_token()
    http_client = _httpx.AsyncClient(
        headers={"Authorization": f"Bearer {token}"},
        timeout=_httpx.Timeout(30.0),
    )
    try:
        async with (
            streamable_http_client(f"{MCP_URL}/mcp", http_client=http_client) as (
                read,
                write,
                _gsid,
            ),
            ClientSession(read, write) as session,
        ):
            await session.initialize()
            r = await session.call_tool(
                "hunt.hunt_query",
                {
                    "time_range": "1h",
                    "must": [{"field": "vulnerability.id", "op": "eq", "value": "CVE-X"}],
                },
            )
            assert r.isError, "expected ValidationError surfaced to the client"
    finally:
        await http_client.aclose()
