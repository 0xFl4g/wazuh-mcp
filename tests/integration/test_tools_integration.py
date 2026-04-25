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
            r = await session.call_tool("agents.get_agent", {"agent_id": "001"})
            assert not r.isError
            for tool in (
                "agents.agent_processes",
                "agents.agent_packages",
                "agents.agent_ports",
            ):
                r = await session.call_tool(tool, {"agent_id": "001", "size": 3})
                # syscollector inventory may legitimately be empty on a
                # fresh agent — don't assert payload, just no upstream
                # bug surfaces (i.e. no upstream_error / not_found).
                if r.isError:
                    text = "".join(getattr(c, "text", "") for c in r.content).lower()
                    assert "upstream" not in text and "not_found" not in text, (
                        f"{tool} surfaced upstream error: {text}"
                    )
    finally:
        await http_client.aclose()


@pytest.mark.integration
async def test_vulns_tools_all_respond(mcp_http_server, keycloak_token):
    """Smoke each vulnerabilities.* tool against the live indexer."""
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
            for tool, args in (
                ("vulnerabilities.list_vulnerabilities_by_agent", {"agent_id": "001", "size": 3}),
                ("vulnerabilities.search_vulnerabilities", {"min_severity": "high", "size": 3}),
            ):
                r = await session.call_tool(tool, args)
                if r.isError:
                    text = "".join(getattr(c, "text", "") for c in r.content).lower()
                    # The vulnerability index may not exist on a fresh
                    # fixture (no scan run yet) — ``not_found`` on the
                    # index itself is acceptable. ``upstream_error`` /
                    # ``invalid_query`` would indicate a wire-format bug.
                    assert "upstream_error" not in text and "invalid_query" not in text, (
                        f"{tool} surfaced wire-format error: {text}"
                    )
    finally:
        await http_client.aclose()


@pytest.mark.integration
async def test_fim_tools_all_respond(mcp_http_server, keycloak_token):
    """Smoke each fim.* tool against the live indexer."""
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
            for tool, args in (
                (
                    "fim.fim_history_for_path",
                    {"path": "/etc/passwd", "time_range": "24h", "size": 3},
                ),
                (
                    "fim.fim_changes_by_agent",
                    {"agent_id": "001", "time_range": "24h", "size": 3},
                ),
            ):
                r = await session.call_tool(tool, args)
                if r.isError:
                    text = "".join(getattr(c, "text", "") for c in r.content).lower()
                    assert "upstream_error" not in text and "invalid_query" not in text, (
                        f"{tool} surfaced wire-format error: {text}"
                    )
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
