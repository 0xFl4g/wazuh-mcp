"""/metrics endpoint returns valid Prom text format including M4a counters.

Exercises the unauthenticated /metrics route mounted on the MCP HTTP
server. After driving a few alerts.* tool calls via a real MCP client,
/metrics must return Prom text containing every M4a metric family so
operators can scrape them.
"""

from __future__ import annotations

import httpx
import pytest

from tests.integration.conftest import MCP_URL

pytestmark = [pytest.mark.integration]


@pytest.mark.integration
async def test_metrics_endpoint_returns_prom_text(mcp_http_server, keycloak_token):
    """Drive a few tool calls, then assert /metrics exposes every M4a family."""
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
            # A couple of calls so mcp_tool_calls_total / duration histogram
            # have observations.
            await session.call_tool("alerts.search_alerts", {"time_range": "24h", "size": 3})
            await session.call_tool("alerts.search_alerts", {"time_range": "1h", "size": 1})
    finally:
        await http_client.aclose()

    async with httpx.AsyncClient(timeout=5) as c:
        resp = await c.get(f"{MCP_URL}/metrics")
    assert resp.status_code == 200
    ctype = resp.headers.get("content-type", "")
    assert ctype.startswith("text/plain"), f"unexpected content-type: {ctype!r}"
    body = resp.text
    for family in [
        "mcp_tool_calls_total",
        "mcp_tool_duration_seconds",
        "wazuh_upstream_errors_total",
        "jwt_refresh_total",
        "rate_limited_total",
        "audit_dropped_total",
    ]:
        assert family in body, f"missing metric family {family}"
