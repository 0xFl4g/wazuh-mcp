"""Integration smoke: resource templates are reachable end-to-end."""

from __future__ import annotations

import pytest

from tests.integration.conftest import MCP_URL


@pytest.mark.integration
async def test_list_resource_templates_returns_three(mcp_http_server, keycloak_token):
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
            templates = await session.list_resource_templates()
    finally:
        await http_client.aclose()

    uris = {t.uriTemplate for t in templates.resourceTemplates}
    assert uris == {
        "wazuh://rules/{rule_id}",
        "wazuh://mitre/technique/{technique_id}",
        "wazuh://agents/{agent_id}/config",
    }


@pytest.mark.integration
async def test_read_mitre_technique(mcp_http_server, keycloak_token):
    """T1110 is in every Wazuh-bundled ATT&CK dataset."""
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
            result = await session.read_resource("wazuh://mitre/technique/T1110")
    finally:
        await http_client.aclose()

    assert result.contents, "expected at least one content block"
    # ttl_seconds is part of the template metadata (resources/templates/list);
    # FastMCP doesn't wire the handler's `_meta` dict through to
    # ReadResourceResult.meta, so the cache hint isn't asserted here. The
    # technique payload itself is in result.contents[0].text.
    payload_text = getattr(result.contents[0], "text", "")
    assert "T1110" in payload_text, "expected the technique id in the payload"
