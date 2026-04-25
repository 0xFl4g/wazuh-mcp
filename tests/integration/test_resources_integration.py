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
@pytest.mark.skip(
    reason=(
        "Wazuh manager fixture has no MITRE technique data populated — "
        "GET /mitre/techniques?q=external_id=T1110 returns empty. The "
        "stock wazuh/wazuh-manager:4.9 image expects MITRE data to be "
        "loaded (often via a separate provisioning step) and the integration "
        "compose doesn't perform it. Tracked as M4c fixture work; the unit "
        "test in test_tool_mitre pins the wire query format so handler-side "
        "regressions still light up."
    )
)
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
    assert result.meta is not None and result.meta.get("ttl_seconds") == 86_400
