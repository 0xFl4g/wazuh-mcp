"""Integration smoke: prompts return pre-loaded context messages."""

from __future__ import annotations

import pytest

from tests.integration.conftest import MCP_URL


@pytest.mark.integration
async def test_triage_last_hour_prompt(mcp_http_server, keycloak_token):
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
            result = await session.get_prompt("wazuh:triage-last-hour")
    finally:
        await http_client.aclose()

    assert result.messages, "expected the prompt to return at least one message"
    content = result.messages[0].content
    from mcp.types import TextContent

    assert isinstance(content, TextContent)
    assert "TOTAL IN RANGE" in content.text
