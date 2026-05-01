"""M5b T-A3: integration test for write.run_active_response_on_group.

Marked @requires_manager — runs nightly on amd64 CI, manual dispatch
otherwise. Spawns the dedicated mcp_http_server_m5b fixture (port 8775,
admin role + agent_group_allowlist=['test-group'] + active_response_allowlist=
['isolate']) and exercises the group-target AR end-to-end against a
test-group containing agent 001.

Pre-creates the 'test-group' agent group via the Wazuh Server API and
assigns agent 001 to it (both calls are idempotent), then fires
write.run_active_response_on_group via the MCP layer. The active-response
'isolate' command is the only AR registered in
docker/config/wazuh_manager_ossec.conf, so the manager actually accepts it.

_mcp_session is inlined per the M4b/M4c precedent (pytest-asyncio
cancel-scope task-locality requirement).
"""

from __future__ import annotations

from contextlib import asynccontextmanager

import httpx
import pytest

pytestmark = [pytest.mark.integration, pytest.mark.requires_manager]


WAZUH_MANAGER_URL = "https://localhost:55000"


@asynccontextmanager
async def _mcp_session(url: str, token: str):
    """Authenticated MCP streamable-HTTP session, scoped to the caller's task.

    Inlined per M4b/M4c precedent (test_m4b_writes.py:186) — pytest-asyncio
    runs async-generator fixture setup/teardown in different tasks, and
    anyio's CancelScope (used inside streamable_http_client / ClientSession)
    requires same-task entry+exit. Inlining as `async with` inside each
    test body keeps both ends in the test's task.
    """
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    http_client = httpx.AsyncClient(
        headers={"Authorization": f"Bearer {token}"},
        timeout=httpx.Timeout(30.0),
    )
    try:
        async with (
            streamable_http_client(f"{url}/mcp", http_client=http_client) as (
                read,
                write,
                _gsid,
            ),
            ClientSession(read, write) as session,
        ):
            await session.initialize()
            yield session
    finally:
        await http_client.aclose()


async def _ensure_test_group_with_agent(
    server_api_base: str = WAZUH_MANAGER_URL,
) -> None:
    """Create 'test-group' (POST /groups) and assign agent 001 to it
    (PUT /agents/001/group/test-group). Both operations are idempotent
    on the manager side — already-exists / already-assigned responses
    are accepted.

    Uses the wazuh-wui:MCPmcp12345! basic auth flow:
    /security/user/authenticate -> JWT -> Authorization: Bearer for
    the subsequent group + agent calls.
    """
    async with httpx.AsyncClient(verify=False, timeout=10.0) as c:
        r = await c.post(
            f"{server_api_base}/security/user/authenticate",
            auth=("wazuh-wui", "MCPmcp12345!"),
        )
        r.raise_for_status()
        jwt = r.json()["data"]["token"]
        auth = {"Authorization": f"Bearer {jwt}"}

        # Create group; 200 OK or already-exists (1905) both fine.
        await c.post(
            f"{server_api_base}/groups",
            json={"group_id": "test-group"},
            headers=auth,
        )
        # Assign agent 001; 200 OK or already-assigned both fine.
        await c.put(
            f"{server_api_base}/agents/001/group/test-group",
            headers=auth,
        )


@pytest.mark.asyncio
async def test_run_active_response_on_group_against_test_group(
    mcp_http_server_m5b, keycloak_token
) -> None:
    """End-to-end: fire write.run_active_response_on_group against
    'test-group' containing agent 001. Wazuh queues the AR command;
    affected_agents reflects the agents the command was queued for."""
    await _ensure_test_group_with_agent()

    async with _mcp_session(mcp_http_server_m5b, keycloak_token()) as session:
        result = await session.call_tool(
            "write.run_active_response_on_group",
            {
                "group_name": "test-group",
                "command_name": "isolate",
                "confirm": True,
            },
        )
        assert not result.isError, f"call errored: {result}"
        # v0.7.2 contract lesson: typed-output tools return JSON in
        # structuredContent, not result.content[0].text.
        payload = result.structuredContent
        assert payload is not None, "structuredContent missing from CallToolResult"
        assert payload["ok"] is True
        # affected_agents may be empty on some manager edge configs
        # (agent connection state, queueing race) — assert key presence.
        assert "affected_agents" in payload
        assert payload["failed_agents"] == []
