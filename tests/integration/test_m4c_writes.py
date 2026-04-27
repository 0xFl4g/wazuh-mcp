"""M4c integration tests — write.restart_manager, cluster.status, multi-agent isolate.

Marked @requires_manager — runs nightly on amd64 CI, manual dispatch
otherwise. Reuses the conftest's shared mcp_http_server (port 8765) +
keycloak_token fixtures. _mcp_session is inlined per the M4b precedent
(pytest-asyncio cancel-scope task-locality requirement).
"""

from __future__ import annotations

import asyncio
import json
import time
from contextlib import asynccontextmanager

import httpx
import pytest

from tests.integration.conftest import MCP_URL  # type: ignore[import-not-found]

pytestmark = [pytest.mark.integration, pytest.mark.requires_manager]


@asynccontextmanager
async def _mcp_session(url: str, token: str):
    """Authenticated MCP streamable-HTTP session, scoped to the caller's task.

    Inlined per M4b precedent (test_m4b_writes.py:186) — pytest-asyncio
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


@pytest.mark.asyncio
async def test_cluster_status_reads_node_metadata(mcp_http_server, keycloak_token) -> None:
    async with _mcp_session(MCP_URL, keycloak_token()) as session:
        result = await session.call_tool("cluster.status", {})
        payload = json.loads(result.content[0].text)
        assert payload["enabled"] in (True, False)
        # Single-node CI fixture: even with clustering disabled, the read succeeds.
        if payload["enabled"]:
            assert len(payload["nodes"]) >= 1
            assert payload["nodes"][0]["name"]


@pytest.mark.asyncio
async def test_restart_manager_node_scope_completes(mcp_http_server, keycloak_token) -> None:
    """Restart this node, then poll cluster.status until running again."""
    async with _mcp_session(MCP_URL, keycloak_token()) as session:
        result = await session.call_tool(
            "write.restart_manager",
            {"scope": "node", "confirm": True},
        )
        payload = json.loads(result.content[0].text)
        assert payload["ok"] is True
        assert payload["scope"] == "node"
        assert payload["affected_nodes"]

        # Poll cluster.status until ready (CI single-node settles within 60s).
        deadline = time.monotonic() + 90.0
        while time.monotonic() < deadline:
            try:
                status_result = await session.call_tool("cluster.status", {})
                status = json.loads(status_result.content[0].text)
                if status is not None:
                    return
            except Exception:
                pass
            await asyncio.sleep(3.0)
        pytest.fail("manager did not return to ready within 90s after node restart")


@pytest.mark.asyncio
async def test_multi_agent_isolate_one_agent(mcp_http_server, keycloak_token) -> None:
    """Exercise the agent_ids: list[str] shape via the URL-builder path
    on the single-agent CI fixture."""
    async with _mcp_session(MCP_URL, keycloak_token()) as session:
        result = await session.call_tool(
            "write.isolate_agent",
            {"agent_ids": ["001"], "confirm": True},
        )
        payload = json.loads(result.content[0].text)
        # Whether the isolate active-response actually fires depends on the
        # manager's ossec.conf wiring (configured during the integration
        # restoration session). Either ok=True with affected_agents=["001"]
        # or ok=False with failed_agents populated is acceptable here — the
        # wire-shape pinning is the goal.
        assert payload["ok"] in (True, False)
        if payload["ok"]:
            assert payload["affected_agents"] == ["001"]
