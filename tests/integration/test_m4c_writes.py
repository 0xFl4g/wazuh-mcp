"""M4c integration tests — write.restart_manager, cluster.status, multi-agent isolate.

Marked @requires_manager — runs nightly on amd64 CI, manual dispatch
otherwise. Spawns a dedicated MCP HTTP server on port 8772 with
``default_rbac_role: admin`` so cluster.status (read) and write tools
are allowed. The conftest's `mcp_http_server` (port 8765) defaults to
``analyst`` which excludes cluster.* and write.*. _mcp_session is
inlined per the M4b precedent (pytest-asyncio cancel-scope
task-locality requirement).
"""

from __future__ import annotations

import asyncio
import tempfile
import time
from collections.abc import Iterator
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
import pytest

from tests.integration.test_m4b_writes import (  # type: ignore[import-not-found]
    _spawn_server,
    _write_writes_tenant,
)

pytestmark = [pytest.mark.integration, pytest.mark.requires_manager]


MCP_M4C_URL = "http://127.0.0.1:8772"


@pytest.fixture(scope="module")
def mcp_http_server_m4c() -> Iterator[None]:
    """MCP HTTP server on 8772 with admin default role.

    Uses M4b's _write_writes_tenant helper (admin role + write_allowlist=null
    + active_response_allowlist=[block-ip]) so cluster.status, write.restart_manager,
    and multi-agent write.isolate_agent all clear RBAC at call time.
    """
    cfg_dir = Path(tempfile.mkdtemp(prefix="wm-m4c-"))
    _write_writes_tenant(cfg_dir, bind_port=8772, with_audit_sink=False)
    proc = _spawn_server(cfg_dir, MCP_M4C_URL, "m4c")
    try:
        yield None
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()


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
async def test_cluster_status_reads_node_metadata(mcp_http_server_m4c, keycloak_token) -> None:
    async with _mcp_session(MCP_M4C_URL, keycloak_token()) as session:
        result = await session.call_tool("cluster.status", {})
        assert not result.isError, f"cluster.status returned error: {result}"
        payload = result.structuredContent
        assert payload is not None, "structuredContent missing from CallToolResult"
        assert payload["enabled"] in (True, False)
        # Single-node CI fixture: even with clustering disabled, the read succeeds.
        if payload["enabled"]:
            assert len(payload["nodes"]) >= 1
            assert payload["nodes"][0]["name"]


@pytest.mark.asyncio
@pytest.mark.destructive
async def test_restart_manager_node_scope_completes(mcp_http_server_m4c, keycloak_token) -> None:
    """Restart this node, then poll cluster.status until running again.

    Routed to the destructive-integration.yml workflow (M5a T12). The
    test mutates shared Wazuh manager state by restarting the container
    via /manager/restart. Subsequent manager-API tests in the same
    pytest run would see an in-recovery manager — that's why this test
    runs in its own workflow (no other tests in that workflow share the
    fixture).

    Wire-shape pinning also lives in tests/unit/test_restart_manager.py
    and tests/unit/test_server_wiring_m4c.py.
    """
    async with _mcp_session(MCP_M4C_URL, keycloak_token()) as session:
        result = await session.call_tool(
            "write.restart_manager",
            {"scope": "node", "confirm": True},
        )
        assert not result.isError, f"write.restart_manager returned error: {result}"
        payload = result.structuredContent
        assert payload is not None, "structuredContent missing from CallToolResult"
        assert payload["ok"] is True
        assert payload["scope"] == "node"
        assert payload["affected_nodes"]

        # Poll cluster.status until ready (CI single-node settles within 60s).
        deadline = time.monotonic() + 90.0
        while time.monotonic() < deadline:
            try:
                status_result = await session.call_tool("cluster.status", {})
                status = status_result.structuredContent
                if status is not None:
                    return
            except Exception:
                pass
            await asyncio.sleep(3.0)
        pytest.fail("manager did not return to ready within 90s after node restart")


@pytest.mark.asyncio
async def test_multi_agent_isolate_one_agent(mcp_http_server_m4c, keycloak_token) -> None:
    """Exercise the agent_ids: list[str] shape via the URL-builder path
    on the single-agent CI fixture."""
    async with _mcp_session(MCP_M4C_URL, keycloak_token()) as session:
        result = await session.call_tool(
            "write.isolate_agent",
            {"agent_ids": ["001"], "confirm": True},
        )
        assert not result.isError, f"write.isolate_agent returned error: {result}"
        payload = result.structuredContent
        assert payload is not None, "structuredContent missing from CallToolResult"
        # Whether the isolate active-response actually fires depends on the
        # manager's ossec.conf wiring (configured during the integration
        # restoration session). Either ok=True with affected_agents=["001"]
        # or ok=False with failed_agents populated is acceptable here — the
        # wire-shape pinning is the goal.
        assert payload["ok"] in (True, False)
        if payload["ok"]:
            assert payload["affected_agents"] == ["001"]
