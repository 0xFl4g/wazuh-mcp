"""M4b write tools against the real Wazuh manager.

Requires amd64 runner; auto-skips on arm64+darwin via @requires_manager.

Two inline MCP HTTP servers are spawned per module:
- port 8770: write-enabled tenant (``write_allowlist: None`` => all writes
  registered), ``active_response_allowlist: ["block-ip"]`` so the
  not-in-allowlist contrast is meaningful, and ``default_rbac_role: admin``
  so the service-account token (which carries no ``wazuh_mcp_role`` claim)
  falls through to admin and can actually invoke write tools.
- port 8771: same tenant config plus a ``wazuh_indexer`` audit sink with
  ``batch: 1, flush_ms: 200`` so the requested + completed events flush
  through to ``wazuh-mcp-audit-YYYY.MM.DD`` fast enough for the roundtrip
  assertion.

Follows the M4a inline-per-file fixture precedent (see
``test_m4a_rbac.py``, ``test_m4a_rate_limit.py``,
``test_m4a_audit_indexer_sink.py``) instead of plumbing new fixtures into
the shared conftest.
"""

from __future__ import annotations

import asyncio
import shutil
import subprocess
import tempfile
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest

from tests.integration._helpers import (  # type: ignore[import-not-found]
    _spawn_server,
    _write_writes_tenant,
)
from wazuh_mcp.secrets.value import SecretValue
from wazuh_mcp.wazuh.indexer import IndexerClient

pytestmark = [pytest.mark.integration, pytest.mark.requires_manager]


MCP_WRITES_URL = "http://127.0.0.1:8770"
MCP_WRITES_AUDIT_URL = "http://127.0.0.1:8771"


@pytest.fixture(scope="module")
def mcp_http_server_writes() -> Iterator[None]:
    """MCP HTTP server on 8770 with writes enabled + admin default role."""
    cfg_dir = Path(tempfile.mkdtemp(prefix="wm-m4b-writes-"))
    _write_writes_tenant(cfg_dir, bind_port=8770, with_audit_sink=False)
    proc = _spawn_server(cfg_dir, MCP_WRITES_URL, "writes")
    try:
        yield None
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        shutil.rmtree(cfg_dir, ignore_errors=True)


@pytest.fixture(scope="module")
def mcp_http_server_writes_with_sink() -> Iterator[None]:
    """MCP HTTP server on 8771 with writes enabled + wazuh_indexer audit sink."""
    cfg_dir = Path(tempfile.mkdtemp(prefix="wm-m4b-writes-sink-"))
    _write_writes_tenant(cfg_dir, bind_port=8771, with_audit_sink=True)
    proc = _spawn_server(cfg_dir, MCP_WRITES_AUDIT_URL, "writes+sink")
    try:
        yield None
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        shutil.rmtree(cfg_dir, ignore_errors=True)


@asynccontextmanager
async def _mcp_session(url: str, token: str):
    """Authenticated MCP streamable-HTTP session, scoped to the caller's task.

    The original M4b fixtures opened ``AsyncExitStack`` and ``yield``-ed the
    session — but pytest-asyncio runs an async-generator fixture's setup and
    teardown in different tasks, and anyio's ``CancelScope`` (used inside
    ``streamable_http_client`` and ``ClientSession``) requires same-task
    entry/exit. Result: every M4b test errored at teardown with
    ``RuntimeError: Attempted to exit cancel scope in a different task than
    it was entered in``. Inlining ``async with _mcp_session(...)`` inside
    each test body keeps both ends in the test's own task — same approach
    the M4a integration tests already use (see ``test_m4a_rbac.py``).
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


class _RawIndexerClient:
    """Thin wrapper around :class:`IndexerClient` that accepts a query
    fragment (``{"match": {...}}``) and wraps it as ``{"query": fragment}``.

    The audit-roundtrip test expresses its intent in the fragment form; the
    wrapper keeps that call-site readable without leaking the full ES body
    envelope into the test.
    """

    def __init__(self, inner: IndexerClient) -> None:
        self._inner = inner

    async def search(self, *, index: str, query: dict[str, Any]) -> dict[str, Any]:
        return await self._inner.search(index=index, query={"query": query})


@pytest.fixture
async def raw_indexer_client() -> AsyncIterator[_RawIndexerClient]:
    """Raw indexer client configured against the seeded OpenSearch instance.

    Separate from the shared ``indexer`` fixture so the M4b write tests
    can use the fragment-accepting wrapper without perturbing M4a callers.
    """
    inner = IndexerClient(
        base_url="https://localhost:9200",
        user=SecretValue("admin"),
        password=SecretValue("admin"),
        verify_tls=False,
    )
    try:
        yield _RawIndexerClient(inner)
    finally:
        await inner.aclose()


async def test_isolate_then_restart_agent_roundtrip(mcp_http_server_writes, keycloak_token) -> None:
    """Happy path: isolate, check audit events landed, restart, verify both ok."""
    async with _mcp_session(MCP_WRITES_URL, keycloak_token()) as session:
        iso = await session.call_tool(
            "write.isolate_agent", {"agent_ids": ["001"], "confirm": True}
        )
        assert not iso.isError

        restart = await session.call_tool(
            "write.restart_agent", {"agent_id": "001", "confirm": True}
        )
        assert not restart.isError


async def test_add_then_remove_from_group(mcp_http_server_writes, keycloak_token) -> None:
    async with _mcp_session(MCP_WRITES_URL, keycloak_token()) as session:
        add = await session.call_tool(
            "write.add_agent_to_group",
            {"agent_id": "001", "group_id": "test-group", "confirm": True},
        )
        assert not add.isError
        remove = await session.call_tool(
            "write.remove_agent_from_group",
            {"agent_id": "001", "group_id": "test-group", "confirm": True},
        )
        assert not remove.isError


async def test_create_rule_uploads_file(mcp_http_server_writes, keycloak_token) -> None:
    async with _mcp_session(MCP_WRITES_URL, keycloak_token()) as session:
        result = await session.call_tool(
            "write.create_rule",
            {
                "rule": {
                    "id": 100_100,
                    "level": 5,
                    "description": "wazuh-mcp M4b integration test rule",
                },
                "confirm": True,
            },
        )
        assert not result.isError


async def test_run_active_response_rejected_when_command_not_allowlisted(
    mcp_http_server_writes, keycloak_token
) -> None:
    async with _mcp_session(MCP_WRITES_URL, keycloak_token()) as session:
        result = await session.call_tool(
            "write.run_active_response",
            {
                "agent_ids": ["001"],
                "command_name": "not-in-allowlist",
                "custom_args": None,
                "confirm": True,
            },
        )
    assert result.isError
    text = "".join(getattr(c, "text", "") for c in result.content).lower()
    assert "allowlist" in text or "forbidden" in text


async def test_confirm_missing_rejected_at_args_parse(
    mcp_http_server_writes, keycloak_token
) -> None:
    async with _mcp_session(MCP_WRITES_URL, keycloak_token()) as session:
        result = await session.call_tool("write.isolate_agent", {"agent_ids": ["001"]})
    assert result.isError


async def test_audit_events_double_land_in_indexer(
    mcp_http_server_writes_with_sink, keycloak_token, raw_indexer_client
) -> None:
    """One tool call -> both requested + completed audits in wazuh-mcp-audit-*.

    Uses ``write.add_agent_to_group`` because that's a manager-side
    metadata edit — it needs a registered agent + an existing group, both
    of which the seed script provides, but no running agent process. The
    decorator's double-emit contract is the same regardless of which
    write tool is invoked, so swapping in a non-active-response tool here
    keeps the test focused on the audit invariant rather than the
    agent-process roundtrip.
    """
    async with _mcp_session(MCP_WRITES_AUDIT_URL, keycloak_token()) as session:
        await session.call_tool(
            "write.add_agent_to_group",
            {"agent_id": "001", "group_id": "test-group", "confirm": True},
        )
    await asyncio.sleep(3)
    today = datetime.now(UTC).strftime("%Y.%m.%d")
    resp = await raw_indexer_client.search(
        index=f"wazuh-mcp-audit-{today}",
        query={"match": {"tool": "write.add_agent_to_group"}},
    )
    outcomes = [h["_source"]["outcome"] for h in resp["hits"]["hits"]]
    assert "write.requested" in outcomes
    assert "ok" in outcomes
