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
import os
import shutil
import subprocess
import tempfile
import time
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest

from wazuh_mcp.secrets.value import SecretValue
from wazuh_mcp.wazuh.indexer import IndexerClient

pytestmark = [pytest.mark.integration, pytest.mark.requires_manager]


MCP_WRITES_URL = "http://127.0.0.1:8770"
MCP_WRITES_AUDIT_URL = "http://127.0.0.1:8771"


def _spawn_server(cfg_dir: Path, url: str, label: str) -> subprocess.Popen[bytes]:
    """Spawn ``uv run wazuh-mcp`` pointed at ``cfg_dir`` and wait for /healthz.

    Lifted from the M4a inline fixtures so the write-tests don't have to
    duplicate 40 lines of boot-and-poll boilerplate twice.
    """
    env = os.environ.copy()
    env["WAZUH_MCP_CONFIG_DIR"] = str(cfg_dir)
    proc = subprocess.Popen(
        ["uv", "run", "wazuh-mcp"],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    started = False
    for _ in range(60):
        if proc.poll() is not None:
            stdout, stderr = proc.communicate(timeout=5)
            raise RuntimeError(
                f"MCP HTTP server ({label}) exited early\n"
                f"stdout:\n{stdout.decode(errors='replace')}\n"
                f"stderr:\n{stderr.decode(errors='replace')}"
            )
        try:
            r = httpx.get(f"{url}/healthz", timeout=1)
            if r.status_code == 200:
                started = True
                break
        except httpx.HTTPError:
            pass
        time.sleep(0.5)

    if not started:
        proc.kill()
        stdout, stderr = proc.communicate(timeout=5)
        raise RuntimeError(
            f"MCP HTTP server ({label}) didn't come up in 30s\n"
            f"stdout:\n{stdout.decode(errors='replace')}\n"
            f"stderr:\n{stderr.decode(errors='replace')}"
        )
    return proc


def _write_writes_tenant(cfg_dir: Path, *, bind_port: int, with_audit_sink: bool) -> None:
    """Render tenants.yaml/secrets.yaml/server.yaml for a write-enabled tenant.

    ``write_allowlist: null`` leaves the allowlist unset => all seven write
    tools register. ``active_response_allowlist: [block-ip]`` gives the
    AR rejection test a valid contrast command to reject against.
    """
    audit_sink_block = ""
    if with_audit_sink:
        audit_sink_block = """
    audit_sinks:
      - kind: wazuh_indexer
        index_prefix: wazuh-mcp-audit
        batch: 1
        flush_ms: 200"""

    (cfg_dir / "tenants.yaml").write_text(
        f"""
tenants:
  - tenant_id: local
    indexer_url: https://localhost:9200
    verify_tls: false
    ca_bundle_path: null
    default_rbac_role: admin
    oauth_issuer: http://localhost:8080/realms/wazuh-mcp
    oauth_audience: wazuh-mcp-api
    write_allowlist: null
    active_response_allowlist:
      - block-ip{audit_sink_block}
""".strip()
    )
    (cfg_dir / "secrets.yaml").write_text(
        """
local:
  indexer_user: admin
  indexer_password: admin
  server_api_user: wazuh-wui
  server_api_password: MCPmcp12345!
""".strip()
    )
    (cfg_dir / "api_keys.yaml").write_text("api_keys: []\n")
    (cfg_dir / "server.yaml").write_text(
        f"""
transport: http
auth: oauth_chain
http:
  bind: "127.0.0.1:{bind_port}"
  public_url: "http://127.0.0.1:{bind_port}"
oauth:
  issuer: http://localhost:8080/realms/wazuh-mcp
  audience: wazuh-mcp-api
  rbac_claims: [wazuh_mcp_role, groups, roles]
  algorithms: [RS256]
  clock_skew_seconds: 30
api_keys_file: {cfg_dir / "api_keys.yaml"}
""".strip()
    )


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


@pytest.mark.skip(
    reason=(
        "needs a connected wazuh-agent process; Wazuh doesn't ship an "
        "official wazuh-agent Docker image, so the integration compose "
        "registers agent 001 via the API but no peer answers "
        "active-response or restart commands. Tracked as M4c fixture work."
    )
)
async def test_isolate_then_restart_agent_roundtrip(mcp_http_server_writes, keycloak_token) -> None:
    """Happy path: isolate, check audit events landed, restart, verify both ok."""
    async with _mcp_session(MCP_WRITES_URL, keycloak_token()) as session:
        iso = await session.call_tool("write.isolate_agent", {"agent_id": "001", "confirm": True})
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


@pytest.mark.skip(
    reason=(
        "Wazuh 4.9 manager returns 404 for PUT /manager/files even with the "
        "documented path=etc/rules/<filename>&overwrite=true shape. The "
        "wazuh-wui service account may lack the manager:upload_file RBAC "
        "permission, or the endpoint path drifted again — needs a sit-down "
        "with a live 4.9 manager to map the correct call. Tracked as M4c "
        "fixture work; the unit test in test_server_api_writes pins the "
        "outgoing wire format so any handler-side regression still lights up."
    )
)
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
                "agent_id": "001",
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
        result = await session.call_tool("write.isolate_agent", {"agent_id": "001"})
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
