"""WazuhIndexerSink roundtrip: audit events land in wazuh-mcp-audit-*.

Spawns an MCP HTTP server (port 8768) whose tenant has a ``wazuh_indexer``
audit sink configured. After a tool call, the batched sink should flush
an audit doc to ``wazuh-mcp-audit-YYYY.MM.DD`` in the seeded indexer;
the test queries the indexer directly and asserts at least one doc with
the expected tool name lands there.
"""
from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

pytestmark = [pytest.mark.integration]


MCP_AUDIT_URL = "http://127.0.0.1:8768"


@pytest.fixture(scope="module")
def mcp_http_server_indexer_sink():
    """MCP server with a wazuh_indexer audit sink on the local tenant."""
    cfg_dir = Path(tempfile.mkdtemp(prefix="wm-m4a-audit-"))

    (cfg_dir / "tenants.yaml").write_text(
        """
tenants:
  - tenant_id: local
    indexer_url: https://localhost:9200
    verify_tls: false
    ca_bundle_path: null
    default_rbac_role: admin
    oauth_issuer: http://localhost:8080/realms/wazuh-mcp
    oauth_audience: wazuh-mcp-api
    audit_sinks:
      - kind: wazuh_indexer
        index_prefix: wazuh-mcp-audit
        batch: 1
        flush_ms: 200
""".strip()
    )
    (cfg_dir / "secrets.yaml").write_text(
        """
local:
  indexer_user: admin
  indexer_password: admin
""".strip()
    )
    (cfg_dir / "api_keys.yaml").write_text("api_keys: []\n")
    (cfg_dir / "server.yaml").write_text(
        f"""
transport: http
auth: oauth_chain
http:
  bind: "127.0.0.1:8768"
  public_url: "{MCP_AUDIT_URL}"
oauth:
  issuer: http://localhost:8080/realms/wazuh-mcp
  audience: wazuh-mcp-api
  rbac_claims: [wazuh_mcp_role, groups, roles]
  algorithms: [RS256]
  clock_skew_seconds: 30
api_keys_file: {cfg_dir / "api_keys.yaml"}
""".strip()
    )

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
                "MCP HTTP server (audit-sink) exited early\n"
                f"stdout:\n{stdout.decode(errors='replace')}\n"
                f"stderr:\n{stderr.decode(errors='replace')}"
            )
        try:
            r = httpx.get(f"{MCP_AUDIT_URL}/healthz", timeout=1)
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
            "MCP HTTP server (audit-sink) didn't come up in 30s\n"
            f"stdout:\n{stdout.decode(errors='replace')}\n"
            f"stderr:\n{stderr.decode(errors='replace')}"
        )

    try:
        yield None
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        shutil.rmtree(cfg_dir, ignore_errors=True)


@pytest.mark.integration
async def test_audit_events_land_in_indexer(
    mcp_http_server_indexer_sink, keycloak_token, indexer
):
    """A tool call on the sink-configured tenant produces an audit doc
    searchable in today's wazuh-mcp-audit-YYYY.MM.DD index."""
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
            streamable_http_client(f"{MCP_AUDIT_URL}/mcp", http_client=http_client) as (
                read,
                write,
                _gsid,
            ),
            ClientSession(read, write) as session,
        ):
            await session.initialize()
            r = await session.call_tool(
                "alerts.search_alerts", {"time_range": "24h", "size": 1}
            )
            assert not r.isError, f"tool call failed: {r}"
    finally:
        await http_client.aclose()

    # Give the batched sink time to flush (configured flush_ms=200, batch=1).
    await asyncio.sleep(3)

    today = datetime.now(UTC).strftime("%Y.%m.%d")
    resp = await indexer.search(
        index=f"wazuh-mcp-audit-{today}",
        query={"query": {"match_all": {}}},
    )
    hits = resp.get("hits", {}).get("hits", [])
    assert len(hits) >= 1, (
        f"no audit docs landed in wazuh-mcp-audit-{today}; got: {resp}"
    )
    tools_seen = {h.get("_source", {}).get("tool") for h in hits}
    assert "alerts.search_alerts" in tools_seen, (
        f"expected alerts.search_alerts in audit docs, got tools: {tools_seen}"
    )
    sample = next(
        h["_source"] for h in hits if h.get("_source", {}).get("tool") == "alerts.search_alerts"
    )
    assert "outcome" in sample, f"audit doc missing 'outcome' field: {sample}"
