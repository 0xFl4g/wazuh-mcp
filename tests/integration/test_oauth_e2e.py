"""End-to-end OAuth tests against Keycloak + MCP HTTP server.

Prerequisites (run via ``docker/bootstrap.sh``):
  - wazuh-indexer healthy on https://localhost:9200 with seeded alerts
  - Keycloak 26 on http://localhost:8080 with realm ``wazuh-mcp`` imported
    (client ``wazuh-mcp-client`` must have ``serviceAccountsEnabled: true``)

The test module spawns the MCP HTTP server as a subprocess bound to
127.0.0.1:8765. Config is written to a temp dir and injected via the
``WAZUH_MCP_CONFIG_DIR`` environment variable.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

import httpx
import pytest

MCP_URL = "http://127.0.0.1:8765"
KC_ISSUER = "http://localhost:8080/realms/wazuh-mcp"


@pytest.fixture(scope="module")
def mcp_http_server():
    cfg_dir = Path(tempfile.mkdtemp(prefix="wm-m2-"))

    (cfg_dir / "tenants.yaml").write_text(
        """
tenants:
  - tenant_id: local
    indexer_url: https://localhost:9200
    verify_tls: false
    ca_bundle_path: null
    default_rbac_role: soc_analyst
    oauth_issuer: http://localhost:8080/realms/wazuh-mcp
    oauth_audience: wazuh-mcp-api
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
  bind: "127.0.0.1:8765"
  public_url: "{MCP_URL}"
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
                "MCP HTTP server exited early\n"
                f"stdout:\n{stdout.decode(errors='replace')}\n"
                f"stderr:\n{stderr.decode(errors='replace')}"
            )
        try:
            r = httpx.get(f"{MCP_URL}/healthz", timeout=1)
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
            "MCP HTTP server didn't come up in 30s\n"
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
def test_protected_resource_metadata_exposes_configured_issuer(mcp_http_server):
    resp = httpx.get(f"{MCP_URL}/.well-known/oauth-protected-resource", timeout=5)
    assert resp.status_code == 200
    body = resp.json()
    assert body["resource"] == MCP_URL
    assert body["authorization_servers"] == [KC_ISSUER]


@pytest.mark.integration
def test_mcp_unauthenticated_request_rejected(mcp_http_server):
    resp = httpx.post(f"{MCP_URL}/mcp", json={}, timeout=5)
    assert resp.status_code == 401
    assert "Bearer" in resp.headers.get("WWW-Authenticate", "")


@pytest.mark.integration
def test_mcp_with_valid_oauth_token_initializes(mcp_http_server, keycloak_token):
    token = keycloak_token()
    init = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "e2e-test", "version": "0.1"},
        },
    }
    # Starlette's Mount redirects `/mcp` to `/mcp/`; follow it so this test
    # mirrors what a real MCP client does end-to-end.
    resp = httpx.post(
        f"{MCP_URL}/mcp",
        json=init,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json, text/event-stream",
        },
        timeout=15,
        follow_redirects=True,
    )
    assert resp.status_code in (200, 202), (
        f"unexpected status {resp.status_code}: {resp.text[:500]}"
    )
    assert b"unauthorized" not in resp.content.lower()


@pytest.mark.integration
def test_mcp_rejects_garbage_bearer(mcp_http_server):
    """A structurally invalid bearer value is rejected with 401."""
    resp = httpx.post(
        f"{MCP_URL}/mcp",
        json={},
        headers={"Authorization": "Bearer aaa.bbb.ccc"},
        timeout=5,
    )
    assert resp.status_code == 401


# ---- Full-protocol smoke (MCP Python client over Streamable HTTP) ----
#
# These drive the real MCP client SDK through the OAuth-gated /mcp endpoint
# so ``uv run pytest -m integration`` doubles as a full end-to-end smoke:
# token mint -> transport -> middleware -> tool dispatch -> indexer query.


@pytest.mark.integration
async def test_mcp_tools_list_includes_search_alerts(mcp_http_server, keycloak_token):
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
                _get_session_id,
            ),
            ClientSession(read, write) as session,
        ):
            await session.initialize()
            tools = await session.list_tools()
    finally:
        await http_client.aclose()

    names = [t.name for t in tools.tools]
    # search_alerts gets renamed later in M3 — accept either name so this commit
    # doesn't depend on the rename landing first.
    assert "search_alerts" in names or "alerts.search_alerts" in names, (
        f"tools/list missing search_alerts: {names}"
    )


@pytest.mark.integration
async def test_mcp_tools_call_search_alerts_returns_seeded_data(
    mcp_http_server, keycloak_token
):
    import httpx as _httpx
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    token = keycloak_token()
    http_client = _httpx.AsyncClient(
        headers={"Authorization": f"Bearer {token}"},
        timeout=_httpx.Timeout(30.0),
    )
    tool_name = "alerts.search_alerts"  # post-rename name
    try:
        async with (
            streamable_http_client(f"{MCP_URL}/mcp", http_client=http_client) as (
                read,
                write,
                _get_session_id,
            ),
            ClientSession(read, write) as session,
        ):
            await session.initialize()
            try:
                result = await session.call_tool(
                    tool_name, {"time_range": "24h", "size": 5}
                )
            except Exception:
                # fall back to the pre-rename name during the transitional window
                result = await session.call_tool(
                    "search_alerts", {"time_range": "24h", "size": 5}
                )
    finally:
        await http_client.aclose()

    assert not result.isError, f"tools/call returned error: {result}"
    # After the later flatten, shape is flat; before, it's nested. Drill defensively.
    outer = result.structuredContent
    assert outer is not None, "structuredContent missing from CallToolResult"
    # pre-flatten shape nests under "structuredContent"; post-flatten is the outer dict
    inner = outer.get("structuredContent", outer)
    assert inner.get("total", 0) >= 1, f"no alerts returned: {inner}"
    assert isinstance(inner.get("alerts"), list)
    assert len(inner["alerts"]) >= 1
