"""RBAC deny at both list-time and call-time under the M4a wrapper.

Spawns a second MCP HTTP server (port 8766) configured with
``default_rbac_role: readonly``. Service-account tokens carry no
``wazuh_mcp_role`` claim, so the tenant default applies and every session
the server mints has ``rbac_role == "readonly"``. The default allowlist
for ``readonly`` excludes ``hunt.*``; the test asserts that hunt tools
are filtered from ``tools/list`` AND denied at ``tools/call`` time even
if a client bypasses list filtering.
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

pytestmark = [pytest.mark.integration, pytest.mark.requires_manager]


MCP_RO_URL = "http://127.0.0.1:8766"


@pytest.fixture(scope="module")
def mcp_http_server_readonly():
    """Spin up an MCP HTTP server whose tenant default role is ``readonly``.

    Mirrors the ``mcp_http_server`` fixture in ``test_oauth_e2e.py`` but
    overrides ``default_rbac_role`` and the bind port so the two servers
    can coexist in one CI run.
    """
    cfg_dir = Path(tempfile.mkdtemp(prefix="wm-m4a-ro-"))

    (cfg_dir / "tenants.yaml").write_text(
        """
tenants:
  - tenant_id: local
    indexer_url: https://localhost:9200
    verify_tls: false
    ca_bundle_path: null
    default_rbac_role: readonly
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
  bind: "127.0.0.1:8766"
  public_url: "{MCP_RO_URL}"
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
                "MCP HTTP server (readonly) exited early\n"
                f"stdout:\n{stdout.decode(errors='replace')}\n"
                f"stderr:\n{stderr.decode(errors='replace')}"
            )
        try:
            r = httpx.get(f"{MCP_RO_URL}/healthz", timeout=1)
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
            "MCP HTTP server (readonly) didn't come up in 30s\n"
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
async def test_readonly_role_filters_list_tools(mcp_http_server_readonly, keycloak_token):
    """tools/list must hide hunt.hunt_query for a readonly-role session."""
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
            streamable_http_client(f"{MCP_RO_URL}/mcp", http_client=http_client) as (
                read,
                write,
                _gsid,
            ),
            ClientSession(read, write) as session,
        ):
            await session.initialize()
            tools = await session.list_tools()
    finally:
        await http_client.aclose()

    names = {t.name for t in tools.tools}
    assert "hunt.hunt_query" not in names, (
        f"hunt.hunt_query must be filtered for readonly role, got: {sorted(names)}"
    )
    # readonly still has alerts.*; smoke that list isn't empty or catastrophic.
    assert "alerts.search_alerts" in names


@pytest.mark.integration
async def test_readonly_role_denied_at_call_time(mcp_http_server_readonly, keycloak_token):
    """Even if a client bypasses list_tools, the call must be rejected.

    The RBAC wrapper hides denied tools by surfacing them as ``Unknown tool``
    (info-hiding), so the assertion accepts either that phrasing or a
    generic ``isError`` payload.
    """
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
            streamable_http_client(f"{MCP_RO_URL}/mcp", http_client=http_client) as (
                read,
                write,
                _gsid,
            ),
            ClientSession(read, write) as session,
        ):
            await session.initialize()
            result = await session.call_tool(
                "hunt.hunt_query",
                {"time_range": "1h", "must": []},
            )
    finally:
        await http_client.aclose()

    assert result.isError, "readonly role must be denied hunt.hunt_query at call time"
    text = "".join(getattr(c, "text", "") for c in result.content).lower()
    # Info-hiding: denied tool looks like an unknown tool. The permissive
    # fallback is "just isError" so we don't lock ourselves to one phrasing.
    assert "unknown tool" in text or result.isError
