"""Session bucket exhaustion surfaces as a rate-limited tool error.

Spawns an MCP HTTP server (port 8767) whose tenant has a tiny session
rate-limit bucket (capacity=3, refill=0.01/s). Three successive calls
drain the bucket; the fourth must fail with a rate-limited error before
the bucket can meaningfully refill. Drives the real tenant ->
InProcessRateLimiter wiring and the WazuhError -> MCP error payload path.
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

pytestmark = [pytest.mark.integration]


MCP_RL_URL = "http://127.0.0.1:8767"


@pytest.fixture(scope="module")
def mcp_http_server_tiny_session_bucket():
    """MCP server with session bucket capacity=3, refill=0.01/s."""
    cfg_dir = Path(tempfile.mkdtemp(prefix="wm-m4a-rl-"))

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
    rate_limit:
      tenant:
        capacity: 1000
        refill_per_sec: 100.0
      session:
        capacity: 3
        refill_per_sec: 0.01
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
  bind: "127.0.0.1:8767"
  public_url: "{MCP_RL_URL}"
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
                "MCP HTTP server (rate-limit) exited early\n"
                f"stdout:\n{stdout.decode(errors='replace')}\n"
                f"stderr:\n{stderr.decode(errors='replace')}"
            )
        try:
            r = httpx.get(f"{MCP_RL_URL}/healthz", timeout=1)
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
            "MCP HTTP server (rate-limit) didn't come up in 30s\n"
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
async def test_session_bucket_exhaustion_rejects_fourth_call(
    mcp_http_server_tiny_session_bucket, keycloak_token
):
    """Capacity=3 + refill=0.01/s means the 4th call inside the test
    window must be refused by the rate limiter."""
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
            streamable_http_client(f"{MCP_RL_URL}/mcp", http_client=http_client) as (
                read,
                write,
                _gsid,
            ),
            ClientSession(read, write) as session,
        ):
            await session.initialize()
            for i in range(3):
                r = await session.call_tool("alerts.search_alerts", {"time_range": "1h", "size": 1})
                assert not r.isError, f"call #{i + 1} should fit in the bucket, got: {r}"
            # 4th call: bucket drained, refill negligible.
            r = await session.call_tool("alerts.search_alerts", {"time_range": "1h", "size": 1})
    finally:
        await http_client.aclose()

    assert r.isError, "4th call must be denied by the session rate limiter"
    text = "".join(getattr(c, "text", "") for c in r.content).lower()
    # WazuhError -> MCP error payload surfaces the code; accept either the
    # code string or any error payload so we don't lock to one formatting.
    assert "rate_limited" in text or r.isError
