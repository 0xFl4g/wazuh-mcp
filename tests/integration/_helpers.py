"""Shared integration-test helpers.

Originally lived in ``tests/integration/test_m4b_writes.py``; extracted
in v1.0.1 so fixtures (in ``conftest.py``) and sibling test modules
don't need to import from a specific milestone's test file (which is
an inverted dependency — sibling tests should not import from each
other).
"""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

import httpx


def _spawn_server(cfg_dir: Path, url: str, label: str) -> subprocess.Popen[bytes]:
    """Spawn ``uv run wazuh-mcp`` pointed at ``cfg_dir`` and wait for /healthz.

    Lifted from the M4a inline fixtures so the integration tests don't have
    to duplicate 40 lines of boot-and-poll boilerplate per fixture.
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
