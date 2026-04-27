"""Fixtures for integration tests.

Assumes docker/integration-compose.yml is running and seeded.
"""

from __future__ import annotations

import io
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

import httpx
import pytest

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import AuditEmitter
from wazuh_mcp.observability.sinks.stream import StderrSink
from wazuh_mcp.secrets.value import SecretValue
from wazuh_mcp.wazuh.indexer import IndexerClient

KEYCLOAK_URL = os.environ.get("KEYCLOAK_URL", "http://localhost:8080")
KEYCLOAK_REALM = "wazuh-mcp"
KEYCLOAK_CLIENT_ID = "wazuh-mcp-client"
KEYCLOAK_CLIENT_SECRET = "test-client-secret"
KEYCLOAK_TOKEN_URL = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"

WAZUH_MANAGER_URL = os.environ.get("WAZUH_MANAGER_URL", "https://localhost:55000")
WAZUH_MANAGER_USER = os.environ.get("WAZUH_MANAGER_USER", "wazuh-wui")
WAZUH_MANAGER_PASSWORD = os.environ.get("WAZUH_MANAGER_PASSWORD", "MCPmcp12345!")

# Shared MCP HTTP server fixture address. The fixture itself lives below;
# callers pull MCP_URL from this conftest so multiple test modules can
# reference one canonical bind address without redefining it.
MCP_URL = "http://127.0.0.1:8765"


@pytest.fixture(scope="module")
def mcp_http_server():
    """Spawn the default MCP HTTP server on 127.0.0.1:8765 with analyst RBAC.

    Lives in conftest so tests that don't define their own server fixture
    (test_oauth_e2e, test_m4a_metrics, test_prompts/resources/tools_integration)
    can share one boot per module without each importing it from a sibling
    test file (which trips ruff F811 once both the import and the param
    share the fixture name).
    """
    cfg_dir = Path(tempfile.mkdtemp(prefix="wm-m2-"))

    (cfg_dir / "tenants.yaml").write_text(
        """
tenants:
  - tenant_id: local
    indexer_url: https://localhost:9200
    verify_tls: false
    ca_bundle_path: null
    default_rbac_role: analyst
    oauth_issuer: http://localhost:8080/realms/wazuh-mcp
    oauth_audience: wazuh-mcp-api
    rate_limit:
      tenant:
        capacity: 100
        refill_per_sec: 10.0
      session:
        capacity: 10
        refill_per_sec: 1.0
    audit_sinks:
      - kind: wazuh_indexer
        index_prefix: local-audit
  - tenant_id: tenant_b
    indexer_url: https://localhost:9200
    verify_tls: false
    ca_bundle_path: null
    default_rbac_role: analyst
    oauth_issuer: http://localhost:8080/realms/wazuh-mcp
    oauth_audience: wazuh-mcp-api
    rate_limit:
      tenant:
        capacity: 2
        refill_per_sec: 0.001
      session:
        capacity: 100
        refill_per_sec: 1.0
    audit_sinks:
      - kind: wazuh_indexer
        index_prefix: tenant-b-audit
""".strip()
    )
    (cfg_dir / "secrets.yaml").write_text(
        """
local:
  indexer_user: admin
  indexer_password: admin
  server_api_user: wazuh-wui
  server_api_password: MCPmcp12345!
tenant_b:
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


@pytest.fixture
def session() -> Session:
    return Session(
        user_id="integration",
        tenant_id="local",
        rbac_role="admin",
        auth_method="config",
    )


@pytest.fixture
def audit() -> AuditEmitter:
    return AuditEmitter(global_sinks=[StderrSink(stream=io.StringIO())])


@pytest.fixture
async def indexer():
    client = IndexerClient(
        base_url="https://localhost:9200",
        user=SecretValue("admin"),
        password=SecretValue("admin"),
        verify_tls=False,
    )
    try:
        yield client
    finally:
        await client.aclose()


@pytest.fixture
def keycloak_token():
    """Mint a real RS256 access token against the wazuh-mcp realm.

    Uses ``grant_type=client_credentials`` on the service account associated
    with ``wazuh-mcp-client``. This bypasses Keycloak 26's Direct Grant flow
    (which rejects password grants against the seeded users with
    ``"Account is not fully set up"`` regardless of the user's
    ``requiredActions`` state).

    The resulting token carries the realm-level audience (``wazuh-mcp-api``)
    and hardcoded ``tenant_id`` claim via the client's protocol mappers, so
    it is accepted by ``OAuthSessionFactory`` end-to-end. No ``wazuh_mcp_role``
    claim is emitted for the service-account user, so the server falls back
    to the tenant's ``default_rbac_role`` — this is a deliberate, covered
    code path.
    """

    def _get() -> str:
        resp = httpx.post(
            KEYCLOAK_TOKEN_URL,
            data={
                "grant_type": "client_credentials",
                "client_id": KEYCLOAK_CLIENT_ID,
                "client_secret": KEYCLOAK_CLIENT_SECRET,
            },
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json()["access_token"]

    return _get


@pytest.fixture
def server_api_token():
    """Mint a raw Wazuh Server API JWT - bypasses the OAuth plumbing for
    pure Server-API-surface integration tests.
    """

    def _get() -> str:
        resp = httpx.post(
            f"{WAZUH_MANAGER_URL}/security/user/authenticate?raw=true",
            auth=(WAZUH_MANAGER_USER, WAZUH_MANAGER_PASSWORD),
            verify=False,
            timeout=10,
        )
        resp.raise_for_status()
        return resp.text.strip()

    return _get
