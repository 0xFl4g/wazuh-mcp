"""Fixtures for integration tests.

Assumes docker/integration-compose.yml is running and seeded.
"""

from __future__ import annotations

import io
import os

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


@pytest.fixture
def session() -> Session:
    return Session(
        user_id="integration",
        tenant_id="local",
        rbac_role="soc_analyst",
        auth_method="config",
    )


@pytest.fixture
def audit() -> AuditEmitter:
    return AuditEmitter(sinks=[StderrSink(stream=io.StringIO())])


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
