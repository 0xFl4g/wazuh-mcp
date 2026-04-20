"""Fixtures for integration tests.

Assumes docker/integration-compose.yml is running and seeded.
"""

from __future__ import annotations

import io

import pytest

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import AuditEmitter
from wazuh_mcp.secrets.value import SecretValue
from wazuh_mcp.wazuh.indexer import IndexerClient


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
    return AuditEmitter(stream=io.StringIO())


@pytest.fixture
async def indexer():
    client = IndexerClient(
        base_url="https://localhost:9200",
        user=SecretValue("admin"),
        password=SecretValue("SecretPassword"),
        verify_tls=False,
    )
    try:
        yield client
    finally:
        await client.aclose()
