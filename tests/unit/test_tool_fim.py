"""Unit tests for fim.* tools."""

import io

import pytest

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import AuditEmitter
from wazuh_mcp.observability.sinks.stream import StderrSink
from wazuh_mcp.secrets.value import SecretValue
from wazuh_mcp.tools.fim import (
    FimChangesArgs,
    FimHistoryArgs,
    fim_changes_by_agent,
    fim_history_for_path,
)
from wazuh_mcp.wazuh.indexer import IndexerClient


@pytest.fixture
def session() -> Session:
    return Session(
        user_id="u",
        tenant_id="t",
        rbac_role="soc_analyst",
        auth_method="oauth",
    )


@pytest.fixture
def audit() -> AuditEmitter:
    return AuditEmitter(global_sinks=[StderrSink(stream=io.StringIO())])


@pytest.fixture
async def indexer(httpx_mock):
    client = IndexerClient(
        base_url="https://indexer.example",
        user=SecretValue("admin"),
        password=SecretValue("admin"),
        verify_tls=False,
    )
    try:
        yield client
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_fim_history_happy(session, audit, indexer, httpx_mock):
    httpx_mock.add_response(
        url="https://indexer.example/wazuh-alerts-*/_search",
        method="POST",
        json={
            "hits": {
                "total": {"value": 1},
                "hits": [
                    {
                        "_source": {
                            "agent": {"id": "001"},
                            "timestamp": "2026-04-22T00:00:00Z",
                            "syscheck": {
                                "path": "/etc/passwd",
                                "event": "modified",
                                "sha256_after": "abc",
                            },
                        },
                        "sort": [1],
                    }
                ],
            }
        },
    )
    result = await fim_history_for_path(
        args=FimHistoryArgs(path="/etc/passwd", time_range="24h", size=1),
        session=session,
        indexer=indexer,
    )
    assert result.total == 1
    assert result.events[0].path == "/etc/passwd"
    assert result.truncated is True


@pytest.mark.asyncio
async def test_fim_changes_rejects_bad_agent_id(session, audit, indexer):
    with pytest.raises(ValueError):
        await fim_changes_by_agent(
            args=FimChangesArgs(agent_id="not-a-number", time_range="24h"),
            session=session,
            indexer=indexer,
        )
