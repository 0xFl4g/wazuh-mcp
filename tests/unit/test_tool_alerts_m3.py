"""Unit tests for the new M3 alerts tools (get_alert, by_agent, by_mitre)."""

import io

import pytest

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import AuditEmitter
from wazuh_mcp.secrets.value import SecretValue
from wazuh_mcp.tools.alerts import (
    AlertsByAgentArgs,
    AlertsByMitreArgs,
    GetAlertArgs,
    alerts_by_agent,
    alerts_by_mitre,
    get_alert,
)
from wazuh_mcp.wazuh.errors import WazuhError
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
    return AuditEmitter(stream=io.StringIO())


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
async def test_get_alert_happy_path(session, audit, indexer, httpx_mock):
    httpx_mock.add_response(
        url="https://indexer.example/wazuh-alerts-*/_search",
        method="POST",
        json={
            "hits": {
                "hits": [
                    {
                        "_id": "abc",
                        "_source": {
                            "timestamp": "2026-04-22T00:00:00Z",
                            "agent": {"id": "001", "name": "web-01"},
                            "rule": {
                                "id": "100",
                                "level": 10,
                                "description": "test",
                            },
                        },
                    }
                ]
            }
        },
    )
    result = await get_alert(
        args=GetAlertArgs(alert_id="abc"),
        session=session,
        indexer=indexer,
        audit=audit,
    )
    assert result.alert.id == "abc"


@pytest.mark.asyncio
async def test_get_alert_not_found(session, audit, indexer, httpx_mock):
    httpx_mock.add_response(
        url="https://indexer.example/wazuh-alerts-*/_search",
        method="POST",
        json={"hits": {"hits": []}},
    )
    with pytest.raises(WazuhError) as exc_info:
        await get_alert(
            args=GetAlertArgs(alert_id="missing"),
            session=session,
            indexer=indexer,
            audit=audit,
        )
    assert exc_info.value.code == "not_found"


@pytest.mark.asyncio
async def test_alerts_by_agent_happy(session, audit, indexer, httpx_mock):
    httpx_mock.add_response(
        url="https://indexer.example/wazuh-alerts-*/_search",
        method="POST",
        json={
            "hits": {
                "total": {"value": 2},
                "hits": [
                    {
                        "_id": "a1",
                        "_source": {
                            "timestamp": "t",
                            "agent": {"id": "001"},
                            "rule": {"id": "1", "level": 3, "description": "x"},
                        },
                        "sort": [1],
                    },
                    {
                        "_id": "a2",
                        "_source": {
                            "timestamp": "t",
                            "agent": {"id": "001"},
                            "rule": {"id": "2", "level": 3, "description": "y"},
                        },
                        "sort": [2],
                    },
                ],
            }
        },
    )
    result = await alerts_by_agent(
        args=AlertsByAgentArgs(agent_id="001", time_range="24h", size=2),
        session=session,
        indexer=indexer,
        audit=audit,
    )
    assert result.total == 2
    assert result.truncated is True
    assert result.next_cursor == [2]


@pytest.mark.asyncio
async def test_alerts_by_mitre_rejects_bad_technique_id(session, audit, indexer):
    with pytest.raises(ValueError):
        await alerts_by_mitre(
            args=AlertsByMitreArgs(technique_id="NOT_VALID", time_range="24h"),
            session=session,
            indexer=indexer,
            audit=audit,
        )
