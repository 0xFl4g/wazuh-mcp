"""Unit tests for MCP prompts."""

import io

import pytest

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import AuditEmitter
from wazuh_mcp.observability.sinks.stream import StderrSink
from wazuh_mcp.prompts.agent_posture import handle as agent_posture_handle
from wazuh_mcp.prompts.investigate_alert import handle as investigate_alert_handle
from wazuh_mcp.prompts.triage_last_hour import handle as triage_handle
from wazuh_mcp.secrets.value import SecretValue
from wazuh_mcp.wazuh.indexer import IndexerClient
from wazuh_mcp.wazuh.server_api import ServerApiClient


def _jwt() -> str:
    import base64 as _b
    import json as _j
    import time as _t

    h = _b.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=").decode()
    p = (
        _b.urlsafe_b64encode(
            _j.dumps({"exp": int(_t.time()) + 900, "iat": int(_t.time())}).encode()
        )
        .rstrip(b"=")
        .decode()
    )
    return f"{h}.{p}.sig"


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
    c = IndexerClient(
        base_url="https://indexer.example",
        user=SecretValue("admin"),
        password=SecretValue("admin"),
        verify_tls=False,
    )
    try:
        yield c
    finally:
        await c.aclose()


@pytest.fixture
async def server_api(httpx_mock):
    httpx_mock.add_response(
        url="https://manager.example:55000/security/user/authenticate",
        method="POST",
        json={"data": {"token": _jwt()}},
        is_optional=True,
    )
    c = ServerApiClient(
        base_url="https://manager.example:55000",
        user=SecretValue("u"),
        password=SecretValue("p"),
        verify_tls=False,
    )
    try:
        yield c
    finally:
        await c.aclose()


@pytest.mark.asyncio
async def test_investigate_alert_returns_context_loaded_message(
    session, audit, indexer, server_api, httpx_mock
):
    # get_alert -> one hit
    httpx_mock.add_response(
        url="https://indexer.example/wazuh-alerts-*/_search",
        method="POST",
        json={
            "hits": {
                "hits": [
                    {
                        "_id": "abc",
                        "_source": {
                            "timestamp": "t",
                            "agent": {"id": "001", "name": "web-01"},
                            "rule": {
                                "id": "1",
                                "level": 10,
                                "description": "test",
                            },
                        },
                    }
                ]
            }
        },
    )
    # get_agent -> one hit (triggers server_api mint)
    httpx_mock.add_response(
        url="https://manager.example:55000/agents?agents_list=001",
        method="GET",
        json={"data": {"affected_items": [{"id": "001", "name": "web-01"}]}},
    )
    # alerts_by_agent -> zero
    httpx_mock.add_response(
        url="https://indexer.example/wazuh-alerts-*/_search",
        method="POST",
        json={"hits": {"total": {"value": 0}, "hits": []}},
    )

    out = await investigate_alert_handle(
        alert_id="abc",
        session=session,
        indexer=indexer,
        server_api=server_api,
        audit=audit,
    )
    text = out["content"]["text"]
    assert "abc" in text
    assert "web-01" in text


@pytest.mark.asyncio
async def test_investigate_alert_not_found_returns_message_not_raises(
    session, audit, indexer, server_api, httpx_mock
):
    httpx_mock.add_response(
        url="https://indexer.example/wazuh-alerts-*/_search",
        method="POST",
        json={"hits": {"hits": []}},
    )
    out = await investigate_alert_handle(
        alert_id="nope",
        session=session,
        indexer=indexer,
        server_api=server_api,
        audit=audit,
    )
    text = out["content"]["text"]
    assert "not found" in text.lower()


@pytest.mark.asyncio
async def test_triage_last_hour_returns_pre_loaded_results(session, audit, indexer, httpx_mock):
    httpx_mock.add_response(
        url="https://indexer.example/wazuh-alerts-*/_search",
        method="POST",
        json={
            "hits": {
                "total": {"value": 1},
                "hits": [
                    {
                        "_id": "a1",
                        "_source": {
                            "timestamp": "t",
                            "agent": {"id": "001"},
                            "rule": {
                                "id": "1",
                                "level": 10,
                                "description": "x",
                            },
                        },
                    }
                ],
            }
        },
    )
    out = await triage_handle(session=session, indexer=indexer, audit=audit)
    text = out["content"]["text"]
    assert "TOTAL IN RANGE: 1" in text


@pytest.mark.asyncio
async def test_agent_posture_not_found(session, audit, indexer, server_api, httpx_mock):
    httpx_mock.add_response(
        url="https://manager.example:55000/agents?agents_list=999",
        method="GET",
        json={"data": {"affected_items": []}},
    )
    out = await agent_posture_handle(
        agent_id="999",
        session=session,
        indexer=indexer,
        server_api=server_api,
        audit=audit,
    )
    text = out["content"]["text"]
    assert "not found" in text.lower()
