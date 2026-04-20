import io
import json

import pytest
from pytest_httpx import HTTPXMock

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import AuditEmitter
from wazuh_mcp.secrets.value import SecretValue
from wazuh_mcp.tools.alerts import SearchAlertsArgs, search_alerts
from wazuh_mcp.wazuh.indexer import IndexerClient

BASE = "https://wazuh.test:9200"


def _session():
    return Session(user_id="alice", tenant_id="acme",
                   rbac_role="soc_analyst", auth_method="config")


def _client():
    return IndexerClient(
        base_url=BASE,
        user=SecretValue("admin"),
        password=SecretValue("pw"),
        verify_tls=False,
    )


def _hit(alert_id: str, level: int = 10):
    return {
        "_id": alert_id,
        "_source": {
            "timestamp": "2026-04-20T10:00:00.000+0000",
            "@timestamp": "2026-04-20T10:00:00.000Z",
            "agent": {"id": "001", "name": "web-01"},
            "rule": {"id": "5710", "level": level,
                     "description": "ssh brute-force"},
        },
        "sort": ["2026-04-20T10:00:00.000Z"],
    }


async def test_search_alerts_returns_structured_and_text(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url=f"{BASE}/wazuh-alerts-*/_search",
        method="POST",
        json={"hits": {"total": {"value": 2},
                       "hits": [_hit("a1"), _hit("a2")]}},
    )
    buf = io.StringIO()
    emitter = AuditEmitter(stream=buf)
    client = _client()
    try:
        result = await search_alerts(
            args=SearchAlertsArgs(time_range="1h"),
            session=_session(),
            indexer=client,
            audit=emitter,
        )
    finally:
        await client.aclose()

    assert result["structuredContent"]["total"] == 2
    assert len(result["structuredContent"]["alerts"]) == 2
    assert result["structuredContent"]["next_cursor"] == ["2026-04-20T10:00:00.000Z"]
    assert "2 alert" in result["text"]

    event = json.loads(buf.getvalue().strip())
    assert event["tool"] == "search_alerts"
    assert event["result_count"] == 2
    assert event["outcome"] == "ok"


async def test_search_alerts_rejects_invalid_time_range():
    client = _client()
    try:
        with pytest.raises(ValueError):
            await search_alerts(
                args=SearchAlertsArgs(time_range="bogus"),
                session=_session(),
                indexer=client,
                audit=AuditEmitter(stream=io.StringIO()),
            )
    finally:
        await client.aclose()


async def test_search_alerts_audits_on_upstream_error(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url=f"{BASE}/wazuh-alerts-*/_search",
        method="POST",
        status_code=429,
        json={"error": "too many"},
    )
    buf = io.StringIO()
    client = _client()
    try:
        with pytest.raises(Exception):
            await search_alerts(
                args=SearchAlertsArgs(time_range="1h"),
                session=_session(),
                indexer=client,
                audit=AuditEmitter(stream=buf),
            )
    finally:
        await client.aclose()
    event = json.loads(buf.getvalue().strip())
    assert event["outcome"] == "error"
    assert event["error_code"] == "rate_limited"


async def test_search_alerts_truncated_when_hits_equal_size(httpx_mock: HTTPXMock):
    hits = [_hit(f"a{i}") for i in range(25)]
    httpx_mock.add_response(
        url=f"{BASE}/wazuh-alerts-*/_search",
        method="POST",
        json={"hits": {"total": {"value": 500}, "hits": hits}},
    )
    client = _client()
    try:
        result = await search_alerts(
            args=SearchAlertsArgs(time_range="1h"),
            session=_session(),
            indexer=client,
            audit=AuditEmitter(stream=io.StringIO()),
        )
    finally:
        await client.aclose()
    assert result["structuredContent"]["truncated"] is True
