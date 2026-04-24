import asyncio
import io
import json

import pytest
from pydantic import ValidationError
from pytest_httpx import HTTPXMock

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import AuditEmitter
from wazuh_mcp.observability.sinks.stream import StderrSink
from wazuh_mcp.secrets.value import SecretValue
from wazuh_mcp.tools.alerts import SearchAlertsArgs, search_alerts
from wazuh_mcp.wazuh.errors import WazuhError
from wazuh_mcp.wazuh.indexer import IndexerClient

BASE = "https://wazuh.test:9200"


def _session():
    return Session(user_id="alice", tenant_id="acme", rbac_role="soc_analyst", auth_method="config")


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
            "rule": {"id": "5710", "level": level, "description": "ssh brute-force"},
        },
        "sort": ["2026-04-20T10:00:00.000Z"],
    }


def _emitter(stream: io.StringIO) -> AuditEmitter:
    return AuditEmitter(sinks=[StderrSink(stream=stream)])


async def _drain(emitter: AuditEmitter) -> None:
    await asyncio.sleep(0.05)
    await emitter.stop()


async def test_search_alerts_returns_structured_result(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url=f"{BASE}/wazuh-alerts-*/_search",
        method="POST",
        json={"hits": {"total": {"value": 2}, "hits": [_hit("a1"), _hit("a2")]}},
    )
    buf = io.StringIO()
    emitter = _emitter(buf)
    await emitter.start()
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
    await _drain(emitter)

    assert result.total == 2
    assert len(result.alerts) == 2
    assert result.next_cursor == ["2026-04-20T10:00:00.000Z"]

    event = json.loads(buf.getvalue().strip())
    assert event["tool"] == "alerts.search_alerts"
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
                audit=_emitter(io.StringIO()),
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
    emitter = _emitter(buf)
    await emitter.start()
    client = _client()
    try:
        with pytest.raises(WazuhError):
            await search_alerts(
                args=SearchAlertsArgs(time_range="1h"),
                session=_session(),
                indexer=client,
                audit=emitter,
            )
    finally:
        await client.aclose()
    await _drain(emitter)
    event = json.loads(buf.getvalue().strip())
    assert event["outcome"] == "error"
    assert event["error_code"] == "rate_limited"


async def test_search_alerts_audits_parse_error(httpx_mock: HTTPXMock):
    # Malformed hit: missing rule entirely → Alert.from_hit raises ValidationError
    bad_hit = {
        "_id": "bad",
        "_source": {"timestamp": "2026-04-20T10:00:00.000+0000"},
        "sort": ["2026-04-20T10:00:00.000Z"],
    }
    httpx_mock.add_response(
        url=f"{BASE}/wazuh-alerts-*/_search",
        method="POST",
        json={"hits": {"total": {"value": 1}, "hits": [bad_hit]}},
    )
    buf = io.StringIO()
    emitter = _emitter(buf)
    await emitter.start()
    client = _client()
    try:
        with pytest.raises(ValidationError):
            await search_alerts(
                args=SearchAlertsArgs(time_range="1h"),
                session=_session(),
                indexer=client,
                audit=emitter,
            )
    finally:
        await client.aclose()
    await _drain(emitter)
    event = json.loads(buf.getvalue().strip())
    assert event["outcome"] == "error"
    assert event["error_code"] == "parse_error"


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
            audit=_emitter(io.StringIO()),
        )
    finally:
        await client.aclose()
    assert result.truncated is True
