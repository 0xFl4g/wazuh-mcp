"""Tool-level tests for alerts.search_alerts.

M4a: tool bodies no longer emit audit events directly (the @instrumented_tool
decorator owns audit). These tests verify the structured-result contract,
upstream error mapping, and argument validation. Audit-shape assertions
live in test_instrumented_tool.py.
"""

import pytest
from pydantic import ValidationError
from pytest_httpx import HTTPXMock

from wazuh_mcp.auth.session import Session
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


async def test_search_alerts_returns_structured_result(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url=f"{BASE}/wazuh-alerts-*/_search",
        method="POST",
        json={"hits": {"total": {"value": 2}, "hits": [_hit("a1"), _hit("a2")]}},
    )
    client = _client()
    try:
        result = await search_alerts(
            args=SearchAlertsArgs(time_range="1h"),
            session=_session(),
            indexer=client,
        )
    finally:
        await client.aclose()

    assert result.total == 2
    assert len(result.alerts) == 2
    assert result.next_cursor == ["2026-04-20T10:00:00.000Z"]


async def test_search_alerts_rejects_invalid_time_range():
    client = _client()
    try:
        with pytest.raises(ValueError):
            await search_alerts(
                args=SearchAlertsArgs(time_range="bogus"),
                session=_session(),
                indexer=client,
            )
    finally:
        await client.aclose()


async def test_search_alerts_maps_upstream_error(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url=f"{BASE}/wazuh-alerts-*/_search",
        method="POST",
        status_code=429,
        json={"error": "too many"},
    )
    client = _client()
    try:
        with pytest.raises(WazuhError) as exc_info:
            await search_alerts(
                args=SearchAlertsArgs(time_range="1h"),
                session=_session(),
                indexer=client,
            )
    finally:
        await client.aclose()
    assert exc_info.value.code == "rate_limited"


async def test_search_alerts_parse_error_propagates(httpx_mock: HTTPXMock):
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
    client = _client()
    try:
        with pytest.raises(ValidationError):
            await search_alerts(
                args=SearchAlertsArgs(time_range="1h"),
                session=_session(),
                indexer=client,
            )
    finally:
        await client.aclose()


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
        )
    finally:
        await client.aclose()
    assert result.truncated is True
