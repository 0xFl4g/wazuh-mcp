"""End-to-end integration test for search_alerts.

Prerequisites:
  docker compose -f docker/integration-compose.yml up -d
  # wait for healthcheck
  uv run python docker/seed_alerts.py

Run:
  uv run pytest -m integration -v
"""

from __future__ import annotations

import pytest

from wazuh_mcp.tools.alerts import SearchAlertsArgs, search_alerts


@pytest.mark.integration
async def test_search_alerts_returns_seeded_data(session, audit, indexer):
    result = await search_alerts(
        args=SearchAlertsArgs(time_range="1h"),
        session=session,
        indexer=indexer,
        audit=audit,
    )
    assert result["structuredContent"]["total"] >= 20
    assert len(result["structuredContent"]["alerts"]) >= 1
    assert result["structuredContent"]["next_cursor"] is not None


@pytest.mark.integration
async def test_search_alerts_min_level_filters(session, audit, indexer):
    result = await search_alerts(
        args=SearchAlertsArgs(time_range="1h", min_level=12),
        session=session,
        indexer=indexer,
        audit=audit,
    )
    for alert in result["structuredContent"]["alerts"]:
        assert alert["rule"]["level"] >= 12


@pytest.mark.integration
async def test_search_alerts_cursor_paginates(session, audit, indexer):
    first = await search_alerts(
        args=SearchAlertsArgs(time_range="1h", size=5),
        session=session,
        indexer=indexer,
        audit=audit,
    )
    cursor = first["structuredContent"]["next_cursor"]
    assert cursor is not None

    second = await search_alerts(
        args=SearchAlertsArgs(time_range="1h", size=5, cursor=cursor),
        session=session,
        indexer=indexer,
        audit=audit,
    )
    first_ids = {a["id"] for a in first["structuredContent"]["alerts"]}
    second_ids = {a["id"] for a in second["structuredContent"]["alerts"]}
    assert first_ids.isdisjoint(second_ids), "pagination returned overlapping alerts"
