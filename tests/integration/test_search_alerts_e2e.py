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
async def test_search_alerts_returns_seeded_data(session, indexer):
    result = await search_alerts(
        args=SearchAlertsArgs(time_range="24h"),
        session=session,
        indexer=indexer,
    )
    # result is now SearchAlertsResult, not a dict.
    assert result.total >= 5
    assert len(result.alerts) >= 1
    assert result.next_cursor is not None


@pytest.mark.integration
async def test_search_alerts_min_level_filters(session, indexer):
    result = await search_alerts(
        args=SearchAlertsArgs(time_range="24h", min_level=12),
        session=session,
        indexer=indexer,
    )
    for alert in result.alerts:
        assert alert.rule.level >= 12


@pytest.mark.integration
async def test_search_alerts_cursor_paginates(session, indexer):
    first = await search_alerts(
        args=SearchAlertsArgs(time_range="24h", size=5),
        session=session,
        indexer=indexer,
    )
    cursor = first.next_cursor
    assert cursor is not None

    second = await search_alerts(
        args=SearchAlertsArgs(time_range="24h", size=5, cursor=cursor),
        session=session,
        indexer=indexer,
    )
    first_ids = {a.id for a in first.alerts}
    second_ids = {a.id for a in second.alerts}
    assert first_ids.isdisjoint(second_ids), "pagination returned overlapping alerts"
