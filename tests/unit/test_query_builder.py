import pytest

from wazuh_mcp.wazuh.query import (
    DEFAULT_ALERT_FIELDS,
    MAX_ALERT_SIZE,
    build_search_alerts_query,
)


def test_minimal_query_is_time_bounded():
    q = build_search_alerts_query(time_range="1h")
    ranges = [c for c in q["query"]["bool"]["must"] if "range" in c]
    assert ranges
    assert ranges[0]["range"]["@timestamp"]["gte"] == "now-1h"


def test_level_filter_applied():
    q = build_search_alerts_query(time_range="1h", min_level=12)
    must = q["query"]["bool"]["must"]
    level_clause = next(c for c in must if "range" in c and "rule.level" in c["range"])
    assert level_clause["range"]["rule.level"]["gte"] == 12


def test_agent_id_filter_applied():
    q = build_search_alerts_query(time_range="1h", agent_id="001")
    must = q["query"]["bool"]["must"]
    term = next(c for c in must if "term" in c)
    assert term["term"]["agent.id"] == "001"


def test_size_is_capped():
    q = build_search_alerts_query(time_range="1h", size=1_000_000)
    assert q["size"] == MAX_ALERT_SIZE


def test_size_default():
    q = build_search_alerts_query(time_range="1h")
    assert q["size"] == 25


def test_sort_desc_timestamp():
    q = build_search_alerts_query(time_range="1h")
    assert q["sort"] == [{"@timestamp": "desc"}]


def test_source_projection_default():
    q = build_search_alerts_query(time_range="1h")
    assert q["_source"] == DEFAULT_ALERT_FIELDS


def test_search_after_cursor_applied():
    q = build_search_alerts_query(
        time_range="1h", cursor=["2026-04-20T10:00:00.000Z"]
    )
    assert q["search_after"] == ["2026-04-20T10:00:00.000Z"]


def test_terminate_after_enforced():
    q = build_search_alerts_query(time_range="1h")
    assert q["terminate_after"] == 10_000


@pytest.mark.parametrize("bad", ["", "1", "1y", "30d", "now-1h", "foo"])
def test_invalid_time_range_rejected(bad):
    with pytest.raises(ValueError):
        build_search_alerts_query(time_range=bad)


@pytest.mark.parametrize("good", ["1m", "15m", "1h", "6h", "24h", "7d", "1d"])
def test_accepted_time_ranges(good):
    build_search_alerts_query(time_range=good)


def test_level_must_be_in_range():
    with pytest.raises(ValueError):
        build_search_alerts_query(time_range="1h", min_level=-1)
    with pytest.raises(ValueError):
        build_search_alerts_query(time_range="1h", min_level=16)
