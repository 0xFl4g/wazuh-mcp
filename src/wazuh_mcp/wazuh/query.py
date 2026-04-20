"""OpenSearch DSL builders.

No tool accepts raw DSL. Builders take structured, validated inputs and
produce clamped/capped queries. This is the single-point enforcement of
size caps, time-range limits, and `terminate_after`.
"""

from __future__ import annotations

import re
from typing import Any, Final

MAX_ALERT_SIZE: Final[int] = 100
DEFAULT_ALERT_SIZE: Final[int] = 25
TERMINATE_AFTER: Final[int] = 10_000

DEFAULT_ALERT_FIELDS: Final[list[str]] = [
    "timestamp",
    "@timestamp",
    "agent.id",
    "agent.name",
    "agent.ip",
    "rule.id",
    "rule.level",
    "rule.description",
    "rule.mitre.id",
    "rule.mitre.tactic",
    "location",
    "decoder.name",
]

_TIME_RANGE_RE: Final[re.Pattern[str]] = re.compile(r"^([1-9][0-9]*)([mhd])$")
_UNIT_SECONDS: Final[dict[str, int]] = {"m": 60, "h": 3600, "d": 86400}
_MAX_LOOKBACK_SECONDS: Final[int] = 30 * 86400


def _validate_time_range(tr: str) -> None:
    m = _TIME_RANGE_RE.match(tr)
    if not m:
        raise ValueError(
            f"time_range must match '<int><m|h|d>' (e.g., '1h', '24h', '7d'); got {tr!r}"
        )
    n, unit = int(m.group(1)), m.group(2)
    if n * _UNIT_SECONDS[unit] >= _MAX_LOOKBACK_SECONDS:
        raise ValueError(f"time_range exceeds 30-day lookback cap: {tr!r}")


def build_search_alerts_query(
    *,
    time_range: str,
    min_level: int | None = None,
    agent_id: str | None = None,
    size: int = DEFAULT_ALERT_SIZE,
    cursor: list[Any] | None = None,
) -> dict[str, Any]:
    _validate_time_range(time_range)
    if min_level is not None and not (0 <= min_level <= 15):
        raise ValueError("min_level must be 0..15")

    must: list[dict[str, Any]] = [
        {"range": {"@timestamp": {"gte": f"now-{time_range}"}}}
    ]
    if min_level is not None:
        must.append({"range": {"rule.level": {"gte": min_level}}})
    if agent_id is not None:
        must.append({"term": {"agent.id": agent_id}})

    query: dict[str, Any] = {
        "query": {"bool": {"must": must}},
        "size": min(max(1, size), MAX_ALERT_SIZE),
        "sort": [{"@timestamp": "desc"}],
        "_source": DEFAULT_ALERT_FIELDS,
        "terminate_after": TERMINATE_AFTER,
    }
    if cursor is not None:
        query["search_after"] = cursor
    return query
