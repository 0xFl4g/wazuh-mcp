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

_AGENT_ID_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9]{3,10}$")
_MITRE_ID_RE: Final[re.Pattern[str]] = re.compile(r"^T[0-9]{4}(\.[0-9]{3})?$")
_CVE_ID_RE: Final[re.Pattern[str]] = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
_SEVERITIES: Final[list[str]] = ["Low", "Medium", "High", "Critical"]


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
    """Build an OpenSearch DSL query for the `wazuh-alerts-*` index.

    Accepts a constrained, validated set of filters. Raw DSL is never
    accepted — the returned dict is constructed server-side.

    Args:
        time_range: Relative lookback as '<int><m|h|d>' (e.g. '1h', '24h',
            '7d'). Must resolve to strictly less than 30 days.
        min_level: Minimum rule.level (0..15) to include, or None.
        agent_id: Filter to a single agent.id (literal match), or None.
        size: Max hits to return. Clamped to [1, 100]; default 25.
        cursor: Opaque search_after cursor from a prior response, or
            None. Empty list is treated the same as None.

    Raises:
        ValueError: if time_range is malformed or exceeds the lookback
            cap, or if min_level is outside 0..15.
    """
    _validate_time_range(time_range)
    if min_level is not None and not (0 <= min_level <= 15):
        raise ValueError("min_level must be 0..15")

    must: list[dict[str, Any]] = [{"range": {"@timestamp": {"gte": f"now-{time_range}"}}}]
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
    if cursor:  # treats None AND empty list as "no cursor"
        query["search_after"] = cursor
    return query


DEFAULT_VULN_FIELDS: Final[list[str]] = [
    "vulnerability.id",
    "vulnerability.severity",
    "vulnerability.scores.base.score",
    "vulnerability.published_at",
    "vulnerability.detected_at",
    "vulnerability.status",
    "package.name",
    "package.version",
    "agent.id",
    "timestamp",
    "@timestamp",
]

DEFAULT_FIM_FIELDS: Final[list[str]] = [
    "agent.id",
    "timestamp",
    "@timestamp",
    "syscheck.path",
    "syscheck.event",
    "syscheck.sha256_after",
    "syscheck.md5_after",
    "syscheck.size_after",
    "syscheck.uid_after",
    "syscheck.gid_after",
]


def build_get_alert_query(alert_id: str) -> dict[str, Any]:
    """Fetch a single alert by its document id via /wazuh-alerts-*/_search."""
    if not alert_id or any(c in alert_id for c in "/\\"):
        raise ValueError("invalid alert_id")
    return {
        "query": {"term": {"_id": alert_id}},
        "size": 1,
        "_source": DEFAULT_ALERT_FIELDS,
        "terminate_after": 10,
    }


def build_alerts_by_agent_query(
    *,
    agent_id: str,
    time_range: str,
    size: int = DEFAULT_ALERT_SIZE,
    cursor: list[Any] | None = None,
) -> dict[str, Any]:
    if not _AGENT_ID_RE.match(agent_id):
        raise ValueError("invalid agent_id")
    _validate_time_range(time_range)
    query: dict[str, Any] = {
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": f"now-{time_range}"}}},
                    {"term": {"agent.id": agent_id}},
                ]
            }
        },
        "size": min(max(1, size), MAX_ALERT_SIZE),
        "sort": [{"@timestamp": "desc"}],
        "_source": DEFAULT_ALERT_FIELDS,
        "terminate_after": TERMINATE_AFTER,
    }
    if cursor:
        query["search_after"] = cursor
    return query


def build_alerts_by_mitre_query(
    *,
    technique_id: str,
    time_range: str,
    size: int = DEFAULT_ALERT_SIZE,
    cursor: list[Any] | None = None,
) -> dict[str, Any]:
    if not _MITRE_ID_RE.match(technique_id):
        raise ValueError("invalid technique_id")
    _validate_time_range(time_range)
    query: dict[str, Any] = {
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": f"now-{time_range}"}}},
                    {"term": {"rule.mitre.id": technique_id}},
                ]
            }
        },
        "size": min(max(1, size), MAX_ALERT_SIZE),
        "sort": [{"@timestamp": "desc"}],
        "_source": DEFAULT_ALERT_FIELDS,
        "terminate_after": TERMINATE_AFTER,
    }
    if cursor:
        query["search_after"] = cursor
    return query


def build_vulnerabilities_by_agent_query(
    *,
    agent_id: str,
    min_severity: str | None = None,
    size: int = DEFAULT_ALERT_SIZE,
    cursor: list[Any] | None = None,
) -> dict[str, Any]:
    if not _AGENT_ID_RE.match(agent_id):
        raise ValueError("invalid agent_id")
    must: list[dict[str, Any]] = [{"term": {"agent.id": agent_id}}]
    if min_severity is not None:
        sev = min_severity.capitalize()
        if sev not in _SEVERITIES:
            raise ValueError(f"invalid severity: {min_severity!r}")
        allowed = _SEVERITIES[_SEVERITIES.index(sev):]
        must.append({"terms": {"vulnerability.severity": allowed}})
    query: dict[str, Any] = {
        "query": {"bool": {"must": must}},
        "size": min(max(1, size), MAX_ALERT_SIZE),
        "sort": [{"vulnerability.detected_at": "desc"}],
        "_source": DEFAULT_VULN_FIELDS,
        "terminate_after": TERMINATE_AFTER,
    }
    if cursor:
        query["search_after"] = cursor
    return query


def build_search_vulnerabilities_query(
    *,
    cve_id: str | None = None,
    min_severity: str | None = None,
    size: int = DEFAULT_ALERT_SIZE,
    cursor: list[Any] | None = None,
) -> dict[str, Any]:
    if cve_id is None and min_severity is None:
        raise ValueError("at least one of cve_id or min_severity must be set")
    must: list[dict[str, Any]] = []
    if cve_id is not None:
        if not _CVE_ID_RE.match(cve_id):
            raise ValueError("invalid cve_id")
        must.append({"term": {"vulnerability.id": cve_id}})
    if min_severity is not None:
        sev = min_severity.capitalize()
        if sev not in _SEVERITIES:
            raise ValueError(f"invalid severity: {min_severity!r}")
        allowed = _SEVERITIES[_SEVERITIES.index(sev):]
        must.append({"terms": {"vulnerability.severity": allowed}})
    query: dict[str, Any] = {
        "query": {"bool": {"must": must}},
        "size": min(max(1, size), MAX_ALERT_SIZE),
        "sort": [{"vulnerability.detected_at": "desc"}],
        "_source": DEFAULT_VULN_FIELDS,
        "terminate_after": TERMINATE_AFTER,
    }
    if cursor:
        query["search_after"] = cursor
    return query


def build_fim_history_for_path_query(
    *,
    path: str,
    time_range: str,
    size: int = DEFAULT_ALERT_SIZE,
    cursor: list[Any] | None = None,
) -> dict[str, Any]:
    if not path or len(path) > 1024:
        raise ValueError("invalid path")
    _validate_time_range(time_range)
    query: dict[str, Any] = {
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": f"now-{time_range}"}}},
                    {"term": {"syscheck.path": path}},
                ]
            }
        },
        "size": min(max(1, size), MAX_ALERT_SIZE),
        "sort": [{"@timestamp": "desc"}],
        "_source": DEFAULT_FIM_FIELDS,
        "terminate_after": TERMINATE_AFTER,
    }
    if cursor:
        query["search_after"] = cursor
    return query


def build_fim_changes_by_agent_query(
    *,
    agent_id: str,
    time_range: str,
    size: int = DEFAULT_ALERT_SIZE,
    cursor: list[Any] | None = None,
) -> dict[str, Any]:
    if not _AGENT_ID_RE.match(agent_id):
        raise ValueError("invalid agent_id")
    _validate_time_range(time_range)
    query: dict[str, Any] = {
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": f"now-{time_range}"}}},
                    {"term": {"agent.id": agent_id}},
                    {"exists": {"field": "syscheck.path"}},
                ]
            }
        },
        "size": min(max(1, size), MAX_ALERT_SIZE),
        "sort": [{"@timestamp": "desc"}],
        "_source": DEFAULT_FIM_FIELDS,
        "terminate_after": TERMINATE_AFTER,
    }
    if cursor:
        query["search_after"] = cursor
    return query
