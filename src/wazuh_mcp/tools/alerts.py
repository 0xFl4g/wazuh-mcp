"""alerts.* tools — search, get-by-id, by-agent, by-mitre.

Pattern every M3 tool follows:
  1. Validate args (strict Pydantic, extra=forbid).
  2. Build server-side DSL via wazuh/query.py — never accept raw DSL.
  3. Call indexer.
  4. Map hits → strict Pydantic models.
  5. Return a Pydantic result model; FastMCP auto-promotes to structuredContent.

Authored text summaries are intentionally absent — Claude generates better
summaries from structured data than hand-authored strings.

M4a note: audit emission is owned by @instrumented_tool (see server.py
wiring). Tool bodies no longer call audit.emit themselves.
"""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field

from wazuh_mcp.auth.session import Session
from wazuh_mcp.wazuh.errors import WazuhError
from wazuh_mcp.wazuh.indexer import IndexerClient
from wazuh_mcp.wazuh.models import Alert
from wazuh_mcp.wazuh.query import (
    build_alerts_by_agent_query,
    build_alerts_by_mitre_query,
    build_get_alert_query,
    build_search_alerts_query,
)


class SearchAlertsArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    time_range: Annotated[str, Field(description="Relative lookback, e.g. '1h', '24h', '7d'")] = (
        "1h"
    )
    min_level: Annotated[int | None, Field(ge=0, le=15, description="Minimum rule.level")] = None
    agent_id: Annotated[str | None, Field(description="Filter to a single agent.id")] = None
    size: Annotated[int, Field(ge=1, le=100, description="Max alerts to return (hard cap 100)")] = (
        25
    )
    cursor: Annotated[
        list[Any] | None, Field(description="Opaque search_after cursor from prior call")
    ] = None


class SearchAlertsResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    alerts: list[Alert]
    total: int
    next_cursor: list[Any] | None
    truncated: bool


async def search_alerts(
    *,
    args: SearchAlertsArgs,
    session: Session,
    indexer: IndexerClient,
) -> SearchAlertsResult:
    """Tool name: alerts.search_alerts (registered in server.py).

    Returns a flat Pydantic model — FastMCP promotes it to CallToolResult's
    structuredContent directly. No handler-side text summary.
    """
    query = build_search_alerts_query(
        time_range=args.time_range,
        min_level=args.min_level,
        agent_id=args.agent_id,
        size=args.size,
        cursor=args.cursor,
    )
    body = await indexer.search(index="wazuh-alerts-*", query=query)

    raw_hits = body.get("hits", {}).get("hits", [])
    hits_block = body.get("hits", {})
    total_block = hits_block.get("total", {})
    total = total_block.get("value", 0) if isinstance(total_block, dict) else int(total_block)
    alerts = [Alert.from_hit(h) for h in raw_hits]
    next_cursor: list[Any] | None = None
    if raw_hits and "sort" in raw_hits[-1]:
        next_cursor = raw_hits[-1]["sort"]
    truncated = len(alerts) == args.size

    return SearchAlertsResult(
        alerts=alerts,
        total=total,
        next_cursor=next_cursor,
        truncated=truncated,
    )


class GetAlertArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alert_id: Annotated[str, Field(min_length=1, max_length=128)]


class GetAlertResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    alert: Alert


async def get_alert(
    *,
    args: GetAlertArgs,
    session: Session,
    indexer: IndexerClient,
) -> GetAlertResult:
    """Tool name: alerts.get_alert."""
    query = build_get_alert_query(args.alert_id)
    body = await indexer.search(index="wazuh-alerts-*", query=query)

    hits = body.get("hits", {}).get("hits", [])
    if not hits:
        raise WazuhError("not_found", "alert not found", 404)

    alert = Alert.from_hit(hits[0])
    return GetAlertResult(alert=alert)


class AlertsByAgentArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_id: Annotated[str, Field(min_length=1, max_length=16)]
    time_range: str = "24h"
    size: Annotated[int, Field(ge=1, le=100)] = 25
    cursor: Annotated[list[Any] | None, Field()] = None


async def alerts_by_agent(
    *,
    args: AlertsByAgentArgs,
    session: Session,
    indexer: IndexerClient,
) -> SearchAlertsResult:
    """Tool name: alerts.alerts_by_agent."""
    return await _filtered_alerts_search(
        build_query=lambda: build_alerts_by_agent_query(
            agent_id=args.agent_id,
            time_range=args.time_range,
            size=args.size,
            cursor=args.cursor,
        ),
        wanted_size=args.size,
        indexer=indexer,
    )


class AlertsByMitreArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    technique_id: Annotated[str, Field(min_length=4, max_length=16)]
    time_range: str = "24h"
    size: Annotated[int, Field(ge=1, le=100)] = 25
    cursor: Annotated[list[Any] | None, Field()] = None


async def alerts_by_mitre(
    *,
    args: AlertsByMitreArgs,
    session: Session,
    indexer: IndexerClient,
) -> SearchAlertsResult:
    """Tool name: alerts.alerts_by_mitre."""
    return await _filtered_alerts_search(
        build_query=lambda: build_alerts_by_mitre_query(
            technique_id=args.technique_id,
            time_range=args.time_range,
            size=args.size,
            cursor=args.cursor,
        ),
        wanted_size=args.size,
        indexer=indexer,
    )


async def _filtered_alerts_search(
    *,
    build_query,
    wanted_size: int,
    indexer: IndexerClient,
) -> SearchAlertsResult:
    """Shared path for alerts-index filtered searches."""
    query = build_query()
    body = await indexer.search(index="wazuh-alerts-*", query=query)

    raw_hits = body.get("hits", {}).get("hits", [])
    total_block = body.get("hits", {}).get("total", {})
    total = total_block.get("value", 0) if isinstance(total_block, dict) else int(total_block)
    alerts = [Alert.from_hit(h) for h in raw_hits]
    next_cursor: list[Any] | None = None
    if raw_hits and "sort" in raw_hits[-1]:
        next_cursor = raw_hits[-1]["sort"]
    truncated = len(alerts) == wanted_size

    return SearchAlertsResult(
        alerts=alerts,
        total=total,
        next_cursor=next_cursor,
        truncated=truncated,
    )
