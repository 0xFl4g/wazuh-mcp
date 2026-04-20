"""search_alerts tool — M1's only tool.

Establishes the pattern every M3 tool follows:
  1. Validate args (strict Pydantic).
  2. Resolve session (caller supplies it; session is session-pinned).
  3. Build server-side DSL.
  4. Call indexer.
  5. Map hits → strict Pydantic models (parse errors audited).
  6. Emit structuredContent + short text summary.
  7. Audit every exit path.
"""

from __future__ import annotations

import time
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import AuditEmitter
from wazuh_mcp.wazuh.errors import WazuhError
from wazuh_mcp.wazuh.indexer import IndexerClient
from wazuh_mcp.wazuh.models import Alert
from wazuh_mcp.wazuh.query import build_search_alerts_query


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


def _summarise(alerts: list[Alert], total: int) -> str:
    if not alerts:
        return f"0 alerts matched (total in range: {total})."
    top: dict[str, int] = {}
    for a in alerts:
        top[a.rule.description] = top.get(a.rule.description, 0) + 1
    top_sorted = sorted(top.items(), key=lambda kv: kv[1], reverse=True)[:3]
    top_str = "; ".join(f"{desc} ({n})" for desc, n in top_sorted)
    return f"{len(alerts)} alert(s) returned (total: {total}). Top rules: {top_str}."


async def search_alerts(
    *,
    args: SearchAlertsArgs,
    session: Session,
    indexer: IndexerClient,
    audit: AuditEmitter,
) -> dict[str, Any]:
    started = time.monotonic()
    arg_dict = args.model_dump(exclude_none=True)

    try:
        query = build_search_alerts_query(
            time_range=args.time_range,
            min_level=args.min_level,
            agent_id=args.agent_id,
            size=args.size,
            cursor=args.cursor,
        )
        body = await indexer.search(index="wazuh-alerts-*", query=query)
    except WazuhError as e:
        audit.emit(
            session=session,
            tool="search_alerts",
            args=arg_dict,
            outcome="error",
            result_count=0,
            duration_ms=int((time.monotonic() - started) * 1000),
            error_code=e.code,
        )
        raise
    except ValueError:
        audit.emit(
            session=session,
            tool="search_alerts",
            args=arg_dict,
            outcome="error",
            result_count=0,
            duration_ms=int((time.monotonic() - started) * 1000),
            error_code="invalid_query",
        )
        raise

    try:
        raw_hits = body.get("hits", {}).get("hits", [])
        hits_block = body.get("hits", {})
        total_block = hits_block.get("total", {})
        total = total_block.get("value", 0) if isinstance(total_block, dict) else int(total_block)
        alerts = [Alert.from_hit(h) for h in raw_hits]
        next_cursor: list[Any] | None = None
        if raw_hits and "sort" in raw_hits[-1]:
            next_cursor = raw_hits[-1]["sort"]
        truncated = len(alerts) == args.size
    except Exception:
        audit.emit(
            session=session,
            tool="search_alerts",
            args=arg_dict,
            outcome="error",
            result_count=0,
            duration_ms=int((time.monotonic() - started) * 1000),
            error_code="parse_error",
        )
        raise

    audit.emit(
        session=session,
        tool="search_alerts",
        args=arg_dict,
        outcome="ok",
        result_count=len(alerts),
        duration_ms=int((time.monotonic() - started) * 1000),
    )

    return {
        "structuredContent": {
            "alerts": [a.model_dump() for a in alerts],
            "total": total,
            "next_cursor": next_cursor,
            "truncated": truncated,
        },
        "text": _summarise(alerts, total),
    }
