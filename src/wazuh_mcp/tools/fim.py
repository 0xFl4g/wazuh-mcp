"""fim.* tools — file-integrity-monitoring history views over the alerts index.

M4a note: audit emission is owned by @instrumented_tool.
"""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field

from wazuh_mcp.auth.session import Session
from wazuh_mcp.wazuh.indexer import IndexerClient
from wazuh_mcp.wazuh.models import FimEvent
from wazuh_mcp.wazuh.query import (
    build_fim_changes_by_agent_query,
    build_fim_history_for_path_query,
)


class FimHistoryArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: Annotated[str, Field(min_length=1, max_length=1024)]
    time_range: str = "24h"
    size: Annotated[int, Field(ge=1, le=100)] = 25
    cursor: list[Any] | None = None


class FimChangesArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_id: Annotated[str, Field(min_length=1, max_length=16)]
    time_range: str = "24h"
    size: Annotated[int, Field(ge=1, le=100)] = 25
    cursor: list[Any] | None = None


class FimResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    events: list[FimEvent]
    total: int
    next_cursor: list[Any] | None
    truncated: bool


async def fim_history_for_path(
    *,
    args: FimHistoryArgs,
    session: Session,
    indexer: IndexerClient,
) -> FimResult:
    """Tool name: fim.fim_history_for_path."""
    return await _fim_search(
        build=lambda: build_fim_history_for_path_query(
            path=args.path,
            time_range=args.time_range,
            size=args.size,
            cursor=args.cursor,
        ),
        wanted_size=args.size,
        indexer=indexer,
    )


async def fim_changes_by_agent(
    *,
    args: FimChangesArgs,
    session: Session,
    indexer: IndexerClient,
) -> FimResult:
    """Tool name: fim.fim_changes_by_agent."""
    return await _fim_search(
        build=lambda: build_fim_changes_by_agent_query(
            agent_id=args.agent_id,
            time_range=args.time_range,
            size=args.size,
            cursor=args.cursor,
        ),
        wanted_size=args.size,
        indexer=indexer,
    )


async def _fim_search(
    *,
    build,
    wanted_size: int,
    indexer: IndexerClient,
) -> FimResult:
    query = build()
    body = await indexer.search(index="wazuh-alerts-*", query=query)

    raw_hits = body.get("hits", {}).get("hits", [])
    total_block = body.get("hits", {}).get("total", {})
    total = total_block.get("value", 0) if isinstance(total_block, dict) else int(total_block)
    events = [FimEvent.from_hit(h) for h in raw_hits]
    next_cursor: list[Any] | None = None
    if raw_hits and "sort" in raw_hits[-1]:
        next_cursor = raw_hits[-1]["sort"]
    truncated = len(events) == wanted_size

    return FimResult(
        events=events,
        total=total,
        next_cursor=next_cursor,
        truncated=truncated,
    )
