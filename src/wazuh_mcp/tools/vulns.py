"""vulnerabilities.* tools — 4.8+ reads from the wazuh-states-vulnerabilities-* indices."""

from __future__ import annotations

import time
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import AuditEmitter
from wazuh_mcp.wazuh.errors import WazuhError
from wazuh_mcp.wazuh.indexer import IndexerClient
from wazuh_mcp.wazuh.models import Vulnerability
from wazuh_mcp.wazuh.query import (
    build_search_vulnerabilities_query,
    build_vulnerabilities_by_agent_query,
)

VULN_INDEX = "wazuh-states-vulnerabilities-*"


class ListVulnerabilitiesByAgentArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_id: Annotated[str, Field(min_length=1, max_length=16)]
    min_severity: Annotated[
        str | None,
        Field(description="Low | Medium | High | Critical"),
    ] = None
    size: Annotated[int, Field(ge=1, le=100)] = 25
    cursor: list[Any] | None = None


class SearchVulnerabilitiesArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cve_id: Annotated[str | None, Field(description="e.g. CVE-2024-1234")] = None
    min_severity: Annotated[
        str | None,
        Field(description="Low | Medium | High | Critical"),
    ] = None
    size: Annotated[int, Field(ge=1, le=100)] = 25
    cursor: list[Any] | None = None


class VulnerabilitiesResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    vulnerabilities: list[Vulnerability]
    total: int
    next_cursor: list[Any] | None
    truncated: bool


async def list_vulnerabilities_by_agent(
    *,
    args: ListVulnerabilitiesByAgentArgs,
    session: Session,
    indexer: IndexerClient,
    audit: AuditEmitter,
) -> VulnerabilitiesResult:
    """Tool name: vulnerabilities.list_vulnerabilities_by_agent."""
    return await _vuln_search(
        tool_name="vulnerabilities.list_vulnerabilities_by_agent",
        build=lambda: build_vulnerabilities_by_agent_query(
            agent_id=args.agent_id,
            min_severity=args.min_severity,
            size=args.size,
            cursor=args.cursor,
        ),
        args_dict=args.model_dump(exclude_none=True),
        wanted_size=args.size,
        session=session,
        indexer=indexer,
        audit=audit,
    )


async def search_vulnerabilities(
    *,
    args: SearchVulnerabilitiesArgs,
    session: Session,
    indexer: IndexerClient,
    audit: AuditEmitter,
) -> VulnerabilitiesResult:
    """Tool name: vulnerabilities.search_vulnerabilities."""
    return await _vuln_search(
        tool_name="vulnerabilities.search_vulnerabilities",
        build=lambda: build_search_vulnerabilities_query(
            cve_id=args.cve_id,
            min_severity=args.min_severity,
            size=args.size,
            cursor=args.cursor,
        ),
        args_dict=args.model_dump(exclude_none=True),
        wanted_size=args.size,
        session=session,
        indexer=indexer,
        audit=audit,
    )


async def _vuln_search(
    *,
    tool_name: str,
    build,
    args_dict: dict[str, Any],
    wanted_size: int,
    session: Session,
    indexer: IndexerClient,
    audit: AuditEmitter,
) -> VulnerabilitiesResult:
    started = time.monotonic()
    try:
        query = build()
        body = await indexer.search(index=VULN_INDEX, query=query)
    except WazuhError as e:
        audit.emit(
            session=session,
            tool=tool_name,
            args=args_dict,
            outcome="error",
            result_count=0,
            duration_ms=int((time.monotonic() - started) * 1000),
            error_code=e.code,
        )
        raise
    except ValueError:
        audit.emit(
            session=session,
            tool=tool_name,
            args=args_dict,
            outcome="error",
            result_count=0,
            duration_ms=int((time.monotonic() - started) * 1000),
            error_code="invalid_query",
        )
        raise

    raw_hits = body.get("hits", {}).get("hits", [])
    total_block = body.get("hits", {}).get("total", {})
    total = (
        total_block.get("value", 0)
        if isinstance(total_block, dict)
        else int(total_block)
    )
    vulns = [Vulnerability.from_hit(h) for h in raw_hits]
    next_cursor: list[Any] | None = None
    if raw_hits and "sort" in raw_hits[-1]:
        next_cursor = raw_hits[-1]["sort"]
    truncated = len(vulns) == wanted_size

    audit.emit(
        session=session,
        tool=tool_name,
        args=args_dict,
        outcome="ok",
        result_count=len(vulns),
        duration_ms=int((time.monotonic() - started) * 1000),
    )
    return VulnerabilitiesResult(
        vulnerabilities=vulns,
        total=total,
        next_cursor=next_cursor,
        truncated=truncated,
    )
