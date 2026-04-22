"""agents.* tools — all Server API-backed (port 55000)."""

from __future__ import annotations

import time
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import AuditEmitter
from wazuh_mcp.wazuh.errors import WazuhError
from wazuh_mcp.wazuh.models import Agent
from wazuh_mcp.wazuh.server_api import ServerApiClient


class ListAgentsArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Annotated[
        str | None,
        Field(description="active | disconnected | pending | never_connected"),
    ] = None
    group: Annotated[str | None, Field(max_length=64)] = None
    size: Annotated[int, Field(ge=1, le=500)] = 100
    offset: Annotated[int, Field(ge=0, le=10_000)] = 0


class AgentsResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    agents: list[Agent]
    total: int
    truncated: bool


class GetAgentArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_id: Annotated[str, Field(min_length=1, max_length=16)]


class AgentResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    agent: Agent


class AgentSubquery(BaseModel):
    """Shared args for processes / packages / ports."""

    model_config = ConfigDict(extra="forbid")

    agent_id: Annotated[str, Field(min_length=1, max_length=16)]
    size: Annotated[int, Field(ge=1, le=500)] = 100
    offset: Annotated[int, Field(ge=0, le=10_000)] = 0


class AgentInventoryResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    agent_id: str
    items: list[dict[str, Any]]
    total: int
    truncated: bool


async def list_agents(
    *,
    args: ListAgentsArgs,
    session: Session,
    server_api: ServerApiClient,
    audit: AuditEmitter,
) -> AgentsResult:
    """Tool name: agents.list_agents."""
    return await _run_server_api_tool(
        tool_name="agents.list_agents",
        path="/agents",
        params=_nonempty(
            {
                "status": args.status,
                "group": args.group,
                "limit": args.size,
                "offset": args.offset,
            }
        ),
        args_dict=args.model_dump(exclude_none=True),
        session=session,
        server_api=server_api,
        audit=audit,
        shape=_shape_agent_list,
        wanted_size=args.size,
    )


async def get_agent(
    *,
    args: GetAgentArgs,
    session: Session,
    server_api: ServerApiClient,
    audit: AuditEmitter,
) -> AgentResult:
    """Tool name: agents.get_agent."""
    started = time.monotonic()
    arg_dict = args.model_dump()
    try:
        body = await server_api.get(
            "/agents",
            params={"agents_list": args.agent_id},
            run_as=session.wazuh_user,
        )
    except WazuhError as e:
        audit.emit(
            session=session,
            tool="agents.get_agent",
            args=arg_dict,
            outcome="error",
            result_count=0,
            duration_ms=int((time.monotonic() - started) * 1000),
            error_code=e.code,
        )
        raise

    items = (body.get("data") or {}).get("affected_items") or []
    if not items:
        audit.emit(
            session=session,
            tool="agents.get_agent",
            args=arg_dict,
            outcome="error",
            result_count=0,
            duration_ms=int((time.monotonic() - started) * 1000),
            error_code="not_found",
        )
        raise WazuhError("not_found", "agent not found", 404)

    agent = Agent.from_api(items[0])
    audit.emit(
        session=session,
        tool="agents.get_agent",
        args=arg_dict,
        outcome="ok",
        result_count=1,
        duration_ms=int((time.monotonic() - started) * 1000),
    )
    return AgentResult(agent=agent)


async def agent_processes(
    *,
    args: AgentSubquery,
    session: Session,
    server_api: ServerApiClient,
    audit: AuditEmitter,
) -> AgentInventoryResult:
    """Tool name: agents.agent_processes."""
    return await _inventory(
        tool_name="agents.agent_processes",
        path=f"/syscollector/{args.agent_id}/processes",
        args=args,
        session=session,
        server_api=server_api,
        audit=audit,
    )


async def agent_packages(
    *,
    args: AgentSubquery,
    session: Session,
    server_api: ServerApiClient,
    audit: AuditEmitter,
) -> AgentInventoryResult:
    """Tool name: agents.agent_packages."""
    return await _inventory(
        tool_name="agents.agent_packages",
        path=f"/syscollector/{args.agent_id}/packages",
        args=args,
        session=session,
        server_api=server_api,
        audit=audit,
    )


async def agent_ports(
    *,
    args: AgentSubquery,
    session: Session,
    server_api: ServerApiClient,
    audit: AuditEmitter,
) -> AgentInventoryResult:
    """Tool name: agents.agent_ports."""
    return await _inventory(
        tool_name="agents.agent_ports",
        path=f"/syscollector/{args.agent_id}/ports",
        args=args,
        session=session,
        server_api=server_api,
        audit=audit,
    )


async def _inventory(
    *,
    tool_name: str,
    path: str,
    args: AgentSubquery,
    session: Session,
    server_api: ServerApiClient,
    audit: AuditEmitter,
) -> AgentInventoryResult:
    started = time.monotonic()
    arg_dict = args.model_dump(exclude_none=True)
    try:
        body = await server_api.get(
            path,
            params={"limit": args.size, "offset": args.offset},
            run_as=session.wazuh_user,
        )
    except WazuhError as e:
        audit.emit(
            session=session,
            tool=tool_name,
            args=arg_dict,
            outcome="error",
            result_count=0,
            duration_ms=int((time.monotonic() - started) * 1000),
            error_code=e.code,
        )
        raise

    data = body.get("data") or {}
    items = list(data.get("affected_items") or [])
    total = int(data.get("total_affected_items") or len(items))
    truncated = len(items) == args.size

    audit.emit(
        session=session,
        tool=tool_name,
        args=arg_dict,
        outcome="ok",
        result_count=len(items),
        duration_ms=int((time.monotonic() - started) * 1000),
    )
    return AgentInventoryResult(
        agent_id=args.agent_id,
        items=items,
        total=total,
        truncated=truncated,
    )


async def _run_server_api_tool(
    *,
    tool_name: str,
    path: str,
    params: dict[str, Any],
    args_dict: dict[str, Any],
    session: Session,
    server_api: ServerApiClient,
    audit: AuditEmitter,
    shape,
    wanted_size: int,
) -> AgentsResult:
    started = time.monotonic()
    try:
        body = await server_api.get(path, params=params, run_as=session.wazuh_user)
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

    result = shape(body, wanted_size)
    audit.emit(
        session=session,
        tool=tool_name,
        args=args_dict,
        outcome="ok",
        result_count=len(result.agents),
        duration_ms=int((time.monotonic() - started) * 1000),
    )
    return result


def _shape_agent_list(body: dict[str, Any], wanted_size: int) -> AgentsResult:
    data = body.get("data") or {}
    items = list(data.get("affected_items") or [])
    total = int(data.get("total_affected_items") or len(items))
    return AgentsResult(
        agents=[Agent.from_api(it) for it in items],
        total=total,
        truncated=len(items) == wanted_size,
    )


def _nonempty(d: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in d.items() if v is not None}
