"""agents.* tools — all Server API-backed (port 55000).

M4a note: audit emission is owned by @instrumented_tool (see server.py
wiring). Tool bodies no longer call audit.emit themselves.
"""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field

from wazuh_mcp.auth.session import Session
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
) -> AgentsResult:
    """Tool name: agents.list_agents."""
    params = _nonempty(
        {
            "status": args.status,
            "group": args.group,
            "limit": args.size,
            "offset": args.offset,
        }
    )
    body = await server_api.get("/agents", params=params, run_as=session.wazuh_user)
    return _shape_agent_list(body, args.size)


async def get_agent(
    *,
    args: GetAgentArgs,
    session: Session,
    server_api: ServerApiClient,
) -> AgentResult:
    """Tool name: agents.get_agent."""
    body = await server_api.get(
        "/agents",
        params={"agents_list": args.agent_id},
        run_as=session.wazuh_user,
    )

    items = (body.get("data") or {}).get("affected_items") or []
    if not items:
        raise WazuhError("not_found", "agent not found", 404)

    agent = Agent.from_api(items[0])
    return AgentResult(agent=agent)


async def agent_processes(
    *,
    args: AgentSubquery,
    session: Session,
    server_api: ServerApiClient,
) -> AgentInventoryResult:
    """Tool name: agents.agent_processes."""
    return await _inventory(
        path=f"/syscollector/{args.agent_id}/processes",
        args=args,
        session=session,
        server_api=server_api,
    )


async def agent_packages(
    *,
    args: AgentSubquery,
    session: Session,
    server_api: ServerApiClient,
) -> AgentInventoryResult:
    """Tool name: agents.agent_packages."""
    return await _inventory(
        path=f"/syscollector/{args.agent_id}/packages",
        args=args,
        session=session,
        server_api=server_api,
    )


async def agent_ports(
    *,
    args: AgentSubquery,
    session: Session,
    server_api: ServerApiClient,
) -> AgentInventoryResult:
    """Tool name: agents.agent_ports."""
    return await _inventory(
        path=f"/syscollector/{args.agent_id}/ports",
        args=args,
        session=session,
        server_api=server_api,
    )


async def _inventory(
    *,
    path: str,
    args: AgentSubquery,
    session: Session,
    server_api: ServerApiClient,
) -> AgentInventoryResult:
    body = await server_api.get(
        path,
        params={"limit": args.size, "offset": args.offset},
        run_as=session.wazuh_user,
    )

    data = body.get("data") or {}
    items = list(data.get("affected_items") or [])
    total = int(data.get("total_affected_items") or len(items))
    truncated = len(items) == args.size

    return AgentInventoryResult(
        agent_id=args.agent_id,
        items=items,
        total=total,
        truncated=truncated,
    )


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
