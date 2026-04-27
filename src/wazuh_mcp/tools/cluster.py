"""cluster.* read tools (M4c).

Currently single-tool: cluster.status.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from wazuh_mcp.auth.session import Session


class ClusterStatusArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ClusterNode(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    type: Literal["master", "worker"]
    status: str


class ClusterStatusResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    enabled: bool
    running: bool
    nodes: list[ClusterNode]


async def cluster_status(
    *,
    args: ClusterStatusArgs,
    session: Session,
    server_api: Any,
) -> ClusterStatusResult:
    raw = await server_api.cluster_status()
    return ClusterStatusResult(
        enabled=bool(raw.get("enabled", False)),
        running=bool(raw.get("running", False)),
        nodes=[
            ClusterNode(
                name=str(n.get("name", "")),
                type=n.get("type", "worker"),
                status=str(n.get("status", "")),
            )
            for n in raw.get("nodes", [])
        ],
    )
