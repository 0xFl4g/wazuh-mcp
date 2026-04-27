"""cluster.status read tool tests (M4c T11)."""

from __future__ import annotations

import pytest

from wazuh_mcp.auth.session import Session
from wazuh_mcp.tools.cluster import (
    ClusterNode,
    ClusterStatusArgs,
    cluster_status,
)


def _session() -> Session:
    return Session(
        user_id="alice",
        tenant_id="tenant_a",
        rbac_role="analyst",
        auth_method="oauth",
        wazuh_user=None,
    )


def test_args_takes_no_fields() -> None:
    args = ClusterStatusArgs()
    assert args is not None


@pytest.mark.asyncio
async def test_handler_returns_status_with_nodes() -> None:
    class _StubClient:
        async def cluster_status(self):  # type: ignore[no-untyped-def]
            return {
                "enabled": True,
                "running": True,
                "nodes": [
                    {"name": "node-master", "type": "master", "status": "running"},
                    {"name": "node-worker", "type": "worker", "status": "running"},
                ],
            }

    args = ClusterStatusArgs()
    result = await cluster_status(args=args, session=_session(), server_api=_StubClient())
    assert result.enabled is True
    assert result.running is True
    assert len(result.nodes) == 2
    assert result.nodes[0] == ClusterNode(name="node-master", type="master", status="running")


@pytest.mark.asyncio
async def test_handler_returns_disabled_when_clustering_off() -> None:
    class _StubClient:
        async def cluster_status(self):  # type: ignore[no-untyped-def]
            return {"enabled": False, "running": False, "nodes": []}

    args = ClusterStatusArgs()
    result = await cluster_status(args=args, session=_session(), server_api=_StubClient())
    assert result.enabled is False
    assert result.running is False
    assert result.nodes == []
