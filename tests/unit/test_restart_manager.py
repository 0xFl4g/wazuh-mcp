"""write.restart_manager handler tests (M4c T11)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from wazuh_mcp.auth.session import Session
from wazuh_mcp.tools.write import (
    RestartManagerArgs,
    restart_manager,
)
from wazuh_mcp.wazuh.errors import WazuhError


def _session() -> Session:
    return Session(
        user_id="alice",
        tenant_id="tenant_a",
        rbac_role="admin",
        auth_method="oauth",
        wazuh_user="alice-wazuh",
    )


def test_args_default_scope_is_cluster() -> None:
    args = RestartManagerArgs(confirm=True)
    assert args.scope == "cluster"


def test_args_accepts_node_scope() -> None:
    args = RestartManagerArgs(scope="node", confirm=True)
    assert args.scope == "node"


def test_args_rejects_invalid_scope() -> None:
    with pytest.raises(ValidationError):
        RestartManagerArgs(scope="rolling", confirm=True)


def test_args_rejects_confirm_false() -> None:
    with pytest.raises(ValidationError):
        RestartManagerArgs(confirm=False)


@pytest.mark.asyncio
async def test_handler_cluster_scope_calls_pre_status_then_restart() -> None:
    calls: list[str] = []

    class _StubClient:
        async def cluster_status(self):  # type: ignore[no-untyped-def]
            calls.append("status")
            return {
                "enabled": True,
                "running": True,
                "nodes": [
                    {"name": "node-master", "type": "master", "status": "running"},
                ],
            }

        async def restart_cluster(self, *, scope, run_as):  # type: ignore[no-untyped-def]
            calls.append(f"restart:{scope}")
            return {"data": {"affected_items": ["node-master"]}}

    args = RestartManagerArgs(scope="cluster", confirm=True)
    result = await restart_manager(args=args, session=_session(), server_api=_StubClient())
    assert calls == ["status", "restart:cluster"]
    assert result.ok is True
    assert result.scope == "cluster"
    assert result.affected_nodes == ["node-master"]


@pytest.mark.asyncio
async def test_handler_node_scope_calls_pre_status_then_node_restart() -> None:
    captured_scope: list[str] = []

    class _StubClient:
        async def cluster_status(self):  # type: ignore[no-untyped-def]
            return {
                "enabled": False,
                "running": False,
                "nodes": [],
            }

        async def restart_cluster(self, *, scope, run_as):  # type: ignore[no-untyped-def]
            captured_scope.append(scope)
            return {"data": {"affected_items": ["this-node"]}}

    args = RestartManagerArgs(scope="node", confirm=True)
    result = await restart_manager(args=args, session=_session(), server_api=_StubClient())
    # Even with clustering disabled, node-scope is allowed.
    assert captured_scope == ["node"]
    assert result.scope == "node"


@pytest.mark.asyncio
async def test_handler_cluster_scope_with_clustering_disabled_raises_upstream_error() -> None:
    class _StubClient:
        async def cluster_status(self):  # type: ignore[no-untyped-def]
            return {"enabled": False, "running": False, "nodes": []}

        async def restart_cluster(self, *, scope, run_as):  # type: ignore[no-untyped-def]
            pytest.fail("restart should not be called when cluster scope requested but disabled")

    args = RestartManagerArgs(scope="cluster", confirm=True)
    with pytest.raises(WazuhError) as exc_info:
        await restart_manager(args=args, session=_session(), server_api=_StubClient())
    assert exc_info.value.code == "upstream_error"
    assert "cluster" in exc_info.value.message
