"""M5b T-A2: write.run_active_response_on_group handler tests."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from wazuh_mcp.auth.session import Session
from wazuh_mcp.tools.write import (
    RunActiveResponseOnGroupArgs,
    run_active_response_on_group,
)
from wazuh_mcp.wazuh.errors import WazuhError


def _session(wazuh_user: str | None = "alice") -> Session:
    return Session(
        user_id="u1",
        tenant_id="t1",
        rbac_role="admin",
        auth_method="oauth",
        wazuh_user=wazuh_user,
    )


@pytest.mark.asyncio
async def test_handler_calls_server_api_with_group_name():
    sapi = AsyncMock()
    sapi.run_active_response_on_group.return_value = {
        "data": {"affected_items": ["001", "002"], "failed_items": []}
    }
    args = RunActiveResponseOnGroupArgs(
        group_name="soc-tier1",
        command_name="restart-wazuh",
        custom_args=None,
        confirm=True,
    )
    result = await run_active_response_on_group(
        args=args,
        session=_session(),
        server_api=sapi,
        ar_group_allowlist=["soc-tier1", "soc-tier2"],
    )
    assert result.ok is True
    assert result.affected_agents == ["001", "002"]
    assert result.failed_agents == []
    sapi.run_active_response_on_group.assert_awaited_once_with(
        group_name="soc-tier1",
        command="restart-wazuh",
        custom_args=None,
        run_as="alice",
    )


@pytest.mark.asyncio
async def test_handler_rejects_group_not_in_allowlist():
    sapi = AsyncMock()
    args = RunActiveResponseOnGroupArgs(
        group_name="prod-critical",
        command_name="restart-wazuh",
        custom_args=None,
        confirm=True,
    )
    with pytest.raises(WazuhError) as exc_info:
        await run_active_response_on_group(
            args=args,
            session=_session(),
            server_api=sapi,
            ar_group_allowlist=["soc-tier1"],
        )
    assert exc_info.value.code == "forbidden"
    assert "prod-critical" in exc_info.value.message
    assert "agent_group_allowlist" in exc_info.value.message
    sapi.run_active_response_on_group.assert_not_awaited()


def test_args_rejects_missing_confirm():
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        RunActiveResponseOnGroupArgs(  # ty: ignore[missing-argument]
            group_name="g1",
            command_name="cmd",
            custom_args=None,
            # confirm intentionally missing
        )


def test_args_rejects_confirm_false():
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        RunActiveResponseOnGroupArgs(
            group_name="g1",
            command_name="cmd",
            custom_args=None,
            confirm=False,
        )
