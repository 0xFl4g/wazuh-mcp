"""M4b write tool handlers — confirm/RBAC/allowlist/run_as contracts."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from pydantic import ValidationError

from wazuh_mcp.auth.session import Session
from wazuh_mcp.tools.write import (
    AddAgentToGroupArgs,
    CreateRuleArgs,
    IsolateAgentArgs,
    RemoveAgentFromGroupArgs,
    RestartAgentArgs,
    RunActiveResponseArgs,
    UpdateRuleArgs,
    add_agent_to_group,
    create_rule,
    isolate_agent,
    remove_agent_from_group,
    restart_agent,
    run_active_response,
    update_rule,
)
from wazuh_mcp.wazuh.errors import WazuhError
from wazuh_mcp.wazuh.rule_render import RuleDefinition


def _session() -> Session:
    return Session(
        user_id="u",
        tenant_id="t",
        rbac_role="admin",
        auth_method="config",
        wazuh_user="alice",
    )


@pytest.fixture
def server_api():
    api = AsyncMock()
    api.isolate_agent = AsyncMock(return_value={"data": {"affected_items": ["003"]}})
    api.restart_agent = AsyncMock(return_value={"data": {"affected_items": ["003"]}})
    api.add_agent_to_group = AsyncMock(return_value={"data": {"affected_items": ["003"]}})
    api.remove_agent_from_group = AsyncMock(return_value={"data": {"affected_items": ["003"]}})
    api.upload_rule_file = AsyncMock(
        return_value={"data": {"affected_items": ["wazuh-mcp-100100.xml"]}}
    )
    api.run_active_response = AsyncMock(return_value={"data": {"affected_items": ["003"]}})
    return api


# --- module surface ---


def test_module_exports_all_seven_handlers_and_args() -> None:
    # Smoke test: every name the plan pins must be importable and callable/class.
    assert callable(isolate_agent)
    assert callable(restart_agent)
    assert callable(add_agent_to_group)
    assert callable(remove_agent_from_group)
    assert callable(create_rule)
    assert callable(update_rule)
    assert callable(run_active_response)
    for cls in (
        IsolateAgentArgs,
        RestartAgentArgs,
        AddAgentToGroupArgs,
        RemoveAgentFromGroupArgs,
        CreateRuleArgs,
        UpdateRuleArgs,
        RunActiveResponseArgs,
    ):
        assert isinstance(cls, type)


# --- confirm contract (all tools) ---


def test_confirm_must_be_literal_true_on_isolate() -> None:
    # confirm=False is a type-check failure at Args parse (Literal[True]).
    with pytest.raises(ValidationError):
        IsolateAgentArgs(agent_ids=["003"], confirm=False)


def test_confirm_missing_on_isolate() -> None:
    with pytest.raises(ValidationError):
        IsolateAgentArgs(agent_ids=["003"])  # ty: ignore[missing-argument]


# --- run_as passthrough ---


@pytest.mark.asyncio
async def test_isolate_agent_passes_run_as(server_api) -> None:
    args = IsolateAgentArgs(agent_ids=["003"], confirm=True)
    await isolate_agent(args=args, session=_session(), server_api=server_api)
    server_api.isolate_agent.assert_awaited_once_with(agent_ids=["003"], run_as="alice")


@pytest.mark.asyncio
async def test_run_active_response_rejects_when_allowlist_empty(server_api) -> None:
    args = RunActiveResponseArgs(
        agent_ids=["003"], command_name="block-ip", custom_args=None, confirm=True
    )
    session = _session()
    with pytest.raises(WazuhError) as exc:
        await run_active_response(
            args=args, session=session, server_api=server_api, ar_allowlist=[]
        )
    assert exc.value.code == "forbidden"
    server_api.run_active_response.assert_not_awaited()


@pytest.mark.asyncio
async def test_run_active_response_rejects_command_not_in_allowlist(server_api) -> None:
    args = RunActiveResponseArgs(
        agent_ids=["003"], command_name="dangerous", custom_args=None, confirm=True
    )
    with pytest.raises(WazuhError) as exc:
        await run_active_response(
            args=args,
            session=_session(),
            server_api=server_api,
            ar_allowlist=["block-ip", "disable-account"],
        )
    assert exc.value.code == "forbidden"


@pytest.mark.asyncio
async def test_run_active_response_allows_command_in_allowlist(server_api) -> None:
    args = RunActiveResponseArgs(
        agent_ids=["003"],
        command_name="block-ip",
        custom_args={"srcip": "10.0.0.1"},
        confirm=True,
    )
    result = await run_active_response(
        args=args,
        session=_session(),
        server_api=server_api,
        ar_allowlist=["block-ip", "disable-account"],
    )
    assert result.ok is True
    server_api.run_active_response.assert_awaited_once_with(
        agent_ids=["003"],
        command="block-ip",
        custom_args={"srcip": "10.0.0.1"},
        run_as="alice",
    )


# --- rule handlers ---


@pytest.mark.asyncio
async def test_create_rule_uploads_rendered_xml(server_api) -> None:
    rd = RuleDefinition(id=100_100, level=5, description="Failed SSH login")
    args = CreateRuleArgs(rule=rd, confirm=True)
    result = await create_rule(args=args, session=_session(), server_api=server_api)
    assert result.ok is True
    server_api.upload_rule_file.assert_awaited_once()
    call = server_api.upload_rule_file.call_args
    assert call.kwargs["filename"] == "wazuh-mcp-100100.xml"
    # Payload is bytes of rendered XML; must contain our rule id.
    assert b'id="100100"' in call.kwargs["xml"]
    assert call.kwargs["run_as"] == "alice"


@pytest.mark.asyncio
async def test_update_rule_uploads_rendered_xml(server_api) -> None:
    rd = RuleDefinition(id=100_100, level=5, description="Failed SSH login")
    args = UpdateRuleArgs(rule_id=100_100, rule=rd, confirm=True)
    result = await update_rule(args=args, session=_session(), server_api=server_api)
    assert result.ok is True
    server_api.upload_rule_file.assert_awaited_once()


@pytest.mark.asyncio
async def test_update_rule_id_mismatch_rejected() -> None:
    rd = RuleDefinition(id=100_100, level=5, description="d")
    with pytest.raises(ValidationError, match="rule_id"):
        UpdateRuleArgs(rule_id=100_200, rule=rd, confirm=True)


# --- result models expose consistent shape ---


@pytest.mark.asyncio
async def test_result_contains_timestamp_and_affected_ids(server_api) -> None:
    args = RestartAgentArgs(agent_id="003", confirm=True)
    result = await restart_agent(args=args, session=_session(), server_api=server_api)
    assert result.ok is True
    assert result.affected_agents == ["003"]
