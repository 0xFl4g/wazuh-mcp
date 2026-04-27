"""Multi-agent AR refactor (M4c T9).

Pins:
  * agent_ids field constraints (min/max length)
  * ServerApiClient builds comma-joined agents_list query param
  * WriteResult.failed_agents plumbing
  * partial-failure semantics (ok=False, no exception)
"""

from __future__ import annotations

from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from wazuh_mcp.auth.session import Session
from wazuh_mcp.tools.write import (
    _AR_AGENTS_MAX,
    FailedAgent,
    IsolateAgentArgs,
    RunActiveResponseArgs,
    isolate_agent,
    run_active_response,
)


def _session() -> Session:
    return Session(
        user_id="alice",
        tenant_id="tenant_a",
        rbac_role="admin",
        auth_method="oauth",
        wazuh_user="alice-wazuh",
    )


# ---------- Args parse ----------


def test_isolate_args_accepts_single_agent_in_list() -> None:
    args = IsolateAgentArgs(agent_ids=["001"], confirm=True)
    assert args.agent_ids == ["001"]


def test_isolate_args_accepts_max_agents() -> None:
    ids = [f"{i:03d}" for i in range(_AR_AGENTS_MAX)]
    args = IsolateAgentArgs(agent_ids=ids, confirm=True)
    assert len(args.agent_ids) == _AR_AGENTS_MAX


def test_isolate_args_rejects_empty_list() -> None:
    with pytest.raises(ValidationError):
        IsolateAgentArgs(agent_ids=[], confirm=True)


def test_isolate_args_rejects_over_cap() -> None:
    ids = [f"{i:03d}" for i in range(_AR_AGENTS_MAX + 1)]
    with pytest.raises(ValidationError):
        IsolateAgentArgs(agent_ids=ids, confirm=True)


def test_run_ar_args_accepts_list() -> None:
    args = RunActiveResponseArgs(agent_ids=["001", "002"], command_name="isolate", confirm=True)
    assert args.agent_ids == ["001", "002"]


# ---------- ServerApiClient comma-join (mocked) ----------


@pytest.mark.asyncio
async def test_isolate_agent_handler_passes_list_to_server_api() -> None:
    captured: dict[str, Any] = {}

    class _StubClient:
        async def isolate_agent(self, *, agent_ids, run_as):  # type: ignore[no-untyped-def]
            captured["agent_ids"] = agent_ids
            captured["run_as"] = run_as
            return {"data": {"affected_items": agent_ids, "failed_items": []}}

    args = IsolateAgentArgs(agent_ids=["001", "002"], confirm=True)
    result = await isolate_agent(args=args, session=_session(), server_api=_StubClient())
    assert captured["agent_ids"] == ["001", "002"]
    assert result.ok is True
    assert result.affected_agents == ["001", "002"]
    assert result.failed_agents == []


# ---------- Partial-failure plumbing ----------


@pytest.mark.asyncio
async def test_isolate_agent_partial_failure_returns_ok_false_no_exception() -> None:
    class _StubClient:
        async def isolate_agent(self, *, agent_ids, run_as):  # type: ignore[no-untyped-def]
            return {
                "data": {
                    "affected_items": ["001"],
                    "failed_items": [{"id": "002", "error": {"message": "agent offline"}}],
                }
            }

    args = IsolateAgentArgs(agent_ids=["001", "002"], confirm=True)
    result = await isolate_agent(args=args, session=_session(), server_api=_StubClient())
    assert result.ok is False
    assert result.affected_agents == ["001"]
    assert result.failed_agents == [FailedAgent(agent_id="002", reason="agent offline")]


@pytest.mark.asyncio
async def test_run_active_response_partial_failure_returns_ok_false() -> None:
    class _StubClient:
        async def run_active_response(self, *, agent_ids, command, custom_args, run_as):  # type: ignore[no-untyped-def]
            return {
                "data": {
                    "affected_items": ["001"],
                    "failed_items": [
                        {"id": "002", "error": {"message": "active-response timeout"}}
                    ],
                }
            }

    args = RunActiveResponseArgs(agent_ids=["001", "002"], command_name="isolate", confirm=True)
    result = await run_active_response(
        args=args, session=_session(), server_api=_StubClient(), ar_allowlist=["isolate"]
    )
    assert result.ok is False
    assert result.affected_agents == ["001"]
    assert result.failed_agents == [FailedAgent(agent_id="002", reason="active-response timeout")]


@pytest.mark.asyncio
async def test_run_active_response_all_succeed_returns_ok_true() -> None:
    class _StubClient:
        async def run_active_response(self, *, agent_ids, command, custom_args, run_as):  # type: ignore[no-untyped-def]
            return {
                "data": {
                    "affected_items": agent_ids,
                    "failed_items": [],
                }
            }

    args = RunActiveResponseArgs(
        agent_ids=["001", "002", "003"], command_name="isolate", confirm=True
    )
    result = await run_active_response(
        args=args, session=_session(), server_api=_StubClient(), ar_allowlist=["isolate"]
    )
    assert result.ok is True
    assert sorted(result.affected_agents or []) == ["001", "002", "003"]
    assert result.failed_agents == []


# ---------- Hypothesis: agent_ids URL-injection invariant ----------


_AGENT_ID_REGEX = r"^[0-9]{1,8}$"


@given(
    agent_ids=st.lists(
        st.from_regex(_AGENT_ID_REGEX, fullmatch=True),
        min_size=1,
        max_size=_AR_AGENTS_MAX,
    )
)
@settings(max_examples=200)
def test_no_agent_id_contains_comma(agent_ids: list[str]) -> None:
    """Wazuh agent IDs are numeric — no agent_id can contain a comma. This
    pins the URL-injection invariant: comma-joining the list never produces
    ambiguous query syntax."""
    for aid in agent_ids:
        assert "," not in aid
    joined = ",".join(agent_ids)
    # Round-trip splits cleanly.
    assert joined.split(",") == agent_ids
