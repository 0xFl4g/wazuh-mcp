"""M4b write tools — seven operations that mutate Wazuh state.

Contract every handler follows:
 1. Pydantic Args with `confirm: Literal[True]` (caller MUST set true).
 2. Handler takes (args, session, server_api, [ar_allowlist for run_active_response]).
 3. For run_active_response only: command_name must be in the tenant's
    active_response_allowlist.
 4. Call server_api.<verb>(..., run_as=session.wazuh_user).
 5. Return a structured Result model with ok/affected_agents/timestamp.

The pre-call audit (outcome=write.requested) and the post-call audit are
emitted by @instrumented_tool at the decorator layer. Handlers do NOT
emit audit directly.
"""
from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from wazuh_mcp.auth.session import Session
from wazuh_mcp.wazuh.errors import WazuhError
from wazuh_mcp.wazuh.rule_render import RuleDefinition, render_rule_xml

# ---------- Shared result shape ----------


class WriteResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    ok: bool
    affected_agents: list[str] | None = None
    affected_files: list[str] | None = None
    timestamp: datetime


def _extract_affected_ids(resp: dict[str, Any]) -> list[str]:
    """Wazuh returns {'data': {'affected_items': [...]}} for multi-item write
    endpoints. Read defensively."""
    data = resp.get("data", {})
    items = data.get("affected_items") or []
    return [str(i) for i in items]


# ---------- 1. isolate_agent ----------


class IsolateAgentArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    agent_id: Annotated[str, Field(min_length=1, max_length=16)]
    confirm: Annotated[
        Literal[True],
        Field(description=(
            "Must be set to true by a human user. Setting this from an "
            "automated agent without explicit human instruction violates "
            "the tool's safety contract and is recorded in the audit log."
        )),
    ]


async def isolate_agent(
    *,
    args: IsolateAgentArgs,
    session: Session,
    server_api: Any,
) -> WriteResult:
    resp = await server_api.isolate_agent(agent_id=args.agent_id, run_as=session.wazuh_user)
    return WriteResult(
        ok=True,
        affected_agents=_extract_affected_ids(resp),
        timestamp=datetime.now(UTC),
    )


# ---------- 2. restart_agent ----------


class RestartAgentArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    agent_id: Annotated[str, Field(min_length=1, max_length=16)]
    confirm: Literal[True]


async def restart_agent(
    *,
    args: RestartAgentArgs,
    session: Session,
    server_api: Any,
) -> WriteResult:
    resp = await server_api.restart_agent(agent_id=args.agent_id, run_as=session.wazuh_user)
    return WriteResult(
        ok=True,
        affected_agents=_extract_affected_ids(resp),
        timestamp=datetime.now(UTC),
    )


# ---------- 3. add_agent_to_group ----------


class AddAgentToGroupArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    agent_id: Annotated[str, Field(min_length=1, max_length=16)]
    group_id: Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9_-]+$")]
    confirm: Literal[True]


async def add_agent_to_group(
    *,
    args: AddAgentToGroupArgs,
    session: Session,
    server_api: Any,
) -> WriteResult:
    resp = await server_api.add_agent_to_group(
        agent_id=args.agent_id, group_id=args.group_id, run_as=session.wazuh_user
    )
    return WriteResult(
        ok=True,
        affected_agents=_extract_affected_ids(resp),
        timestamp=datetime.now(UTC),
    )


# ---------- 4. remove_agent_from_group ----------


class RemoveAgentFromGroupArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    agent_id: Annotated[str, Field(min_length=1, max_length=16)]
    group_id: Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9_-]+$")]
    confirm: Literal[True]


async def remove_agent_from_group(
    *,
    args: RemoveAgentFromGroupArgs,
    session: Session,
    server_api: Any,
) -> WriteResult:
    resp = await server_api.remove_agent_from_group(
        agent_id=args.agent_id, group_id=args.group_id, run_as=session.wazuh_user
    )
    return WriteResult(
        ok=True,
        affected_agents=_extract_affected_ids(resp),
        timestamp=datetime.now(UTC),
    )


# ---------- 5. create_rule ----------


class CreateRuleArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    rule: RuleDefinition
    confirm: Literal[True]


def _rule_filename(rule_id: int) -> str:
    return f"wazuh-mcp-{rule_id}.xml"


async def create_rule(
    *,
    args: CreateRuleArgs,
    session: Session,
    server_api: Any,
) -> WriteResult:
    xml_body = f'<group name="wazuh-mcp">{render_rule_xml(args.rule)}</group>'
    await server_api.upload_rule_file(
        filename=_rule_filename(args.rule.id),
        xml=xml_body.encode("utf-8"),
        run_as=session.wazuh_user,
    )
    return WriteResult(
        ok=True,
        affected_files=[_rule_filename(args.rule.id)],
        timestamp=datetime.now(UTC),
    )


# ---------- 6. update_rule ----------


class UpdateRuleArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    rule_id: Annotated[int, Field(ge=100_000, le=999_999)]
    rule: RuleDefinition
    confirm: Literal[True]

    @model_validator(mode="after")
    def _rule_id_matches(self) -> UpdateRuleArgs:
        if self.rule_id != self.rule.id:
            raise ValueError(
                f"rule_id ({self.rule_id}) must match rule.id ({self.rule.id})"
            )
        return self


async def update_rule(
    *,
    args: UpdateRuleArgs,
    session: Session,
    server_api: Any,
) -> WriteResult:
    xml_body = f'<group name="wazuh-mcp">{render_rule_xml(args.rule)}</group>'
    await server_api.upload_rule_file(
        filename=_rule_filename(args.rule_id),
        xml=xml_body.encode("utf-8"),
        run_as=session.wazuh_user,
    )
    return WriteResult(
        ok=True,
        affected_files=[_rule_filename(args.rule_id)],
        timestamp=datetime.now(UTC),
    )


# ---------- 7. run_active_response ----------


class RunActiveResponseArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    agent_id: Annotated[str, Field(min_length=1, max_length=16)]
    command_name: Annotated[str, Field(min_length=1, max_length=128)]
    custom_args: dict[str, Any] | None = None
    confirm: Literal[True]


async def run_active_response(
    *,
    args: RunActiveResponseArgs,
    session: Session,
    server_api: Any,
    ar_allowlist: Sequence[str],
) -> WriteResult:
    if args.command_name not in ar_allowlist:
        raise WazuhError(
            "forbidden",
            f"active-response command {args.command_name!r} not allowlisted for tenant",
            403,
        )
    resp = await server_api.run_active_response(
        agent_id=args.agent_id,
        command=args.command_name,
        custom_args=args.custom_args,
        run_as=session.wazuh_user,
    )
    return WriteResult(
        ok=True,
        affected_agents=_extract_affected_ids(resp),
        timestamp=datetime.now(UTC),
    )
