"""hunt.* tools — constrained-grammar hunting + IOC pivot preset.

Security posture:
- Field names come from a fixed FIELD_ALLOWLIST. Anything off the list
  raises ValidationError before a DSL dict is constructed.
- Ops come from OP_ALLOWLIST. No `script`, `runtime_mappings`,
  `script_score`, `painless`, or raw `bool.should` can be reached by
  construction - those aren't ops.
- Flat must + must_not only (no nested bool).
- Clause count capped at 20; in-op value-list capped at 100; prefix op
  values require >=3 chars to prevent full-index scans.
"""

from __future__ import annotations

import time
from typing import Annotated, Any, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import AuditEmitter
from wazuh_mcp.wazuh.errors import WazuhError
from wazuh_mcp.wazuh.indexer import IndexerClient
from wazuh_mcp.wazuh.models import Alert
from wazuh_mcp.wazuh.query import (
    DEFAULT_ALERT_FIELDS,
    DEFAULT_ALERT_SIZE,
    MAX_ALERT_SIZE,
    TERMINATE_AFTER,
    _validate_time_range,
)

FIELD_ALLOWLIST: Final[frozenset[str]] = frozenset(
    [
        "agent.id",
        "agent.name",
        "agent.ip",
        "rule.id",
        "rule.level",
        "rule.groups",
        "rule.mitre.id",
        "rule.mitre.tactic",
        "location",
        "decoder.name",
        "full_log",
        "data.srcip",
        "data.dstip",
        "data.srcuser",
        "data.dstuser",
        "data.srcport",
        "data.dstport",
        "data.url",
        "data.hostname",
        "syscheck.path",
        "syscheck.sha256_after",
        "syscheck.md5_after",
        "timestamp",
        "@timestamp",
    ]
)

OP_ALLOWLIST: Final[tuple[str, ...]] = (
    "eq",
    "ne",
    "gt",
    "gte",
    "lt",
    "lte",
    "in",
    "exists",
    "prefix",
)

_MAX_CLAUSES: Final[int] = 20
_MAX_IN_LENGTH: Final[int] = 100
_MIN_PREFIX_LENGTH: Final[int] = 3


class HuntClause(BaseModel):
    model_config = ConfigDict(extra="forbid")

    field: str
    op: Literal["eq", "ne", "gt", "gte", "lt", "lte", "in", "exists", "prefix"]
    value: str | int | float | bool | list[str | int | float]

    @field_validator("field")
    @classmethod
    def _field_in_allowlist(cls, v: str) -> str:
        if v not in FIELD_ALLOWLIST:
            raise ValueError(f"field not allowed: {v!r}")
        return v

    @model_validator(mode="after")
    def _op_value_consistency(self) -> HuntClause:
        if self.op == "in":
            if not isinstance(self.value, list):
                raise ValueError("op='in' requires a list value")
            if len(self.value) == 0 or len(self.value) > _MAX_IN_LENGTH:
                raise ValueError(
                    f"'in' value must have 1..{_MAX_IN_LENGTH} items"
                )
        elif self.op == "exists":
            if self.value is not True:
                raise ValueError("op='exists' requires value=true")
        elif self.op == "prefix":
            if not isinstance(self.value, str) or len(self.value) < _MIN_PREFIX_LENGTH:
                raise ValueError(
                    f"op='prefix' requires a string of at least {_MIN_PREFIX_LENGTH} chars"
                )
        else:
            if isinstance(self.value, list):
                raise ValueError(f"op={self.op!r} does not accept a list value")
        return self


class HuntQueryArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    time_range: Annotated[str, Field(description="<int><m|h|d>, up to 30d")]
    must: list[HuntClause]
    must_not: list[HuntClause] = Field(default_factory=list)
    size: Annotated[int, Field(ge=1, le=MAX_ALERT_SIZE)] = DEFAULT_ALERT_SIZE
    cursor: list[Any] | None = None

    @field_validator("time_range")
    @classmethod
    def _check_time_range(cls, v: str) -> str:
        _validate_time_range(v)
        return v

    @model_validator(mode="after")
    def _clause_cap(self) -> HuntQueryArgs:
        if len(self.must) + len(self.must_not) > _MAX_CLAUSES:
            raise ValueError(f"total clause count must be <= {_MAX_CLAUSES}")
        if len(self.must) == 0 and len(self.must_not) == 0:
            raise ValueError("at least one clause required")
        return self


class HuntQueryResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    alerts: list[Alert]
    total: int
    next_cursor: list[Any] | None
    truncated: bool


def _render_clause(c: HuntClause) -> dict[str, Any]:
    """Render one HuntClause into a validated OpenSearch DSL fragment.

    Only produces term/terms/range/exists/prefix dicts. Never emits
    script/runtime_mappings/nested bool.
    """
    if c.op == "eq":
        return {"term": {c.field: c.value}}
    if c.op == "ne":
        # `ne` flattens to must_not at the outer builder level.
        return {"term": {c.field: c.value}}
    if c.op == "in":
        return {"terms": {c.field: c.value}}
    if c.op == "exists":
        return {"exists": {"field": c.field}}
    if c.op == "prefix":
        return {"prefix": {c.field: c.value}}
    range_key = {"gt": "gt", "gte": "gte", "lt": "lt", "lte": "lte"}[c.op]
    return {"range": {c.field: {range_key: c.value}}}


def _build_hunt_dsl(args: HuntQueryArgs) -> dict[str, Any]:
    must: list[dict[str, Any]] = [
        {"range": {"@timestamp": {"gte": f"now-{args.time_range}"}}}
    ]
    must_not: list[dict[str, Any]] = []

    for c in args.must:
        if c.op == "ne":
            must_not.append(_render_clause(c))
        else:
            must.append(_render_clause(c))
    for c in args.must_not:
        if c.op == "ne":
            must.append(_render_clause(c))
        else:
            must_not.append(_render_clause(c))

    bool_block: dict[str, Any] = {"must": must}
    if must_not:
        bool_block["must_not"] = must_not

    query: dict[str, Any] = {
        "query": {"bool": bool_block},
        "size": args.size,
        "sort": [{"@timestamp": "desc"}],
        "_source": DEFAULT_ALERT_FIELDS,
        "terminate_after": TERMINATE_AFTER,
    }
    if args.cursor:
        query["search_after"] = args.cursor
    return query


async def hunt_query(
    *,
    args: HuntQueryArgs,
    session: Session,
    indexer: IndexerClient,
    audit: AuditEmitter,
) -> HuntQueryResult:
    """Tool name: hunt.hunt_query."""
    started = time.monotonic()
    arg_dict = args.model_dump(exclude_none=True)

    try:
        query = _build_hunt_dsl(args)
        body = await indexer.search(index="wazuh-alerts-*", query=query)
    except WazuhError as e:
        audit.emit(
            session=session,
            tool="hunt.hunt_query",
            args=arg_dict,
            outcome="error",
            result_count=0,
            duration_ms=int((time.monotonic() - started) * 1000),
            error_code=e.code,
        )
        raise

    raw_hits = body.get("hits", {}).get("hits", [])
    total_block = body.get("hits", {}).get("total", {})
    total = (
        total_block.get("value", 0)
        if isinstance(total_block, dict)
        else int(total_block)
    )
    alerts = [Alert.from_hit(h) for h in raw_hits]
    next_cursor: list[Any] | None = None
    if raw_hits and "sort" in raw_hits[-1]:
        next_cursor = raw_hits[-1]["sort"]
    truncated = len(alerts) == args.size

    audit.emit(
        session=session,
        tool="hunt.hunt_query",
        args=arg_dict,
        outcome="ok",
        result_count=len(alerts),
        duration_ms=int((time.monotonic() - started) * 1000),
    )
    return HuntQueryResult(
        alerts=alerts,
        total=total,
        next_cursor=next_cursor,
        truncated=truncated,
    )


# ---- pivot_by_ioc ----

class PivotByIocArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["hash", "ip", "user", "domain"]
    value: Annotated[str, Field(min_length=1, max_length=256)]
    time_range: str = "24h"
    size: Annotated[int, Field(ge=1, le=MAX_ALERT_SIZE)] = DEFAULT_ALERT_SIZE
    cursor: list[Any] | None = None


_PIVOT_FIELDS: Final[dict[str, tuple[str, ...]]] = {
    "hash": ("syscheck.sha256_after", "syscheck.md5_after"),
    "ip": ("data.srcip", "data.dstip"),
    "user": ("data.srcuser", "data.dstuser"),
    "domain": ("data.hostname", "data.url"),
}


async def pivot_by_ioc(
    *,
    args: PivotByIocArgs,
    session: Session,
    indexer: IndexerClient,
    audit: AuditEmitter,
) -> HuntQueryResult:
    """Tool name: hunt.pivot_by_ioc - preset over hunt_query.

    Runs against the FIRST field in the preset tuple. The second field
    (if any) must be probed via a follow-up call; `should`/OR is
    deliberately out of the hunt grammar.
    """
    fields = _PIVOT_FIELDS[args.kind]
    primary_field = fields[0]
    hq_args = HuntQueryArgs(
        time_range=args.time_range,
        must=[HuntClause(field=primary_field, op="eq", value=args.value)],
        size=args.size,
        cursor=args.cursor,
    )
    result = await hunt_query(
        args=hq_args,
        session=session,
        indexer=indexer,
        audit=audit,
    )
    audit.emit(
        session=session,
        tool="hunt.pivot_by_ioc",
        args=args.model_dump(exclude_none=True),
        outcome="ok",
        result_count=len(result.alerts),
        duration_ms=0,
    )
    return result
