"""Unit tests for hunt.hunt_query and hunt.pivot_by_ioc."""

import io

import pytest

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import AuditEmitter
from wazuh_mcp.secrets.value import SecretValue
from wazuh_mcp.tools.hunt import (
    HuntClause,
    HuntQueryArgs,
    PivotByIocArgs,
    _build_hunt_dsl,
    pivot_by_ioc,
)
from wazuh_mcp.wazuh.indexer import IndexerClient


@pytest.fixture
def session() -> Session:
    return Session(
        user_id="u",
        tenant_id="t",
        rbac_role="soc_analyst",
        auth_method="oauth",
    )


@pytest.fixture
def audit() -> AuditEmitter:
    return AuditEmitter(stream=io.StringIO())


@pytest.fixture
async def indexer(httpx_mock):
    client = IndexerClient(
        base_url="https://indexer.example",
        user=SecretValue("admin"),
        password=SecretValue("admin"),
        verify_tls=False,
    )
    try:
        yield client
    finally:
        await client.aclose()


def test_clause_rejects_field_off_allowlist():
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        HuntClause(field="vulnerability.id", op="eq", value="CVE-2024-1234")


def test_clause_rejects_prefix_too_short():
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        HuntClause(field="data.srcip", op="prefix", value="10")


def test_clause_rejects_in_too_large():
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        HuntClause(field="rule.id", op="in", value=["x"] * 101)


def test_hunt_args_enforces_clause_cap():
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        HuntQueryArgs(
            time_range="24h",
            must=[HuntClause(field="rule.id", op="eq", value="1")] * 21,
        )


def test_hunt_args_requires_at_least_one_clause():
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        HuntQueryArgs(time_range="24h", must=[])


def test_build_hunt_dsl_has_no_dangerous_keys():
    import json

    args = HuntQueryArgs(
        time_range="24h",
        must=[
            HuntClause(field="data.srcip", op="eq", value="10.0.0.5"),
            HuntClause(field="rule.level", op="gte", value=10),
        ],
        must_not=[HuntClause(field="agent.id", op="eq", value="000")],
    )
    q = _build_hunt_dsl(args)
    # Walk the structure and collect all dict keys; assert none are dangerous.
    # Substring search on str(q) gives false positives (e.g. "description"
    # contains "script") so we check keys semantically.
    keys: set[str] = set()

    def _collect(node: object) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                keys.add(k)
                _collect(v)
        elif isinstance(node, list):
            for item in node:
                _collect(item)

    _collect(q)
    for dangerous in ("script", "runtime_mappings", "script_score", "painless"):
        assert dangerous not in keys
    # And the query body must not contain those substrings either
    # (defence-in-depth: catches string values that reference them).
    body_without_source = dict(q)
    body_without_source.pop("_source", None)
    serialised = json.dumps(body_without_source)
    for dangerous in ("script", "runtime_mappings", "script_score", "painless"):
        assert dangerous not in serialised


def test_build_hunt_dsl_flattens_ne_to_must_not():
    args = HuntQueryArgs(
        time_range="24h",
        must=[HuntClause(field="rule.id", op="ne", value="100")],
    )
    q = _build_hunt_dsl(args)
    bool_block = q["query"]["bool"]
    assert {"term": {"rule.id": "100"}} in bool_block.get("must_not", [])


@pytest.mark.asyncio
async def test_pivot_by_ioc_hash_uses_sha256_field(session, audit, indexer, httpx_mock):
    httpx_mock.add_response(
        url="https://indexer.example/wazuh-alerts-*/_search",
        method="POST",
        json={"hits": {"total": {"value": 0}, "hits": []}},
    )
    result = await pivot_by_ioc(
        args=PivotByIocArgs(kind="hash", value="abc123def456", time_range="24h"),
        session=session,
        indexer=indexer,
        audit=audit,
    )
    assert result.total == 0

    req = httpx_mock.get_requests()[0]
    assert "sha256_after" in req.content.decode()
