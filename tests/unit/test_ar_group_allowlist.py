"""Per-tenant agent_group_allowlist resolver tests (M5b T-A1)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from wazuh_mcp.auth.session import Session
from wazuh_mcp.rbac.resolver import make_ar_group_allowlist
from wazuh_mcp.tenancy.config import TenantConfig
from wazuh_mcp.tenancy.registry import SingleTenantRegistry


def _tenant(tenant_id: str = "t1", group_allow: list[str] | None = None) -> TenantConfig:
    return TenantConfig(
        tenant_id=tenant_id,
        indexer_url="https://idx:9200",  # ty: ignore[invalid-argument-type]
        default_rbac_role="admin",
        agent_group_allowlist=group_allow or [],
    )


def test_default_agent_group_allowlist_is_empty() -> None:
    t = _tenant()
    assert t.agent_group_allowlist == []


def test_valid_group_name_accepted() -> None:
    t = _tenant(group_allow=["test-group", "soc_responders.tier1"])
    assert t.agent_group_allowlist == ["test-group", "soc_responders.tier1"]


def test_invalid_group_name_with_special_char_rejected() -> None:
    with pytest.raises(ValidationError) as exc_info:
        _tenant(group_allow=["bad/name"])
    assert "invalid agent group name" in str(exc_info.value)


def test_empty_group_name_rejected() -> None:
    with pytest.raises(ValidationError):
        _tenant(group_allow=[""])


def test_group_allowlist_overflow_rejected() -> None:
    too_many = [f"g{i}" for i in range(51)]
    with pytest.raises(ValidationError) as exc_info:
        _tenant(group_allow=too_many)
    assert "exceeds max 50" in str(exc_info.value)


def test_resolver_returns_tenant_allowlist() -> None:
    t = _tenant(tenant_id="t1", group_allow=["soc-tier1", "soc-tier2"])
    registry = SingleTenantRegistry(t)
    audit_calls: list[dict] = []

    class _CapturingEmitter:
        def emit(self, **kwargs):
            audit_calls.append(kwargs)

    resolve = make_ar_group_allowlist(registry, _CapturingEmitter())  # ty: ignore[invalid-argument-type]
    session = Session(
        user_id="u1",
        tenant_id="t1",
        rbac_role="admin",
        auth_method="oauth",
        wazuh_user="alice",
    )
    assert resolve(session) == ["soc-tier1", "soc-tier2"]
    assert audit_calls == []  # happy path: no audit


def test_resolver_unknown_tenant_emits_audit_and_returns_empty() -> None:
    t = _tenant(tenant_id="t1")
    registry = SingleTenantRegistry(t)
    audit_calls: list[dict] = []

    class _CapturingEmitter:
        def emit(self, **kwargs):
            audit_calls.append(kwargs)

    resolve = make_ar_group_allowlist(registry, _CapturingEmitter())  # ty: ignore[invalid-argument-type]
    session = Session(
        user_id="u1",
        tenant_id="phantom-tenant",
        rbac_role="admin",
        auth_method="oauth",
        wazuh_user=None,
    )
    assert resolve(session) == []
    assert len(audit_calls) == 1
    assert audit_calls[0]["tool"] == "<rbac.resolve>"
    assert audit_calls[0]["error_code"] == "forbidden"
    assert audit_calls[0]["error_reason"] == "tenant_not_registered"
    assert audit_calls[0]["outcome"] == "error"
