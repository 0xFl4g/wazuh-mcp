"""rbac/resolver.py — per-tenant policy resolution factories (M4c T3, Tier-A)."""

from __future__ import annotations

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import MultiSinkAuditEmitter
from wazuh_mcp.rbac.resolver import (
    make_ar_allowlist,
    make_rbac_policy,
    make_write_allowlist,
)
from wazuh_mcp.tenancy.config import TenantConfig
from wazuh_mcp.tenancy.registry import SingleTenantRegistry


class _CapturingSink:
    def __init__(self) -> None:
        self.events: list[dict] = []

    async def start(self) -> None: ...

    async def stop(self) -> None: ...

    def submit(self, event: dict) -> None:
        self.events.append(event)


def _cfg(
    tenant_id: str,
    *,
    role_tool_allowlist: dict[str, list[str]] | None = None,
    write_allowlist: list[str] | None = None,
    active_response_allowlist: list[str] | None = None,
) -> TenantConfig:
    return TenantConfig(
        tenant_id=tenant_id,
        indexer_url="https://indexer.example.com:9200",
        verify_tls=False,
        default_rbac_role="readonly",
        oauth_issuer=f"https://issuer-{tenant_id}.example.com",
        oauth_audience="aud",
        role_tool_allowlist=role_tool_allowlist,
        write_allowlist=write_allowlist,
        active_response_allowlist=active_response_allowlist or [],
    )


def _session(tenant_id: str = "tenant_a", role: str = "admin") -> Session:
    return Session(
        user_id="alice",
        tenant_id=tenant_id,
        rbac_role=role,
        auth_method="oauth",
        wazuh_user="alice-wazuh",
    )


# ---------- make_rbac_policy ----------


def test_rbac_policy_returns_default_when_override_absent() -> None:
    sink = _CapturingSink()
    emitter = MultiSinkAuditEmitter(sinks=[sink])
    registry = SingleTenantRegistry(_cfg("tenant_a", role_tool_allowlist=None))
    policy = make_rbac_policy(registry, emitter)
    result = policy(_session("tenant_a"))
    # DEFAULT_ROLE_TOOL_ALLOWLIST contains admin/analyst/readonly.
    assert "admin" in result
    assert result["admin"] == ["*"]
    assert sink.events == []


def test_rbac_policy_applies_tenant_override() -> None:
    sink = _CapturingSink()
    emitter = MultiSinkAuditEmitter(sinks=[sink])
    override = {"admin": ["alerts.*"], "responder": ["write.isolate_agent"]}
    registry = SingleTenantRegistry(_cfg("tenant_a", role_tool_allowlist=override))
    policy = make_rbac_policy(registry, emitter)
    result = policy(_session("tenant_a"))
    assert result["admin"] == ["alerts.*"]
    assert result["responder"] == ["write.isolate_agent"]
    # readonly not in override, fall through to default
    assert "readonly" in result


def test_rbac_policy_unknown_tenant_returns_empty_dict() -> None:
    sink = _CapturingSink()
    emitter = MultiSinkAuditEmitter(sinks=[sink])
    registry = SingleTenantRegistry(_cfg("tenant_a"))
    policy = make_rbac_policy(registry, emitter)
    result = policy(_session("tenant_phantom"))
    assert result == {}


def test_rbac_policy_unknown_tenant_emits_audit() -> None:
    sink = _CapturingSink()
    emitter = MultiSinkAuditEmitter(sinks=[sink])
    registry = SingleTenantRegistry(_cfg("tenant_a"))
    policy = make_rbac_policy(registry, emitter)
    policy(_session("tenant_phantom"))
    assert len(sink.events) == 1
    event = sink.events[0]
    assert event["tool"] == "<rbac.resolve>"
    assert event["tenant"] == "tenant_phantom"
    assert event["outcome"] == "error"
    assert event["error_code"] == "forbidden"
    assert event["error_reason"] == "tenant_not_registered"


# ---------- make_write_allowlist ----------


def test_write_allowlist_returns_none_when_unset() -> None:
    sink = _CapturingSink()
    emitter = MultiSinkAuditEmitter(sinks=[sink])
    registry = SingleTenantRegistry(_cfg("tenant_a", write_allowlist=None))
    resolver = make_write_allowlist(registry, emitter)
    assert resolver(_session("tenant_a")) is None


def test_write_allowlist_returns_empty_list() -> None:
    sink = _CapturingSink()
    emitter = MultiSinkAuditEmitter(sinks=[sink])
    registry = SingleTenantRegistry(_cfg("tenant_a", write_allowlist=[]))
    resolver = make_write_allowlist(registry, emitter)
    assert resolver(_session("tenant_a")) == []


def test_write_allowlist_returns_explicit_list() -> None:
    sink = _CapturingSink()
    emitter = MultiSinkAuditEmitter(sinks=[sink])
    registry = SingleTenantRegistry(_cfg("tenant_a", write_allowlist=["write.isolate_agent"]))
    resolver = make_write_allowlist(registry, emitter)
    assert resolver(_session("tenant_a")) == ["write.isolate_agent"]


def test_write_allowlist_unknown_tenant_returns_empty_list() -> None:
    sink = _CapturingSink()
    emitter = MultiSinkAuditEmitter(sinks=[sink])
    registry = SingleTenantRegistry(_cfg("tenant_a"))
    resolver = make_write_allowlist(registry, emitter)
    assert resolver(_session("tenant_phantom")) == []


def test_write_allowlist_unknown_tenant_emits_audit() -> None:
    sink = _CapturingSink()
    emitter = MultiSinkAuditEmitter(sinks=[sink])
    registry = SingleTenantRegistry(_cfg("tenant_a"))
    resolver = make_write_allowlist(registry, emitter)
    resolver(_session("tenant_phantom"))
    assert len(sink.events) == 1
    assert sink.events[0]["tool"] == "<rbac.resolve>"
    assert sink.events[0]["error_reason"] == "tenant_not_registered"


# ---------- make_ar_allowlist ----------


def test_ar_allowlist_returns_tenants_list() -> None:
    sink = _CapturingSink()
    emitter = MultiSinkAuditEmitter(sinks=[sink])
    registry = SingleTenantRegistry(
        _cfg("tenant_a", active_response_allowlist=["isolate", "kill_process"])
    )
    resolver = make_ar_allowlist(registry, emitter)
    assert resolver(_session("tenant_a")) == ["isolate", "kill_process"]


def test_ar_allowlist_returns_empty_for_default_config() -> None:
    sink = _CapturingSink()
    emitter = MultiSinkAuditEmitter(sinks=[sink])
    registry = SingleTenantRegistry(_cfg("tenant_a"))
    resolver = make_ar_allowlist(registry, emitter)
    assert resolver(_session("tenant_a")) == []


def test_ar_allowlist_unknown_tenant_returns_empty_list() -> None:
    sink = _CapturingSink()
    emitter = MultiSinkAuditEmitter(sinks=[sink])
    registry = SingleTenantRegistry(_cfg("tenant_a"))
    resolver = make_ar_allowlist(registry, emitter)
    assert resolver(_session("tenant_phantom")) == []


def test_ar_allowlist_unknown_tenant_emits_audit() -> None:
    sink = _CapturingSink()
    emitter = MultiSinkAuditEmitter(sinks=[sink])
    registry = SingleTenantRegistry(_cfg("tenant_a"))
    resolver = make_ar_allowlist(registry, emitter)
    resolver(_session("tenant_phantom"))
    assert len(sink.events) == 1
    assert sink.events[0]["tool"] == "<rbac.resolve>"
    assert sink.events[0]["error_reason"] == "tenant_not_registered"
