"""Multi-tenant per-call policy resolution (M4c T4).

Pins the headline M4c invariant: a single resolver closure returns
the right allowlist for whatever tenant_id the session carries, on
every call. Closure does not capture tenant_a's config and serve it
to a tenant_b session.
"""

from __future__ import annotations

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import MultiSinkAuditEmitter
from wazuh_mcp.rbac.resolver import (
    make_ar_allowlist,
    make_rbac_policy,
    make_write_allowlist,
)
from wazuh_mcp.tenancy.config import TenantConfig


class _DictRegistry:
    """Minimal multi-tenant registry impl for tests."""

    def __init__(self, tenants: dict[str, TenantConfig]) -> None:
        self._tenants = dict(tenants)

    def get(self, tenant_id: str) -> TenantConfig:
        if tenant_id not in self._tenants:
            raise KeyError(f"unknown tenant: {tenant_id}")
        return self._tenants[tenant_id]


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


def _session(tenant_id: str, *, role: str = "admin") -> Session:
    return Session(
        user_id=f"user-{tenant_id}",
        tenant_id=tenant_id,
        rbac_role=role,
        auth_method="oauth",
        wazuh_user=None,
    )


def _two_tenant_registry() -> _DictRegistry:
    return _DictRegistry(
        {
            "tenant_a": _cfg(
                "tenant_a",
                role_tool_allowlist={"admin": ["alerts.*"], "responder": ["write.isolate_agent"]},
                write_allowlist=["write.isolate_agent"],
                active_response_allowlist=["isolate"],
            ),
            "tenant_b": _cfg(
                "tenant_b",
                role_tool_allowlist={"admin": ["agents.*"], "soc": ["alerts.search_alerts"]},
                write_allowlist=None,  # registration-default (no filter)
                active_response_allowlist=["restart_service"],
            ),
        }
    )


def test_rbac_policy_resolves_per_tenant_per_call() -> None:
    sink = _CapturingSink()
    emitter = MultiSinkAuditEmitter(sinks=[sink])
    policy = make_rbac_policy(_two_tenant_registry(), emitter)

    result_a = policy(_session("tenant_a"))
    assert result_a["admin"] == ["alerts.*"]
    assert result_a["responder"] == ["write.isolate_agent"]

    result_b = policy(_session("tenant_b"))
    assert result_b["admin"] == ["agents.*"]
    assert result_b["soc"] == ["alerts.search_alerts"]
    # tenant_b doesn't have a "responder" key
    assert "responder" not in result_b


def test_write_allowlist_resolves_per_tenant_per_call() -> None:
    sink = _CapturingSink()
    emitter = MultiSinkAuditEmitter(sinks=[sink])
    resolver = make_write_allowlist(_two_tenant_registry(), emitter)

    assert resolver(_session("tenant_a")) == ["write.isolate_agent"]
    assert resolver(_session("tenant_b")) is None  # tenant_b has no filter


def test_ar_allowlist_resolves_per_tenant_per_call() -> None:
    sink = _CapturingSink()
    emitter = MultiSinkAuditEmitter(sinks=[sink])
    resolver = make_ar_allowlist(_two_tenant_registry(), emitter)

    assert resolver(_session("tenant_a")) == ["isolate"]
    assert resolver(_session("tenant_b")) == ["restart_service"]


def test_resolution_does_not_capture_first_session_tenant() -> None:
    """Closure must not memoize the first call's tenant config."""
    sink = _CapturingSink()
    emitter = MultiSinkAuditEmitter(sinks=[sink])
    policy = make_rbac_policy(_two_tenant_registry(), emitter)

    # Call with tenant_a, then tenant_b, then tenant_a again — each call
    # must resolve afresh.
    a1 = policy(_session("tenant_a"))
    b1 = policy(_session("tenant_b"))
    a2 = policy(_session("tenant_a"))

    assert a1 == a2
    assert a1 != b1
    assert sink.events == []  # no audit events on the happy path


def test_unknown_tenant_amid_known_tenants_emits_one_audit_per_resolver() -> None:
    sink = _CapturingSink()
    emitter = MultiSinkAuditEmitter(sinks=[sink])
    registry = _two_tenant_registry()
    rbac = make_rbac_policy(registry, emitter)
    write = make_write_allowlist(registry, emitter)
    ar = make_ar_allowlist(registry, emitter)

    sess = _session("tenant_phantom")
    assert rbac(sess) == {}
    assert write(sess) == []
    assert ar(sess) == []

    # Three independent resolver calls → three audit events on the
    # unknown-tenant path. No deduplication (per spec §5.1).
    assert len(sink.events) == 3
    for event in sink.events:
        assert event["tool"] == "<rbac.resolve>"
        assert event["tenant"] == "tenant_phantom"
        assert event["error_reason"] == "tenant_not_registered"
