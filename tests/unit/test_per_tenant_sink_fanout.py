"""Per-tenant sink fan-out routing (M4d T6).

Pins:
  * emit(session_a) fans out to globals + per_tenant_sinks[tenant_a]
  * NOT to per_tenant_sinks[tenant_b]
  * Unknown tenant routes to globals only
  * global_sinks=None defaults to [StderrSink()]
  * Same-config sinks for two tenants are distinct instances
"""

from __future__ import annotations

from typing import Any

import pytest

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import MultiSinkAuditEmitter


class _CapturingSink:
    """Minimal in-memory sink that records every event submitted."""

    def __init__(self, name: str = "capture") -> None:
        self.name = name
        self.events: list[dict[str, Any]] = []

    async def start(self) -> None: ...

    async def stop(self) -> None: ...

    def submit(self, event: dict[str, Any]) -> None:
        self.events.append(event)


def _session(tenant_id: str, *, user_id: str = "alice") -> Session:
    return Session(
        user_id=user_id,
        tenant_id=tenant_id,
        rbac_role="admin",
        auth_method="oauth",
        wazuh_user=None,
    )


def test_emit_routes_to_globals_plus_session_tenant_sinks() -> None:
    g = _CapturingSink("global")
    a = _CapturingSink("tenant_a")
    b = _CapturingSink("tenant_b")

    emitter = MultiSinkAuditEmitter(
        global_sinks=[g],
        per_tenant_sinks={"tenant_a": [a], "tenant_b": [b]},
    )

    emitter.emit(
        session=_session("tenant_a"),
        tool="alerts.search_alerts",
        args={},
        outcome="ok",
        result_count=10,
        duration_ms=42,
    )

    assert len(g.events) == 1
    assert len(a.events) == 1
    assert len(b.events) == 0
    assert g.events[0]["tenant"] == "tenant_a"


def test_emit_unknown_tenant_routes_to_globals_only() -> None:
    g = _CapturingSink("global")
    a = _CapturingSink("tenant_a")

    emitter = MultiSinkAuditEmitter(
        global_sinks=[g],
        per_tenant_sinks={"tenant_a": [a]},
    )

    emitter.emit(
        session=_session("tenant_phantom"),
        tool="<rbac.resolve>",
        args={},
        outcome="error",
        result_count=0,
        duration_ms=0,
        error_code="forbidden",
        error_reason="tenant_not_registered",
    )

    assert len(g.events) == 1
    assert len(a.events) == 0
    assert g.events[0]["error_reason"] == "tenant_not_registered"


def test_global_sinks_none_defaults_to_stderr() -> None:
    """The empty constructor preserves the M4a default behavior."""
    from wazuh_mcp.observability.sinks.stream import StderrSink

    emitter = MultiSinkAuditEmitter()
    assert len(emitter.global_sinks) == 1
    assert isinstance(emitter.global_sinks[0], StderrSink)


def test_empty_per_tenant_sinks_means_globals_only() -> None:
    g = _CapturingSink("global")
    emitter = MultiSinkAuditEmitter(global_sinks=[g], per_tenant_sinks={})

    emitter.emit(
        session=_session("tenant_a"),
        tool="alerts.search_alerts",
        args={},
        outcome="ok",
        result_count=1,
        duration_ms=5,
    )
    assert len(g.events) == 1


def test_two_tenants_with_same_sink_config_get_distinct_instances() -> None:
    """The dict structure is identity-keyed; passing the SAME sink instance
    for two tenants would be wrong (both tenants share that sink). Operators
    should pass distinct instances. Verify by constructing two identical-
    looking sinks and confirming routing keeps them separate."""
    g = _CapturingSink("global")
    a = _CapturingSink("tenant_a")
    b = _CapturingSink("tenant_b")  # same class, different instance

    emitter = MultiSinkAuditEmitter(
        global_sinks=[g],
        per_tenant_sinks={"tenant_a": [a], "tenant_b": [b]},
    )

    emitter.emit(
        session=_session("tenant_a"),
        tool="t1",
        args={},
        outcome="ok",
        result_count=1,
        duration_ms=1,
    )
    emitter.emit(
        session=_session("tenant_b"),
        tool="t2",
        args={},
        outcome="ok",
        result_count=1,
        duration_ms=1,
    )

    assert len(a.events) == 1
    assert len(b.events) == 1
    assert a.events[0]["tool"] == "t1"
    assert b.events[0]["tool"] == "t2"


def test_emit_preserves_error_reason_kwarg_from_m4c() -> None:
    """error_reason kwarg from M4c T1 must still flow through the new emit shape."""
    g = _CapturingSink("global")
    emitter = MultiSinkAuditEmitter(global_sinks=[g])

    emitter.emit(
        session=_session("tenant_a"),
        tool="<rbac.resolve>",
        args={},
        outcome="error",
        result_count=0,
        duration_ms=0,
        error_code="forbidden",
        error_reason="tenant_not_registered",
    )
    assert g.events[0]["error_reason"] == "tenant_not_registered"


# ---------- _build_per_tenant_sinks helper ----------


def test_build_per_tenant_sinks_returns_dict_keyed_by_tenant_id(tmp_path) -> None:
    from wazuh_mcp.server import _build_per_tenant_sinks
    from wazuh_mcp.tenancy.config import TenantConfig
    from wazuh_mcp.tenancy.m4_config import StderrSinkConfig

    t_a = TenantConfig(
        tenant_id="tenant_a",
        indexer_url="https://indexer.example.com:9200",
        verify_tls=False,
        default_rbac_role="readonly",
        oauth_issuer="https://issuer-a.example.com",
        oauth_audience="aud",
        audit_sinks=[StderrSinkConfig()],
    )
    t_b = TenantConfig(
        tenant_id="tenant_b",
        indexer_url="https://indexer.example.com:9200",
        verify_tls=False,
        default_rbac_role="readonly",
        oauth_issuer="https://issuer-b.example.com",
        oauth_audience="aud",
        audit_sinks=[StderrSinkConfig()],
    )
    result = _build_per_tenant_sinks([t_a, t_b], indexer_pool=None)
    assert set(result.keys()) == {"tenant_a", "tenant_b"}
    assert len(result["tenant_a"]) == 1
    assert len(result["tenant_b"]) == 1


def test_build_per_tenant_sinks_raises_with_tenant_id_in_message() -> None:
    """If a tenant's _build_sinks fails, error message names the tenant."""
    from wazuh_mcp.server import _build_per_tenant_sinks
    from wazuh_mcp.tenancy.config import TenantConfig
    from wazuh_mcp.tenancy.m4_config import WazuhIndexerSinkConfig

    # wazuh_indexer sink in stdio mode (indexer_pool=None) raises.
    t_bad = TenantConfig(
        tenant_id="tenant_bad",
        indexer_url="https://indexer.example.com:9200",
        verify_tls=False,
        default_rbac_role="readonly",
        oauth_issuer="https://issuer-bad.example.com",
        oauth_audience="aud",
        audit_sinks=[WazuhIndexerSinkConfig(index_prefix="bad-audit")],
    )
    with pytest.raises(RuntimeError, match="tenant 'tenant_bad' failed to build"):
        _build_per_tenant_sinks([t_bad], indexer_pool=None)
