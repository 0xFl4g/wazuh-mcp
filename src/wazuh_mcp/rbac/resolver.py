"""Per-tenant policy resolution factories.

Each factory takes a ``TenantRegistry`` and returns a session-keyed callable.
On unknown tenant_id (registry KeyError), the resolver emits an audit event
with sentinel ``tool="<rbac.resolve>"`` and returns a fail-closed safe default
(empty role table for RBAC, empty allowlist for both write filters).

The factories are pure module-level functions; the closures they return are
the long-lived per-server callables wired into ``_register_everything``,
``_install_rbac_hooks``, and the write handlers.
"""

from __future__ import annotations

from collections.abc import Callable

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import MultiSinkAuditEmitter
from wazuh_mcp.rbac.policy import effective_allowlist_for
from wazuh_mcp.tenancy.registry import TenantRegistry

_RESOLVE_SENTINEL = "<rbac.resolve>"
_REASON = "tenant_not_registered"


def make_rbac_policy(
    registry: TenantRegistry,
    audit_emitter: MultiSinkAuditEmitter,
) -> Callable[[Session], dict[str, list[str]]]:
    def _policy(session: Session) -> dict[str, list[str]]:
        try:
            cfg = registry.get(session.tenant_id)
        except KeyError:
            audit_emitter.emit(
                session=session,
                tool=_RESOLVE_SENTINEL,
                args={},
                outcome="error",
                result_count=0,
                duration_ms=0,
                error_code="forbidden",
                error_reason=_REASON,
            )
            return {}
        return effective_allowlist_for(tenant_override=cfg.role_tool_allowlist)

    return _policy


def make_write_allowlist(
    registry: TenantRegistry,
    audit_emitter: MultiSinkAuditEmitter,
) -> Callable[[Session], list[str] | None]:
    def _resolve(session: Session) -> list[str] | None:
        try:
            cfg = registry.get(session.tenant_id)
        except KeyError:
            audit_emitter.emit(
                session=session,
                tool=_RESOLVE_SENTINEL,
                args={},
                outcome="error",
                result_count=0,
                duration_ms=0,
                error_code="forbidden",
                error_reason=_REASON,
            )
            return []
        return cfg.write_allowlist

    return _resolve


def make_ar_allowlist(
    registry: TenantRegistry,
    audit_emitter: MultiSinkAuditEmitter,
) -> Callable[[Session], list[str]]:
    def _resolve(session: Session) -> list[str]:
        try:
            cfg = registry.get(session.tenant_id)
        except KeyError:
            audit_emitter.emit(
                session=session,
                tool=_RESOLVE_SENTINEL,
                args={},
                outcome="error",
                result_count=0,
                duration_ms=0,
                error_code="forbidden",
                error_reason=_REASON,
            )
            return []
        return cfg.active_response_allowlist

    return _resolve
