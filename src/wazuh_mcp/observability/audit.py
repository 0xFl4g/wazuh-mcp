"""Audit emitter — one structured JSON event per tool call, fanned out to
pluggable sinks.

The legacy single-stream AuditEmitter is preserved under that name as an
alias for MultiSinkAuditEmitter so existing tool handlers (which import
from wazuh_mcp.observability.audit import AuditEmitter) keep working
without churn.

Stderr is the safe default under the MCP stdio transport: the server's
stdout carries JSON-RPC frames, and any bytes written to stdout that
aren't a framed message corrupt the wire. StdoutSink exists for HTTP-mode
deploys or operators collecting logs from stdout, but operators must
choose it explicitly in config.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.sinks.base import AuditSink, QueuedSink
from wazuh_mcp.observability.sinks.stream import StderrSink


def _hash_args(args: dict[str, Any]) -> str:
    payload = json.dumps(args, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


class MultiSinkAuditEmitter:
    """Dual-track fan-out audit emitter.

    `emit(session=...)` fans out to:
      * every sink in ``self.global_sinks`` (always — operator's safety net)
      * every sink in ``self.per_tenant_sinks.get(session.tenant_id, [])`` (overlay)

    Unknown tenant_id (no entry) routes to globals only — audit visibility
    preserved for the unknown-tenant defense-in-depth path (M4c resolver
    miss audit, M4d non-registered-tenant audit, etc.).
    """

    def __init__(
        self,
        *,
        global_sinks: Sequence[AuditSink] | None = None,
        per_tenant_sinks: Mapping[str, Sequence[AuditSink]] | None = None,
        drop_metric: Any | None = None,
    ) -> None:
        self.global_sinks: list[AuditSink] = (
            list(global_sinks) if global_sinks is not None else [StderrSink()]
        )
        self.per_tenant_sinks: dict[str, list[AuditSink]] = {
            tid: list(sinks) for tid, sinks in (per_tenant_sinks or {}).items()
        }
        # Flatten for uniform start/stop iteration with rollback semantics.
        self._all_sinks: list[AuditSink] = self.global_sinks + [
            s for sinks in self.per_tenant_sinks.values() for s in sinks
        ]
        # Public alias for backwards-compat readability — some external
        # introspection paths (and the M4a drop_metric wiring) reach for
        # `self.sinks`. Keep it as the flat list so existing iterations
        # continue to work.
        self.sinks: list[AuditSink] = self._all_sinks
        if drop_metric is not None:
            self._wire_drop_metric(drop_metric)

    def _wire_drop_metric(self, drop_metric: Any) -> None:
        # Tenant label is "<global>" for global sinks; tenant_id for per-tenant
        # sinks. Identity-keyed lookup so two same-config sinks (different
        # tenants) get distinct labels.
        global_ids = {id(s) for s in self.global_sinks}
        per_tenant_owner: dict[int, str] = {}
        for tid, sinks in self.per_tenant_sinks.items():
            for s in sinks:
                per_tenant_owner[id(s)] = tid
        for s in self._all_sinks:
            if not isinstance(s, QueuedSink):
                continue
            tenant_label = (
                "<global>" if id(s) in global_ids else per_tenant_owner.get(id(s), "<unknown>")
            )
            sink_name = getattr(s, "name", s.__class__.__name__)

            def _recorder(
                event: dict[str, Any],
                reason: str,
                _name: str = sink_name,
                _tenant: str = tenant_label,
            ) -> None:
                drop_metric.add(1, {"sink": _name, "tenant": _tenant, "reason": reason})

            s._record_drop = _recorder  # ty: ignore[invalid-assignment]

    async def start(self) -> None:
        # Start sinks in flat order; roll back on failure.
        started: list[AuditSink] = []
        try:
            for s in self._all_sinks:
                await s.start()
                started.append(s)
        except BaseException:
            for s in reversed(started):
                with contextlib.suppress(Exception):
                    await s.stop()
            raise

    async def stop(self) -> None:
        # Best-effort: each sink's stop() is independent; collect failures.
        errors: list[BaseException] = []
        for s in self._all_sinks:
            try:
                await s.stop()
            except BaseException as exc:
                errors.append(exc)
        if errors:
            raise BaseExceptionGroup("sink stop failures", errors)

    def emit(
        self,
        *,
        session: Session,
        tool: str,
        args: dict[str, Any],
        outcome: str,
        result_count: int,
        duration_ms: int,
        error_code: str | None = None,
        error_reason: str | None = None,
    ) -> None:
        event: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "tool": tool,
            "user": session.user_id,
            "tenant": session.tenant_id,
            "rbac_role": session.rbac_role,
            "arg_hash": _hash_args(args),
            "outcome": outcome,
            "result_count": result_count,
            "duration_ms": duration_ms,
        }
        if error_code is not None:
            event["error_code"] = error_code
        if error_reason is not None:
            event["error_reason"] = error_reason
        for sink in self.global_sinks:
            sink.submit(event)
        for sink in self.per_tenant_sinks.get(session.tenant_id, []):
            sink.submit(event)


# Legacy name kept for existing call sites in tools/*.
AuditEmitter = MultiSinkAuditEmitter
