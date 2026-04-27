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
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.sinks.base import AuditSink, QueuedSink
from wazuh_mcp.observability.sinks.stream import StderrSink


def _hash_args(args: dict[str, Any]) -> str:
    payload = json.dumps(args, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


class MultiSinkAuditEmitter:
    """Fan-out audit emitter. Each emit enqueues on every sink's async queue."""

    def __init__(
        self,
        *,
        sinks: Sequence[AuditSink] | None = None,
        drop_metric: Any | None = None,
    ) -> None:
        _sinks: list[AuditSink] = list(sinks) if sinks else [StderrSink()]
        self.sinks: list[AuditSink] = _sinks
        if drop_metric is not None:
            for s in self.sinks:
                if isinstance(s, QueuedSink):
                    sink_name = getattr(s, "name", s.__class__.__name__)

                    def _recorder(
                        event: dict[str, Any],
                        reason: str,
                        _name: str = sink_name,
                    ) -> None:
                        drop_metric.add(1, {"sink": _name, "reason": reason})

                    s._record_drop = _recorder  # ty: ignore[invalid-assignment]

    async def start(self) -> None:
        # Start sinks in order, rolling back any that did start if a later
        # sink's start() raises. Otherwise stop() would later run on a
        # never-started sink and mask the real failure.
        started: list[AuditSink] = []
        try:
            for s in self.sinks:
                await s.start()
                started.append(s)
        except BaseException:
            for s in reversed(started):
                # Best-effort cleanup; the original exception wins.
                with contextlib.suppress(Exception):
                    await s.stop()
            raise

    async def stop(self) -> None:
        # Best-effort: each sink's stop() is independent; one failing must
        # not prevent the others from shutting down. Collect and re-raise
        # as an ExceptionGroup so callers can inspect every failure.
        errors: list[BaseException] = []
        for s in self.sinks:
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
        for sink in self.sinks:
            sink.submit(event)


# Legacy name kept for existing call sites in tools/*.
AuditEmitter = MultiSinkAuditEmitter
