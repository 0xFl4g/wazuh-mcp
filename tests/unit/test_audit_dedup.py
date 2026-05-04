"""MultiSinkAuditEmitter dedup-field population tests."""

from __future__ import annotations

import re

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import MultiSinkAuditEmitter
from wazuh_mcp.observability.audit_context import reset_request_id, set_request_id


class _CapturingSink:
    """Minimal AuditSink-like double that captures every submitted event."""

    name = "capturing"

    def __init__(self) -> None:
        self.events: list[dict[str, object]] = []

    async def start(self) -> None:
        return None

    async def stop(self) -> None:
        return None

    def submit(self, event: dict[str, object]) -> None:
        self.events.append(event)


def _session(tenant: str = "default", user: str = "alice") -> Session:
    return Session(
        user_id=user,
        tenant_id=tenant,
        rbac_role="analyst",
        auth_method="config",
    )


_UUID4_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")


def _emit_one(emitter: MultiSinkAuditEmitter, *, tool: str = "alerts.search_alerts") -> None:
    emitter.emit(
        session=_session(),
        tool=tool,
        args={"q": "x"},
        outcome="ok",
        result_count=1,
        duration_ms=10,
    )


def test_emit_sets_event_id_uuid4() -> None:
    sink = _CapturingSink()
    emitter = MultiSinkAuditEmitter(global_sinks=[sink])
    _emit_one(emitter)
    ev = sink.events[0]
    assert "event_id" in ev
    assert _UUID4_RE.match(ev["event_id"])  # ty: ignore[no-matching-overload]


def test_emit_event_id_unique_per_call() -> None:
    sink = _CapturingSink()
    emitter = MultiSinkAuditEmitter(global_sinks=[sink])
    for _ in range(1000):
        _emit_one(emitter)
    ids = {e["event_id"] for e in sink.events}
    assert len(ids) == 1000


def test_emit_request_id_none_outside_request_scope() -> None:
    sink = _CapturingSink()
    emitter = MultiSinkAuditEmitter(global_sinks=[sink])
    _emit_one(emitter)
    assert sink.events[0]["request_id"] is None


def test_emit_request_id_populated_from_context() -> None:
    sink = _CapturingSink()
    emitter = MultiSinkAuditEmitter(global_sinks=[sink])
    token = set_request_id("rpc-77")
    try:
        _emit_one(emitter)
    finally:
        reset_request_id(token)
    assert sink.events[0]["request_id"] == "rpc-77"


def test_emit_request_id_resets_after_scope_exits() -> None:
    sink = _CapturingSink()
    emitter = MultiSinkAuditEmitter(global_sinks=[sink])
    token = set_request_id("rpc-77")
    _emit_one(emitter)  # in scope
    reset_request_id(token)
    _emit_one(emitter)  # out of scope
    assert sink.events[0]["request_id"] == "rpc-77"
    assert sink.events[1]["request_id"] is None


def test_existing_fields_unchanged() -> None:
    """Regression: the v1.0 event shape is preserved alongside the new fields."""
    sink = _CapturingSink()
    emitter = MultiSinkAuditEmitter(global_sinks=[sink])
    _emit_one(emitter, tool="cluster.status")
    ev = sink.events[0]
    for k in (
        "timestamp",
        "tool",
        "user",
        "tenant",
        "rbac_role",
        "arg_hash",
        "outcome",
        "result_count",
        "duration_ms",
    ):
        assert k in ev, f"missing {k}"
    assert ev["tool"] == "cluster.status"
    assert ev["user"] == "alice"
    assert ev["tenant"] == "default"
