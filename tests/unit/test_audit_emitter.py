"""Pin the additive `error_reason` kwarg added in M4c T1."""

from __future__ import annotations

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import MultiSinkAuditEmitter


class _CapturingSink:
    """In-memory sink: records every event submitted."""

    def __init__(self) -> None:
        self.events: list[dict] = []

    async def start(self) -> None: ...

    async def stop(self) -> None: ...

    def submit(self, event: dict) -> None:
        self.events.append(event)


def _session() -> Session:
    return Session(
        user_id="alice",
        tenant_id="tenant_a",
        rbac_role="admin",
        auth_method="oauth",
        wazuh_user="alice-wazuh",
    )


def test_emit_writes_error_reason_when_provided() -> None:
    sink = _CapturingSink()
    emitter = MultiSinkAuditEmitter(sinks=[sink])
    emitter.emit(
        session=_session(),
        tool="<rbac.resolve>",
        args={},
        outcome="error",
        result_count=0,
        duration_ms=0,
        error_code="forbidden",
        error_reason="tenant_not_registered",
    )
    assert len(sink.events) == 1
    event = sink.events[0]
    assert event["error_code"] == "forbidden"
    assert event["error_reason"] == "tenant_not_registered"


def test_emit_omits_error_reason_when_not_provided() -> None:
    sink = _CapturingSink()
    emitter = MultiSinkAuditEmitter(sinks=[sink])
    emitter.emit(
        session=_session(),
        tool="alerts.search_alerts",
        args={"limit": 10},
        outcome="ok",
        result_count=10,
        duration_ms=42,
    )
    assert len(sink.events) == 1
    assert "error_reason" not in sink.events[0]


def test_emit_writes_error_reason_with_error_code() -> None:
    """error_reason without error_code is unusual but allowed; both fields are independent."""
    sink = _CapturingSink()
    emitter = MultiSinkAuditEmitter(sinks=[sink])
    emitter.emit(
        session=_session(),
        tool="alerts.search_alerts",
        args={},
        outcome="error",
        result_count=0,
        duration_ms=0,
        error_code="forbidden",
        error_reason="rbac_role_denied",
    )
    event = sink.events[0]
    assert event["error_code"] == "forbidden"
    assert event["error_reason"] == "rbac_role_denied"
