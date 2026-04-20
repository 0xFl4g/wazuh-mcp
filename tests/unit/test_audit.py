import io
import json

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import AuditEmitter


def _session() -> Session:
    return Session(user_id="alice", tenant_id="acme",
                   rbac_role="soc_analyst", auth_method="config")


def test_emits_one_json_line_per_call():
    buf = io.StringIO()
    emitter = AuditEmitter(stream=buf)
    emitter.emit(
        session=_session(),
        tool="search_alerts",
        args={"time_range": "1h"},
        outcome="ok",
        result_count=24,
        duration_ms=142,
    )
    lines = buf.getvalue().strip().split("\n")
    assert len(lines) == 1
    event = json.loads(lines[0])
    assert event["tool"] == "search_alerts"
    assert event["user"] == "alice"
    assert event["tenant"] == "acme"
    assert event["outcome"] == "ok"
    assert event["result_count"] == 24
    assert event["duration_ms"] == 142
    assert "timestamp" in event
    assert "arg_hash" in event


def test_args_are_hashed_not_raw():
    buf = io.StringIO()
    AuditEmitter(stream=buf).emit(
        session=_session(),
        tool="search_alerts",
        args={"time_range": "1h", "agent_id": "sensitive-host-name"},
        outcome="ok",
        result_count=0,
        duration_ms=10,
    )
    payload = buf.getvalue()
    assert "sensitive-host-name" not in payload
    event = json.loads(payload)
    assert len(event["arg_hash"]) == 64


def test_hash_is_deterministic_across_key_order():
    buf1, buf2 = io.StringIO(), io.StringIO()
    for buf, args in (
        (buf1, {"time_range": "1h", "min_level": 12}),
        (buf2, {"min_level": 12, "time_range": "1h"}),
    ):
        AuditEmitter(stream=buf).emit(
            session=_session(),
            tool="search_alerts",
            args=args,
            outcome="ok",
            result_count=0,
            duration_ms=0,
        )
    h1 = json.loads(buf1.getvalue())["arg_hash"]
    h2 = json.loads(buf2.getvalue())["arg_hash"]
    assert h1 == h2


def test_error_outcome_captures_code():
    buf = io.StringIO()
    AuditEmitter(stream=buf).emit(
        session=_session(),
        tool="search_alerts",
        args={},
        outcome="error",
        result_count=0,
        duration_ms=7,
        error_code="rate_limited",
    )
    event = json.loads(buf.getvalue())
    assert event["outcome"] == "error"
    assert event["error_code"] == "rate_limited"


def test_default_stream_is_stderr_to_protect_stdio_transport():
    # Under MCP stdio transport the server's stdout is the JSON-RPC wire.
    # Default emitter must write to stderr so audit events don't corrupt it.
    import sys

    emitter = AuditEmitter()
    assert emitter._stream is sys.stderr
