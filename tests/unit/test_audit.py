import asyncio
import io
import json

import pytest

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import AuditEmitter, MultiSinkAuditEmitter
from wazuh_mcp.observability.sinks.stream import StderrSink


def _session() -> Session:
    return Session(user_id="alice", tenant_id="acme", rbac_role="soc_analyst", auth_method="config")


async def _drain(emitter: MultiSinkAuditEmitter) -> None:
    # Allow the background drain task to flush enqueued events to the stream
    # before assertions run. 0.05s is enough on a healthy loop; the drain loop
    # polls the queue with a 0.1s timeout so we don't need longer.
    await asyncio.sleep(0.05)
    await emitter.stop()


@pytest.mark.asyncio
async def test_emits_one_json_line_per_call() -> None:
    buf = io.StringIO()
    emitter = MultiSinkAuditEmitter(global_sinks=[StderrSink(stream=buf)])
    await emitter.start()
    emitter.emit(
        session=_session(),
        tool="search_alerts",
        args={"time_range": "1h"},
        outcome="ok",
        result_count=24,
        duration_ms=142,
    )
    await _drain(emitter)
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


@pytest.mark.asyncio
async def test_args_are_hashed_not_raw() -> None:
    buf = io.StringIO()
    emitter = MultiSinkAuditEmitter(global_sinks=[StderrSink(stream=buf)])
    await emitter.start()
    emitter.emit(
        session=_session(),
        tool="search_alerts",
        args={"time_range": "1h", "agent_id": "sensitive-host-name"},
        outcome="ok",
        result_count=0,
        duration_ms=10,
    )
    await _drain(emitter)
    payload = buf.getvalue()
    assert "sensitive-host-name" not in payload
    event = json.loads(payload)
    assert len(event["arg_hash"]) == 64


@pytest.mark.asyncio
async def test_hash_is_deterministic_across_key_order() -> None:
    buf1, buf2 = io.StringIO(), io.StringIO()
    for buf, args in (
        (buf1, {"time_range": "1h", "min_level": 12}),
        (buf2, {"min_level": 12, "time_range": "1h"}),
    ):
        emitter = MultiSinkAuditEmitter(global_sinks=[StderrSink(stream=buf)])
        await emitter.start()
        emitter.emit(
            session=_session(),
            tool="search_alerts",
            args=args,
            outcome="ok",
            result_count=0,
            duration_ms=0,
        )
        await _drain(emitter)
    h1 = json.loads(buf1.getvalue())["arg_hash"]
    h2 = json.loads(buf2.getvalue())["arg_hash"]
    assert h1 == h2


@pytest.mark.asyncio
async def test_error_outcome_captures_code() -> None:
    buf = io.StringIO()
    emitter = MultiSinkAuditEmitter(global_sinks=[StderrSink(stream=buf)])
    await emitter.start()
    emitter.emit(
        session=_session(),
        tool="search_alerts",
        args={},
        outcome="error",
        result_count=0,
        duration_ms=7,
        error_code="rate_limited",
    )
    await _drain(emitter)
    event = json.loads(buf.getvalue())
    assert event["outcome"] == "error"
    assert event["error_code"] == "rate_limited"


def test_audit_emitter_alias_preserved() -> None:
    # 17 existing tool handlers do `from wazuh_mcp.observability.audit import
    # AuditEmitter`. The legacy name must continue to resolve to the new
    # MultiSinkAuditEmitter class so those imports keep working unchanged.
    assert AuditEmitter is MultiSinkAuditEmitter


def test_default_sinks_is_single_stderr_sink_for_stdio_safety() -> None:
    # Under MCP stdio transport the server's stdout is the JSON-RPC wire.
    # Default emitter must fan out to a StderrSink so audit events don't
    # corrupt it.
    emitter = MultiSinkAuditEmitter()
    assert len(emitter.sinks) == 1
    assert isinstance(emitter.sinks[0], StderrSink)
