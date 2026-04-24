"""MultiSinkAuditEmitter: fan-out to multiple sinks, metric-bumped drops."""
from __future__ import annotations

import asyncio
import io

import pytest

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import MultiSinkAuditEmitter
from wazuh_mcp.observability.sinks.stream import StderrSink


@pytest.mark.asyncio
async def test_emit_fans_out_to_all_sinks() -> None:
    out1, out2 = io.StringIO(), io.StringIO()
    sink1 = StderrSink(stream=out1)
    sink2 = StderrSink(stream=out2)
    em = MultiSinkAuditEmitter(sinks=[sink1, sink2])
    await em.start()
    s = Session(user_id="u", tenant_id="t", rbac_role="analyst", auth_method="config")
    em.emit(session=s, tool="alerts.search_alerts", args={"q": "x"},
            outcome="ok", result_count=3, duration_ms=12)
    await asyncio.sleep(0.1)
    await em.stop()
    assert "alerts.search_alerts" in out1.getvalue()
    assert "alerts.search_alerts" in out2.getvalue()


@pytest.mark.asyncio
async def test_empty_sinks_defaults_to_stderr_sink() -> None:
    em = MultiSinkAuditEmitter(sinks=[])
    # default should be a single StderrSink
    assert len(em.sinks) == 1
    assert em.sinks[0].__class__.__name__ == "StderrSink"


@pytest.mark.asyncio
async def test_emit_args_hashed_not_logged() -> None:
    out = io.StringIO()
    em = MultiSinkAuditEmitter(sinks=[StderrSink(stream=out)])
    await em.start()
    s = Session(user_id="u", tenant_id="t", rbac_role="analyst", auth_method="config")
    em.emit(session=s, tool="t", args={"password": "hunter2"},
            outcome="ok", result_count=0, duration_ms=1)
    await asyncio.sleep(0.1)
    await em.stop()
    assert "hunter2" not in out.getvalue()
    assert "arg_hash" in out.getvalue()


@pytest.mark.asyncio
async def test_none_sinks_also_defaults() -> None:
    em = MultiSinkAuditEmitter(sinks=None)
    assert len(em.sinks) == 1
    assert em.sinks[0].__class__.__name__ == "StderrSink"


@pytest.mark.asyncio
async def test_emit_synchronous_non_blocking() -> None:
    """emit() must never block — it enqueues on each sink and returns."""
    import time
    em = MultiSinkAuditEmitter(sinks=[StderrSink(stream=io.StringIO())])
    await em.start()
    s = Session(user_id="u", tenant_id="t", rbac_role="analyst", auth_method="config")
    t0 = time.perf_counter()
    for _ in range(1000):
        em.emit(session=s, tool="t", args={}, outcome="ok", result_count=0, duration_ms=0)
    elapsed = time.perf_counter() - t0
    await em.stop()
    # 1000 synchronous emits should complete quickly even under test conditions.
    assert elapsed < 0.5, f"emit() took {elapsed:.3f}s for 1000 calls — should be non-blocking"
