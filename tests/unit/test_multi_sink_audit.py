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
    em = MultiSinkAuditEmitter(global_sinks=[sink1, sink2])
    await em.start()
    s = Session(user_id="u", tenant_id="t", rbac_role="analyst", auth_method="config")
    em.emit(
        session=s,
        tool="alerts.search_alerts",
        args={"q": "x"},
        outcome="ok",
        result_count=3,
        duration_ms=12,
    )
    await asyncio.sleep(0.1)
    await em.stop()
    assert "alerts.search_alerts" in out1.getvalue()
    assert "alerts.search_alerts" in out2.getvalue()


@pytest.mark.asyncio
async def test_empty_sinks_is_explicit_no_op() -> None:
    # Post-M4d: an explicit empty list means "no sinks"; only `None`
    # falls back to the StderrSink safety net (see test_none_sinks_also_defaults).
    em = MultiSinkAuditEmitter(global_sinks=[])
    assert em.sinks == []


@pytest.mark.asyncio
async def test_emit_args_hashed_not_logged() -> None:
    out = io.StringIO()
    em = MultiSinkAuditEmitter(global_sinks=[StderrSink(stream=out)])
    await em.start()
    s = Session(user_id="u", tenant_id="t", rbac_role="analyst", auth_method="config")
    em.emit(
        session=s,
        tool="t",
        args={"password": "hunter2"},
        outcome="ok",
        result_count=0,
        duration_ms=1,
    )
    await asyncio.sleep(0.1)
    await em.stop()
    assert "hunter2" not in out.getvalue()
    assert "arg_hash" in out.getvalue()


@pytest.mark.asyncio
async def test_none_sinks_also_defaults() -> None:
    em = MultiSinkAuditEmitter(global_sinks=None)
    assert len(em.sinks) == 1
    assert em.sinks[0].__class__.__name__ == "StderrSink"


@pytest.mark.asyncio
async def test_start_rolls_back_on_partial_failure() -> None:
    """If sink 2's start() raises, sink 1's start() is rolled back via stop()
    so a later stop() on the whole emitter doesn't re-run on an un-started
    sink and mask the real failure.
    """
    good_stop_calls = {"n": 0}

    class _GoodSink:
        name = "good"

        async def start(self) -> None:
            pass

        async def stop(self) -> None:
            good_stop_calls["n"] += 1

        def submit(self, event):
            pass

    class _FailingSink:
        name = "failing"

        async def start(self):
            raise RuntimeError("sink start failed")

        async def stop(self):
            pass

        def submit(self, event):
            pass

    good = _GoodSink()
    bad = _FailingSink()
    em = MultiSinkAuditEmitter(global_sinks=[good, bad])
    with pytest.raises(RuntimeError, match="sink start failed"):
        await em.start()
    # The good sink MUST have been rolled back (stopped) during start() failure.
    assert good_stop_calls["n"] == 1


@pytest.mark.asyncio
async def test_stop_continues_past_sink_failure() -> None:
    """One sink's stop() raising must not prevent others from stopping.
    All failures are surfaced in a BaseExceptionGroup so the caller can
    see every per-sink failure rather than just the first.
    """
    good_stop_calls = {"n": 0}

    class _FailingOnStop:
        name = "failing_stop"

        async def start(self) -> None:
            pass

        async def stop(self) -> None:
            raise RuntimeError("stop failed")

        def submit(self, event):
            pass

    class _GoodSink:
        name = "good"

        async def start(self) -> None:
            pass

        async def stop(self) -> None:
            good_stop_calls["n"] += 1

        def submit(self, event):
            pass

    fail = _FailingOnStop()
    good = _GoodSink()
    em = MultiSinkAuditEmitter(global_sinks=[fail, good])
    await em.start()
    with pytest.raises(BaseExceptionGroup):
        await em.stop()
    # Downstream sink MUST have been stopped even though an earlier sink raised.
    assert good_stop_calls["n"] == 1


@pytest.mark.asyncio
async def test_emit_synchronous_non_blocking() -> None:
    """emit() must never block — it enqueues on each sink and returns."""
    import time

    em = MultiSinkAuditEmitter(global_sinks=[StderrSink(stream=io.StringIO())])
    await em.start()
    s = Session(user_id="u", tenant_id="t", rbac_role="analyst", auth_method="config")
    t0 = time.perf_counter()
    for _ in range(1000):
        em.emit(session=s, tool="t", args={}, outcome="ok", result_count=0, duration_ms=0)
    elapsed = time.perf_counter() - t0
    await em.stop()
    # 1000 synchronous emits should complete quickly even under test conditions.
    assert elapsed < 0.5, f"emit() took {elapsed:.3f}s for 1000 calls — should be non-blocking"
