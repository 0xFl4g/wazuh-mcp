"""Multi-tenant MultiSinkAuditEmitter lifecycle (M4d T7).

start() iterates the flat _all_sinks list (globals + per-tenant) and
rolls back on failure. stop() is exception-group-safe across all sinks.
"""

from __future__ import annotations

import pytest


class _RecordingSink:
    """Sink that records start/stop calls. Optionally raises on start."""

    def __init__(self, name: str, raise_on_start: bool = False) -> None:
        self.name = name
        self.raise_on_start = raise_on_start
        self.started = False
        self.stopped = False
        self.start_calls = 0
        self.stop_calls = 0

    async def start(self) -> None:
        self.start_calls += 1
        if self.raise_on_start:
            raise RuntimeError(f"sink {self.name} start failed")
        self.started = True

    async def stop(self) -> None:
        self.stop_calls += 1
        self.stopped = True

    def submit(self, event):  # type: ignore[no-untyped-def]
        pass


@pytest.mark.asyncio
async def test_start_iterates_globals_then_per_tenant_in_dict_order() -> None:
    from wazuh_mcp.observability.audit import MultiSinkAuditEmitter

    g = _RecordingSink("global")
    a = _RecordingSink("a")
    b = _RecordingSink("b")
    emitter = MultiSinkAuditEmitter(
        global_sinks=[g],
        per_tenant_sinks={"tenant_a": [a], "tenant_b": [b]},
    )
    await emitter.start()
    assert g.started is True
    assert a.started is True
    assert b.started is True


@pytest.mark.asyncio
async def test_start_rollback_on_per_tenant_failure() -> None:
    """If tenant_b's sink fails, globals + tenant_a's sinks must be stopped."""
    from wazuh_mcp.observability.audit import MultiSinkAuditEmitter

    g = _RecordingSink("global")
    a = _RecordingSink("a")
    b_bad = _RecordingSink("b", raise_on_start=True)
    emitter = MultiSinkAuditEmitter(
        global_sinks=[g],
        per_tenant_sinks={"tenant_a": [a], "tenant_b": [b_bad]},
    )
    with pytest.raises(RuntimeError, match="sink b start failed"):
        await emitter.start()
    # Globals + tenant_a were started, then rolled back.
    assert g.stop_calls == 1
    assert a.stop_calls == 1
    # b never finished start, so its stop wasn't called by rollback.
    assert b_bad.stop_calls == 0


@pytest.mark.asyncio
async def test_stop_collects_failures_into_exception_group() -> None:
    """All sinks get stop() attempts even if some fail."""
    from wazuh_mcp.observability.audit import MultiSinkAuditEmitter

    class _FailingStopSink(_RecordingSink):
        async def stop(self) -> None:
            self.stop_calls += 1
            raise RuntimeError(f"sink {self.name} stop failed")

    g = _RecordingSink("global")
    a_bad = _FailingStopSink("a")
    b = _RecordingSink("b")
    emitter = MultiSinkAuditEmitter(
        global_sinks=[g],
        per_tenant_sinks={"tenant_a": [a_bad], "tenant_b": [b]},
    )
    await emitter.start()
    with pytest.raises(BaseExceptionGroup) as exc_info:
        await emitter.stop()
    # All three sinks attempted stop — best-effort.
    assert g.stop_calls == 1
    assert a_bad.stop_calls == 1
    assert b.stop_calls == 1
    # The failing tenant_a's stop is in the exception group.
    assert len(exc_info.value.exceptions) == 1


@pytest.mark.asyncio
async def test_start_failure_in_global_rolls_back_nothing_per_tenant() -> None:
    """If the FIRST global fails, no per-tenant sink ever started; rollback
    has nothing to do for per-tenant. Globals after the failed one also
    haven't started."""
    from wazuh_mcp.observability.audit import MultiSinkAuditEmitter

    g_bad = _RecordingSink("global_bad", raise_on_start=True)
    a = _RecordingSink("a")
    emitter = MultiSinkAuditEmitter(
        global_sinks=[g_bad],
        per_tenant_sinks={"tenant_a": [a]},
    )
    with pytest.raises(RuntimeError, match="sink global_bad start failed"):
        await emitter.start()
    assert a.start_calls == 0  # never reached
    assert a.stop_calls == 0
