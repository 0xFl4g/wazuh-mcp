"""QueuedSink: bounded queue, fan-out drop-oldest, exponential backoff, clean
shutdown."""

from __future__ import annotations

import asyncio
import time
from typing import Any

import pytest

from wazuh_mcp.observability.sinks.base import QueuedSink


class _ListSink(QueuedSink):
    """Test sink: collects delivered events in memory."""

    def __init__(self, *, fail_first_n: int = 0, maxsize: int = 10, max_attempts: int = 3):
        super().__init__(maxsize=maxsize, max_attempts=max_attempts, backoff_base_s=0.001)
        self.delivered: list[dict[str, Any]] = []
        self.attempts = 0
        self._fail_first_n = fail_first_n
        self.dropped: list[tuple[dict[str, Any], str]] = []

    async def _deliver(self, event: dict[str, Any]) -> None:
        self.attempts += 1
        if self._fail_first_n > 0:
            self._fail_first_n -= 1
            raise RuntimeError("synthetic delivery failure")
        self.delivered.append(event)

    def _record_drop(self, event: dict[str, Any], reason: str) -> None:
        self.dropped.append((event, reason))


@pytest.mark.asyncio
async def test_normal_delivery() -> None:
    sink = _ListSink()
    await sink.start()
    sink.submit({"tool": "alerts.search_alerts", "n": 1})
    sink.submit({"tool": "alerts.search_alerts", "n": 2})
    await sink.stop()
    assert sink.delivered == [
        {"tool": "alerts.search_alerts", "n": 1},
        {"tool": "alerts.search_alerts", "n": 2},
    ]


@pytest.mark.asyncio
async def test_retry_then_success() -> None:
    sink = _ListSink(fail_first_n=2)
    await sink.start()
    sink.submit({"n": 1})
    await asyncio.sleep(0.1)  # let backoff play out
    await sink.stop()
    assert sink.delivered == [{"n": 1}]
    assert sink.attempts == 3  # 2 failures + 1 success


@pytest.mark.asyncio
async def test_drop_after_max_attempts() -> None:
    sink = _ListSink(fail_first_n=100, max_attempts=3)
    await sink.start()
    sink.submit({"n": 1})
    await asyncio.sleep(0.2)
    await sink.stop()
    assert sink.delivered == []
    assert len(sink.dropped) == 1
    assert sink.dropped[0][1] == "delivery_failed"


@pytest.mark.asyncio
async def test_bounded_queue_drops_oldest_when_full() -> None:
    sink = _ListSink(maxsize=3)
    # Don't start the drain yet — queue fills.
    sink.submit({"n": 1})
    sink.submit({"n": 2})
    sink.submit({"n": 3})
    sink.submit({"n": 4})  # should evict {"n": 1}
    assert any(d[1] == "overflow" for d in sink.dropped)
    await sink.start()
    await sink.stop()
    # Remaining events drained in order (2, 3, 4 — 1 was dropped)
    delivered_ns = [e["n"] for e in sink.delivered]
    assert delivered_ns == [2, 3, 4]


@pytest.mark.asyncio
async def test_stop_drains_remaining() -> None:
    sink = _ListSink()
    await sink.start()
    for i in range(5):
        sink.submit({"n": i})
    await sink.stop()
    assert len(sink.delivered) == 5


@pytest.mark.asyncio
async def test_shutdown_timeout_does_not_hang() -> None:
    """Slow/failing delivery does not extend shutdown beyond shutdown_timeout."""
    sink = _ListSink(fail_first_n=1_000_000, max_attempts=5)  # will never succeed
    sink._shutdown_timeout = 0.3  # tight bound for the test
    await sink.start()
    for i in range(20):
        sink.submit({"n": i})
    t0 = time.monotonic()
    await sink.stop()
    elapsed = time.monotonic() - t0
    # Should return well before 5s * 20 events worst-case backoff.
    assert elapsed < 1.5, f"stop() hung for {elapsed:.2f}s"


@pytest.mark.asyncio
async def test_backoff_interruptible_by_stop() -> None:
    """A stop() during backoff returns quickly, not after the sleep finishes."""
    sink = _ListSink(fail_first_n=100, max_attempts=5)
    sink._backoff_base = 2.0  # 2s base - shutdown must be faster
    await sink.start()
    sink.submit({"n": 1})
    await asyncio.sleep(0.05)  # let the first failure happen and enter backoff
    t0 = time.monotonic()
    await sink.stop()
    elapsed = time.monotonic() - t0
    assert elapsed < 1.0, f"stop() took {elapsed:.2f}s - backoff wasn't interruptible"


@pytest.mark.asyncio
async def test_record_drop_exception_does_not_leak() -> None:
    """A buggy _record_drop override never propagates to submit() or kills drain."""

    class _BuggyHook(QueuedSink):
        name = "buggy"

        def __init__(self):
            super().__init__(maxsize=2, max_attempts=1, backoff_base_s=0.001)
            self.delivered: list[dict] = []

        async def _deliver(self, event):
            self.delivered.append(event)

        def _record_drop(self, event, reason):
            raise RuntimeError("buggy hook")

    sink = _BuggyHook()
    # Pre-start overflow exercises _safe_record_drop before drain runs.
    for i in range(5):
        sink.submit({"n": i})  # must not raise
    await sink.start()
    await sink.stop()
    # Drain still works; some events delivered.
    assert len(sink.delivered) > 0


@pytest.mark.asyncio
async def test_submit_before_start_buffers_and_drains() -> None:
    """submit() before start() buffers; start() drains the buffer."""
    sink = _ListSink(maxsize=5)
    sink.submit({"n": 1})
    sink.submit({"n": 2})
    await sink.start()
    await sink.stop()
    assert sink.delivered == [{"n": 1}, {"n": 2}]


@pytest.mark.asyncio
async def test_stop_without_start_is_idempotent() -> None:
    sink = _ListSink()
    await sink.stop()  # must not hang or raise
