"""AuditSink protocol + QueuedSink base.

Each sink owns an asyncio.Queue + a background drain task. submit() is
non-blocking (enqueue-or-drop-oldest). The drain task delivers one event
at a time with exponential backoff on transient failure and bounded
attempts before dropping.

Subclasses implement:
  - async def _deliver(self, event: dict) -> None
  - def _record_drop(self, event: dict, reason: Literal["overflow","delivery_failed"]) -> None

The emitter wires _record_drop to the audit_dropped_total metric.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import Any, Protocol

_logger = logging.getLogger("wazuh_mcp.audit_sink")


class AuditSink(Protocol):
    async def start(self) -> None: ...
    async def stop(self) -> None: ...
    def submit(self, event: dict[str, Any]) -> None: ...


class QueuedSink:
    name: str = "queued"

    def __init__(
        self,
        *,
        maxsize: int = 10_000,
        max_attempts: int = 5,
        backoff_base_s: float = 0.1,
        shutdown_timeout_s: float = 5.0,
    ) -> None:
        # Store constructor args only — do NOT create loop-bound primitives
        # here. asyncio.Queue / asyncio.Event bind to the running loop on
        # first await, so constructing them in __init__ (which may run before
        # any event loop exists or in a different loop than start()) causes
        # RuntimeError at await time.
        self._maxsize = maxsize
        self._max_attempts = max_attempts
        self._backoff_base = backoff_base_s
        self._shutdown_timeout = shutdown_timeout_s
        self._queue: asyncio.Queue[dict[str, Any]] | None = None
        self._stop: asyncio.Event | None = None
        self._task: asyncio.Task[None] | None = None
        self._pre_start_buffer: list[dict[str, Any]] = []

    def submit(self, event: dict[str, Any]) -> None:
        # Pre-start path: buffer to an in-memory list, bounded by the same
        # maxsize semantics as the live queue (drop-oldest on overflow).
        if self._queue is None:
            if len(self._pre_start_buffer) >= self._maxsize:
                evicted = self._pre_start_buffer.pop(0)
                self._safe_record_drop(evicted, "overflow")
            self._pre_start_buffer.append(event)
            return

        try:
            self._queue.put_nowait(event)
            return
        except asyncio.QueueFull:
            pass

        # Drain may have freed a slot between the failed put_nowait and now;
        # retry before evicting to avoid spurious overflow drops under
        # contention.
        try:
            self._queue.put_nowait(event)
            return
        except asyncio.QueueFull:
            pass

        # Still full — evict oldest.
        try:
            evicted = self._queue.get_nowait()
            self._safe_record_drop(evicted, "overflow")
            self._queue.task_done()
        except asyncio.QueueEmpty:
            # Race: queue cleared between put_nowait fail and get. Retry.
            pass

        # Now put the new event; if still full (shouldn't be), drop it.
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            self._safe_record_drop(event, "overflow")

    async def start(self) -> None:
        self._queue = asyncio.Queue(maxsize=self._maxsize)
        self._stop = asyncio.Event()
        # Flush anything that arrived before start.
        buffered = self._pre_start_buffer
        self._pre_start_buffer = []
        for ev in buffered:
            self.submit(ev)
        self._task = asyncio.create_task(self._drain_loop(), name=f"audit-sink-{self.name}")

    async def stop(self) -> None:
        if self._stop is None or self._queue is None:
            # start() was never called — nothing to do.
            return
        self._stop.set()
        # Drain whatever's left, but bounded: a failing upstream must not
        # keep shutdown pinned on max_attempts * backoff per event.
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(self._queue.join(), timeout=self._shutdown_timeout)
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task

    async def _drain_loop(self) -> None:
        assert self._queue is not None and self._stop is not None
        while not self._stop.is_set() or not self._queue.empty():
            try:
                event = await asyncio.wait_for(self._queue.get(), timeout=0.1)
            except TimeoutError:
                continue
            try:
                await self._deliver_with_retry(event)
            finally:
                self._queue.task_done()

    async def _deliver_with_retry(self, event: dict[str, Any]) -> None:
        assert self._stop is not None
        attempt = 0
        while attempt < self._max_attempts:
            try:
                await self._deliver(event)
                return
            except Exception:
                attempt += 1
                if attempt >= self._max_attempts:
                    self._safe_record_drop(event, "delivery_failed")
                    return
                backoff = self._backoff_base * (2 ** (attempt - 1))
                # Interruptible backoff: if _stop fires during the wait,
                # abandon the retry so shutdown can proceed promptly.
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=backoff)
                    # _stop was set during backoff; abandon retry.
                    return
                except TimeoutError:
                    # Normal: backoff completed without stop. Continue retrying.
                    pass

    async def _deliver(self, event: dict[str, Any]) -> None:  # pragma: no cover - abstract
        raise NotImplementedError

    def _record_drop(self, event: dict[str, Any], reason: str) -> None:
        pass  # subclasses or emitter override to bump the metric

    def _safe_record_drop(self, event: dict[str, Any], reason: str) -> None:
        """Wrap _record_drop so a buggy subclass override cannot poison the
        hot path (submit) or kill the drain task."""
        try:
            self._record_drop(event, reason)
        except Exception:  # never propagate from the drop recorder
            _logger.exception(
                "audit sink _record_drop failed for sink=%s reason=%s",
                self.name,
                reason,
            )
