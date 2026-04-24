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
from typing import Any, Protocol


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
    ) -> None:
        self._queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=maxsize)
        self._max_attempts = max_attempts
        self._backoff_base = backoff_base_s
        self._task: asyncio.Task[None] | None = None
        self._stop = asyncio.Event()

    def submit(self, event: dict[str, Any]) -> None:
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            # Drop oldest: pull one off, push the new one.
            try:
                evicted = self._queue.get_nowait()
                self._record_drop(evicted, "overflow")
                self._queue.task_done()
            except asyncio.QueueEmpty:
                # Race: queue cleared between put_nowait fail and get. Retry.
                pass
            try:
                self._queue.put_nowait(event)
            except asyncio.QueueFull:
                self._record_drop(event, "overflow")

    async def start(self) -> None:
        self._task = asyncio.create_task(self._drain_loop(), name=f"audit-sink-{self.name}")

    async def stop(self) -> None:
        self._stop.set()
        # Drain whatever's left.
        await self._queue.join()
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task

    async def _drain_loop(self) -> None:
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
        attempt = 0
        while attempt < self._max_attempts:
            try:
                await self._deliver(event)
                return
            except Exception:
                attempt += 1
                if attempt >= self._max_attempts:
                    self._record_drop(event, "delivery_failed")
                    return
                await asyncio.sleep(self._backoff_base * (2 ** (attempt - 1)))

    async def _deliver(self, event: dict[str, Any]) -> None:   # pragma: no cover - abstract
        raise NotImplementedError

    def _record_drop(self, event: dict[str, Any], reason: str) -> None:
        pass   # subclasses or emitter override to bump the metric
