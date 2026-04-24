"""HTTP audit sink: POSTs batched JSON arrays to an operator webhook.

Batching strategy: flush when the internal batch reaches `batch` events
or `flush_ms` elapses since the last flush, whichever comes first.
Uses the QueuedSink drain loop indirectly by overriding it — the per-
event backoff from QueuedSink doesn't compose cleanly with batched HTTP,
so HttpSink implements its own loop.

IMPORTANT: this overrides _drain_loop, so it must honor the same
invariants the base's _drain_loop enforces:
- exit when _stop.is_set() AND queue empty AND buf empty
- task_done() after every queue.get()
- use self._safe_record_drop, never self._record_drop
- interruptible backoff via _stop.wait()
"""
from __future__ import annotations

import asyncio
import json
from typing import Any

import httpx

from wazuh_mcp.observability.sinks.base import QueuedSink


class HttpSink(QueuedSink):
    name = "http"

    def __init__(
        self,
        *,
        url: str,
        batch: int = 50,
        flush_ms: int = 500,
        max_attempts: int = 5,
        backoff_base_s: float = 0.1,
        timeout: float = 10.0,
        **kw: Any,
    ) -> None:
        super().__init__(max_attempts=max_attempts, backoff_base_s=backoff_base_s, **kw)
        self._url = url
        self._batch = batch
        self._flush_s = flush_ms / 1000.0
        self._timeout = timeout

    async def _drain_loop(self) -> None:
        assert self._queue is not None
        assert self._stop is not None
        buf: list[dict[str, Any]] = []
        while not self._stop.is_set() or not self._queue.empty() or buf:
            # Pull events for up to flush_s or until we hit batch.
            deadline = asyncio.get_running_loop().time() + self._flush_s
            while len(buf) < self._batch:
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    break
                try:
                    ev = await asyncio.wait_for(self._queue.get(), timeout=remaining)
                except TimeoutError:
                    break
                try:
                    buf.append(ev)
                finally:
                    self._queue.task_done()
            if buf:
                await self._send_with_retry(buf)
                buf = []

    async def _send_with_retry(self, events: list[dict[str, Any]]) -> None:
        assert self._stop is not None
        payload = json.dumps(events, separators=(",", ":")).encode("utf-8")
        attempt = 0
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            while attempt < self._max_attempts:
                try:
                    resp = await client.post(
                        self._url,
                        content=payload,
                        headers={"content-type": "application/json"},
                    )
                    if 200 <= resp.status_code < 300:
                        return
                    raise httpx.HTTPStatusError("non-2xx", request=resp.request, response=resp)
                except Exception:
                    attempt += 1
                    if attempt >= self._max_attempts:
                        for ev in events:
                            self._safe_record_drop(ev, "delivery_failed")
                        return
                    # Interruptible backoff: abandon on _stop.
                    backoff = self._backoff_base * (2 ** (attempt - 1))
                    try:
                        await asyncio.wait_for(self._stop.wait(), timeout=backoff)
                        # _stop fired during backoff — abandon retry, drop the events.
                        for ev in events:
                            self._safe_record_drop(ev, "delivery_failed")
                        return
                    except TimeoutError:
                        pass

    # Make the abstract _deliver resolvable (HttpSink uses its own loop).
    async def _deliver(self, event: dict[str, Any]) -> None:   # pragma: no cover
        raise RuntimeError("HttpSink uses batched _drain_loop, not per-event _deliver")
