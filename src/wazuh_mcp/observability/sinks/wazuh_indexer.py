"""Audit sink that writes to Wazuh's own indexer via _bulk.

Operators get an auditable record of MCP activity in their existing Wazuh
Dashboards. No new credentials — uses the existing IndexerClientPool.
Events land in a daily index `{prefix}-YYYY.MM.DD`; a fixed index
template is installed once per sink lifetime to pin the mapping.

IMPORTANT invariants (inherited from QueuedSink base):
- honor _stop for interruptible backoff
- task_done() after every queue.get()
- use self._safe_record_drop, never self._record_drop
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import UTC, datetime
from typing import Any

from wazuh_mcp.observability.sinks.base import QueuedSink

_logger = logging.getLogger(__name__)


class WazuhIndexerSink(QueuedSink):
    name = "wazuh_indexer"

    def __init__(
        self,
        *,
        pool: Any,
        tenant_id: str,
        index_prefix: str = "wazuh-mcp-audit",
        batch: int = 100,
        flush_ms: int = 1000,
        max_attempts: int = 5,
        backoff_base_s: float = 0.1,
        **kw: Any,
    ) -> None:
        super().__init__(max_attempts=max_attempts, backoff_base_s=backoff_base_s, **kw)
        self._pool = pool
        self._tenant_id = tenant_id
        self._prefix = index_prefix
        self._batch = batch
        self._flush_s = flush_ms / 1000.0
        self._template_installed = False

    async def _ensure_template(self) -> None:
        if self._template_installed:
            return
        client = await self._pool.acquire(self._tenant_id)
        body: dict[str, Any] = {
            "index_patterns": [f"{self._prefix}-*"],
            # Priority resolves overlap between operator-chosen index_prefix
            # values when their patterns happen to overlap (e.g. one operator
            # picks 'wazuh-mcp-audit' and another picks 'wazuh-mcp-audit-foo';
            # both patterns match 'wazuh-mcp-audit-foo-*'). OpenSearch v7.8+
            # composable index templates require a priority distinguisher to
            # accept overlapping patterns; without one, the second template
            # install returns 400 and audit events land nowhere.
            "priority": 100,
            "template": {
                "settings": {
                    "number_of_shards": 1,
                    "number_of_replicas": 0,
                },
                "mappings": {
                    "dynamic": False,
                    "properties": {
                        "timestamp": {"type": "date"},
                        "tool": {"type": "keyword"},
                        "user": {"type": "keyword"},
                        "tenant": {"type": "keyword"},
                        "rbac_role": {"type": "keyword"},
                        "arg_hash": {"type": "keyword"},
                        "outcome": {"type": "keyword"},
                        "result_count": {"type": "long"},
                        "duration_ms": {"type": "long"},
                        "error_code": {"type": "keyword"},
                        "event_id": {"type": "keyword"},
                        "request_id": {"type": "keyword"},
                    },
                },
            },
        }
        await client.put_index_template(name=f"{self._prefix}-template", body=body)
        self._template_installed = True

    def _today_index(self) -> str:
        return f"{self._prefix}-{datetime.now(UTC).strftime('%Y.%m.%d')}"

    def _build_bulk_body(self, events: list[dict[str, Any]]) -> str:
        index = self._today_index()
        lines: list[str] = []
        for ev in events:
            action: dict[str, Any] = {"index": {"_index": index}}
            event_id = ev.get("event_id")
            if event_id is not None:
                action["index"]["_id"] = event_id
            lines.append(json.dumps(action))
            lines.append(json.dumps(ev))
        return "\n".join(lines) + "\n"

    async def _drain_loop(self) -> None:
        assert self._queue is not None
        assert self._stop is not None
        buf: list[dict[str, Any]] = []
        while not self._stop.is_set() or not self._queue.empty() or buf:
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
        attempt = 0
        last_exc: BaseException | None = None
        while attempt < self._max_attempts:
            try:
                await self._ensure_template()
                client = await self._pool.acquire(self._tenant_id)
                resp = await client.bulk(body=self._build_bulk_body(events))
                if resp.get("errors"):
                    raise RuntimeError(f"bulk reported errors: {resp}")
                return
            except Exception as exc:
                last_exc = exc
                attempt += 1
                if attempt >= self._max_attempts:
                    _logger.warning(
                        "WazuhIndexerSink delivery failed after %d attempts "
                        "(tenant=%s, batch_size=%d, last_exc=%r)",
                        self._max_attempts,
                        self._tenant_id,
                        len(events),
                        last_exc,
                    )
                    for ev in events:
                        self._safe_record_drop(ev, "delivery_failed")
                    return
                backoff = self._backoff_base * (2 ** (attempt - 1))
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=backoff)
                    for ev in events:
                        self._safe_record_drop(ev, "delivery_failed")
                    return
                except TimeoutError:
                    pass

    async def _deliver(self, event: dict[str, Any]) -> None:  # pragma: no cover
        raise RuntimeError("WazuhIndexerSink uses batched _drain_loop")
