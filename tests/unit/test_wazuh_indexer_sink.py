"""WazuhIndexerSink: _bulk API batches against the existing IndexerClientPool."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from unittest.mock import AsyncMock

import pytest

from wazuh_mcp.observability.sinks.wazuh_indexer import WazuhIndexerSink


class _FakePool:
    def __init__(self) -> None:
        self.client = AsyncMock()
        self.client.bulk = AsyncMock(return_value={"errors": False, "items": []})
        self.client.put_index_template = AsyncMock(return_value={"acknowledged": True})
        self.acquire = AsyncMock(return_value=self.client)


@pytest.mark.asyncio
async def test_events_land_in_dated_index() -> None:
    pool = _FakePool()
    sink = WazuhIndexerSink(
        pool=pool, index_prefix="wazuh-mcp-audit", batch=3, flush_ms=50, tenant_id="t1"
    )
    await sink.start()
    for i in range(3):
        sink.submit({"tool": "alerts.search_alerts", "n": i})
    await asyncio.sleep(0.2)
    await sink.stop()
    assert pool.client.bulk.called
    # Inspect the bulk body: either positional arg 0 or kwarg "body".
    call = pool.client.bulk.call_args
    body = call.kwargs.get("body") if call.kwargs.get("body") is not None else call.args[0]
    today = datetime.now(UTC).strftime("%Y.%m.%d")
    assert f"wazuh-mcp-audit-{today}" in str(body)


@pytest.mark.asyncio
async def test_index_template_installed_once() -> None:
    pool = _FakePool()
    sink = WazuhIndexerSink(
        pool=pool, index_prefix="wazuh-mcp-audit", batch=1, flush_ms=10, tenant_id="t1"
    )
    await sink.start()
    sink.submit({"n": 1})
    sink.submit({"n": 2})
    await asyncio.sleep(0.2)
    await sink.stop()
    # Template install is idempotent and fires at most once per sink lifetime.
    assert pool.client.put_index_template.call_count == 1


@pytest.mark.asyncio
async def test_template_index_patterns_use_configured_prefix() -> None:
    """T-G5b regression test.

    Previously the module-level ``_INDEX_TEMPLATE_BODY`` constant pinned
    ``index_patterns=["wazuh-mcp-audit-*"]``, which never matched per-tenant
    prefixes like ``tenant-b-audit-*``. The template body is now constructed
    inside ``_ensure_template`` so it closes over ``self._prefix``.
    """
    pool = _FakePool()
    sink = WazuhIndexerSink(pool=pool, tenant_id="tenant_b", index_prefix="tenant-b-audit")
    await sink._ensure_template()

    pool.client.put_index_template.assert_awaited_once()
    call = pool.client.put_index_template.await_args
    assert call.kwargs["name"] == "tenant-b-audit-template"
    body = call.kwargs["body"]
    assert body["index_patterns"] == ["tenant-b-audit-*"], (
        f"template index_patterns must close over self._prefix; got {body['index_patterns']!r}"
    )
    # Mapping shape preserved across the refactor.
    props = body["template"]["mappings"]["properties"]
    for required in ("timestamp", "tool", "tenant", "outcome"):
        assert required in props, f"missing mapping property {required!r}"
