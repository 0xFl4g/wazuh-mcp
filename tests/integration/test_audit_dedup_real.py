"""Real-Wazuh integration test for v1.2 audit dedup.

Marked @pytest.mark.integration. Spun up via docker/bootstrap.sh which
starts wazuh-indexer; this test does not need the manager or keycloak.

Uses the existing 'indexer' fixture (a configured IndexerClient). The
WazuhIndexerSink expects a pool with .acquire(tenant_id); a small
_PoolWrapper adapts the single client to that interface.

Index name: 'wazuh-mcp-audit-dedup-itest-YYYY.MM.DD' — unique prefix
per test run to avoid cross-test interference. Best-effort cleanup
via DELETE _index after each test; if cleanup fails, the next CI run
gets a fresh wazuh-indexer container anyway.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

import pytest

from wazuh_mcp.observability.sinks.wazuh_indexer import WazuhIndexerSink

pytestmark = pytest.mark.integration


class _PoolWrapper:
    """Adapts a single IndexerClient to the pool.acquire(tenant_id) interface
    expected by WazuhIndexerSink. The sink only ever calls .acquire(); it
    never calls .release() so the wrapper is minimal."""

    def __init__(self, client: Any) -> None:
        self._client = client

    async def acquire(self, tenant_id: str) -> Any:
        return self._client


def _today_index(prefix: str) -> str:
    return f"{prefix}-{datetime.now(UTC).strftime('%Y.%m.%d')}"


def _event(
    event_id: str,
    *,
    tool: str = "alerts.search_alerts",
    request_id: str | None = None,
) -> dict[str, Any]:
    return {
        "timestamp": datetime.now(UTC).isoformat(),
        "tool": tool,
        "user": "alice",
        "tenant": "default",
        "rbac_role": "analyst",
        "arg_hash": "h" * 64,
        "outcome": "ok",
        "result_count": 1,
        "duration_ms": 10,
        "event_id": event_id,
        "request_id": request_id,
    }


@pytest.fixture
async def indexer_sink(indexer) -> AsyncIterator[WazuhIndexerSink]:
    """Build a WazuhIndexerSink against the real wazuh-indexer fixture.

    Uses a unique index_prefix per pid so cross-test isolation is automatic.
    Best-effort cleanup of created indices on teardown via the indexer client's
    underlying httpx client (DELETE wazuh-mcp-audit-dedup-itest-*).
    """
    prefix = f"wazuh-mcp-audit-dedup-itest-{os.getpid()}"
    pool = _PoolWrapper(indexer)
    sink = WazuhIndexerSink(
        pool=pool,
        tenant_id="default",
        index_prefix=prefix,
        batch=10,
        flush_ms=200,
        max_attempts=2,
    )
    await sink.start()
    try:
        yield sink
    finally:
        await sink.stop()
        # Best-effort cleanup. IndexerClient exposes _client (httpx.AsyncClient)
        # for raw HTTP. Two deletes:
        #   1. The created daily indices.
        #   2. The composable index template. CRITICAL: leaving the template
        #      behind makes OpenSearch reject any subsequent template install
        #      that has overlapping patterns (e.g. M4a's 'wazuh-mcp-audit-*'
        #      overlaps with our 'wazuh-mcp-audit-dedup-itest-{pid}-*'). The
        #      conflict surfaces as a 400 from put_index_template, which
        #      cascades into audit-event drops in unrelated tests.
        with contextlib.suppress(Exception):
            await indexer._client.delete(f"/{prefix}-*")  # deliberate private access
        with contextlib.suppress(Exception):
            await indexer._client.delete(f"/_index_template/{prefix}-template")


async def _count_docs(indexer: Any, prefix: str) -> int:
    """Search for all docs in today's index and return hit count."""
    today_idx = _today_index(prefix)
    try:
        resp = await indexer.search(
            index=today_idx,
            query={"query": {"match_all": {}}, "size": 100},
        )
    except Exception:
        # Index may not exist yet on the first poll (sink hasn't flushed).
        return 0
    hits = resp.get("hits", {}).get("hits", [])
    return len(hits)


@pytest.mark.asyncio
async def test_same_event_id_dedupes_to_one_doc(
    indexer_sink: WazuhIndexerSink, indexer: Any
) -> None:
    """50 emits with the same event_id -> exactly 1 document in the index."""
    for _ in range(50):
        indexer_sink.submit(_event("forced-id-A"))
    # Wait for the batched sink to flush (flush_ms=200) AND OpenSearch refresh (1s default).
    await asyncio.sleep(2.0)
    count = await _count_docs(indexer, indexer_sink._prefix)  # deliberate private access
    assert count == 1, f"expected 1 doc with deduped event_id, got {count}"


@pytest.mark.asyncio
async def test_distinct_event_ids_produce_distinct_docs(
    indexer_sink: WazuhIndexerSink, indexer: Any
) -> None:
    """50 emits with distinct event_ids -> 50 docs."""
    for _ in range(50):
        indexer_sink.submit(_event(str(uuid.uuid4())))
    await asyncio.sleep(2.0)
    count = await _count_docs(indexer, indexer_sink._prefix)  # deliberate private access
    assert count == 50, f"expected 50 distinct docs, got {count}"


@pytest.mark.asyncio
async def test_request_id_is_queryable(indexer_sink: WazuhIndexerSink, indexer: Any) -> None:
    """Events tagged with request_id can be retrieved via term query on that field."""
    indexer_sink.submit(_event(str(uuid.uuid4()), request_id="rpc-find-me"))
    indexer_sink.submit(_event(str(uuid.uuid4()), request_id="rpc-other"))
    await asyncio.sleep(2.0)

    today_idx = _today_index(indexer_sink._prefix)  # deliberate private access
    resp = await indexer.search(
        index=today_idx,
        query={"query": {"term": {"request_id": "rpc-find-me"}}},
    )
    hits = resp.get("hits", {}).get("hits", [])
    assert len(hits) == 1, f"expected 1 hit by term query on request_id, got {len(hits)}"
    assert hits[0]["_source"]["request_id"] == "rpc-find-me"


@pytest.mark.asyncio
async def test_dedup_survives_simulated_retry(indexer_sink: WazuhIndexerSink, indexer: Any) -> None:
    """Submitting the same event multiple times (sim retry) yields exactly 1 doc."""
    eid = "retry-target"
    for _ in range(5):
        indexer_sink.submit(_event(eid))
    await asyncio.sleep(2.0)
    count = await _count_docs(indexer, indexer_sink._prefix)  # deliberate private access
    assert count == 1, f"expected 1 doc after 5 same-event_id submits, got {count}"
