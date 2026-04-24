"""HttpSink: batched POSTs with backoff on transient failure."""
from __future__ import annotations

import asyncio

import pytest

from wazuh_mcp.observability.sinks.http import HttpSink


@pytest.mark.asyncio
async def test_batches_and_posts(httpx_mock) -> None:
    httpx_mock.add_response(url="https://siem.example/ingest", method="POST", status_code=200)
    sink = HttpSink(url="https://siem.example/ingest", batch=3, flush_ms=100, max_attempts=3)
    await sink.start()
    for i in range(3):
        sink.submit({"n": i})
    # Give the flush loop time to pick up the batch.
    await asyncio.sleep(0.3)
    await sink.stop()
    reqs = httpx_mock.get_requests()
    assert len(reqs) >= 1
    # Combined payload is the batch.
    body = reqs[0].read()
    assert b'"n":0' in body and b'"n":1' in body and b'"n":2' in body


@pytest.mark.asyncio
async def test_retries_on_5xx_then_succeeds(httpx_mock) -> None:
    httpx_mock.add_response(url="https://siem.example/ingest", status_code=503)
    httpx_mock.add_response(url="https://siem.example/ingest", status_code=200)
    sink = HttpSink(url="https://siem.example/ingest", batch=1, flush_ms=10, max_attempts=3,
                    backoff_base_s=0.001)
    await sink.start()
    sink.submit({"n": 1})
    await asyncio.sleep(0.3)
    await sink.stop()
    assert len(httpx_mock.get_requests()) == 2


@pytest.mark.asyncio
@pytest.mark.httpx_mock(assert_all_responses_were_requested=False)
async def test_drops_after_max_attempts(httpx_mock) -> None:
    for _ in range(5):
        httpx_mock.add_response(url="https://siem.example/ingest", status_code=503)
    drops: list[str] = []
    sink = HttpSink(url="https://siem.example/ingest", batch=1, flush_ms=10, max_attempts=3,
                    backoff_base_s=0.001)
    sink._record_drop = lambda ev, reason: drops.append(reason)
    await sink.start()
    sink.submit({"n": 1})
    await asyncio.sleep(0.5)
    await sink.stop()
    assert "delivery_failed" in drops
