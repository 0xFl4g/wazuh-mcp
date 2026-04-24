"""FileSink: JSON lines + size-based rotation + keep-N."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from wazuh_mcp.observability.sinks.file import FileSink


@pytest.mark.asyncio
async def test_writes_jsonl(tmp_path: Path) -> None:
    log = tmp_path / "audit.log"
    sink = FileSink(path=log, rotate_size_bytes=10_000, keep=3)
    await sink.start()
    for i in range(5):
        sink.submit({"n": i})
    await sink.stop()
    lines = log.read_text().splitlines()
    assert len(lines) == 5
    assert [json.loads(x)["n"] for x in lines] == list(range(5))


@pytest.mark.asyncio
async def test_rotation_creates_numbered_archives(tmp_path: Path) -> None:
    log = tmp_path / "audit.log"
    # Very small rotate_size_bytes forces rotation after almost every write.
    sink = FileSink(path=log, rotate_size_bytes=50, keep=3)
    await sink.start()
    for i in range(20):
        sink.submit({"n": i, "pad": "x" * 40})
    await sink.stop()
    # Expect audit.log (current) + audit.log.1, .2, .3 (archives)
    archives = sorted(tmp_path.glob("audit.log.*"))  # noqa: ASYNC240
    assert 1 <= len(archives) <= 3


@pytest.mark.asyncio
async def test_keep_bounds_archives(tmp_path: Path) -> None:
    log = tmp_path / "audit.log"
    sink = FileSink(path=log, rotate_size_bytes=50, keep=2)
    await sink.start()
    for i in range(100):
        sink.submit({"n": i, "pad": "x" * 40})
    await sink.stop()
    archives = list(tmp_path.glob("audit.log.*"))  # noqa: ASYNC240
    assert len(archives) <= 2
