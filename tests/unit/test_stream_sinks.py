"""StderrSink and StdoutSink: JSON lines to a stream."""
from __future__ import annotations

import io
import json

import pytest

from wazuh_mcp.observability.sinks.stream import StderrSink, StdoutSink


@pytest.mark.asyncio
async def test_stderr_sink_writes_jsonl() -> None:
    stream = io.StringIO()
    sink = StderrSink(stream=stream)
    await sink.start()
    sink.submit({"tool": "alerts.search_alerts", "n": 1})
    sink.submit({"tool": "hunt.hunt_query", "n": 2})
    await sink.stop()
    lines = stream.getvalue().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["tool"] == "alerts.search_alerts"
    assert json.loads(lines[1])["tool"] == "hunt.hunt_query"


@pytest.mark.asyncio
async def test_stdout_sink_defaults_to_stdout(monkeypatch, capsys) -> None:
    sink = StdoutSink()
    await sink.start()
    sink.submit({"x": 1})
    await sink.stop()
    captured = capsys.readouterr()
    assert json.loads(captured.out.strip())["x"] == 1
