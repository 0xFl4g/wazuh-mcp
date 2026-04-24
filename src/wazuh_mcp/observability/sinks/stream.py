"""Stream-backed audit sinks.

StderrSink is the safe default under MCP stdio transport (stdout carries
JSON-RPC frames; writing audit bytes there corrupts the wire).

StdoutSink is opt-in and ONLY safe in HTTP-mode deployments where stdout
isn't on the MCP wire.
"""

from __future__ import annotations

import json
import sys
from typing import IO, Any

from wazuh_mcp.observability.sinks.base import QueuedSink


class StderrSink(QueuedSink):
    name = "stderr"

    def __init__(self, *, stream: IO[str] | None = None, **kw: Any) -> None:
        super().__init__(**kw)
        self._stream = stream if stream is not None else sys.stderr

    async def _deliver(self, event: dict[str, Any]) -> None:
        self._stream.write(json.dumps(event) + "\n")
        self._stream.flush()


class StdoutSink(QueuedSink):
    name = "stdout"

    def __init__(self, *, stream: IO[str] | None = None, **kw: Any) -> None:
        super().__init__(**kw)
        self._stream = stream if stream is not None else sys.stdout

    async def _deliver(self, event: dict[str, Any]) -> None:
        self._stream.write(json.dumps(event) + "\n")
        self._stream.flush()
