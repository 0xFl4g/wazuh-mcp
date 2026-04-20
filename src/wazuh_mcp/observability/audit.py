"""Audit emitter — one structured JSON event per tool call.

M1 writes JSON lines to a stream (stderr by default). The default is stderr,
not stdout, because under the MCP stdio transport the server's stdout is the
JSON-RPC wire: any bytes written to stdout that aren't a framed JSON-RPC
message corrupt the protocol and hang/kill the session. Audit events must
therefore go to stderr (or an injected sink) so they never interleave with
protocol frames.

M4 swaps this for pluggable sinks (file, HTTP, back-to-Wazuh) with async
delivery + bounded disk ring-buffer.
"""

from __future__ import annotations

import hashlib
import json
import sys
from datetime import UTC, datetime
from typing import IO, Any

from wazuh_mcp.auth.session import Session


def _hash_args(args: dict[str, Any]) -> str:
    payload = json.dumps(args, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


class AuditEmitter:
    def __init__(self, stream: IO[str] | None = None) -> None:
        # Default to stderr, not stdout: under stdio MCP transport the server's
        # stdout carries JSON-RPC frames, and interleaving audit events on
        # stdout would corrupt the wire protocol.
        self._stream = stream if stream is not None else sys.stderr

    def emit(
        self,
        *,
        session: Session,
        tool: str,
        args: dict[str, Any],
        outcome: str,
        result_count: int,
        duration_ms: int,
        error_code: str | None = None,
    ) -> None:
        event: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "tool": tool,
            "user": session.user_id,
            "tenant": session.tenant_id,
            "rbac_role": session.rbac_role,
            "arg_hash": _hash_args(args),
            "outcome": outcome,
            "result_count": result_count,
            "duration_ms": duration_ms,
        }
        if error_code is not None:
            event["error_code"] = error_code
        self._stream.write(json.dumps(event) + "\n")
        self._stream.flush()
