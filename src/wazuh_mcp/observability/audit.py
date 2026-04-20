"""Audit emitter — one structured JSON event per tool call.

M1 writes JSON lines to a stream (stdout by default). M4 swaps this for
pluggable sinks (file, HTTP, back-to-Wazuh) with async delivery + bounded
disk ring-buffer.
"""

from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from typing import IO, Any

from wazuh_mcp.auth.session import Session


def _hash_args(args: dict[str, Any]) -> str:
    payload = json.dumps(args, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


class AuditEmitter:
    def __init__(self, stream: IO[str] | None = None) -> None:
        self._stream = stream if stream is not None else sys.stdout

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
            "timestamp": datetime.now(timezone.utc).isoformat(),
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
