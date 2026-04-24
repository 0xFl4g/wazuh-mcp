"""File-backed audit sink with size-based rotation.

Rotation: when the current file exceeds rotate_size_bytes, close it,
shift existing archives (.1 -> .2, .2 -> .3, ...), move current to .1,
and open a new current. `keep` caps the number of archives retained.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from wazuh_mcp.observability.sinks.base import QueuedSink


class FileSink(QueuedSink):
    name = "file"

    def __init__(
        self,
        *,
        path: Path,
        rotate_size_bytes: int = 100 * 1024 * 1024,
        keep: int = 5,
        **kw: Any,
    ) -> None:
        super().__init__(**kw)
        self._path = path
        self._rotate_size = rotate_size_bytes
        self._keep = keep
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def _rotate_if_needed(self) -> None:
        if not self._path.exists():
            return
        if self._path.stat().st_size < self._rotate_size:
            return
        # Shift archives: .N -> .N+1 (drop the oldest if beyond keep)
        for i in range(self._keep, 0, -1):
            src = self._path.with_suffix(self._path.suffix + f".{i}")
            dst = self._path.with_suffix(self._path.suffix + f".{i + 1}")
            if src.exists():
                if i == self._keep:
                    src.unlink()
                else:
                    src.rename(dst)
        # current -> .1
        self._path.rename(self._path.with_suffix(self._path.suffix + ".1"))

    async def _deliver(self, event: dict[str, Any]) -> None:
        self._rotate_if_needed()
        with self._path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")
