"""CLI entry point: `python -m wazuh_mcp` or `wazuh-mcp`.

Reads config directory from $WAZUH_MCP_CONFIG_DIR, defaulting to ./config.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from wazuh_mcp.server import run_stdio


def main() -> int:
    config_dir = Path(os.environ.get("WAZUH_MCP_CONFIG_DIR", "./config")).resolve()
    if not config_dir.is_dir():
        print(f"Config directory not found: {config_dir}", file=sys.stderr)
        return 2
    run_stdio(config_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
