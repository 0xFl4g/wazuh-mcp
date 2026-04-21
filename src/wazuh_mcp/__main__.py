"""CLI entry point: `python -m wazuh_mcp` or `wazuh-mcp`.

Reads config directory from $WAZUH_MCP_CONFIG_DIR, defaulting to ./config.
Chooses transport via server.yaml `transport:` field (stdio|http).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import yaml


def main() -> int:
    config_dir = Path(os.environ.get("WAZUH_MCP_CONFIG_DIR", "./config")).resolve()
    if not config_dir.is_dir():
        print(f"Config directory not found: {config_dir}", file=sys.stderr)
        return 2

    server_yaml = config_dir / "server.yaml"
    transport = "stdio"
    if server_yaml.is_file():
        data = yaml.safe_load(server_yaml.read_text()) or {}
        transport = str(data.get("transport", "stdio")).lower()

    if transport == "stdio":
        from wazuh_mcp.server import run_stdio

        run_stdio(config_dir)
    elif transport == "http":
        from wazuh_mcp.server import run_http

        run_http(config_dir)
    else:
        print(f"Unknown transport {transport!r}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
