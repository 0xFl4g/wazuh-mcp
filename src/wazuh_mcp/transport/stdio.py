"""stdio transport — unchanged from M1.

Separated into this module for parallelism with transport/http.py and so
future transports can be added without touching server.py.
"""

from __future__ import annotations

import asyncio

from mcp.server.fastmcp import FastMCP


def run_stdio(app: FastMCP) -> None:
    asyncio.run(app.run_stdio_async())
