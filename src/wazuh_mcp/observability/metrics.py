"""Prom metric definitions, /metrics route factory, optional stdio
metrics HTTP server.
"""
from __future__ import annotations

import os
from functools import lru_cache
from typing import Any

from opentelemetry import metrics
from prometheus_client import generate_latest
from prometheus_client.exposition import CONTENT_TYPE_LATEST
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.routing import Route

from wazuh_mcp.observability.otel import prom_registry


@lru_cache(maxsize=1)
def m4_counters() -> dict[str, Any]:
    meter = metrics.get_meter("wazuh_mcp")
    return {
        "mcp_tool_calls_total": meter.create_counter(
            "mcp_tool_calls_total",
            description="MCP tool invocations, labeled by tenant/tool/outcome.",
        ),
        "mcp_tool_duration_seconds": meter.create_histogram(
            "mcp_tool_duration_seconds",
            description="Tool invocation latency in seconds.",
            explicit_bucket_boundaries_advisory=[
                0.005,
                0.010,
                0.025,
                0.050,
                0.100,
                0.250,
                0.500,
                1.0,
                2.5,
                5.0,
                10.0,
            ],
        ),
        "wazuh_upstream_errors_total": meter.create_counter(
            "wazuh_upstream_errors_total",
            description="Upstream Wazuh errors, labeled by tenant/upstream/code.",
        ),
        "jwt_refresh_total": meter.create_counter(
            "jwt_refresh_total",
            description="Wazuh Server API JWT refresh attempts.",
        ),
        "rate_limited_total": meter.create_counter(
            "rate_limited_total",
            description="Rate-limit denials, labeled by tenant/scope.",
        ),
        "audit_dropped_total": meter.create_counter(
            "audit_dropped_total",
            description="Audit events dropped, labeled by sink/reason.",
        ),
    }


async def _metrics_endpoint(request: Request) -> PlainTextResponse:
    body = generate_latest(prom_registry())
    return PlainTextResponse(body.decode("utf-8"), media_type=CONTENT_TYPE_LATEST)


def build_metrics_route() -> Route:
    return Route("/metrics", _metrics_endpoint, methods=["GET"])


def maybe_start_stdio_metrics_server() -> None:
    """If WAZUH_MCP_METRICS_ADDR is set, spin up a tiny HTTP server on that addr
    exposing /metrics. Only useful under stdio transport where the HTTP app
    doesn't mount the route. Uses prometheus_client's start_http_server which
    runs a WSGI server on a background thread."""
    addr = os.environ.get("WAZUH_MCP_METRICS_ADDR")
    if not addr:
        return
    host, _, port = addr.rpartition(":")
    from prometheus_client import start_http_server

    start_http_server(int(port), addr=host or "0.0.0.0", registry=prom_registry())
