"""/metrics route returns Prometheus text format including M4a families."""
from __future__ import annotations

import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient

from wazuh_mcp.observability.metrics import build_metrics_route, m4_counters
from wazuh_mcp.observability.otel import init_otel, shutdown_otel


@pytest.fixture(autouse=True)
def _setup():
    init_otel(service_version="0.4.0-dev")
    m4_counters.cache_clear()
    yield
    m4_counters.cache_clear()
    shutdown_otel()


def test_metrics_route_returns_200_and_text_format() -> None:
    app = Starlette(routes=[build_metrics_route()])
    counters = m4_counters()
    counters["mcp_tool_calls_total"].add(
        1, {"tenant": "t1", "tool": "alerts.search_alerts", "outcome": "ok"}
    )
    with TestClient(app) as client:
        resp = client.get("/metrics")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/plain")
    body = resp.text
    assert "mcp_tool_calls_total" in body


def test_all_m4_metric_families_defined() -> None:
    counters = m4_counters()
    for name in [
        "mcp_tool_calls_total",
        "wazuh_upstream_errors_total",
        "jwt_refresh_total",
        "rate_limited_total",
        "audit_dropped_total",
    ]:
        assert name in counters
