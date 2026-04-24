"""OTel bootstrap wires a TracerProvider + MeterProvider with Prom reader."""
from __future__ import annotations

from typing import Any, cast

import pytest
from opentelemetry import metrics, trace

from wazuh_mcp.observability.otel import init_otel, shutdown_otel


@pytest.fixture(autouse=True)
def _reset_global_providers():
    yield
    shutdown_otel()


def test_init_sets_global_providers() -> None:
    init_otel(service_version="0.4.0-dev")
    tracer = trace.get_tracer("test")
    meter = metrics.get_meter("test")
    assert tracer is not None
    assert meter is not None


def test_resource_attrs_present() -> None:
    init_otel(service_version="0.4.0-dev")
    tp = trace.get_tracer_provider()
    # Real SDK attaches resource on concrete providers; the proxy returned by
    # get_tracer_provider before init exposes a resource attr after SDK setup.
    assert hasattr(tp, "resource")
    attrs = cast(Any, tp).resource.attributes
    assert attrs.get("service.name") == "wazuh-mcp"
    assert attrs.get("service.version") == "0.4.0-dev"
    assert attrs.get("service.namespace") == "wazuh"


def test_reinitialize_is_idempotent() -> None:
    init_otel(service_version="0.4.0-dev")
    # Second call must not raise.
    init_otel(service_version="0.4.0-dev")
