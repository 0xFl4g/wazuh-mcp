"""OpenTelemetry SDK bootstrap.

One TracerProvider + one MeterProvider per process. OTLP endpoint is
configured by the operator via standard OTel env vars
(OTEL_EXPORTER_OTLP_ENDPOINT etc); we don't attempt to interpret them
ourselves. The Prometheus exporter is configured inline and reachable
through metrics.get_meter(...); the /metrics route reads its registry.
"""

from __future__ import annotations

from opentelemetry import metrics, trace
from opentelemetry.exporter.prometheus import PrometheusMetricReader
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from prometheus_client import REGISTRY as _GLOBAL_PROM_REGISTRY
from prometheus_client import CollectorRegistry

_initialized = False
_prom_reader: PrometheusMetricReader | None = None
_prom_registry: CollectorRegistry | None = None


def init_otel(*, service_version: str) -> None:
    global _initialized, _prom_reader, _prom_registry
    if _initialized:
        return
    resource = Resource.create(
        {
            "service.name": "wazuh-mcp",
            "service.version": service_version,
            "service.namespace": "wazuh",
        }
    )
    trace.set_tracer_provider(TracerProvider(resource=resource))
    # OTLP span exporter is auto-wired by the SDK when OTEL_EXPORTER_OTLP_ENDPOINT is set;
    # we deliberately don't add a default SpanProcessor because operators opt in via env.

    # opentelemetry-exporter-prometheus 0.62b0's PrometheusMetricReader writes to
    # prometheus_client's module-level REGISTRY — it doesn't accept a registry kwarg.
    # We capture the global registry so prom_registry() callers (the /metrics route)
    # read from the same place the reader writes to.
    _prom_reader = PrometheusMetricReader()
    _prom_registry = _GLOBAL_PROM_REGISTRY
    metrics.set_meter_provider(MeterProvider(resource=resource, metric_readers=[_prom_reader]))
    _initialized = True


def prom_registry() -> CollectorRegistry:
    if _prom_registry is None:
        raise RuntimeError("init_otel() must be called before prom_registry()")
    return _prom_registry


def shutdown_otel() -> None:
    """Reset global state — used in tests; harmless in production where the
    process exits after."""
    global _initialized, _prom_reader, _prom_registry
    _initialized = False
    _prom_reader = None
    _prom_registry = None
