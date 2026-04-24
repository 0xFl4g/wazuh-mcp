"""Auto-instrumentation wiring applies and is idempotent."""
from __future__ import annotations

import pytest

from wazuh_mcp.observability.instrumentation import (
    instrument_httpx,
    instrument_starlette,
    uninstrument_all,
)
from wazuh_mcp.observability.otel import init_otel, shutdown_otel


@pytest.fixture(autouse=True)
def _setup():
    init_otel(service_version="0.4.0-dev")
    yield
    uninstrument_all()
    shutdown_otel()


def test_httpx_instrumentation_applies_once() -> None:
    instrument_httpx()
    instrument_httpx()  # no-op on second call


def test_starlette_instrumentation_applies_to_app() -> None:
    from starlette.applications import Starlette

    app = Starlette()
    instrument_starlette(app)
    # idempotent
    instrument_starlette(app)
