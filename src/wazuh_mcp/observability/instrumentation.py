"""Thin wrapper around OTel auto-instrumentation — keeps setup callsites
centralised in server.py/transport/http.py and lets tests toggle it.
"""
from __future__ import annotations

from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
from opentelemetry.instrumentation.starlette import StarletteInstrumentor
from starlette.applications import Starlette

_httpx_instrumented = False


def instrument_httpx() -> None:
    global _httpx_instrumented
    if _httpx_instrumented:
        return
    HTTPXClientInstrumentor().instrument()
    _httpx_instrumented = True


def instrument_starlette(app: Starlette) -> None:
    # StarletteInstrumentor.instrument_app is idempotent in
    # opentelemetry-instrumentation-starlette 0.62b0 — calling it twice on the
    # same app does not raise. If a future release changes that, catch the
    # "already instrumented" exception here.
    StarletteInstrumentor.instrument_app(app)


def uninstrument_all() -> None:
    global _httpx_instrumented
    if _httpx_instrumented:
        HTTPXClientInstrumentor().uninstrument()
        _httpx_instrumented = False
