"""@instrumented_tool orchestrates RBAC → rate_limit → span → handler → audit."""
from __future__ import annotations

import io
from typing import Any
from unittest.mock import AsyncMock

import pytest

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import MultiSinkAuditEmitter
from wazuh_mcp.observability.decorators import instrumented_tool
from wazuh_mcp.observability.otel import init_otel, shutdown_otel
from wazuh_mcp.observability.sinks.stream import StderrSink
from wazuh_mcp.rate_limit.limiter import InProcessRateLimiter
from wazuh_mcp.tenancy.m4_config import BucketConfig, RateLimitConfig
from wazuh_mcp.transport.session_ctx import CURRENT_SESSION
from wazuh_mcp.wazuh.errors import WazuhError


@pytest.fixture(autouse=True)
def _otel():
    init_otel(service_version="0.4.0-dev")
    yield
    shutdown_otel()


def _policy(session=None) -> dict[str, list[str]]:
    return {"analyst": ["alerts.*"], "admin": ["*"]}


def _limiter() -> InProcessRateLimiter:
    return InProcessRateLimiter(default=RateLimitConfig(
        tenant=BucketConfig(capacity=3, refill_per_sec=1.0),
        session=BucketConfig(capacity=2, refill_per_sec=1.0),
    ))


async def _handler(**kwargs: Any) -> dict[str, int]:
    return {"count": 1}


def _session(role: str = "analyst") -> Session:
    return Session(user_id="u", tenant_id="t", rbac_role=role, auth_method="config")


async def _drain(emitter: MultiSinkAuditEmitter) -> None:
    import asyncio
    await asyncio.sleep(0.05)


@pytest.mark.asyncio
async def test_happy_path_calls_handler_and_audits() -> None:
    out = io.StringIO()
    emitter = MultiSinkAuditEmitter(sinks=[StderrSink(stream=out)])
    await emitter.start()
    try:
        wrapped = instrumented_tool(
            tool_name="alerts.search_alerts",
            handler=_handler,
            rbac_policy=_policy,
            limiter=_limiter(),
            audit=emitter,
        )
        token = CURRENT_SESSION.set(_session())
        try:
            result = await wrapped(q="x")
        finally:
            CURRENT_SESSION.reset(token)
        assert result == {"count": 1}
        await _drain(emitter)
    finally:
        await emitter.stop()
    assert '"tool": "alerts.search_alerts"' in out.getvalue()
    assert '"outcome": "ok"' in out.getvalue()


@pytest.mark.asyncio
async def test_rbac_deny_returns_forbidden_without_handler_call() -> None:
    emitter = MultiSinkAuditEmitter(sinks=[StderrSink(stream=io.StringIO())])
    await emitter.start()
    try:
        handler = AsyncMock()
        wrapped = instrumented_tool(
            tool_name="hunt.hunt_query",
            handler=handler,
            rbac_policy=_policy,
            limiter=_limiter(),
            audit=emitter,
        )
        token = CURRENT_SESSION.set(_session("analyst"))   # analyst not allowed hunt.*
        try:
            with pytest.raises(WazuhError) as exc:
                await wrapped()
            assert exc.value.code == "forbidden"
        finally:
            CURRENT_SESSION.reset(token)
        handler.assert_not_called()
    finally:
        await emitter.stop()


@pytest.mark.asyncio
async def test_rate_limit_exhaustion_returns_rate_limited() -> None:
    emitter = MultiSinkAuditEmitter(sinks=[StderrSink(stream=io.StringIO())])
    await emitter.start()
    try:
        limiter = _limiter()
        wrapped = instrumented_tool(
            tool_name="alerts.search_alerts",
            handler=_handler,
            rbac_policy=_policy,
            limiter=limiter,
            audit=emitter,
        )
        token = CURRENT_SESSION.set(_session())
        try:
            await wrapped()
            await wrapped()
            with pytest.raises(WazuhError) as exc:
                await wrapped()
            assert exc.value.code == "rate_limited"
        finally:
            CURRENT_SESSION.reset(token)
    finally:
        await emitter.stop()


@pytest.mark.asyncio
async def test_handler_exception_audits_error_outcome() -> None:
    out = io.StringIO()
    emitter = MultiSinkAuditEmitter(sinks=[StderrSink(stream=out)])
    await emitter.start()
    try:
        async def _bad(**kw):
            raise WazuhError("upstream_error", "boom", 502)
        wrapped = instrumented_tool(
            tool_name="alerts.get_alert",
            handler=_bad,
            rbac_policy=_policy,
            limiter=_limiter(),
            audit=emitter,
        )
        token = CURRENT_SESSION.set(_session("admin"))
        try:
            with pytest.raises(WazuhError):
                await wrapped()
        finally:
            CURRENT_SESSION.reset(token)
        await _drain(emitter)
    finally:
        await emitter.stop()
    assert '"outcome": "error"' in out.getvalue()
    assert '"error_code": "upstream_error"' in out.getvalue()
