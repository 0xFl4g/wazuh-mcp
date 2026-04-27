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


def _policy(session: Session) -> dict[str, list[str]]:
    return {"analyst": ["alerts.*"], "admin": ["*"]}


def _limiter() -> InProcessRateLimiter:
    return InProcessRateLimiter(
        default=RateLimitConfig(
            tenant=BucketConfig(capacity=3, refill_per_sec=1.0),
            session=BucketConfig(capacity=2, refill_per_sec=1.0),
        )
    )


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
        token = CURRENT_SESSION.set(_session("analyst"))  # analyst not allowed hunt.*
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


@pytest.mark.asyncio
async def test_rbac_deny_does_not_consume_rate_limit_token() -> None:
    """Regression guard: a denied call must not consume a rate-limit token."""
    emitter = MultiSinkAuditEmitter(sinks=[StderrSink(stream=io.StringIO())])
    await emitter.start()
    try:
        limiter = InProcessRateLimiter(
            default=RateLimitConfig(
                tenant=BucketConfig(capacity=1, refill_per_sec=1.0),
                session=BucketConfig(capacity=1, refill_per_sec=1.0),
            )
        )
        # analyst is not allowed hunt.*
        denied_wrapped = instrumented_tool(
            tool_name="hunt.hunt_query",
            handler=_handler,
            rbac_policy=_policy,
            limiter=limiter,
            audit=emitter,
        )
        # analyst IS allowed alerts.*
        allowed_wrapped = instrumented_tool(
            tool_name="alerts.search_alerts",
            handler=_handler,
            rbac_policy=_policy,
            limiter=limiter,
            audit=emitter,
        )
        token = CURRENT_SESSION.set(_session("analyst"))
        try:
            with pytest.raises(WazuhError) as exc:
                await denied_wrapped()  # forbidden — MUST NOT consume a token
            assert exc.value.code == "forbidden"
            # If the RBAC-before-rate-limit order holds, the allowed call now succeeds.
            result = await allowed_wrapped()
            assert result == {"count": 1}
        finally:
            CURRENT_SESSION.reset(token)
    finally:
        await emitter.stop()


@pytest.mark.asyncio
async def test_handler_generic_exception_audits_internal_error() -> None:
    """Non-WazuhError exceptions bubble out as outcome=error, error_code=internal."""
    import asyncio

    out = io.StringIO()
    emitter = MultiSinkAuditEmitter(sinks=[StderrSink(stream=out)])
    await emitter.start()
    try:

        async def _boom(**kw):
            raise RuntimeError("unexpected")

        wrapped = instrumented_tool(
            tool_name="alerts.get_alert",
            handler=_boom,
            rbac_policy=_policy,
            limiter=_limiter(),
            audit=emitter,
        )
        token = CURRENT_SESSION.set(_session("admin"))
        try:
            with pytest.raises(RuntimeError):
                await wrapped()
        finally:
            CURRENT_SESSION.reset(token)
        await asyncio.sleep(0.05)
    finally:
        await emitter.stop()
    assert '"outcome": "error"' in out.getvalue()
    assert '"error_code": "internal"' in out.getvalue()


@pytest.mark.asyncio
async def test_cancelled_handler_still_audits() -> None:
    """Cancelled-in-flight handler emits audit with error_code=cancelled."""
    import asyncio

    out = io.StringIO()
    emitter = MultiSinkAuditEmitter(sinks=[StderrSink(stream=out)])
    await emitter.start()
    try:
        started = asyncio.Event()

        async def _slow(**kw):
            started.set()
            await asyncio.sleep(10)  # will be cancelled

        wrapped = instrumented_tool(
            tool_name="alerts.search_alerts",
            handler=_slow,
            rbac_policy=_policy,
            limiter=_limiter(),
            audit=emitter,
        )
        token = CURRENT_SESSION.set(_session("admin"))
        try:
            task = asyncio.create_task(wrapped())
            await started.wait()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        finally:
            CURRENT_SESSION.reset(token)
        await asyncio.sleep(0.05)
    finally:
        await emitter.stop()
    output = out.getvalue()
    assert '"error_code": "cancelled"' in output


@pytest.mark.asyncio
async def test_pydantic_validation_error_audits_parse_error() -> None:
    """Pydantic ValidationError is audited with error_code=parse_error —
    preserves the M3 per-tool label that was lost when the inner handler
    stopped catching ValidationError itself.
    """
    import asyncio

    from pydantic import BaseModel, ValidationError

    class _Args(BaseModel):
        n: int

    out = io.StringIO()
    emitter = MultiSinkAuditEmitter(sinks=[StderrSink(stream=out)])
    await emitter.start()
    try:

        async def _bad(**kw):
            _Args(**kw)  # raises ValidationError for n=non-int
            return {}

        wrapped = instrumented_tool(
            tool_name="alerts.search_alerts",
            handler=_bad,
            rbac_policy=_policy,
            limiter=_limiter(),
            audit=emitter,
        )
        token = CURRENT_SESSION.set(_session("admin"))
        try:
            with pytest.raises(ValidationError):
                await wrapped(n="not_an_int")
        finally:
            CURRENT_SESSION.reset(token)
        await asyncio.sleep(0.05)
    finally:
        await emitter.stop()
    assert '"error_code": "parse_error"' in out.getvalue()


@pytest.mark.asyncio
async def test_functools_wraps_preserved() -> None:
    """functools.wraps preserves __wrapped__ and __doc__ for FastMCP introspection."""

    async def _original(**kw) -> dict:
        """Original docstring."""
        return {}

    emitter = MultiSinkAuditEmitter(sinks=[StderrSink(stream=io.StringIO())])
    await emitter.start()
    try:
        wrapped = instrumented_tool(
            tool_name="alerts.search_alerts",
            handler=_original,
            rbac_policy=_policy,
            limiter=_limiter(),
            audit=emitter,
        )
        assert wrapped.__wrapped__ is _original  # ty: ignore[unresolved-attribute]
        assert wrapped.__doc__ == "Original docstring."
    finally:
        await emitter.stop()


@pytest.mark.asyncio
async def test_write_tool_emits_requested_then_completed_audit() -> None:
    """A write.* tool emits exactly one write.requested event BEFORE handler
    and one completion event AFTER. Ordering assert-able via a sequential
    sink."""
    import asyncio
    import io

    out = io.StringIO()
    emitter = MultiSinkAuditEmitter(sinks=[StderrSink(stream=out)])
    await emitter.start()
    try:

        async def _handler(**kw):
            return {"ok": True}

        wrapped = instrumented_tool(
            tool_name="write.isolate_agent",
            handler=_handler,
            rbac_policy=_policy,
            limiter=_limiter(),
            audit=emitter,
        )
        token = CURRENT_SESSION.set(_session("admin"))
        try:
            await wrapped(agent_id="003", confirm=True)
        finally:
            CURRENT_SESSION.reset(token)
        await asyncio.sleep(0.05)
    finally:
        await emitter.stop()
    events = [line for line in out.getvalue().splitlines() if line]
    # Two events: requested + ok.
    assert len(events) == 2
    assert '"outcome": "write.requested"' in events[0]
    assert '"tool": "write.isolate_agent"' in events[0]
    assert '"outcome": "ok"' in events[1]
    assert '"tool": "write.isolate_agent"' in events[1]


@pytest.mark.asyncio
async def test_write_tool_requested_audit_then_error_on_upstream_failure() -> None:
    """If the handler raises, the pre-emitted requested event still lands; the
    decorator emits the error completion. Exactly two events."""
    import asyncio
    import io

    out = io.StringIO()
    emitter = MultiSinkAuditEmitter(sinks=[StderrSink(stream=out)])
    await emitter.start()
    try:

        async def _handler(**kw):
            raise WazuhError("upstream_error", "boom", 502)

        wrapped = instrumented_tool(
            tool_name="write.restart_agent",
            handler=_handler,
            rbac_policy=_policy,
            limiter=_limiter(),
            audit=emitter,
        )
        token = CURRENT_SESSION.set(_session("admin"))
        try:
            with pytest.raises(WazuhError):
                await wrapped(agent_id="003", confirm=True)
        finally:
            CURRENT_SESSION.reset(token)
        await asyncio.sleep(0.05)
    finally:
        await emitter.stop()
    events = [line for line in out.getvalue().splitlines() if line]
    assert len(events) == 2
    assert '"outcome": "write.requested"' in events[0]
    assert '"outcome": "error"' in events[1]
    assert '"error_code": "upstream_error"' in events[1]


@pytest.mark.asyncio
async def test_non_write_tool_emits_single_audit_as_before() -> None:
    """Non-write tools keep the M4a single-event contract."""
    import asyncio
    import io

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
        token = CURRENT_SESSION.set(_session("admin"))
        try:
            await wrapped()
        finally:
            CURRENT_SESSION.reset(token)
        await asyncio.sleep(0.05)
    finally:
        await emitter.stop()
    events = [line for line in out.getvalue().splitlines() if line]
    assert len(events) == 1
    assert '"outcome": "ok"' in events[0]


def test_args_model_surfaces_typed_fields_to_fastmcp_introspection() -> None:
    """Pin: FastMCP must see flat typed fields, not collapse to ``kwargs``.

    Latent regression caught after M4a/M4b shipped: the decorator's
    ``_inner(**kwargs)`` was visible to ``inspect.signature`` so FastMCP's
    schema-from-signature introspection produced a single ``kwargs: Any``
    field. Every wire-level tool call then failed at Pydantic validation
    with ``kwargs Field required`` — invisible to unit tests that called
    the wrapper directly with kwargs, and to local arm64+darwin runners
    that auto-skip the integration suite.

    Asserts the schema FastMCP would generate matches the supplied
    ``args_model`` field names. If anyone removes the ``args_model``
    plumbing or drops ``__signature__`` injection, this test goes red
    instead of letting the regression sail through to amd64 CI.
    """
    from mcp.server.fastmcp.utilities.func_metadata import func_metadata

    from wazuh_mcp.tools.alerts import SearchAlertsArgs, SearchAlertsResult
    from wazuh_mcp.tools.write import CreateRuleArgs, IsolateAgentArgs, WriteResult

    for tool_name, args, result, expected in [
        (
            "alerts.search_alerts",
            SearchAlertsArgs,
            SearchAlertsResult,
            {"time_range", "min_level", "agent_id", "size", "cursor"},
        ),
        ("write.isolate_agent", IsolateAgentArgs, WriteResult, {"agent_ids", "confirm"}),
        ("write.create_rule", CreateRuleArgs, WriteResult, {"rule", "confirm"}),
    ]:
        wrapped = instrumented_tool(
            tool_name=tool_name,
            handler=_handler,
            rbac_policy=_policy,
            limiter=_limiter(),
            audit=MultiSinkAuditEmitter(sinks=[StderrSink(stream=io.StringIO())]),
            args_model=args,
            result_model=result,
        )
        meta = func_metadata(wrapped)
        actual = set(meta.arg_model.model_fields.keys())
        assert actual == expected, (
            f"{tool_name}: FastMCP saw fields {actual!r}, expected {expected!r} "
            f"(if this is just {{'kwargs'}} the decorator regressed)"
        )
        # Pin structured-output detection too: ``result_model`` must flow
        # through to ``__signature__.return_annotation`` so FastMCP emits
        # ``CallToolResult.structuredContent`` for typed clients.
        assert meta.output_model is result, (
            f"{tool_name}: FastMCP output_model={meta.output_model!r}, expected {result!r}"
        )
        assert meta.output_schema is not None, (
            f"{tool_name}: missing output_schema (structuredContent broken)"
        )
