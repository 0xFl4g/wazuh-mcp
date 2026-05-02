"""@instrumented_tool composes the M4a cross-cutting concerns around every
MCP tool handler:

  1. RBAC guard (forbidden if not allowed).
  2. Rate limit acquire (rate_limited if buckets exhausted).
  3. OpenTelemetry span (`mcp.tool.call`).
  4. Run handler.
  5. Audit emit on every exit path (ok / error / cancelled).
  6. Metric bumps: mcp_tool_calls_total, mcp_tool_duration_seconds.

RBAC policy is recomputed per-call via a callable that takes the current
Session (so per-tenant overrides are applied at the source of truth); the
callable MUST accept a single Session argument.

Outcome vocabulary: the spec lists ``ok``, ``error``, ``rate_limited``,
``forbidden``, ``auth_expired``, ``not_found``, ``upstream_error``,
``upstream_timeout``, ``invalid_query``. This decorator also uses
``cancelled`` as an operational outcome when the handler is cancelled
mid-flight (e.g. starlette/HTTP client abort) — the audit is still
emitted with ``outcome="error"`` and ``error_code="cancelled"`` so a
tenant cannot burn their rate-limit budget without leaving an audit
trail.
"""

from __future__ import annotations

import functools
import inspect
import time
from collections.abc import Awaitable, Callable
from typing import Any, get_type_hints

from opentelemetry import trace
from pydantic import BaseModel
from pydantic import ValidationError as _PydanticValidationError
from pydantic_core import PydanticUndefined

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import MultiSinkAuditEmitter
from wazuh_mcp.observability.metrics import m4_counters
from wazuh_mcp.rate_limit.limiter import RateLimiter
from wazuh_mcp.rbac.filter import is_allowed
from wazuh_mcp.transport.session_ctx import current_session
from wazuh_mcp.wazuh.errors import WazuhError


def _signature_from_args_model(
    args_model: type[BaseModel],
    return_annotation: Any = inspect.Signature.empty,
) -> inspect.Signature:
    """Build a flat keyword-only ``Signature`` from a Pydantic Args model.

    FastMCP's ``func_metadata`` introspects the wrapped tool function via
    ``inspect.signature(...)`` and creates a Pydantic Args model with one
    field per parameter. With the decorator's ``_inner(**kwargs)`` runtime,
    the introspected signature collapses to a single ``kwargs`` field —
    every wire-level tool call then fails at the Pydantic-validation step
    with ``kwargs Field required``.

    Setting ``__signature__`` on the wrapper bypasses that collapse:
    ``inspect.signature`` honours ``__signature__`` first, before walking
    ``__wrapped__`` or doing parameter inspection. Fields are surfaced
    keyword-only with their ``Annotated[T, FieldInfo(...)]`` so descriptions
    and constraints land in the JSON Schema FastMCP exposes to clients.

    ``return_annotation`` is forwarded so FastMCP's structured-output
    detection sees the real Pydantic result model (e.g. ``SearchAlertsResult``)
    and emits ``CallToolResult.structuredContent`` for clients that want
    typed payloads instead of unstructured text.
    """
    hints = get_type_hints(args_model, include_extras=True)
    params: list[inspect.Parameter] = []
    for name, field in args_model.model_fields.items():
        annotation = hints.get(name, field.annotation)
        default: Any = (
            field.default if field.default is not PydanticUndefined else inspect.Parameter.empty
        )
        params.append(
            inspect.Parameter(
                name,
                inspect.Parameter.KEYWORD_ONLY,
                default=default,
                annotation=annotation,
            )
        )
    return inspect.Signature(parameters=params, return_annotation=return_annotation)


def instrumented_tool(
    *,
    tool_name: str,
    handler: Callable[..., Awaitable[Any]],
    rbac_policy: Callable[[Session], dict[str, list[str]]],
    limiter: RateLimiter,
    audit: MultiSinkAuditEmitter,
    args_model: type[BaseModel] | None = None,
    result_model: type[BaseModel] | None = None,
) -> Callable[..., Awaitable[Any]]:
    tracer = trace.get_tracer("wazuh_mcp")
    counters = m4_counters()

    async def _inner(**kwargs: Any) -> Any:
        session = current_session()

        # 1. RBAC — rbac_policy is always session-aware (explicit contract).
        policy = rbac_policy(session)
        if not is_allowed(session, tool_name, policy):
            err = WazuhError(
                "forbidden",
                f"{tool_name} not permitted for role {session.rbac_role!r}",
                403,
            )
            audit.emit(
                session=session,
                tool=tool_name,
                args=kwargs,
                outcome="error",
                result_count=0,
                duration_ms=0,
                error_code="forbidden",
            )
            counters["mcp_tool_calls_total"].add(
                1,
                {"tenant": session.tenant_id, "tool": tool_name, "outcome": "forbidden"},
            )
            raise err

        # 2. Rate limit
        try:
            await limiter.acquire(session.tenant_id, session.user_id)
        except WazuhError as rle:
            # T-G1: read structured scope field directly. Fall back to "session"
            # for any rate_limited raise that didn't set scope (defensive — all
            # in-tree raise sites set it).
            scope = "tenant" if rle.scope == "rate_limit:tenant" else "session"
            counters["rate_limited_total"].add(1, {"tenant": session.tenant_id, "scope": scope})
            counters["mcp_tool_calls_total"].add(
                1,
                {
                    "tenant": session.tenant_id,
                    "tool": tool_name,
                    "outcome": "rate_limited",
                },
            )
            audit.emit(
                session=session,
                tool=tool_name,
                args=kwargs,
                outcome="error",
                result_count=0,
                duration_ms=0,
                error_code="rate_limited",
            )
            raise

        # 3. Span + 4. handler + 5. audit + 6. metrics
        start = time.perf_counter()
        with tracer.start_as_current_span("mcp.tool.call") as span:
            span.set_attribute("mcp.tool.name", tool_name)
            span.set_attribute("mcp.session.id", session.user_id)
            span.set_attribute("mcp.tenant.id", session.tenant_id)
            span.set_attribute("mcp.user.id", session.user_id)

            # M4b: write tools emit a pre-call "requested" event so operators
            # see intent even if the handler fails, is cancelled, or is
            # rejected for missing confirm / allowlist. Net audit events per
            # write call: exactly 2 (requested + completion-or-error).
            if tool_name.startswith("write."):
                audit.emit(
                    session=session,
                    tool=tool_name,
                    args=kwargs,
                    outcome="write.requested",
                    result_count=0,
                    duration_ms=0,
                )

            try:
                result = await handler(**kwargs)
            except WazuhError as e:
                elapsed = time.perf_counter() - start
                span.set_attribute("mcp.outcome", e.code)
                counters["mcp_tool_calls_total"].add(
                    1,
                    {
                        "tenant": session.tenant_id,
                        "tool": tool_name,
                        "outcome": e.code,
                    },
                )
                counters["mcp_tool_duration_seconds"].record(
                    elapsed,
                    {"tenant": session.tenant_id, "tool": tool_name},
                )
                audit.emit(
                    session=session,
                    tool=tool_name,
                    args=kwargs,
                    outcome="error",
                    result_count=0,
                    duration_ms=int(elapsed * 1000),
                    error_code=e.code,
                )
                raise
            except _PydanticValidationError:
                # Preserve the M3 `parse_error` label. Pre-refactor, each
                # tool body caught ValidationError and emitted error_code=
                # parse_error directly; post-refactor the inner handler
                # raises and the decorator has to keep that label visible
                # in both the metric and the audit trail.
                elapsed = time.perf_counter() - start
                span.set_attribute("mcp.outcome", "parse_error")
                counters["mcp_tool_calls_total"].add(
                    1,
                    {
                        "tenant": session.tenant_id,
                        "tool": tool_name,
                        "outcome": "parse_error",
                    },
                )
                counters["mcp_tool_duration_seconds"].record(
                    elapsed,
                    {"tenant": session.tenant_id, "tool": tool_name},
                )
                audit.emit(
                    session=session,
                    tool=tool_name,
                    args=kwargs,
                    outcome="error",
                    result_count=0,
                    duration_ms=int(elapsed * 1000),
                    error_code="parse_error",
                )
                raise
            except Exception:
                elapsed = time.perf_counter() - start
                span.set_attribute("mcp.outcome", "error")
                counters["mcp_tool_calls_total"].add(
                    1,
                    {
                        "tenant": session.tenant_id,
                        "tool": tool_name,
                        "outcome": "error",
                    },
                )
                counters["mcp_tool_duration_seconds"].record(
                    elapsed,
                    {"tenant": session.tenant_id, "tool": tool_name},
                )
                audit.emit(
                    session=session,
                    tool=tool_name,
                    args=kwargs,
                    outcome="error",
                    result_count=0,
                    duration_ms=int(elapsed * 1000),
                    error_code="internal",
                )
                raise
            except BaseException:
                # Cancellation / SystemExit / KeyboardInterrupt — must NOT
                # swallow, but the rate-limit token was already consumed so
                # we owe an audit + metric bump before the exception
                # propagates. Keeps the "never lose an audit for a call we
                # charged for" invariant.
                elapsed = time.perf_counter() - start
                span.set_attribute("mcp.outcome", "cancelled")
                counters["mcp_tool_calls_total"].add(
                    1,
                    {
                        "tenant": session.tenant_id,
                        "tool": tool_name,
                        "outcome": "cancelled",
                    },
                )
                counters["mcp_tool_duration_seconds"].record(
                    elapsed,
                    {"tenant": session.tenant_id, "tool": tool_name},
                )
                audit.emit(
                    session=session,
                    tool=tool_name,
                    args=kwargs,
                    outcome="error",
                    result_count=0,
                    duration_ms=int(elapsed * 1000),
                    error_code="cancelled",
                )
                raise
            else:
                elapsed = time.perf_counter() - start
                span.set_attribute("mcp.outcome", "ok")
                counters["mcp_tool_calls_total"].add(
                    1,
                    {"tenant": session.tenant_id, "tool": tool_name, "outcome": "ok"},
                )
                counters["mcp_tool_duration_seconds"].record(
                    elapsed,
                    {"tenant": session.tenant_id, "tool": tool_name},
                )
                # Best-effort result_count discovery from Pydantic results.
                # Attrs enumerated here are the list-valued fields on every
                # M3 result model (SearchAlertsResult.alerts, AgentsResult.agents,
                # AgentInventoryResult.items, VulnerabilitiesResult.vulnerabilities,
                # MitreSearchResult.techniques, FimResult.events, HuntQueryResult.alerts).
                # Singleton results (GetAlertResult, AgentResult, MitreTechniqueResult)
                # fall through to count=0 by design — the decorator can't know
                # "single item" without a result-model registry, and 0 keeps the
                # shape consistent with error paths.
                count = 0
                for attr in (
                    "alerts",
                    "agents",
                    "items",
                    "results",
                    "vulnerabilities",
                    "techniques",
                    "events",
                ):
                    val = getattr(result, attr, None)
                    if isinstance(val, list):
                        count = len(val)
                        break
                audit.emit(
                    session=session,
                    tool=tool_name,
                    args=kwargs,
                    outcome="ok",
                    result_count=count,
                    duration_ms=int(elapsed * 1000),
                )
                return result

    # functools.wraps preserves __doc__ and __qualname__ for diagnostic
    # clarity. A distinct __name__ is restored so audit traces and FastMCP's
    # generated Args model name (``{func.__name__}Arguments``) carry the
    # tool identity rather than the inner handler's. ``__signature__`` is
    # synthesized from ``args_model`` so FastMCP's signature-based schema
    # introspection sees the typed fields instead of collapsing to a single
    # ``kwargs`` parameter.
    wrapped = functools.wraps(handler)(_inner)
    wrapped.__name__ = f"instrumented_{tool_name.replace('.', '_')}"
    if args_model is not None:
        # ``result_model`` is passed explicitly rather than read from
        # ``handler``'s return annotation: under PEP 563 (which the wiring
        # module enables) ``inspect.signature(handler).return_annotation``
        # is an unresolved string like ``"SearchAlertsResult"``, and the
        # locally-imported class isn't on the handler's module globals so
        # ``get_type_hints`` can't resolve it either. The caller knows
        # the class, so it just hands it in.
        return_annotation = result_model if result_model is not None else inspect.Signature.empty
        wrapped.__signature__ = _signature_from_args_model(  # ty: ignore[unresolved-attribute]
            args_model, return_annotation=return_annotation
        )
    return wrapped
