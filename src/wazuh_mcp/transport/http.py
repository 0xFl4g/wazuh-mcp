"""Streamable HTTP transport for MCP.

Wraps FastMCP's streamable_http_app() with:
- SessionMiddleware: per-request auth + session contextvar.
- /.well-known/oauth-protected-resource (RFC 9728).
- /healthz (liveness), /readyz (readiness).

All non-/mcp routes are public (not behind auth). /mcp is protected.
"""

from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any

from starlette.applications import Starlette
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Mount, Route

from wazuh_mcp.auth.errors import AuthError
from wazuh_mcp.auth.factory import RequestContext, SessionFactory
from wazuh_mcp.observability.audit import MultiSinkAuditEmitter
from wazuh_mcp.observability.instrumentation import instrument_httpx, instrument_starlette
from wazuh_mcp.observability.metrics import build_metrics_route
from wazuh_mcp.transport.session_ctx import CURRENT_SESSION, set_current_session


def _title_header(name: str) -> str:
    """Return HTTP canonical title-case form, e.g. 'authorization' -> 'Authorization'.

    ASGI servers (and Starlette) lowercase request header names. Factories
    that look up headers by exact key expect the canonical title-case form,
    so we normalize here before handing the context to the factory.
    """
    return "-".join(part.capitalize() for part in name.split("-"))


class SessionMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app: Any,
        *,
        factory: SessionFactory,
        protect_paths: list[str],
        resource_metadata_url: str = "",
    ) -> None:
        super().__init__(app)
        self._factory = factory
        self._protect = tuple(protect_paths)
        self._metadata_url = resource_metadata_url

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        path = request.url.path
        if not any(path == p or path.startswith(p.rstrip("/") + "/") for p in self._protect):
            return await call_next(request)

        # ASGI/HTTP header names are case-insensitive; Starlette lowercases them.
        # Normalize to HTTP title-case ("Authorization") so factories that do an
        # exact-case lookup still work, while lowercase lookups continue to succeed
        # because title-case is the canonical form most callers expect.
        ctx: RequestContext = {
            "headers": {_title_header(k): v for k, v in request.headers.items()},
            "client_ip": request.client.host if request.client else "",
        }
        try:
            session = await self._factory.build(ctx)
        except AuthError as e:
            # RFC 6750 defines only three valid `error` codes: invalid_request,
            # invalid_token, insufficient_scope. Map http_status to compliant codes
            # so strict parsers (browsers, PKCE libs) don't reject the challenge.
            err_code = "insufficient_scope" if e.http_status == 403 else "invalid_token"
            body = {"error": e.public_message}
            challenge = f'Bearer realm="mcp", error="{err_code}"'
            if self._metadata_url:
                # RFC 9728 / MCP 2025-06-18: advertise the protected-resource
                # metadata URL on 401 so clients can discover the auth server
                # without a preflight.
                challenge += f', resource_metadata="{self._metadata_url}"'
            headers = {"WWW-Authenticate": challenge}
            return JSONResponse(body, status_code=e.http_status, headers=headers)

        token = set_current_session(session)
        try:
            return await call_next(request)
        finally:
            CURRENT_SESSION.reset(token)


def _metadata_handler_factory(
    metadata: dict[str, Any],
) -> Callable[[Request], Awaitable[Response]]:
    async def _oauth_protected_resource(request: Request) -> Response:
        return JSONResponse(metadata)

    return _oauth_protected_resource


def build_metadata_endpoint(*, resource_url: str, authorization_server: str) -> Starlette:
    metadata = {
        "resource": resource_url,
        "authorization_servers": [authorization_server],
        "bearer_methods_supported": ["header"],
        "scopes_supported": [],
    }
    handler = _metadata_handler_factory(metadata)
    app = Starlette(
        routes=[
            Route(
                "/.well-known/oauth-protected-resource",
                handler,
                methods=["GET"],
            )
        ]
    )
    return app


def _rate_limiter_health(limiter: object | None) -> dict[str, str]:
    """Return a {backend, redis} status dict for the /healthz response."""
    if limiter is None:
        return {"backend": "none", "redis": "disabled"}
    # Lazy import to avoid pulling redis-py into modules that don't use it.
    from wazuh_mcp.rate_limit.redis_limiter import BreakerState, RedisRateLimiter

    if isinstance(limiter, RedisRateLimiter):
        state = limiter._breaker.state  # deliberate access to breaker state
        if state == BreakerState.CLOSED:
            return {"backend": "redis", "redis": "ok"}
        return {"backend": "redis", "redis": "degraded"}
    return {"backend": "in_process", "redis": "disabled"}


def _make_healthz_handler(
    limiter: object | None = None,
) -> Callable[[Request], Awaitable[Response]]:
    async def _healthz(request: Request) -> Response:
        body: dict[str, object] = {"status": "ok"}
        body["rate_limiter"] = _rate_limiter_health(limiter)
        return JSONResponse(body, status_code=200)

    return _healthz


def build_health_endpoints(*, ready_fn: Callable[[], bool]) -> Starlette:
    async def _readyz(request: Request) -> Response:
        if ready_fn():
            return JSONResponse({"status": "ok"}, status_code=200)
        return JSONResponse({"status": "not_ready"}, status_code=503)

    return Starlette(
        routes=[
            Route("/healthz", _make_healthz_handler(), methods=["GET"]),
            Route("/readyz", _readyz, methods=["GET"]),
        ]
    )


def build_asgi_app(
    *,
    mcp_app: Any,
    factory: SessionFactory,
    resource_url: str,
    authorization_server: str,
    ready_fn: Callable[[], bool],
    audit_emitter: MultiSinkAuditEmitter | None = None,
    limiter: object | None = None,
) -> Any:
    """Compose the full ASGI app: metadata + health + /metrics + session-protected MCP mount.

    M4a additions:
      * /metrics route (unauthenticated, Prom-format).
      * audit_emitter.start()/stop() are hung off the composed lifespan.
      * Starlette + httpx auto-instrumentation are attached here.
    """
    mcp_streamable = mcp_app.streamable_http_app()

    async def _readyz(request: Request) -> Response:
        if ready_fn():
            return JSONResponse({"status": "ok"}, status_code=200)
        return JSONResponse({"status": "not_ready"}, status_code=503)

    metadata = {
        "resource": resource_url,
        "authorization_servers": [authorization_server],
        "bearer_methods_supported": ["header"],
        "scopes_supported": [],
    }
    handler = _metadata_handler_factory(metadata)

    # Compose lifespans: FastMCP's session-manager lifespan MUST run (see
    # "Task group is not initialized" note below), AND the audit emitter's
    # background drain tasks must start/stop alongside the app.
    _mcp_lifespan = mcp_streamable.router.lifespan_context

    @contextlib.asynccontextmanager
    async def _lifespan(app: Starlette) -> AsyncIterator[None]:
        async with _mcp_lifespan(app):
            if audit_emitter is not None:
                await audit_emitter.start()
            try:
                yield
            finally:
                if audit_emitter is not None:
                    await audit_emitter.stop()

    # FastMCP's streamable_http_app() exposes its handler at `/mcp`, so we
    # mount it at the root. The explicit Routes above are declared first
    # and take precedence over the Mount for their own paths. We also
    # forward the sub-app's lifespan so FastMCP's session-manager task group
    # starts up — otherwise requests raise
    # "Task group is not initialized. Make sure to use run()."
    base = Starlette(
        routes=[
            Route(
                "/.well-known/oauth-protected-resource",
                handler,
                methods=["GET"],
            ),
            Route("/healthz", _make_healthz_handler(limiter=limiter), methods=["GET"]),
            Route("/readyz", _readyz, methods=["GET"]),
            build_metrics_route(),
            Mount("/", app=mcp_streamable),
        ],
        lifespan=_lifespan,
    )

    # OTel instrumentation — starlette + outbound httpx calls from the server.
    # Both helpers are idempotent; calling them in test loops is safe.
    instrument_starlette(base)
    instrument_httpx()

    return SessionMiddleware(
        base,
        factory=factory,
        protect_paths=["/mcp"],
        resource_metadata_url=f"{resource_url.rstrip('/')}/.well-known/oauth-protected-resource",
    )
