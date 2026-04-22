"""build_asgi_app composition — verifies which paths go through auth."""

from starlette.testclient import TestClient

from wazuh_mcp.auth.errors import InvalidToken
from wazuh_mcp.auth.factory import RequestContext, SessionFactory
from wazuh_mcp.auth.session import Session
from wazuh_mcp.transport.http import build_asgi_app


class _AlwaysDenyFactory(SessionFactory):
    async def build(self, ctx: RequestContext) -> Session:
        raise InvalidToken()


class _DummyMcpApp:
    """Minimal stand-in that mirrors the real FastMCP surface:
    - Internal /mcp route (what real FastMCP exposes)
    - router.lifespan_context (task group needs startup in production)
    """

    def streamable_http_app(self):
        from contextlib import asynccontextmanager

        from starlette.applications import Starlette
        from starlette.responses import JSONResponse
        from starlette.routing import Route

        started = {"flag": False}

        @asynccontextmanager
        async def lifespan(app):
            started["flag"] = True
            yield

        async def _ok(request):
            # Proves lifespan actually ran for the outer app.
            return JSONResponse({"ok": True, "lifespan_started": started["flag"]})

        app = Starlette(routes=[Route("/mcp", _ok, methods=["GET", "POST"])], lifespan=lifespan)
        # Expose the started flag so the test can assert outer lifespan forwarding.
        app.state.started_flag = started
        return app


def test_health_paths_bypass_auth():
    app = build_asgi_app(
        mcp_app=_DummyMcpApp(),
        factory=_AlwaysDenyFactory(),
        resource_url="https://mcp.example",
        authorization_server="https://idp.example",
        ready_fn=lambda: True,
    )
    client = TestClient(app)
    # All public endpoints reachable without Authorization.
    assert client.get("/healthz").status_code == 200
    assert client.get("/readyz").status_code == 200
    assert client.get("/.well-known/oauth-protected-resource").status_code == 200


def test_mcp_path_requires_auth():
    app = build_asgi_app(
        mcp_app=_DummyMcpApp(),
        factory=_AlwaysDenyFactory(),
        resource_url="https://mcp.example",
        authorization_server="https://idp.example",
        ready_fn=lambda: True,
    )
    client = TestClient(app)
    # /mcp and its sub-paths go through auth.
    assert client.get("/mcp").status_code == 401


def test_mcpfoo_does_not_accidentally_match():
    # Sibling path that starts with "mcp" but isn't /mcp/... must not be
    # auth-gated by the prefix match.
    app = build_asgi_app(
        mcp_app=_DummyMcpApp(),
        factory=_AlwaysDenyFactory(),
        resource_url="https://mcp.example",
        authorization_server="https://idp.example",
        ready_fn=lambda: True,
    )
    client = TestClient(app)
    # /mcpfoo doesn't exist → 404, not 401. The key assertion is "not 401".
    resp = client.get("/mcpfoo")
    assert resp.status_code != 401


def test_outer_app_forwards_sub_app_lifespan():
    """Regression: outer Starlette must forward FastMCP's lifespan so the
    session-manager task group starts. Task 20 found this the hard way.
    """

    class _AllowAll(SessionFactory):
        async def build(self, ctx: RequestContext) -> Session:
            return Session(
                user_id="u",
                tenant_id="t",
                rbac_role="r",
                auth_method="config",
            )

    dummy = _DummyMcpApp()
    app = build_asgi_app(
        mcp_app=dummy,
        factory=_AllowAll(),
        resource_url="https://mcp.example",
        authorization_server="https://idp.example",
        ready_fn=lambda: True,
    )
    # TestClient must be entered as a context manager to trigger lifespan events;
    # otherwise startup/shutdown are skipped and the forwarding wouldn't be tested.
    with TestClient(app) as client:
        resp = client.post("/mcp", json={})
    assert resp.status_code == 200
    assert resp.json()["lifespan_started"] is True
