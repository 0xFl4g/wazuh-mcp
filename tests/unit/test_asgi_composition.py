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
    """Minimal stand-in for FastMCP.streamable_http_app()."""

    def streamable_http_app(self):
        from starlette.applications import Starlette
        from starlette.responses import JSONResponse
        from starlette.routing import Route

        async def _ok(request):
            return JSONResponse({"ok": True})

        return Starlette(routes=[Route("/initialize", _ok)])


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
    assert client.get("/mcp/initialize").status_code == 401


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
