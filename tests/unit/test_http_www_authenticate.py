"""WWW-Authenticate challenge shape tests."""

from starlette.testclient import TestClient

from wazuh_mcp.auth.errors import InvalidToken
from wazuh_mcp.auth.factory import RequestContext, SessionFactory
from wazuh_mcp.auth.session import Session
from wazuh_mcp.transport.http import build_asgi_app


class _AlwaysDeny(SessionFactory):
    async def build(self, ctx: RequestContext) -> Session:
        raise InvalidToken()


class _DummyMcp:
    def streamable_http_app(self):
        from starlette.applications import Starlette
        from starlette.responses import JSONResponse
        from starlette.routing import Route

        async def _ok(request):
            return JSONResponse({"ok": True})

        return Starlette(routes=[Route("/mcp", _ok, methods=["GET", "POST"])])


def test_www_authenticate_includes_resource_metadata_on_401():
    app = build_asgi_app(
        mcp_app=_DummyMcp(),
        factory=_AlwaysDeny(),
        resource_url="https://mcp.example",
        authorization_server="https://idp.example",
        ready_fn=lambda: True,
    )
    client = TestClient(app)
    resp = client.post("/mcp", json={})
    assert resp.status_code == 401
    challenge = resp.headers["WWW-Authenticate"]
    assert challenge.startswith("Bearer ")
    assert 'realm="mcp"' in challenge
    assert 'error="invalid_token"' in challenge
    assert (
        'resource_metadata="https://mcp.example/.well-known/oauth-protected-resource"'
        in challenge
    )


def test_www_authenticate_honors_trailing_slash_in_resource_url():
    app = build_asgi_app(
        mcp_app=_DummyMcp(),
        factory=_AlwaysDeny(),
        resource_url="https://mcp.example/",  # trailing slash
        authorization_server="https://idp.example",
        ready_fn=lambda: True,
    )
    client = TestClient(app)
    resp = client.post("/mcp", json={})
    assert resp.status_code == 401
    # No double slashes.
    assert "example//.well-known" not in resp.headers["WWW-Authenticate"]
    assert (
        'resource_metadata="https://mcp.example/.well-known/oauth-protected-resource"'
        in resp.headers["WWW-Authenticate"]
    )
