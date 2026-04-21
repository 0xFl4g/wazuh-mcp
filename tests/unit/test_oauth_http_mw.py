from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from wazuh_mcp.auth.factory import RequestContext, SessionFactory
from wazuh_mcp.auth.session import Session
from wazuh_mcp.transport.http import SessionMiddleware
from wazuh_mcp.transport.session_ctx import current_session


class _FixedFactory(SessionFactory):
    async def build(self, ctx: RequestContext) -> Session:
        if not ctx.get("headers", {}).get("Authorization"):
            from wazuh_mcp.auth.errors import InvalidToken

            raise InvalidToken()
        return Session(
            user_id="alice", tenant_id="acme", rbac_role="soc_analyst", auth_method="oauth",
        )


async def _session_endpoint(request):
    s = current_session()
    return JSONResponse(
        {"user_id": s.user_id, "tenant_id": s.tenant_id, "auth_method": s.auth_method}
    )


def _app() -> SessionMiddleware:
    base = Starlette(routes=[Route("/probe", _session_endpoint)])
    return SessionMiddleware(base, factory=_FixedFactory(), protect_paths=["/probe"])


def test_authenticated_request_sets_session_in_ctx():
    client = TestClient(_app())
    resp = client.get("/probe", headers={"Authorization": "Bearer dummy"})
    assert resp.status_code == 200
    assert resp.json() == {"user_id": "alice", "tenant_id": "acme", "auth_method": "oauth"}


def test_missing_auth_header_returns_401():
    client = TestClient(_app())
    resp = client.get("/probe")
    assert resp.status_code == 401
    assert resp.headers.get("WWW-Authenticate", "").startswith("Bearer")
    assert resp.json() == {"error": "invalid_token"}


def test_contextvar_cleared_on_exception():
    client = _app()
    tc = TestClient(client)
    tc.get("/probe")  # 401
    resp = tc.get("/probe", headers={"Authorization": "Bearer dummy"})
    assert resp.status_code == 200
