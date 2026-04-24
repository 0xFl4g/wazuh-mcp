"""Server wiring end-to-end (unit): every registered tool routes through
@instrumented_tool and list_tools filters by RBAC.
"""

from __future__ import annotations

import io
from pathlib import Path

import mcp.types as _mt
import pytest
from mcp.server.fastmcp import FastMCP

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import AuditEmitter
from wazuh_mcp.observability.sinks.stream import StderrSink
from wazuh_mcp.rate_limit.limiter import InProcessRateLimiter
from wazuh_mcp.rbac.policy import effective_allowlist_for
from wazuh_mcp.server import _install_rbac_hooks, _register_everything, build_app, load_config
from wazuh_mcp.tenancy.m4_config import RateLimitConfig
from wazuh_mcp.transport.session_ctx import CURRENT_SESSION, set_current_session


@pytest.fixture
def config_dir(tmp_path: Path) -> Path:
    (tmp_path / "tenants.yaml").write_text(
        """
tenants:
  - tenant_id: acme
    indexer_url: https://wazuh.acme.test:9200
    verify_tls: false
    ca_bundle_path: null
    default_rbac_role: admin
""".strip()
    )
    (tmp_path / "secrets.yaml").write_text(
        """
acme:
  indexer_user: admin
  indexer_password: pw
""".strip()
    )
    (tmp_path / "server.yaml").write_text(
        """
active_tenant: acme
user_id: alice
""".strip()
    )
    return tmp_path


class _StubPool:
    async def acquire(self, tenant_id: str):
        return object()


def _policy_allow_admin(_session: Session) -> dict[str, list[str]]:
    return effective_allowlist_for(tenant_override=None)


def _policy_deny_all(_session: Session) -> dict[str, list[str]]:
    return {"admin": []}


def test_build_app_imports_cleanly(config_dir: Path) -> None:
    """Smoke: build_app imports without error after M4a refactor."""
    cfg = load_config(config_dir)
    app = build_app(cfg)
    assert isinstance(app, FastMCP)


def test_rbac_list_tools_handler_identity_pinning() -> None:
    """T14 probe invariant: our wrapper must win over FastMCP's handler
    (last registration wins in the low-level single-slot request_handlers
    dict). If a future SDK bump changes the dispatcher, this fails loudly.
    """
    mcp_app = FastMCP(name="test")
    audit = AuditEmitter(sinks=[StderrSink(stream=io.StringIO())])
    limiter = InProcessRateLimiter(default=RateLimitConfig())
    _register_everything(
        mcp_app,
        indexer_pool=_StubPool(),
        server_api_pool=_StubPool(),
        audit_emitter=audit,
        limiter=limiter,
        rbac_policy=_policy_allow_admin,
    )

    # Capture FastMCP's handler identity before installing RBAC wrappers.
    list_slot = mcp_app._mcp_server.request_handlers[_mt.ListToolsRequest]
    call_slot = mcp_app._mcp_server.request_handlers[_mt.CallToolRequest]
    fastmcp_list_handler = list_slot
    fastmcp_call_handler = call_slot

    _install_rbac_hooks(mcp_app, rbac_policy=_policy_allow_admin)

    # Post-install: the slot MUST have been replaced by a new object.
    assert mcp_app._mcp_server.request_handlers[_mt.ListToolsRequest] is not fastmcp_list_handler
    assert mcp_app._mcp_server.request_handlers[_mt.CallToolRequest] is not fastmcp_call_handler


@pytest.mark.asyncio
async def test_rbac_list_tools_filter_allows_admin_denies_empty() -> None:
    """End-to-end: list_tools with admin role returns every tool; with a
    role that has no patterns returns an empty list."""
    mcp_app = FastMCP(name="test")
    audit = AuditEmitter(sinks=[StderrSink(stream=io.StringIO())])
    limiter = InProcessRateLimiter(default=RateLimitConfig())
    _register_everything(
        mcp_app,
        indexer_pool=_StubPool(),
        server_api_pool=_StubPool(),
        audit_emitter=audit,
        limiter=limiter,
        rbac_policy=_policy_allow_admin,
    )
    _install_rbac_hooks(mcp_app, rbac_policy=_policy_allow_admin)

    session = Session(
        user_id="u", tenant_id="t", rbac_role="admin", auth_method="oauth"
    )
    token = set_current_session(session)
    try:
        # Call FastMCP's bound method directly — our wrapper on the low-
        # level server is tested by the identity-pinning assertion above;
        # exercising the wrapper behaviourally requires invoking it via
        # its slot, which we do below.
        import mcp.types as mt

        req = mt.ListToolsRequest(method="tools/list", params=None)
        handler = mcp_app._mcp_server.request_handlers[mt.ListToolsRequest]
        result = await handler(req)
        tools = result.root.tools  # ty: ignore[unresolved-attribute]
        assert len(tools) == 17

        # Swap in a deny-all policy and re-install to exercise filtering.
        _install_rbac_hooks(mcp_app, rbac_policy=_policy_deny_all)
        handler2 = mcp_app._mcp_server.request_handlers[mt.ListToolsRequest]
        result2 = await handler2(req)
        tools2 = result2.root.tools  # ty: ignore[unresolved-attribute]
        assert len(tools2) == 0
    finally:
        CURRENT_SESSION.reset(token)


@pytest.mark.asyncio
async def test_metrics_route_mounted_on_http_app() -> None:
    """/metrics is registered on the composed ASGI app via build_asgi_app."""
    from starlette.routing import Route

    from wazuh_mcp.auth.factory import SessionFactory
    from wazuh_mcp.observability.otel import init_otel
    from wazuh_mcp.transport.http import build_asgi_app

    init_otel(service_version="test")

    class _NoopFactory(SessionFactory):
        async def build(self, ctx):  # pragma: no cover - unused in this test
            raise RuntimeError("not used")

    mcp_app = FastMCP(name="test")
    asgi = build_asgi_app(
        mcp_app=mcp_app,
        factory=_NoopFactory(),
        resource_url="https://mcp.example",
        authorization_server="https://auth.example",
        ready_fn=lambda: True,
    )

    # Walk the inner Starlette app for /metrics Route.
    base = asgi.app  # SessionMiddleware.app == inner Starlette
    paths = {r.path for r in base.routes if isinstance(r, Route)}
    assert "/metrics" in paths
