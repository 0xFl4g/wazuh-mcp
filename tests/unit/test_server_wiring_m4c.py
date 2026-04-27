"""M4c stdio + HTTP wiring (T6 + T7).

Both modes thread three resolvers (rbac, write_allowlist, ar_allowlist) into
_register_everything. The handlers must call ar_allowlist_policy(session) per
call instead of capturing tenant_cfg.active_response_allowlist at registration
time.
"""

from __future__ import annotations

import inspect

import pytest

from wazuh_mcp.server import _register_everything


def test_register_everything_accepts_resolver_kwargs() -> None:
    sig = inspect.signature(_register_everything)
    params = sig.parameters
    assert "write_allowlist_policy" in params
    assert "ar_allowlist_policy" in params
    # Both should be optional with sensible defaults so existing callers don't
    # break mid-refactor.
    assert params["write_allowlist_policy"].default is None
    assert params["ar_allowlist_policy"].default is None


def test_build_http_app_wires_three_resolvers() -> None:
    """build_http_app closes over registry — proven by absence of
    AttributeError when http_cfg.registry is None and presence of M4c
    resolver imports in server module."""
    import wazuh_mcp.server as server_mod

    src = inspect.getsource(server_mod.build_http_app)
    # The function should reference the three resolver factories.
    assert "make_rbac_policy" in src
    assert "make_write_allowlist" in src
    assert "make_ar_allowlist" in src
    # And it should pass write_allowlist_policy + ar_allowlist_policy
    # to _register_everything.
    assert "write_allowlist_policy=" in src
    assert "ar_allowlist_policy=" in src


@pytest.mark.asyncio
async def test_write_allowlist_denies_per_call() -> None:
    """Per-call write_allowlist filter raises forbidden when tool not allowed."""
    from mcp.server.fastmcp import FastMCP

    from wazuh_mcp.auth.session import Session
    from wazuh_mcp.observability.audit import MultiSinkAuditEmitter
    from wazuh_mcp.rate_limit.limiter import InProcessRateLimiter
    from wazuh_mcp.server import _register_everything
    from wazuh_mcp.tenancy.config import RateLimitConfig
    from wazuh_mcp.transport.session_ctx import set_current_session
    from wazuh_mcp.wazuh.errors import WazuhError

    mcp_app = FastMCP(name="test")
    audit = MultiSinkAuditEmitter(sinks=None)
    limiter = InProcessRateLimiter(default=RateLimitConfig())

    # tenant_a's write_allowlist permits only isolate_agent.
    def _rbac_allow_admin(session: Session) -> dict[str, list[str]]:
        return {"admin": ["*"]}

    def _write_allow_isolate_only(session: Session) -> list[str] | None:
        return ["write.isolate_agent"]

    def _ar_allow_isolate(session: Session) -> list[str]:
        return ["isolate"]

    class _StubServerApiPool:
        async def acquire(self, tenant_id: str):
            class _StubClient:
                async def restart_agent(self, *, agent_id, run_as):
                    return {"data": {"affected_items": [agent_id]}}

            return _StubClient()

    class _StubIndexerPool:
        async def acquire(self, tenant_id: str):
            return None

    _register_everything(
        mcp_app,
        indexer_pool=_StubIndexerPool(),
        server_api_pool=_StubServerApiPool(),
        audit_emitter=audit,
        limiter=limiter,
        rbac_policy=_rbac_allow_admin,
        write_allowlist_policy=_write_allow_isolate_only,
        ar_allowlist_policy=_ar_allow_isolate,
    )

    sess = Session(
        user_id="alice",
        tenant_id="tenant_a",
        rbac_role="admin",
        auth_method="oauth",
        wazuh_user=None,
    )
    set_current_session(sess)

    # write.restart_agent is registered (since registration is unconditional)
    # but call must deny because write_allowlist=[isolate_agent only].
    tools = await mcp_app.list_tools()
    tool_names = {t.name for t in tools}
    assert "write.restart_agent" in tool_names
    assert "write.isolate_agent" in tool_names

    # restart_agent call must raise forbidden. FastMCP's Tool.run wraps the
    # underlying WazuhError in a ToolError via `raise ToolError(...) from e`,
    # so we unwrap via __cause__ to assert against the original error code.
    from mcp.server.fastmcp.exceptions import ToolError

    with pytest.raises(ToolError) as exc_info:
        await mcp_app.call_tool("write.restart_agent", {"agent_id": "001", "confirm": True})
    cause = exc_info.value.__cause__
    assert isinstance(cause, WazuhError)
    assert cause.code == "forbidden"
