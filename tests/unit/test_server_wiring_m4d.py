"""M4d wiring assertions: rate-limiter per_tenant + audit_emitter
per_tenant_sinks populated at boot from registry."""

from __future__ import annotations

import inspect


def test_build_http_app_constructs_limiter_with_per_tenant() -> None:
    """build_http_app passes per_tenant= to InProcessRateLimiter."""
    import wazuh_mcp.server as server_mod

    src = inspect.getsource(server_mod.build_http_app)
    # Limiter must be constructed with per_tenant kwarg.
    assert "per_tenant=" in src
    # And must reference all_tenants() to source the dict.
    assert "all_tenants" in src


def test_build_app_constructs_limiter_with_per_tenant() -> None:
    """Stdio build_app also passes per_tenant=."""
    import wazuh_mcp.server as server_mod

    src = inspect.getsource(server_mod.build_app)
    assert "per_tenant=" in src
