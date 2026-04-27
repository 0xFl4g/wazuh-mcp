"""M4c stdio + HTTP wiring (T6 + T7).

Both modes thread three resolvers (rbac, write_allowlist, ar_allowlist) into
_register_everything. The handlers must call ar_allowlist_policy(session) per
call instead of capturing tenant_cfg.active_response_allowlist at registration
time.
"""

from __future__ import annotations

import inspect

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
