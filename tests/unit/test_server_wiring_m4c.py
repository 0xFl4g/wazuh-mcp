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
