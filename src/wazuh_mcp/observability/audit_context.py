"""Request-scoped audit correlation context.

Exposes a single ``ContextVar[str | None]`` plus helpers for setting,
resetting, and reading the current audit ``request_id``. The getter
falls through to MCP SDK's own ``request_ctx`` when our local contextvar
is unset — which is the common case in production, since no production
code calls ``set_request_id()``. Test fixtures and any future stdio
plumbing path can call ``set_request_id()`` to override.
"""

from __future__ import annotations

import contextvars

_audit_request_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "audit_request_id", default=None
)


def set_request_id(request_id: str | None) -> contextvars.Token[str | None]:
    """Set the audit request_id for the current context.

    Returns a token that callers MUST pass to ``reset_request_id`` on
    request exit. The standard pattern is::

        token = set_request_id(rid)
        try:
            ...
        finally:
            reset_request_id(token)
    """
    return _audit_request_id.set(request_id)


def reset_request_id(token: contextvars.Token[str | None]) -> None:
    """Reset the audit request_id contextvar using the token from ``set_request_id``."""
    _audit_request_id.reset(token)


def get_request_id() -> str | None:
    """Return the current audit request_id.

    Resolution order:
    1. The locally-set value (via ``set_request_id``), if any.
    2. The MCP SDK's ``request_ctx.get().request_id`` if a request is active.
    3. ``None`` (no request scope, no override).
    """
    rid = _audit_request_id.get()
    if rid is not None:
        return rid
    try:
        # Lazy import: keeps the module importable in environments that
        # don't have the MCP SDK installed (unlikely for this repo, but
        # defensive). LookupError is raised by ContextVar.get() with no
        # default; guard for both ImportError and LookupError.
        from mcp.server.lowlevel.server import request_ctx
    except ImportError:
        return None
    ctx = request_ctx.get(None)
    if ctx is None:
        return None
    return str(ctx.request_id)
