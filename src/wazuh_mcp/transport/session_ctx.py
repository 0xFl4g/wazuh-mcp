"""Per-request Session contextvar.

Transports set it in middleware before dispatching into the MCP app.
Tool handlers pull it via current_session(). Python asyncio guarantees
per-task isolation, so concurrent HTTP requests never see each other's
sessions.
"""

from __future__ import annotations

from contextvars import ContextVar, Token

from wazuh_mcp.auth.session import Session

CURRENT_SESSION: ContextVar[Session] = ContextVar("wazuh_mcp_current_session")


def current_session() -> Session:
    """Return the Session for the current asyncio task.

    Raises LookupError if called outside a request context — a signal that
    the middleware was bypassed (programming error, not a runtime failure).
    """
    return CURRENT_SESSION.get()


def set_current_session(session: Session) -> Token[Session]:
    """Set the per-task Session. Callers MUST reset via CURRENT_SESSION.reset(token)."""
    return CURRENT_SESSION.set(session)
