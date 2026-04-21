"""SessionFactory protocol — sole constructor of Session objects.

One implementation per auth mode. Transport layers call .build(ctx) per
request and propagate the returned Session via contextvars to tool handlers.
"""

from __future__ import annotations

from typing import Protocol, TypedDict, runtime_checkable

from wazuh_mcp.auth.session import Session


class RequestContext(TypedDict, total=False):
    """Per-request data transports pass to factories.

    Only keys a factory actually needs are required. stdio supplies an empty
    context; HTTP supplies headers/client_ip.
    """

    headers: dict[str, str]
    client_ip: str


@runtime_checkable
class SessionFactory(Protocol):
    async def build(self, ctx: RequestContext) -> Session:
        """Return a Session. Raise AuthError subclasses on failure."""
        ...
