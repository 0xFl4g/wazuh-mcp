"""ChainSessionFactory — routes by bearer token shape.

- `Bearer wzk_*`     → ApiKeySessionFactory
- `Bearer aaa.bbb.ccc` (3 dot-separated segments) → OAuthSessionFactory
- anything else      → InvalidToken (no blind probing of both)
"""

from __future__ import annotations

from wazuh_mcp.auth.errors import InvalidToken
from wazuh_mcp.auth.factory import RequestContext, SessionFactory
from wazuh_mcp.auth.session import Session


class ChainSessionFactory(SessionFactory):
    def __init__(self, *, oauth: SessionFactory, api_key: SessionFactory) -> None:
        self._oauth = oauth
        self._api_key = api_key

    async def build(self, ctx: RequestContext) -> Session:
        headers = ctx.get("headers", {})
        auth = headers.get("Authorization") or headers.get("authorization") or ""
        if not auth.startswith("Bearer "):
            raise InvalidToken(detail="missing bearer")
        token = auth[len("Bearer "):].strip()
        if token.startswith("wzk_") and "." in token:
            return await self._api_key.build(ctx)
        if token.count(".") == 2:
            return await self._oauth.build(ctx)
        raise InvalidToken(detail="unrecognised token shape")
