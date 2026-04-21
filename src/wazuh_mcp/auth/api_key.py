"""ApiKeySessionFactory.

Token format: `wzk_<tenant>_<nnn>.<base64url-random>`.
The `.` separator splits key_id (wzk-prefixed, may contain underscores)
from the plaintext secret.
"""

from __future__ import annotations

from wazuh_mcp.auth.api_key_store import ApiKeyRecord, YamlApiKeyStore
from wazuh_mcp.auth.errors import InvalidToken
from wazuh_mcp.auth.factory import RequestContext, SessionFactory
from wazuh_mcp.auth.session import Session


class ApiKeySessionFactory(SessionFactory):
    def __init__(self, *, store: YamlApiKeyStore) -> None:
        self._store = store

    async def build(self, ctx: RequestContext) -> Session:
        headers = ctx.get("headers", {})
        auth = headers.get("Authorization") or headers.get("authorization") or ""
        if not auth.startswith("Bearer "):
            raise InvalidToken(detail="missing bearer")
        token = auth[len("Bearer "):].strip()
        if not token.startswith("wzk_") or "." not in token:
            raise InvalidToken(detail="malformed api key")
        key_id, _, plaintext = token.rpartition(".")
        record: ApiKeyRecord | None = self._store.verify(
            key_id=key_id, plaintext=plaintext
        )
        if record is None:
            raise InvalidToken(detail="key verification failed")
        return Session(
            user_id=record.user_id,
            tenant_id=record.tenant_id,
            rbac_role=record.rbac_role,
            auth_method="api_key",
        )
