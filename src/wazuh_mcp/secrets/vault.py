"""HashiCorp Vault-backed SecretStore (KV v2 engine).

hvac has no mature async client, so we wrap blocking calls in
asyncio.to_thread. Each call builds a fresh hvac.Client; the client is
cheap and this keeps the code free of shared-session lifecycle bugs.
Callers should compose with CachingSecretStore to avoid per-request Vault
round trips.

Secret path convention: `{prefix}{tenant_id}/{key}`, read from the KV v2
mount `secret/` (the Vault default). The value at that path must be a
mapping with a `value` key whose value is the secret string.
"""
from __future__ import annotations

import asyncio
from typing import Any

import hvac
import hvac.exceptions

from wazuh_mcp.secrets.value import SecretValue


class VaultSecretStore:
    def __init__(
        self,
        *,
        address: str,
        token: str | None = None,
        role_id: str | None = None,
        secret_id: str | None = None,
        prefix: str = "wazuh-mcp/",
        mount_point: str = "secret",
        **client_kwargs: Any,
    ) -> None:
        if token is None and (role_id is None or secret_id is None):
            raise ValueError(
                "VaultSecretStore needs either a token or AppRole role_id+secret_id"
            )
        self._address = address
        self._token = token
        self._role_id = role_id
        self._secret_id = secret_id
        self._prefix = prefix
        self._mount_point = mount_point
        self._client_kwargs = client_kwargs

    def _build_client(self) -> hvac.Client:
        client = hvac.Client(url=self._address, token=self._token, **self._client_kwargs)
        if self._token is None:
            # AppRole login returns a token and populates client.token as a side effect.
            client.auth.approle.login(role_id=self._role_id, secret_id=self._secret_id)
        return client

    def _path(self, tenant_id: str, key: str) -> str:
        return f"{self._prefix}{tenant_id}/{key}"

    def _read_blocking(self, tenant_id: str, key: str) -> str:
        client = self._build_client()
        if not client.is_authenticated():
            raise PermissionError("vault client not authenticated")
        path = self._path(tenant_id, key)
        try:
            resp = client.secrets.kv.v2.read_secret_version(
                path=path, raise_on_deleted_version=True
            )
        except hvac.exceptions.InvalidPath as exc:
            raise KeyError(path) from exc
        data = resp.get("data", {}).get("data", {})
        if "value" not in data:
            raise ValueError(f"vault path {path!r} missing required 'value' key")
        return str(data["value"])

    async def get(self, tenant_id: str, key: str) -> SecretValue:
        plaintext = await asyncio.to_thread(self._read_blocking, tenant_id, key)
        return SecretValue(plaintext)
