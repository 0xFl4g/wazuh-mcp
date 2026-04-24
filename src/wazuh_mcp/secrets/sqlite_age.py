"""SQLite-backed SecretStore with per-secret age encryption.

Intended for single-node self-hosted deploys that need something stronger
than the M1 YAML driver but don't want AWS/Vault. The DB holds age
ciphertext keyed by (tenant_id, key); decryption requires the operator's
age identity file.

Recipient list for encryption is passed into put() — typically the public
half of the operator's identity. Multi-recipient (add your admin's public
key) is supported by passing more than one.
"""
from __future__ import annotations

from pathlib import Path

import aiosqlite
import pyrage

from wazuh_mcp.secrets.value import SecretValue

_SCHEMA = """
CREATE TABLE IF NOT EXISTS secrets (
    tenant_id TEXT NOT NULL,
    key TEXT NOT NULL,
    ciphertext BLOB NOT NULL,
    PRIMARY KEY (tenant_id, key)
);
"""


class SqliteAgeSecretStore:
    def __init__(self, *, db_path: Path, identity_path: Path) -> None:
        self._db_path = db_path
        self._identity_path = identity_path

    def _load_identity(self) -> pyrage.x25519.Identity:  # ty:ignore[unresolved-attribute]
        return pyrage.x25519.Identity.from_str(self._identity_path.read_text().strip())  # ty:ignore[unresolved-attribute]

    async def init_schema(self) -> None:
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(_SCHEMA)
            await db.commit()

    async def put(
        self,
        tenant_id: str,
        key: str,
        value: str,
        *,
        recipients: list[pyrage.x25519.Recipient],  # ty:ignore[unresolved-attribute]
    ) -> None:
        ciphertext = pyrage.encrypt(value.encode("utf-8"), recipients)  # ty:ignore[unresolved-attribute]
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                "INSERT OR REPLACE INTO secrets (tenant_id, key, ciphertext) VALUES (?, ?, ?)",
                (tenant_id, key, ciphertext),
            )
            await db.commit()

    async def get(self, tenant_id: str, key: str) -> SecretValue:
        async with aiosqlite.connect(self._db_path) as db:
            cursor = await db.execute(
                "SELECT ciphertext FROM secrets WHERE tenant_id = ? AND key = ?",
                (tenant_id, key),
            )
            row = await cursor.fetchone()
            await cursor.close()
        if row is None:
            raise KeyError(f"{tenant_id}/{key}")
        identity = self._load_identity()
        plaintext = pyrage.decrypt(row[0], [identity])  # ty:ignore[unresolved-attribute]
        return SecretValue(plaintext.decode("utf-8"))
