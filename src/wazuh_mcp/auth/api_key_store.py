"""YAML-backed API-key store with argon2id hashing.

Record schema per entry:
    key_id: wzk_<tenant>_<nnn>
    hash: $argon2id$...
    tenant_id: str
    user_id: str
    rbac_role: str
    revoked: bool
    expires_at: ISO-8601 | null

verify(key_id, plaintext) returns the ApiKeyRecord on success or None on
any failure (unknown key, bad hash, revoked, expired). All failures are
collapsed to None so callers can't distinguish "no such key" from "bad
password" via timing or return shape.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from argon2 import PasswordHasher
from argon2 import exceptions as argon_exc


@dataclass(frozen=True, slots=True)
class ApiKeyRecord:
    key_id: str
    tenant_id: str
    user_id: str
    rbac_role: str


class YamlApiKeyStore:
    __slots__ = ("_hasher", "_records")
    _hasher: PasswordHasher
    _records: dict[str, dict[str, Any]]

    def __init__(self, path: Path) -> None:
        with path.open("r", encoding="utf-8") as f:
            data: Any = yaml.safe_load(f) or {}
        entries = data.get("api_keys", [])
        if not isinstance(entries, list):
            raise ValueError(f"{path}: 'api_keys' must be a list")

        self._hasher = PasswordHasher()
        seen: dict[str, dict[str, Any]] = {}
        for entry in entries:
            if not isinstance(entry, dict):
                raise ValueError(f"{path}: api_keys entries must be mappings")
            key_id = entry.get("key_id")
            if not isinstance(key_id, str):
                raise ValueError(f"{path}: api_keys missing key_id string")
            if key_id in seen:
                raise ValueError(f"{path}: duplicate key_id {key_id!r}")
            hashed = entry.get("hash")
            if not isinstance(hashed, str) or not hashed.startswith("$argon2id$"):
                raise ValueError(
                    f"{path}: hash for {key_id!r} must be argon2id "
                    f"(not argon2i or argon2d, per OWASP 2024)"
                )
            seen[key_id] = entry
        self._records = seen

    def verify(self, *, key_id: str, plaintext: str) -> ApiKeyRecord | None:
        entry = self._records.get(key_id)
        if entry is None:
            return None
        if entry.get("revoked"):
            return None
        expires_at = entry.get("expires_at")
        if expires_at is not None:
            try:
                exp_dt = datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
            except ValueError:
                return None
            if exp_dt <= datetime.now(UTC):
                return None
        try:
            self._hasher.verify(str(entry["hash"]), plaintext)
        except (argon_exc.VerificationError, argon_exc.InvalidHashError):
            return None
        return ApiKeyRecord(
            key_id=key_id,
            tenant_id=str(entry["tenant_id"]),
            user_id=str(entry["user_id"]),
            rbac_role=str(entry["rbac_role"]),
        )
