"""YAML-backed SecretStore for development and single-operator deploys.

M4 ships production backends (AWS Secrets Manager, Vault, encrypted SQLite).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from wazuh_mcp.secrets.value import SecretValue


class YamlSecretStore:
    def __init__(self, path: Path) -> None:
        self._path = path
        with path.open("r", encoding="utf-8") as f:
            data: Any = yaml.safe_load(f) or {}
        if not isinstance(data, dict):
            raise ValueError(f"Secrets file {path} must be a mapping")
        self._data: dict[str, dict[str, str]] = {}
        for tenant, kv in data.items():
            if not isinstance(kv, dict):
                raise ValueError(f"Tenant {tenant!r} must be a mapping")
            tenant_secrets: dict[str, str] = {}
            for k, v in kv.items():
                # Reject non-string values. YAML coercion would turn `null` into
                # the string "None" and `1234` into "1234" — both are footguns
                # that produce confusing downstream auth failures. Operators who
                # want these must quote them explicitly in YAML.
                if not isinstance(v, str):
                    raise ValueError(
                        f"secret {k!r} for tenant {tenant!r} must be a string; "
                        f"got {type(v).__name__}. Quote the value in YAML."
                    )
                tenant_secrets[str(k)] = v
            self._data[str(tenant)] = tenant_secrets

    async def get(self, tenant_id: str, key: str) -> SecretValue:
        if tenant_id not in self._data:
            raise KeyError(f"unknown tenant: {tenant_id}")
        tenant_secrets = self._data[tenant_id]
        if key not in tenant_secrets:
            raise KeyError(f"missing secret {key!r} for tenant {tenant_id!r}")
        return SecretValue(tenant_secrets[key])
