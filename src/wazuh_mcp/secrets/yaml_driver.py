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
            self._data[str(tenant)] = {str(k): str(v) for k, v in kv.items()}

    async def get(self, tenant_id: str, key: str) -> SecretValue:
        if tenant_id not in self._data:
            raise KeyError(f"unknown tenant: {tenant_id}")
        tenant_secrets = self._data[tenant_id]
        if key not in tenant_secrets:
            raise KeyError(f"missing secret {key!r} for tenant {tenant_id!r}")
        return SecretValue(tenant_secrets[key])
