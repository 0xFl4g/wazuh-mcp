"""TenantRegistry - resolves tenant_id -> TenantConfig.

M1 ships YamlTenantRegistry. M4 adds a DB-backed driver.
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

import yaml

from wazuh_mcp.tenancy.config import TenantConfig


class TenantRegistry(Protocol):
    def get(self, tenant_id: str) -> TenantConfig:
        """Return the config for tenant_id. Raises KeyError if unknown."""
        ...

    def all_tenants(self) -> list[TenantConfig]:
        """Return all configured tenants. Order is impl-defined but stable per call."""
        ...


class YamlTenantRegistry:
    def __init__(self, path: Path) -> None:
        with path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        raw_tenants = data.get("tenants", [])
        if not isinstance(raw_tenants, list):
            raise ValueError(f"{path}: 'tenants' must be a list")

        self._tenants: dict[str, TenantConfig] = {}
        for entry in raw_tenants:
            cfg = TenantConfig.model_validate(entry)
            if cfg.tenant_id in self._tenants:
                raise ValueError(f"duplicate tenant_id: {cfg.tenant_id}")
            self._tenants[cfg.tenant_id] = cfg

    def get(self, tenant_id: str) -> TenantConfig:
        if tenant_id not in self._tenants:
            raise KeyError(f"unknown tenant: {tenant_id}")
        return self._tenants[tenant_id]

    def all_tenants(self) -> list[TenantConfig]:
        return list(self._tenants.values())


class SingleTenantRegistry:
    """Single-config TenantRegistry adapter for stdio-mode wiring.

    Stdio is single-tenant by construction; this wraps the one ``TenantConfig``
    so the same resolver factories used by HTTP work in stdio without a
    separate code path.
    """

    def __init__(self, tenant: TenantConfig) -> None:
        self._tenant = tenant

    def get(self, tenant_id: str) -> TenantConfig:
        if tenant_id != self._tenant.tenant_id:
            raise KeyError(f"unknown tenant: {tenant_id}")
        return self._tenant

    def all_tenants(self) -> list[TenantConfig]:
        return [self._tenant]
