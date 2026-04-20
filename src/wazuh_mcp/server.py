"""MCP server wiring.

M1: stdio only, single session loaded from config at startup.
M2 replaces `load_config` with an OAuth/API-key entry that yields a
Session per client connection.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from mcp.server.fastmcp import FastMCP

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import AuditEmitter
from wazuh_mcp.secrets.yaml_driver import YamlSecretStore
from wazuh_mcp.tenancy.config import TenantConfig
from wazuh_mcp.tenancy.registry import YamlTenantRegistry
from wazuh_mcp.tools.alerts import SearchAlertsArgs, search_alerts
from wazuh_mcp.wazuh.indexer import IndexerClient


@dataclass(frozen=True)
class AppConfig:
    session: Session
    tenant: TenantConfig
    secrets: YamlSecretStore


def load_config(config_dir: Path) -> AppConfig:
    server_cfg = yaml.safe_load((config_dir / "server.yaml").read_text()) or {}
    registry = YamlTenantRegistry(config_dir / "tenants.yaml")
    secrets = YamlSecretStore(config_dir / "secrets.yaml")

    tenant_id = server_cfg["active_tenant"]
    user_id = server_cfg.get("user_id", "local")
    tenant = registry.get(tenant_id)
    session = Session(
        user_id=user_id,
        tenant_id=tenant_id,
        rbac_role=tenant.default_rbac_role,
        auth_method="config",
    )
    return AppConfig(session=session, tenant=tenant, secrets=secrets)


def build_app(cfg: AppConfig, audit: AuditEmitter | None = None) -> FastMCP:
    audit_emitter = audit or AuditEmitter()
    app = FastMCP(name="wazuh-mcp")

    async def _open_indexer() -> IndexerClient:
        user = await cfg.secrets.get(cfg.tenant.tenant_id, "indexer_user")
        password = await cfg.secrets.get(cfg.tenant.tenant_id, "indexer_password")
        return IndexerClient(
            base_url=str(cfg.tenant.indexer_url),
            user=user,
            password=password,
            verify_tls=cfg.tenant.verify_tls,
            ca_bundle_path=cfg.tenant.ca_bundle_path,
        )

    @app.tool(
        name="search_alerts",
        description=(
            "Search Wazuh alerts by time range and filters. Use when the user "
            "asks about security events, detections, or incidents within a "
            "time window. Returns a paginated list; use `cursor` from a prior "
            "response to continue."
        ),
    )
    async def _search_alerts(
        time_range: str = "1h",
        min_level: int | None = None,
        agent_id: str | None = None,
        size: int = 25,
        cursor: list[Any] | None = None,
    ) -> dict[str, Any]:
        args = SearchAlertsArgs(
            time_range=time_range,
            min_level=min_level,
            agent_id=agent_id,
            size=size,
            cursor=cursor,
        )
        indexer = await _open_indexer()
        try:
            return await search_alerts(
                args=args, session=cfg.session, indexer=indexer, audit=audit_emitter,
            )
        finally:
            await indexer.aclose()

    return app


def run_stdio(config_dir: Path) -> None:
    cfg = load_config(config_dir)
    app = build_app(cfg)
    asyncio.run(app.run_stdio_async())
