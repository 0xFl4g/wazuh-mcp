"""MCP server wiring.

M1 path: stdio + ConfigSessionFactory (single-session from config).
M2 path: see transport/http.py for HTTP mode (uses OAuth/ApiKey factories).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from mcp.server.fastmcp import FastMCP

from wazuh_mcp.auth.api_key import ApiKeySessionFactory
from wazuh_mcp.auth.api_key_store import YamlApiKeyStore
from wazuh_mcp.auth.chain_factory import ChainSessionFactory
from wazuh_mcp.auth.config_factory import ConfigSessionFactory
from wazuh_mcp.auth.factory import SessionFactory
from wazuh_mcp.auth.jwks_cache import JwksCache
from wazuh_mcp.auth.oauth import OAuthSessionFactory
from wazuh_mcp.observability.audit import AuditEmitter
from wazuh_mcp.secrets.yaml_driver import YamlSecretStore
from wazuh_mcp.tenancy.config import TenantConfig
from wazuh_mcp.tenancy.issuer_index import IssuerIndex
from wazuh_mcp.tenancy.registry import YamlTenantRegistry
from wazuh_mcp.tools.alerts import SearchAlertsArgs, search_alerts
from wazuh_mcp.transport.http import build_asgi_app
from wazuh_mcp.transport.session_ctx import (
    CURRENT_SESSION,
    current_session,
    set_current_session,
)
from wazuh_mcp.transport.stdio import run_stdio as _run_stdio
from wazuh_mcp.wazuh.indexer import IndexerClient
from wazuh_mcp.wazuh.indexer_pool import IndexerClientPool


@dataclass(frozen=True)
class AppConfig:
    factory: SessionFactory
    tenant: TenantConfig
    secrets: YamlSecretStore


def load_config(config_dir: Path) -> AppConfig:
    server_cfg = yaml.safe_load((config_dir / "server.yaml").read_text()) or {}
    registry = YamlTenantRegistry(config_dir / "tenants.yaml")
    secrets = YamlSecretStore(config_dir / "secrets.yaml")

    tenant_id = server_cfg["active_tenant"]
    user_id = server_cfg.get("user_id", "local")
    tenant = registry.get(tenant_id)
    factory = ConfigSessionFactory(user_id=user_id, tenant=tenant)
    return AppConfig(factory=factory, tenant=tenant, secrets=secrets)


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
        name="alerts.search_alerts",
        description=(
            "Search Wazuh alerts by time range and filters. Use when the user "
            "asks about security events, detections, or incidents within a "
            "time window. Returns a paginated list; use `cursor` from a prior "
            "response to continue."
        ),
        meta={"toolset": "alerts"},
    )
    async def _search_alerts(
        time_range: str = "1h",
        min_level: int | None = None,
        agent_id: str | None = None,
        size: int = 25,
        cursor: list[Any] | None = None,
    ):
        args = SearchAlertsArgs(
            time_range=time_range,
            min_level=min_level,
            agent_id=agent_id,
            size=size,
            cursor=cursor,
        )
        # stdio has no middleware, so build + set contextvar here.
        # HTTP mode will set the contextvar earlier, in which case current_session
        # already works and we skip the set.
        try:
            session = current_session()
            token = None
        except LookupError:
            session = await cfg.factory.build({})
            token = set_current_session(session)
        indexer = await _open_indexer()
        try:
            return await search_alerts(
                args=args,
                session=session,
                indexer=indexer,
                audit=audit_emitter,
            )
        finally:
            await indexer.aclose()
            if token is not None:
                CURRENT_SESSION.reset(token)

    return app


def run_stdio(config_dir: Path) -> None:
    cfg = load_config(config_dir)
    app = build_app(cfg)
    _run_stdio(app)


# ---- HTTP mode wiring ----


@dataclass(frozen=True)
class HttpAppConfig:
    pool: IndexerClientPool
    chain: ChainSessionFactory
    oauth: OAuthSessionFactory
    issuer_index: IssuerIndex
    resource_url: str
    authorization_server: str


def _tenant_ids(path: Path) -> list[str]:
    data = yaml.safe_load(path.read_text()) or {}
    return [t["tenant_id"] for t in data.get("tenants", [])]


def load_http_config(config_dir: Path) -> HttpAppConfig:
    server_cfg = yaml.safe_load((config_dir / "server.yaml").read_text()) or {}
    registry = YamlTenantRegistry(config_dir / "tenants.yaml")
    secrets = YamlSecretStore(config_dir / "secrets.yaml")

    all_tenants = [registry.get(tid) for tid in _tenant_ids(config_dir / "tenants.yaml")]
    issuer_index = IssuerIndex(all_tenants)

    oauth_cfg = server_cfg["oauth"]
    oauth = OAuthSessionFactory(
        issuer=oauth_cfg["issuer"],
        audience=oauth_cfg["audience"],
        algorithms=list(oauth_cfg.get("algorithms", ["RS256"])),
        rbac_claims=list(oauth_cfg.get("rbac_claims", ["wazuh_mcp_role", "groups", "roles"])),
        issuer_index=issuer_index,
        clock_skew_seconds=int(oauth_cfg.get("clock_skew_seconds", 30)),
        jwks=JwksCache(issuer=oauth_cfg["issuer"]),
    )

    api_store = YamlApiKeyStore(Path(server_cfg["api_keys_file"]))
    api_key_factory = ApiKeySessionFactory(store=api_store)

    chain = ChainSessionFactory(oauth=oauth, api_key=api_key_factory)
    pool = IndexerClientPool(registry=registry, secrets=secrets)

    http_cfg = server_cfg["http"]
    return HttpAppConfig(
        pool=pool,
        chain=chain,
        oauth=oauth,
        issuer_index=issuer_index,
        resource_url=http_cfg["public_url"],
        authorization_server=oauth_cfg["issuer"],
    )


def build_http_app(http_cfg: HttpAppConfig, audit: AuditEmitter | None = None):
    """Build the ASGI app. Returns a Starlette/SessionMiddleware-wrapped app."""
    audit_emitter = audit or AuditEmitter()
    mcp_app = FastMCP(name="wazuh-mcp")

    @mcp_app.tool(
        name="alerts.search_alerts",
        description=(
            "Search Wazuh alerts by time range and filters. Use when the user "
            "asks about security events, detections, or incidents within a "
            "time window. Returns a paginated list; use `cursor` from a prior "
            "response to continue."
        ),
        meta={"toolset": "alerts"},
    )
    async def _search_alerts(
        time_range: str = "1h",
        min_level: int | None = None,
        agent_id: str | None = None,
        size: int = 25,
        cursor: list[Any] | None = None,
    ):
        args = SearchAlertsArgs(
            time_range=time_range,
            min_level=min_level,
            agent_id=agent_id,
            size=size,
            cursor=cursor,
        )
        session = current_session()
        indexer = await http_cfg.pool.acquire(session.tenant_id)
        return await search_alerts(
            args=args,
            session=session,
            indexer=indexer,
            audit=audit_emitter,
        )

    ready = [False]

    def ready_fn() -> bool:
        return ready[0]

    asgi = build_asgi_app(
        mcp_app=mcp_app,
        factory=http_cfg.chain,
        resource_url=http_cfg.resource_url,
        authorization_server=http_cfg.authorization_server,
        ready_fn=ready_fn,
    )

    ready[0] = True
    return asgi


def run_http(config_dir: Path) -> None:
    import uvicorn

    http_cfg = load_http_config(config_dir)
    asgi = build_http_app(http_cfg)

    server_yaml = yaml.safe_load((config_dir / "server.yaml").read_text()) or {}
    bind = server_yaml["http"]["bind"]
    host, _, port = bind.partition(":")
    uvicorn.run(asgi, host=host, port=int(port), proxy_headers=True, log_level="info")
