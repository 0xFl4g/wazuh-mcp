"""MCP server wiring.

M1 path: stdio + ConfigSessionFactory (single-session from config).
M2 path: see transport/http.py for HTTP mode (uses OAuth/ApiKey factories).
M3 path: _register_everything() wires all 17 tools, 3 resources, 3 prompts.
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
from wazuh_mcp.transport.http import build_asgi_app
from wazuh_mcp.transport.session_ctx import (
    current_session,
    set_current_session,
)
from wazuh_mcp.wazuh.indexer import IndexerClient
from wazuh_mcp.wazuh.indexer_pool import IndexerClientPool
from wazuh_mcp.wazuh.server_api import ServerApiClient
from wazuh_mcp.wazuh.server_api_pool import ServerApiClientPool


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

    # Stdio is single-tenant. Build shared clients lazily; cache in
    # single-element holders so repeat acquires return the same client.
    indexer_holder: dict[str, IndexerClient] = {}
    server_api_holder: dict[str, ServerApiClient] = {}

    async def _open_indexer() -> IndexerClient:
        if "c" not in indexer_holder:
            user = await cfg.secrets.get(cfg.tenant.tenant_id, "indexer_user")
            password = await cfg.secrets.get(cfg.tenant.tenant_id, "indexer_password")
            indexer_holder["c"] = IndexerClient(
                base_url=str(cfg.tenant.indexer_url),
                user=user,
                password=password,
                verify_tls=cfg.tenant.verify_tls,
                ca_bundle_path=cfg.tenant.ca_bundle_path,
            )
        return indexer_holder["c"]

    async def _open_server_api() -> ServerApiClient:
        if "c" not in server_api_holder:
            user = await cfg.secrets.get(cfg.tenant.tenant_id, "server_api_user")
            password = await cfg.secrets.get(cfg.tenant.tenant_id, "server_api_password")
            base_url = ServerApiClientPool._derive_server_api_url(cfg.tenant)
            server_api_holder["c"] = ServerApiClient(
                base_url=base_url,
                user=user,
                password=password,
                verify_tls=cfg.tenant.verify_tls,
                ca_bundle_path=cfg.tenant.ca_bundle_path,
            )
        return server_api_holder["c"]

    async def _ensure_session_async() -> Any:
        """Stdio has no HTTP middleware to set the session contextvar, so
        handlers populate it lazily on first call."""
        try:
            return current_session()
        except LookupError:
            sess = await cfg.factory.build({})
            set_current_session(sess)
            return sess

    class _IndexerAdapter:
        async def acquire(self, tenant_id: str) -> IndexerClient:
            await _ensure_session_async()
            return await _open_indexer()

    class _ServerApiAdapter:
        async def acquire(self, tenant_id: str) -> ServerApiClient:
            await _ensure_session_async()
            return await _open_server_api()

    _register_everything(
        app,
        indexer_pool=_IndexerAdapter(),
        server_api_pool=_ServerApiAdapter(),
        audit_emitter=audit_emitter,
    )

    return app


def run_stdio(config_dir: Path) -> None:
    import asyncio

    cfg = load_config(config_dir)
    app = build_app(cfg)

    async def _runner() -> None:
        # stdio has no per-request middleware. Prime the single-session
        # contextvar once before entering the MCP loop so every tool body's
        # `current_session()` call succeeds. Safe because stdio is
        # single-tenant/single-user by construction.
        session = await cfg.factory.build({})
        set_current_session(session)
        await app.run_stdio_async()

    asyncio.run(_runner())


# ---- HTTP mode wiring ----


@dataclass(frozen=True)
class HttpAppConfig:
    pool: IndexerClientPool
    server_api_pool: ServerApiClientPool
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
    server_api_pool = ServerApiClientPool(registry=registry, secrets=secrets)

    http_cfg = server_cfg["http"]
    return HttpAppConfig(
        pool=pool,
        server_api_pool=server_api_pool,
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

    _register_everything(
        mcp_app,
        indexer_pool=http_cfg.pool,
        server_api_pool=http_cfg.server_api_pool,
        audit_emitter=audit_emitter,
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


# ---- Tool/Resource/Prompt registration ----


def _register_everything(
    mcp_app: FastMCP,
    *,
    indexer_pool: Any,
    server_api_pool: Any,
    audit_emitter: AuditEmitter,
) -> None:
    """Register every M3 tool, resource, and prompt onto mcp_app.

    ``indexer_pool`` and ``server_api_pool`` are treated as objects with an
    async ``acquire(tenant_id)`` method. The HTTP path passes the real
    IndexerClientPool / ServerApiClientPool; stdio passes thin adapters.
    """
    # ---------- alerts.* ----------
    from wazuh_mcp.tools.alerts import (
        AlertsByAgentArgs,
        AlertsByMitreArgs,
        GetAlertArgs,
        SearchAlertsArgs,
        alerts_by_agent,
        alerts_by_mitre,
        get_alert,
        search_alerts,
    )

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
    async def _search_alerts(**kwargs):
        args = SearchAlertsArgs(**kwargs)
        session = current_session()
        indexer = await indexer_pool.acquire(session.tenant_id)
        return await search_alerts(args=args, session=session, indexer=indexer, audit=audit_emitter)

    @mcp_app.tool(
        name="alerts.get_alert",
        description="Fetch a single Wazuh alert by its document id.",
        meta={"toolset": "alerts"},
    )
    async def _get_alert(**kwargs):
        args = GetAlertArgs(**kwargs)
        session = current_session()
        indexer = await indexer_pool.acquire(session.tenant_id)
        return await get_alert(args=args, session=session, indexer=indexer, audit=audit_emitter)

    @mcp_app.tool(
        name="alerts.alerts_by_agent",
        description="List alerts for a specific agent over a time range.",
        meta={"toolset": "alerts"},
    )
    async def _alerts_by_agent(**kwargs):
        args = AlertsByAgentArgs(**kwargs)
        session = current_session()
        indexer = await indexer_pool.acquire(session.tenant_id)
        return await alerts_by_agent(
            args=args, session=session, indexer=indexer, audit=audit_emitter
        )

    @mcp_app.tool(
        name="alerts.alerts_by_mitre",
        description="List alerts matching a MITRE ATT&CK technique id.",
        meta={"toolset": "alerts"},
    )
    async def _alerts_by_mitre(**kwargs):
        args = AlertsByMitreArgs(**kwargs)
        session = current_session()
        indexer = await indexer_pool.acquire(session.tenant_id)
        return await alerts_by_mitre(
            args=args, session=session, indexer=indexer, audit=audit_emitter
        )

    # ---------- agents.* ----------
    from wazuh_mcp.tools.agents import (
        AgentSubquery,
        ListAgentsArgs,
        agent_packages,
        agent_ports,
        agent_processes,
        list_agents,
    )
    from wazuh_mcp.tools.agents import (
        GetAgentArgs as _GetAgentArgs,
    )
    from wazuh_mcp.tools.agents import (
        get_agent as _get_agent_fn,
    )

    @mcp_app.tool(
        name="agents.list_agents",
        description="List Wazuh agents, optionally filtered by status or group.",
        meta={"toolset": "agents"},
    )
    async def _list_agents(**kwargs):
        args = ListAgentsArgs(**kwargs)
        session = current_session()
        server_api = await server_api_pool.acquire(session.tenant_id)
        return await list_agents(
            args=args, session=session, server_api=server_api, audit=audit_emitter
        )

    @mcp_app.tool(
        name="agents.get_agent",
        description="Fetch a single Wazuh agent by id.",
        meta={"toolset": "agents"},
    )
    async def _agents_get_agent(**kwargs):
        args = _GetAgentArgs(**kwargs)
        session = current_session()
        server_api = await server_api_pool.acquire(session.tenant_id)
        return await _get_agent_fn(
            args=args, session=session, server_api=server_api, audit=audit_emitter
        )

    @mcp_app.tool(
        name="agents.agent_processes",
        description="List processes seen on an agent (syscollector inventory).",
        meta={"toolset": "agents"},
    )
    async def _agent_processes(**kwargs):
        args = AgentSubquery(**kwargs)
        session = current_session()
        server_api = await server_api_pool.acquire(session.tenant_id)
        return await agent_processes(
            args=args, session=session, server_api=server_api, audit=audit_emitter
        )

    @mcp_app.tool(
        name="agents.agent_packages",
        description="List installed packages on an agent (syscollector inventory).",
        meta={"toolset": "agents"},
    )
    async def _agent_packages(**kwargs):
        args = AgentSubquery(**kwargs)
        session = current_session()
        server_api = await server_api_pool.acquire(session.tenant_id)
        return await agent_packages(
            args=args, session=session, server_api=server_api, audit=audit_emitter
        )

    @mcp_app.tool(
        name="agents.agent_ports",
        description="List open ports on an agent (syscollector inventory).",
        meta={"toolset": "agents"},
    )
    async def _agent_ports(**kwargs):
        args = AgentSubquery(**kwargs)
        session = current_session()
        server_api = await server_api_pool.acquire(session.tenant_id)
        return await agent_ports(
            args=args, session=session, server_api=server_api, audit=audit_emitter
        )

    # ---------- vulnerabilities.* ----------
    from wazuh_mcp.tools.vulns import (
        ListVulnerabilitiesByAgentArgs,
        SearchVulnerabilitiesArgs,
        list_vulnerabilities_by_agent,
        search_vulnerabilities,
    )

    @mcp_app.tool(
        name="vulnerabilities.list_vulnerabilities_by_agent",
        description="List vulnerabilities for an agent (Wazuh 4.8+ indexer-backed).",
        meta={"toolset": "vulnerabilities"},
    )
    async def _list_vulns(**kwargs):
        args = ListVulnerabilitiesByAgentArgs(**kwargs)
        session = current_session()
        indexer = await indexer_pool.acquire(session.tenant_id)
        return await list_vulnerabilities_by_agent(
            args=args, session=session, indexer=indexer, audit=audit_emitter
        )

    @mcp_app.tool(
        name="vulnerabilities.search_vulnerabilities",
        description="Search vulnerabilities by CVE id or minimum severity.",
        meta={"toolset": "vulnerabilities"},
    )
    async def _search_vulns(**kwargs):
        args = SearchVulnerabilitiesArgs(**kwargs)
        session = current_session()
        indexer = await indexer_pool.acquire(session.tenant_id)
        return await search_vulnerabilities(
            args=args, session=session, indexer=indexer, audit=audit_emitter
        )

    # ---------- mitre.* ----------
    from wazuh_mcp.tools.mitre import (
        GetMitreTechniqueArgs,
        SearchMitreArgs,
        get_mitre_technique,
        search_mitre,
    )

    @mcp_app.tool(
        name="mitre.get_mitre_technique",
        description="Look up a MITRE ATT&CK technique by id (e.g. T1110.001).",
        meta={"toolset": "mitre"},
    )
    async def _get_technique(**kwargs):
        args = GetMitreTechniqueArgs(**kwargs)
        session = current_session()
        server_api = await server_api_pool.acquire(session.tenant_id)
        return await get_mitre_technique(
            args=args, session=session, server_api=server_api, audit=audit_emitter
        )

    @mcp_app.tool(
        name="mitre.search_mitre",
        description="Search MITRE techniques by name substring or tactic.",
        meta={"toolset": "mitre"},
    )
    async def _search_mitre(**kwargs):
        args = SearchMitreArgs(**kwargs)
        session = current_session()
        server_api = await server_api_pool.acquire(session.tenant_id)
        return await search_mitre(
            args=args, session=session, server_api=server_api, audit=audit_emitter
        )

    # ---------- hunt.* ----------
    from wazuh_mcp.tools.hunt import (
        HuntQueryArgs,
        PivotByIocArgs,
        hunt_query,
        pivot_by_ioc,
    )

    @mcp_app.tool(
        name="hunt.hunt_query",
        description=(
            "Run a constrained-grammar hunt across alerts. Accepts structured "
            "{field, op, value} clauses from an allowlist - never raw DSL."
        ),
        meta={"toolset": "hunt"},
    )
    async def _hunt(**kwargs):
        args = HuntQueryArgs(**kwargs)
        session = current_session()
        indexer = await indexer_pool.acquire(session.tenant_id)
        return await hunt_query(args=args, session=session, indexer=indexer, audit=audit_emitter)

    @mcp_app.tool(
        name="hunt.pivot_by_ioc",
        description="Pivot alerts by hash/ip/user/domain (preset over hunt_query).",
        meta={"toolset": "hunt"},
    )
    async def _pivot(**kwargs):
        args = PivotByIocArgs(**kwargs)
        session = current_session()
        indexer = await indexer_pool.acquire(session.tenant_id)
        return await pivot_by_ioc(args=args, session=session, indexer=indexer, audit=audit_emitter)

    # ---------- fim.* ----------
    from wazuh_mcp.tools.fim import (
        FimChangesArgs,
        FimHistoryArgs,
        fim_changes_by_agent,
        fim_history_for_path,
    )

    @mcp_app.tool(
        name="fim.fim_history_for_path",
        description="History of file-integrity events for a specific path.",
        meta={"toolset": "fim"},
    )
    async def _fim_history(**kwargs):
        args = FimHistoryArgs(**kwargs)
        session = current_session()
        indexer = await indexer_pool.acquire(session.tenant_id)
        return await fim_history_for_path(
            args=args, session=session, indexer=indexer, audit=audit_emitter
        )

    @mcp_app.tool(
        name="fim.fim_changes_by_agent",
        description="Recent file-integrity changes on a specific agent.",
        meta={"toolset": "fim"},
    )
    async def _fim_changes(**kwargs):
        args = FimChangesArgs(**kwargs)
        session = current_session()
        indexer = await indexer_pool.acquire(session.tenant_id)
        return await fim_changes_by_agent(
            args=args, session=session, indexer=indexer, audit=audit_emitter
        )

    # ---------- resources ----------
    # FastMCP provides @mcp.resource(uri) — if the URI contains {var} it is
    # automatically registered as a ResourceTemplate and dispatched to this
    # handler with the template variables as kwargs. No manual URI pattern
    # matching needed: the SDK handles resources/list, resources/templates/list,
    # and resources/read for us.
    from wazuh_mcp.resources.agent_config import read_agent_config
    from wazuh_mcp.resources.mitre import read_mitre_technique
    from wazuh_mcp.resources.rules import read_rule

    @mcp_app.resource(
        "wazuh://rules/{rule_id}",
        name="Wazuh rule",
        description=(
            "Individual Wazuh detection rule - definition, groups, description. "
            "Attach instead of calling a tool when the model just needs rule metadata."
        ),
        mime_type="application/json",
    )
    async def _resource_rule(rule_id: str):
        session = current_session()
        server_api = await server_api_pool.acquire(session.tenant_id)
        return await read_rule(
            rule_id=rule_id,
            session=session,
            server_api=server_api,
            audit=audit_emitter,
        )

    @mcp_app.resource(
        "wazuh://mitre/technique/{technique_id}",
        name="MITRE ATT&CK technique",
        description=(
            "Individual MITRE ATT&CK technique (TXXXX or TXXXX.YYY). "
            "Stable public corpus - cache aggressively."
        ),
        mime_type="application/json",
    )
    async def _resource_mitre(technique_id: str):
        session = current_session()
        server_api = await server_api_pool.acquire(session.tenant_id)
        return await read_mitre_technique(
            technique_id=technique_id,
            session=session,
            server_api=server_api,
            audit=audit_emitter,
        )

    @mcp_app.resource(
        "wazuh://agents/{agent_id}/config",
        name="Agent configuration",
        description="Current agent configuration snapshot from the Server API.",
        mime_type="application/json",
    )
    async def _resource_agent_config(agent_id: str):
        session = current_session()
        server_api = await server_api_pool.acquire(session.tenant_id)
        return await read_agent_config(
            agent_id=agent_id,
            session=session,
            server_api=server_api,
            audit=audit_emitter,
        )

    # ---------- prompts ----------
    from wazuh_mcp.prompts import agent_posture, investigate_alert, triage_last_hour

    @mcp_app.prompt(
        name="triage_last_hour",
        description=(
            "Triage Wazuh alerts from the last hour (level >= 10). Pre-loads "
            "the alert set so Claude can summarise without further tool calls."
        ),
    )
    async def _prompt_triage_last_hour():
        session = current_session()
        indexer = await indexer_pool.acquire(session.tenant_id)
        return await triage_last_hour.handle(session=session, indexer=indexer, audit=audit_emitter)

    @mcp_app.prompt(
        name="investigate_alert",
        description=(
            "Investigate a single Wazuh alert: fetches the alert, its agent, "
            "and last-hour neighbors on the same agent."
        ),
    )
    async def _prompt_investigate_alert(alert_id: str):
        session = current_session()
        indexer = await indexer_pool.acquire(session.tenant_id)
        server_api = await server_api_pool.acquire(session.tenant_id)
        return await investigate_alert.handle(
            alert_id=alert_id,
            session=session,
            indexer=indexer,
            server_api=server_api,
            audit=audit_emitter,
        )

    @mcp_app.prompt(
        name="agent_posture",
        description=(
            "Summarise an agent's security posture: details + last-24h alerts "
            "+ vulnerability count."
        ),
    )
    async def _prompt_agent_posture(agent_id: str):
        session = current_session()
        indexer = await indexer_pool.acquire(session.tenant_id)
        server_api = await server_api_pool.acquire(session.tenant_id)
        return await agent_posture.handle(
            agent_id=agent_id,
            session=session,
            indexer=indexer,
            server_api=server_api,
            audit=audit_emitter,
        )
