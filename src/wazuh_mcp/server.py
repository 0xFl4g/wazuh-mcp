"""MCP server wiring.

M1 path: stdio + ConfigSessionFactory (single-session from config).
M2 path: see transport/http.py for HTTP mode (uses OAuth/ApiKey factories).
M3 path: _register_everything() wires all 17 tools, 3 resources, 3 prompts.
M4a path: every tool wrapped by @instrumented_tool (RBAC, rate limit, OTel,
audit), /metrics mounted under HTTP, OTel + auto-instrumentation bootstrap,
list_tools/call_tool hooks install RBAC filter/guard on the low-level server.
"""

from __future__ import annotations

import importlib.metadata
import logging
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import mcp.types as _mt
import yaml
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from pydantic import BaseModel

from wazuh_mcp.auth.api_key import ApiKeySessionFactory
from wazuh_mcp.auth.api_key_store import YamlApiKeyStore
from wazuh_mcp.auth.chain_factory import ChainSessionFactory
from wazuh_mcp.auth.config_factory import ConfigSessionFactory
from wazuh_mcp.auth.factory import SessionFactory
from wazuh_mcp.auth.jwks_cache import JwksCache
from wazuh_mcp.auth.oauth import OAuthSessionFactory
from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import MultiSinkAuditEmitter
from wazuh_mcp.observability.decorators import instrumented_tool
from wazuh_mcp.observability.metrics import maybe_start_stdio_metrics_server
from wazuh_mcp.observability.otel import init_otel
from wazuh_mcp.observability.sinks.base import AuditSink
from wazuh_mcp.rate_limit.limiter import InProcessRateLimiter, RateLimiter
from wazuh_mcp.rbac.filter import is_allowed
from wazuh_mcp.rbac.policy import effective_allowlist_for
from wazuh_mcp.secrets.yaml_driver import YamlSecretStore
from wazuh_mcp.tenancy.config import TenantConfig
from wazuh_mcp.tenancy.issuer_index import IssuerIndex
from wazuh_mcp.tenancy.registry import TenantRegistry, YamlTenantRegistry
from wazuh_mcp.transport.http import build_asgi_app
from wazuh_mcp.transport.session_ctx import (
    current_session,
    set_current_session,
)
from wazuh_mcp.wazuh.indexer import IndexerClient
from wazuh_mcp.wazuh.indexer_pool import IndexerClientPool
from wazuh_mcp.wazuh.server_api import ServerApiClient
from wazuh_mcp.wazuh.server_api_pool import ServerApiClientPool

_logger = logging.getLogger("wazuh_mcp.server")


def _service_version() -> str:
    try:
        return importlib.metadata.version("wazuh-mcp")
    except importlib.metadata.PackageNotFoundError:
        return "0.0.0+dev"


@dataclass(frozen=True)
class AppConfig:
    factory: SessionFactory
    tenant: TenantConfig
    secrets: YamlSecretStore
    limiter: RateLimiter | None = None
    audit: MultiSinkAuditEmitter | None = None


def load_config(config_dir: Path) -> AppConfig:
    server_cfg = yaml.safe_load((config_dir / "server.yaml").read_text()) or {}
    registry = YamlTenantRegistry(config_dir / "tenants.yaml")
    secrets = YamlSecretStore(config_dir / "secrets.yaml")

    tenant_id = server_cfg["active_tenant"]
    user_id = server_cfg.get("user_id", "local")
    tenant = registry.get(tenant_id)
    factory = ConfigSessionFactory(user_id=user_id, tenant=tenant)
    return AppConfig(factory=factory, tenant=tenant, secrets=secrets)


def _build_sinks(tenant: TenantConfig, *, indexer_pool: Any) -> list[AuditSink]:
    """Translate TenantConfig.audit_sinks config entries to sink instances."""
    from wazuh_mcp.observability.sinks.file import FileSink
    from wazuh_mcp.observability.sinks.http import HttpSink
    from wazuh_mcp.observability.sinks.stream import StderrSink, StdoutSink
    from wazuh_mcp.observability.sinks.wazuh_indexer import WazuhIndexerSink
    from wazuh_mcp.tenancy.m4_config import (
        FileSinkConfig,
        HttpSinkConfig,
        StderrSinkConfig,
        StdoutSinkConfig,
        WazuhIndexerSinkConfig,
    )

    sinks: list[AuditSink] = []
    for cfg in tenant.audit_sinks:
        if isinstance(cfg, StderrSinkConfig):
            sinks.append(StderrSink())
        elif isinstance(cfg, StdoutSinkConfig):
            sinks.append(StdoutSink())
        elif isinstance(cfg, FileSinkConfig):
            sinks.append(
                FileSink(
                    path=cfg.path,
                    rotate_size_bytes=cfg.rotate_size_mb * 1024 * 1024,
                    keep=cfg.keep,
                )
            )
        elif isinstance(cfg, HttpSinkConfig):
            sinks.append(
                HttpSink(
                    url=str(cfg.url),
                    batch=cfg.batch,
                    flush_ms=cfg.flush_ms,
                    max_attempts=cfg.max_attempts,
                )
            )
        elif isinstance(cfg, WazuhIndexerSinkConfig):
            if indexer_pool is None:
                raise RuntimeError(
                    "wazuh_indexer audit sink requires an indexer_pool; "
                    "only available in HTTP mode."
                )
            sinks.append(
                WazuhIndexerSink(
                    pool=indexer_pool,
                    tenant_id=tenant.tenant_id,
                    index_prefix=cfg.index_prefix,
                    batch=cfg.batch,
                    flush_ms=cfg.flush_ms,
                    max_attempts=cfg.max_attempts,
                )
            )
    return sinks


def _install_rbac_hooks(
    mcp_app: FastMCP,
    *,
    rbac_policy: Callable[[Session], dict[str, list[str]]],
    audit_emitter: MultiSinkAuditEmitter,
) -> None:
    """Install list_tools + call_tool wrappers on the low-level MCP server.

    Per the 2026-04-24 FastMCP probe: FastMCP registers its handlers at
    ``__init__`` time into the low-level ``Server.request_handlers``
    single-slot dict. Re-registering on ``mcp_app._mcp_server`` after
    ``_register_everything`` is the supported extension pattern and the
    last registration wins.
    """
    _fastmcp_list_tools = mcp_app.list_tools
    _fastmcp_call_tool = mcp_app.call_tool

    @mcp_app._mcp_server.list_tools()
    async def _rbac_list_tools() -> list[_mt.Tool]:
        all_tools = await _fastmcp_list_tools()
        try:
            session = current_session()
        except LookupError:
            # stdio pre-session path: the process itself is the trust
            # boundary, allow-all is the right default. Log so an
            # unexpected pre-session list_tools in a stdio deploy still
            # leaves a signal operators can find.
            _logger.info(
                "list_tools without session contextvar — stdio pre-session trust-boundary allow-all"
            )
            return all_tools
        policy = rbac_policy(session)
        return [t for t in all_tools if is_allowed(session, t.name, policy)]

    async def _rbac_call_tool(name: str, arguments: dict[str, Any]) -> Any:
        session = current_session()
        policy = rbac_policy(session)
        if not is_allowed(session, name, policy):
            # Audit the deny BEFORE raising, so a red-team probing denied
            # tools leaves a trail. The @instrumented_tool decorator's
            # forbidden-emit branch is unreachable from here — we short-
            # circuit before dispatch — so this is the only audit event a
            # call-time RBAC rejection will ever produce.
            audit_emitter.emit(
                session=session,
                tool=name,
                args=arguments,
                outcome="error",
                result_count=0,
                duration_ms=0,
                error_code="forbidden",
            )
            # Info-hiding: a denied tool looks identical to an unknown tool
            # from outside (same error, no hint that the tool exists).
            raise ToolError(f"Unknown tool: {name}")
        return await _fastmcp_call_tool(name, arguments)

    # validate_input=False because FastMCP's own call_tool has already
    # promoted us past the cache layer; re-validating here would double-
    # validate and is unnecessary since the inner handler runs the same
    # schema pass.
    mcp_app._mcp_server.call_tool(validate_input=False)(_rbac_call_tool)


def build_app(cfg: AppConfig, audit: MultiSinkAuditEmitter | None = None) -> FastMCP:
    """Build the stdio FastMCP app.

    M4a invariants:
      * init_otel runs first and is idempotent.
      * maybe_start_stdio_metrics_server honors WAZUH_MCP_METRICS_ADDR env var.
      * audit emitter start() is the caller's responsibility — stdio's
        run_stdio() runner below calls it before entering the MCP loop.
    """
    init_otel(service_version=_service_version())
    maybe_start_stdio_metrics_server()

    audit_emitter = (
        audit
        or cfg.audit
        or MultiSinkAuditEmitter(sinks=_build_sinks(cfg.tenant, indexer_pool=None))
    )
    limiter = cfg.limiter or InProcessRateLimiter(default=cfg.tenant.rate_limit)

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

    def _rbac_policy(session: Session) -> dict[str, list[str]]:
        # TODO(M4b): resolve tenant-specific override via TenantRegistry.
        # Today we capture the primary tenant's allowlist — fine for
        # single-tenant stdio, but an enterprise multi-tenant deploy will
        # need session.tenant_id → tenant_cfg.role_tool_allowlist lookup
        # here. The `session` arg must stay in the signature so a future
        # refactor doesn't innocently delete it.
        return effective_allowlist_for(tenant_override=cfg.tenant.role_tool_allowlist)

    _register_everything(
        app,
        indexer_pool=_IndexerAdapter(),
        server_api_pool=_ServerApiAdapter(),
        audit_emitter=audit_emitter,
        limiter=limiter,
        rbac_policy=_rbac_policy,
        tenant_cfg=cfg.tenant,
    )
    _install_rbac_hooks(app, rbac_policy=_rbac_policy, audit_emitter=audit_emitter)

    # Expose the emitter so the stdio runner can manage lifecycle.
    app._wazuh_mcp_audit_emitter = audit_emitter  # ty: ignore[unresolved-attribute]
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
        emitter: MultiSinkAuditEmitter | None = getattr(app, "_wazuh_mcp_audit_emitter", None)
        if emitter is not None:
            await emitter.start()
        try:
            await app.run_stdio_async()
        finally:
            if emitter is not None:
                await emitter.stop()

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
    # M4a wiring — defaults preserve M3 call sites.
    tenant: TenantConfig | None = None
    # M4c: per-tenant policy resolution. ``load_http_config`` builds the
    # registry and keeps it alive here so resolvers can close over it.
    registry: TenantRegistry | None = None
    limiter: RateLimiter | None = None
    audit: MultiSinkAuditEmitter | None = None


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
    # M4a: default to the first tenant's M4a overrides for single-tenant
    # rate-limit/audit-sink wiring. Multi-tenant policy resolution is
    # M4b scope — see plan.
    primary_tenant = all_tenants[0] if all_tenants else None
    return HttpAppConfig(
        pool=pool,
        server_api_pool=server_api_pool,
        chain=chain,
        oauth=oauth,
        issuer_index=issuer_index,
        resource_url=http_cfg["public_url"],
        authorization_server=oauth_cfg["issuer"],
        tenant=primary_tenant,
        registry=registry,
    )


def build_http_app(http_cfg: HttpAppConfig, audit: MultiSinkAuditEmitter | None = None):
    """Build the ASGI app. Returns a Starlette/SessionMiddleware-wrapped app.

    M4a invariants:
      * init_otel runs first.
      * /metrics is mounted on the ASGI app (build_asgi_app handles it).
      * audit emitter start()/stop() is attached to the ASGI lifespan
        by build_asgi_app.
    """
    init_otel(service_version=_service_version())

    sinks: list[AuditSink] = []
    if http_cfg.tenant is not None:
        sinks = _build_sinks(http_cfg.tenant, indexer_pool=http_cfg.pool)
    audit_emitter = audit or http_cfg.audit or MultiSinkAuditEmitter(sinks=sinks or None)

    if http_cfg.limiter is not None:
        limiter = http_cfg.limiter
    elif http_cfg.tenant is not None:
        limiter = InProcessRateLimiter(default=http_cfg.tenant.rate_limit)
    else:
        # Extremely defensive: the M4a tenancy registry always yields at
        # least one tenant. Fall back to permissive defaults so the server
        # still boots.
        from wazuh_mcp.tenancy.m4_config import RateLimitConfig

        limiter = InProcessRateLimiter(default=RateLimitConfig())

    mcp_app = FastMCP(name="wazuh-mcp")

    def _rbac_policy(session: Session) -> dict[str, list[str]]:
        # TODO(M4b): resolve tenant-specific override via TenantRegistry.
        # Today we capture the primary tenant's allowlist — fine for
        # single-tenant HTTP, but an enterprise multi-tenant deploy will
        # need session.tenant_id → tenant_cfg.role_tool_allowlist lookup
        # here. The `session` arg must stay in the signature so a future
        # refactor doesn't innocently delete it.
        override = http_cfg.tenant.role_tool_allowlist if http_cfg.tenant is not None else None
        return effective_allowlist_for(tenant_override=override)

    _register_everything(
        mcp_app,
        indexer_pool=http_cfg.pool,
        server_api_pool=http_cfg.server_api_pool,
        audit_emitter=audit_emitter,
        limiter=limiter,
        rbac_policy=_rbac_policy,
        tenant_cfg=http_cfg.tenant,
    )
    _install_rbac_hooks(mcp_app, rbac_policy=_rbac_policy, audit_emitter=audit_emitter)

    ready = [False]

    def ready_fn() -> bool:
        return ready[0]

    asgi = build_asgi_app(
        mcp_app=mcp_app,
        factory=http_cfg.chain,
        resource_url=http_cfg.resource_url,
        authorization_server=http_cfg.authorization_server,
        ready_fn=ready_fn,
        audit_emitter=audit_emitter,
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
    audit_emitter: MultiSinkAuditEmitter,
    limiter: RateLimiter,
    rbac_policy: Callable[[Session], dict[str, list[str]]],
    tenant_cfg: TenantConfig | None = None,
) -> None:
    """Register every M3 tool, resource, and prompt onto ``mcp_app``.

    Every tool is wrapped by :func:`instrumented_tool` so RBAC, rate-limit,
    OTel, audit, and metrics fire uniformly around each call. Resources
    and prompts are not wrapped in M4a — they keep their existing audit
    emission inside the handler, since they're not part of the tool
    surface the decorator covers.

    ``indexer_pool`` and ``server_api_pool`` are treated as objects with an
    async ``acquire(tenant_id)`` method. The HTTP path passes the real
    pools; stdio passes thin adapters.
    """

    def _wrap(
        *,
        tool_name: str,
        handler: Callable[..., Any],
        description: str,
        meta: dict[str, Any],
        args_model: type[BaseModel],
        result_model: type[BaseModel],
    ) -> None:
        wrapped = instrumented_tool(
            tool_name=tool_name,
            handler=handler,
            rbac_policy=rbac_policy,
            limiter=limiter,
            audit=audit_emitter,
            args_model=args_model,
            result_model=result_model,
        )
        mcp_app.tool(name=tool_name, description=description, meta=meta)(wrapped)

    # ---------- alerts.* ----------
    from wazuh_mcp.tools.alerts import (
        AlertsByAgentArgs,
        AlertsByMitreArgs,
        GetAlertArgs,
        GetAlertResult,
        SearchAlertsArgs,
        SearchAlertsResult,
        alerts_by_agent,
        alerts_by_mitre,
        get_alert,
        search_alerts,
    )

    async def _search_alerts_inner(**kwargs: Any) -> Any:
        args = SearchAlertsArgs(**kwargs)
        session = current_session()
        indexer = await indexer_pool.acquire(session.tenant_id)
        return await search_alerts(args=args, session=session, indexer=indexer)

    _wrap(
        tool_name="alerts.search_alerts",
        handler=_search_alerts_inner,
        description=(
            "Search Wazuh alerts by time range and filters. Use when the user "
            "asks about security events, detections, or incidents within a "
            "time window. Returns a paginated list; use `cursor` from a prior "
            "response to continue."
        ),
        meta={"toolset": "alerts"},
        args_model=SearchAlertsArgs,
        result_model=SearchAlertsResult,
    )

    async def _get_alert_inner(**kwargs: Any) -> Any:
        args = GetAlertArgs(**kwargs)
        session = current_session()
        indexer = await indexer_pool.acquire(session.tenant_id)
        return await get_alert(args=args, session=session, indexer=indexer)

    _wrap(
        tool_name="alerts.get_alert",
        handler=_get_alert_inner,
        description="Fetch a single Wazuh alert by its document id.",
        meta={"toolset": "alerts"},
        args_model=GetAlertArgs,
        result_model=GetAlertResult,
    )

    async def _alerts_by_agent_inner(**kwargs: Any) -> Any:
        args = AlertsByAgentArgs(**kwargs)
        session = current_session()
        indexer = await indexer_pool.acquire(session.tenant_id)
        return await alerts_by_agent(args=args, session=session, indexer=indexer)

    _wrap(
        tool_name="alerts.alerts_by_agent",
        handler=_alerts_by_agent_inner,
        description="List alerts for a specific agent over a time range.",
        meta={"toolset": "alerts"},
        args_model=AlertsByAgentArgs,
        result_model=SearchAlertsResult,
    )

    async def _alerts_by_mitre_inner(**kwargs: Any) -> Any:
        args = AlertsByMitreArgs(**kwargs)
        session = current_session()
        indexer = await indexer_pool.acquire(session.tenant_id)
        return await alerts_by_mitre(args=args, session=session, indexer=indexer)

    _wrap(
        tool_name="alerts.alerts_by_mitre",
        handler=_alerts_by_mitre_inner,
        description="List alerts matching a MITRE ATT&CK technique id.",
        meta={"toolset": "alerts"},
        args_model=AlertsByMitreArgs,
        result_model=SearchAlertsResult,
    )

    # ---------- agents.* ----------
    from wazuh_mcp.tools.agents import (
        AgentInventoryResult,
        AgentResult,
        AgentsResult,
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

    async def _list_agents_inner(**kwargs: Any) -> Any:
        args = ListAgentsArgs(**kwargs)
        session = current_session()
        server_api = await server_api_pool.acquire(session.tenant_id)
        return await list_agents(args=args, session=session, server_api=server_api)

    _wrap(
        tool_name="agents.list_agents",
        handler=_list_agents_inner,
        description="List Wazuh agents, optionally filtered by status or group.",
        meta={"toolset": "agents"},
        args_model=ListAgentsArgs,
        result_model=AgentsResult,
    )

    async def _get_agent_inner(**kwargs: Any) -> Any:
        args = _GetAgentArgs(**kwargs)
        session = current_session()
        server_api = await server_api_pool.acquire(session.tenant_id)
        return await _get_agent_fn(args=args, session=session, server_api=server_api)

    _wrap(
        tool_name="agents.get_agent",
        handler=_get_agent_inner,
        description="Fetch a single Wazuh agent by id.",
        meta={"toolset": "agents"},
        args_model=_GetAgentArgs,
        result_model=AgentResult,
    )

    async def _agent_processes_inner(**kwargs: Any) -> Any:
        args = AgentSubquery(**kwargs)
        session = current_session()
        server_api = await server_api_pool.acquire(session.tenant_id)
        return await agent_processes(args=args, session=session, server_api=server_api)

    _wrap(
        tool_name="agents.agent_processes",
        handler=_agent_processes_inner,
        description="List processes seen on an agent (syscollector inventory).",
        meta={"toolset": "agents"},
        args_model=AgentSubquery,
        result_model=AgentInventoryResult,
    )

    async def _agent_packages_inner(**kwargs: Any) -> Any:
        args = AgentSubquery(**kwargs)
        session = current_session()
        server_api = await server_api_pool.acquire(session.tenant_id)
        return await agent_packages(args=args, session=session, server_api=server_api)

    _wrap(
        tool_name="agents.agent_packages",
        handler=_agent_packages_inner,
        description="List installed packages on an agent (syscollector inventory).",
        meta={"toolset": "agents"},
        args_model=AgentSubquery,
        result_model=AgentInventoryResult,
    )

    async def _agent_ports_inner(**kwargs: Any) -> Any:
        args = AgentSubquery(**kwargs)
        session = current_session()
        server_api = await server_api_pool.acquire(session.tenant_id)
        return await agent_ports(args=args, session=session, server_api=server_api)

    _wrap(
        tool_name="agents.agent_ports",
        handler=_agent_ports_inner,
        description="List open ports on an agent (syscollector inventory).",
        meta={"toolset": "agents"},
        args_model=AgentSubquery,
        result_model=AgentInventoryResult,
    )

    # ---------- vulnerabilities.* ----------
    from wazuh_mcp.tools.vulns import (
        ListVulnerabilitiesByAgentArgs,
        SearchVulnerabilitiesArgs,
        VulnerabilitiesResult,
        list_vulnerabilities_by_agent,
        search_vulnerabilities,
    )

    async def _list_vulns_inner(**kwargs: Any) -> Any:
        args = ListVulnerabilitiesByAgentArgs(**kwargs)
        session = current_session()
        indexer = await indexer_pool.acquire(session.tenant_id)
        return await list_vulnerabilities_by_agent(args=args, session=session, indexer=indexer)

    _wrap(
        tool_name="vulnerabilities.list_vulnerabilities_by_agent",
        handler=_list_vulns_inner,
        description="List vulnerabilities for an agent (Wazuh 4.8+ indexer-backed).",
        meta={"toolset": "vulnerabilities"},
        args_model=ListVulnerabilitiesByAgentArgs,
        result_model=VulnerabilitiesResult,
    )

    async def _search_vulns_inner(**kwargs: Any) -> Any:
        args = SearchVulnerabilitiesArgs(**kwargs)
        session = current_session()
        indexer = await indexer_pool.acquire(session.tenant_id)
        return await search_vulnerabilities(args=args, session=session, indexer=indexer)

    _wrap(
        tool_name="vulnerabilities.search_vulnerabilities",
        handler=_search_vulns_inner,
        description="Search vulnerabilities by CVE id or minimum severity.",
        meta={"toolset": "vulnerabilities"},
        args_model=SearchVulnerabilitiesArgs,
        result_model=VulnerabilitiesResult,
    )

    # ---------- mitre.* ----------
    from wazuh_mcp.tools.mitre import (
        GetMitreTechniqueArgs,
        MitreSearchResult,
        MitreTechniqueResult,
        SearchMitreArgs,
        get_mitre_technique,
        search_mitre,
    )

    async def _get_technique_inner(**kwargs: Any) -> Any:
        args = GetMitreTechniqueArgs(**kwargs)
        session = current_session()
        server_api = await server_api_pool.acquire(session.tenant_id)
        return await get_mitre_technique(args=args, session=session, server_api=server_api)

    _wrap(
        tool_name="mitre.get_mitre_technique",
        handler=_get_technique_inner,
        description="Look up a MITRE ATT&CK technique by id (e.g. T1110.001).",
        meta={"toolset": "mitre"},
        args_model=GetMitreTechniqueArgs,
        result_model=MitreTechniqueResult,
    )

    async def _search_mitre_inner(**kwargs: Any) -> Any:
        args = SearchMitreArgs(**kwargs)
        session = current_session()
        server_api = await server_api_pool.acquire(session.tenant_id)
        return await search_mitre(args=args, session=session, server_api=server_api)

    _wrap(
        tool_name="mitre.search_mitre",
        handler=_search_mitre_inner,
        description="Search MITRE techniques by name substring or tactic.",
        meta={"toolset": "mitre"},
        args_model=SearchMitreArgs,
        result_model=MitreSearchResult,
    )

    # ---------- hunt.* ----------
    from wazuh_mcp.tools.hunt import (
        HuntQueryArgs,
        HuntQueryResult,
        PivotByIocArgs,
        hunt_query,
        pivot_by_ioc,
    )

    async def _hunt_inner(**kwargs: Any) -> Any:
        args = HuntQueryArgs(**kwargs)
        session = current_session()
        indexer = await indexer_pool.acquire(session.tenant_id)
        return await hunt_query(args=args, session=session, indexer=indexer)

    _wrap(
        tool_name="hunt.hunt_query",
        handler=_hunt_inner,
        description=(
            "Run a constrained-grammar hunt across alerts. Accepts structured "
            "{field, op, value} clauses from an allowlist - never raw DSL."
        ),
        meta={"toolset": "hunt"},
        args_model=HuntQueryArgs,
        result_model=HuntQueryResult,
    )

    async def _pivot_inner(**kwargs: Any) -> Any:
        args = PivotByIocArgs(**kwargs)
        session = current_session()
        indexer = await indexer_pool.acquire(session.tenant_id)
        return await pivot_by_ioc(args=args, session=session, indexer=indexer)

    _wrap(
        tool_name="hunt.pivot_by_ioc",
        handler=_pivot_inner,
        description="Pivot alerts by hash/ip/user/domain (preset over hunt_query).",
        meta={"toolset": "hunt"},
        args_model=PivotByIocArgs,
        result_model=HuntQueryResult,
    )

    # ---------- fim.* ----------
    from wazuh_mcp.tools.fim import (
        FimChangesArgs,
        FimHistoryArgs,
        FimResult,
        fim_changes_by_agent,
        fim_history_for_path,
    )

    async def _fim_history_inner(**kwargs: Any) -> Any:
        args = FimHistoryArgs(**kwargs)
        session = current_session()
        indexer = await indexer_pool.acquire(session.tenant_id)
        return await fim_history_for_path(args=args, session=session, indexer=indexer)

    _wrap(
        tool_name="fim.fim_history_for_path",
        handler=_fim_history_inner,
        description="History of file-integrity events for a specific path.",
        meta={"toolset": "fim"},
        args_model=FimHistoryArgs,
        result_model=FimResult,
    )

    async def _fim_changes_inner(**kwargs: Any) -> Any:
        args = FimChangesArgs(**kwargs)
        session = current_session()
        indexer = await indexer_pool.acquire(session.tenant_id)
        return await fim_changes_by_agent(args=args, session=session, indexer=indexer)

    _wrap(
        tool_name="fim.fim_changes_by_agent",
        handler=_fim_changes_inner,
        description="Recent file-integrity changes on a specific agent.",
        meta={"toolset": "fim"},
        args_model=FimChangesArgs,
        result_model=FimResult,
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

    # ---------- M4b write.* tools ----------
    # TenantConfig.write_allowlist semantics:
    #   None (default) -> every write.* tool registered.
    #   Non-empty list -> only named tools registered.
    #   Empty list     -> no write tools registered at all.
    # When tenant_cfg is None (legacy callers), default to "register all"
    # with an empty active-response allowlist (run_active_response will then
    # reject every call, which is the right default for a missing config).
    from wazuh_mcp.tools.write import (
        AddAgentToGroupArgs,
        CreateRuleArgs,
        IsolateAgentArgs,
        RemoveAgentFromGroupArgs,
        RestartAgentArgs,
        RunActiveResponseArgs,
        UpdateRuleArgs,
        WriteResult,
    )
    from wazuh_mcp.tools.write import (
        add_agent_to_group as _add_agent_to_group,
    )
    from wazuh_mcp.tools.write import (
        create_rule as _create_rule,
    )
    from wazuh_mcp.tools.write import (
        isolate_agent as _isolate_agent,
    )
    from wazuh_mcp.tools.write import (
        remove_agent_from_group as _remove_agent_from_group,
    )
    from wazuh_mcp.tools.write import (
        restart_agent as _restart_agent,
    )
    from wazuh_mcp.tools.write import (
        run_active_response as _run_active_response,
    )
    from wazuh_mcp.tools.write import (
        update_rule as _update_rule,
    )

    def _should_register(name: str, allowlist: list[str] | None) -> bool:
        if allowlist is None:
            return True
        return name in allowlist

    allowlist: list[str] | None = tenant_cfg.write_allowlist if tenant_cfg is not None else None
    ar_allowlist: list[str] = tenant_cfg.active_response_allowlist if tenant_cfg is not None else []

    _write_desc_prefix = (
        "WRITE tool. Destructive side effects. Before calling, explicitly "
        "confirm with the human user what action they want taken and that "
        "they approve. Only set confirm:true after the human has explicitly "
        "approved the specific call. "
    )

    if _should_register("write.isolate_agent", allowlist):

        async def _isolate_inner(**kwargs: Any) -> Any:
            args = IsolateAgentArgs(**kwargs)
            session = current_session()
            sapi = await server_api_pool.acquire(session.tenant_id)
            return await _isolate_agent(args=args, session=session, server_api=sapi)

        mcp_app.tool(
            name="write.isolate_agent",
            description=_write_desc_prefix
            + "Isolates a Wazuh agent (blocks network traffic via Wazuh's isolate active-response).",
            meta={"toolset": "writes"},
        )(
            instrumented_tool(
                tool_name="write.isolate_agent",
                handler=_isolate_inner,
                rbac_policy=rbac_policy,
                limiter=limiter,
                audit=audit_emitter,
                args_model=IsolateAgentArgs,
                result_model=WriteResult,
            )
        )

    if _should_register("write.restart_agent", allowlist):

        async def _restart_inner(**kwargs: Any) -> Any:
            args = RestartAgentArgs(**kwargs)
            session = current_session()
            sapi = await server_api_pool.acquire(session.tenant_id)
            return await _restart_agent(args=args, session=session, server_api=sapi)

        mcp_app.tool(
            name="write.restart_agent",
            description=_write_desc_prefix + "Restarts the Wazuh agent process on the named agent.",
            meta={"toolset": "writes"},
        )(
            instrumented_tool(
                tool_name="write.restart_agent",
                handler=_restart_inner,
                rbac_policy=rbac_policy,
                limiter=limiter,
                audit=audit_emitter,
                args_model=RestartAgentArgs,
                result_model=WriteResult,
            )
        )

    if _should_register("write.add_agent_to_group", allowlist):

        async def _add_group_inner(**kwargs: Any) -> Any:
            args = AddAgentToGroupArgs(**kwargs)
            session = current_session()
            sapi = await server_api_pool.acquire(session.tenant_id)
            return await _add_agent_to_group(args=args, session=session, server_api=sapi)

        mcp_app.tool(
            name="write.add_agent_to_group",
            description=_write_desc_prefix
            + "Adds an agent to a Wazuh group (applies group rules + shared config).",
            meta={"toolset": "writes"},
        )(
            instrumented_tool(
                tool_name="write.add_agent_to_group",
                handler=_add_group_inner,
                rbac_policy=rbac_policy,
                limiter=limiter,
                audit=audit_emitter,
                args_model=AddAgentToGroupArgs,
                result_model=WriteResult,
            )
        )

    if _should_register("write.remove_agent_from_group", allowlist):

        async def _remove_group_inner(**kwargs: Any) -> Any:
            args = RemoveAgentFromGroupArgs(**kwargs)
            session = current_session()
            sapi = await server_api_pool.acquire(session.tenant_id)
            return await _remove_agent_from_group(args=args, session=session, server_api=sapi)

        mcp_app.tool(
            name="write.remove_agent_from_group",
            description=_write_desc_prefix + "Removes an agent from a Wazuh group.",
            meta={"toolset": "writes"},
        )(
            instrumented_tool(
                tool_name="write.remove_agent_from_group",
                handler=_remove_group_inner,
                rbac_policy=rbac_policy,
                limiter=limiter,
                audit=audit_emitter,
                args_model=RemoveAgentFromGroupArgs,
                result_model=WriteResult,
            )
        )

    if _should_register("write.create_rule", allowlist):

        async def _create_rule_inner(**kwargs: Any) -> Any:
            args = CreateRuleArgs(**kwargs)
            session = current_session()
            sapi = await server_api_pool.acquire(session.tenant_id)
            return await _create_rule(args=args, session=session, server_api=sapi)

        mcp_app.tool(
            name="write.create_rule",
            description=_write_desc_prefix
            + "Uploads a new Wazuh rule file. Activation requires a manager restart out of band.",
            meta={"toolset": "writes"},
        )(
            instrumented_tool(
                tool_name="write.create_rule",
                handler=_create_rule_inner,
                rbac_policy=rbac_policy,
                limiter=limiter,
                audit=audit_emitter,
                args_model=CreateRuleArgs,
                result_model=WriteResult,
            )
        )

    if _should_register("write.update_rule", allowlist):

        async def _update_rule_inner(**kwargs: Any) -> Any:
            args = UpdateRuleArgs(**kwargs)
            session = current_session()
            sapi = await server_api_pool.acquire(session.tenant_id)
            return await _update_rule(args=args, session=session, server_api=sapi)

        mcp_app.tool(
            name="write.update_rule",
            description=_write_desc_prefix
            + "Updates an existing Wazuh rule file. Activation requires a manager restart.",
            meta={"toolset": "writes"},
        )(
            instrumented_tool(
                tool_name="write.update_rule",
                handler=_update_rule_inner,
                rbac_policy=rbac_policy,
                limiter=limiter,
                audit=audit_emitter,
                args_model=UpdateRuleArgs,
                result_model=WriteResult,
            )
        )

    if _should_register("write.run_active_response", allowlist):

        async def _run_ar_inner(**kwargs: Any) -> Any:
            args = RunActiveResponseArgs(**kwargs)
            session = current_session()
            sapi = await server_api_pool.acquire(session.tenant_id)
            return await _run_active_response(
                args=args,
                session=session,
                server_api=sapi,
                ar_allowlist=ar_allowlist,
            )

        mcp_app.tool(
            name="write.run_active_response",
            description=_write_desc_prefix
            + "Runs a tenant-allowlisted active-response command on a single agent. "
            + "The command must be enumerated in TenantConfig.active_response_allowlist.",
            meta={"toolset": "writes"},
        )(
            instrumented_tool(
                tool_name="write.run_active_response",
                handler=_run_ar_inner,
                rbac_policy=rbac_policy,
                limiter=limiter,
                audit=audit_emitter,
                args_model=RunActiveResponseArgs,
                result_model=WriteResult,
            )
        )
