# wazuh-mcp M4c — Per-tenant policy resolution + write-surface completion

Status: Design approved 2026-04-27. Successor to `2026-04-24-wazuh-mcp-m4b-design.md` and the integration-restoration patch `v0.5.1`. Ship target `v0.6.0-m4c`.

## 0. Scope

M4c is the multi-tenant correctness milestone. M4a stood up the RBAC + rate-limit + audit chokepoint; M4b stood up the write surface but captured all three tenant-scoped allowlists (`role_tool_allowlist`, `write_allowlist`, `active_response_allowlist`) at server-build time from the *primary* tenant only. In a multi-tenant HTTP deployment, every authenticated session is bound to the primary tenant's policy regardless of the session's own tenant. M4c closes that gap by moving all three allowlists to call-time per-tenant resolution and finishes the write surface that M4b left open.

### 0.1 Items shipped

1. **Per-tenant policy resolution** — `role_tool_allowlist`, `write_allowlist`, and `active_response_allowlist` resolve per-call via `session.tenant_id → TenantRegistry.get(...) → effective_*`. Three resolver factories in a new `rbac/resolver.py` module. Stdio uses a `SingleTenantRegistry` adapter so both modes share the resolver wiring.
2. **`write.restart_manager`** — the rule-activation completion of the M4b write surface. One tool with `scope: Literal["node", "cluster"] = "cluster"`. Fire-and-forget (returns on Wazuh's 200 ack, does not poll).
3. **`cluster.status`** — thin read tool over `GET /cluster/status`, paired with restart_manager so operators can poll cluster readiness without leaving MCP.
4. **Multi-agent `write.run_active_response`** — `agent_ids: list[str]` (1≤len≤50) replaces the M4b single-`agent_id` shape. Server-side fan-out via Wazuh's `agents_list` query param. Partial-failure semantics added.
5. **`confirm_required` cleanup** — removed from `SAFE_CODES` (declared client-visible since M4b T1 but never raised at runtime; the `confirm: Literal[True]` parse gate IS the confirm contract).

### 0.2 Non-goals

- **No `group_id` target** for `run_active_response`. TOCTOU semantics + post-resolution cap weirdness make this a separate design pass; deferred.
- **No backwards-compat shim** for `agent_id → agent_ids`. Pre-1.0.0, no known external pinned callers, breaking-change release-notes carry the migration. M4b is 3 days old.
- **No third opt-in gate** on `write.restart_manager`. The existing two-layer model (`write_allowlist` per-tenant + RBAC role) is the floor.
- **No multi-manager integration fixture in CI.** True cross-tenant integration with two distinct Wazuh clusters is M5 cross-tenant-leak-test territory. Multi-tenant resolution is pinned at the unit level in M4c.
- **No MCP elicitation.** SDK 1.27 has no native support; activating `confirm_required` via post-parse elicitation is deferred until the SDK lands the feature. Removing the dead vocabulary is the cleanup.
- **No `cancelled` outcome vocabulary, `WazuhError.scope` field, or Vault integration tests.** Carry-over deferrals from M4b.

## 1. Goals and non-goals

### Goals

1. Move `role_tool_allowlist`, `write_allowlist`, and `active_response_allowlist` from server-build-time capture to call-time per-tenant resolution. A session minted for tenant B sees tenant B's allowlists even when the server was built with tenant A as primary.
2. Factor policy resolution into `rbac/resolver.py` so the wiring module (`server.py`, already 1200+ lines) stays focused on app construction. Both stdio and HTTP modes import the same factories.
3. Ship `write.restart_manager` and `cluster.status` to complete the M4b rule-activation flow operationally inside MCP rather than out-of-band.
4. Expand `write.run_active_response` to multi-agent batched remediation with partial-failure plumbing through `WriteResult.failed_agents`.
5. Remove `confirm_required` from `SAFE_CODES` — never raised at runtime, kept only as a "future elicitation" placeholder. Cleanup eliminates dead vocabulary.
6. Preserve every M4a/M4b chokepoint invariant: `@instrumented_tool` is still the sole audit/metric emitter; write tools still emit a `write.requested → ok/error` audit pair; non-write tools still emit a single event; RBAC still gates list_tools and call_tool.

### Non-goals

- Changing the M4a RBAC default roles (`admin`, `analyst`, `readonly`).
- Changing `TenantConfig` schema. The three allowlist fields keep their existing types — the change is purely wiring.
- Per-tenant FastMCP app instances. M4c registers the union of all writes for every tenant; per-tenant filtering is purely call-time. (Per-tenant app instances would be a much larger refactor with no comparable benefit.)
- Surface-narrowing `list_tools` per-tenant. With unconditional registration, all tenants see the same tool surface; denial happens at call-time. This is a deliberate operator-visible delta from M4b's `write_allowlist=[]` "tools hidden" behavior — see §6.

## 2. Locked design decisions

### 2.1 Three resolver factories in `rbac/resolver.py`

```python
# src/wazuh_mcp/rbac/resolver.py
from collections.abc import Callable

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import MultiSinkAuditEmitter
from wazuh_mcp.rbac.policy import effective_allowlist_for
from wazuh_mcp.tenancy.registry import TenantRegistry

_RESOLVE_SENTINEL = "<rbac.resolve>"


def make_rbac_policy(
    registry: TenantRegistry,
    audit_emitter: MultiSinkAuditEmitter,
) -> Callable[[Session], dict[str, list[str]]]:
    def _policy(session: Session) -> dict[str, list[str]]:
        try:
            cfg = registry.get(session.tenant_id)
        except KeyError:
            audit_emitter.emit(
                session=session,
                tool=_RESOLVE_SENTINEL,
                args={},
                outcome="error",
                result_count=0,
                duration_ms=0,
                error_code="forbidden",
                error_reason="tenant_not_registered",
            )
            return {}
        return effective_allowlist_for(tenant_override=cfg.role_tool_allowlist)
    return _policy


def make_write_allowlist(
    registry: TenantRegistry,
    audit_emitter: MultiSinkAuditEmitter,
) -> Callable[[Session], list[str] | None]:
    def _resolve(session: Session) -> list[str] | None:
        try:
            cfg = registry.get(session.tenant_id)
        except KeyError:
            audit_emitter.emit(
                session=session,
                tool=_RESOLVE_SENTINEL,
                args={},
                outcome="error",
                result_count=0,
                duration_ms=0,
                error_code="forbidden",
                error_reason="tenant_not_registered",
            )
            return []                  # safe default: deny all writes
        return cfg.write_allowlist     # None = no filter; [] or list = filter
    return _resolve


def make_ar_allowlist(
    registry: TenantRegistry,
    audit_emitter: MultiSinkAuditEmitter,
) -> Callable[[Session], list[str]]:
    def _resolve(session: Session) -> list[str]:
        try:
            cfg = registry.get(session.tenant_id)
        except KeyError:
            audit_emitter.emit(
                session=session,
                tool=_RESOLVE_SENTINEL,
                args={},
                outcome="error",
                result_count=0,
                duration_ms=0,
                error_code="forbidden",
                error_reason="tenant_not_registered",
            )
            return []                  # safe default: deny all AR
        return cfg.active_response_allowlist
    return _resolve
```

KeyError → audit emit + safe-default. Deduplication of audit events across the three resolvers (each could fire on the same call for an unknown tenant) is **not** done; 3× audit on a vanishingly-rare event is preferable to module-level memoization state. Sentinel `tool="<rbac.resolve>"` distinguishes resolver misses from real tool calls in audit dashboards.

The resolver factories call the existing `MultiSinkAuditEmitter.emit(...)` (audit.py:89) but pass a new `error_reason: str | None = None` kwarg — this is an additive extension to the emitter. M4c phase 1 adds the kwarg; existing callers (the M4a `_install_rbac_hooks` denial path, the M4b write decorator) continue to omit it. The reason is written directly to the event dict alongside `error_code` — not hashed into `arg_hash` — so it's audit-visible.

### 2.2 `SingleTenantRegistry` adapter

Stdio is single-tenant by construction; it has `cfg.tenant: TenantConfig` and no `tenants.yaml`. To share the resolver wiring with HTTP, `tenancy/registry.py` gains:

```python
class SingleTenantRegistry:
    def __init__(self, tenant: TenantConfig) -> None:
        self._tenant = tenant

    def get(self, tenant_id: str) -> TenantConfig:
        if tenant_id != self._tenant.tenant_id:
            raise KeyError(f"unknown tenant: {tenant_id}")
        return self._tenant
```

5 lines, same `TenantRegistry` Protocol shape. Stdio's session is primed once with `cfg.tenant.tenant_id`, so `registry.get(session.tenant_id)` always hits.

### 2.3 Registry threading through `HttpAppConfig`

`load_http_config` already builds `YamlTenantRegistry`; today it's discarded after feeding `IssuerIndex`. M4c keeps the registry alive on `HttpAppConfig`:

```python
@dataclass(frozen=True)
class HttpAppConfig:
    pool: IndexerClientPool
    server_api_pool: ServerApiClientPool
    chain: ChainSessionFactory
    oauth: OAuthSessionFactory
    issuer_index: IssuerIndex
    resource_url: str
    authorization_server: str
    tenant: TenantConfig | None = None              # kept (sink/limiter wiring)
    registry: TenantRegistry | None = None          # NEW (resolver wiring)
    limiter: RateLimiter | None = None
    audit: MultiSinkAuditEmitter | None = None
```

`build_http_app` closes the three resolvers over `http_cfg.registry`. The `tenant` field stays for sink + limiter wiring (which remains primary-tenant scoped — multi-tenant rate-limit / sink fan-out is a separate concern, deferred).

### 2.4 Unconditional write registration

`_register_everything` no longer takes `tenant_cfg=` for filtering. All 8 writes (7 from M4b + new `write.restart_manager`) plus `cluster.status` register every time. Per-tenant gating moves to handler bodies via the resolvers:

```python
async def _inner_run_active_response(
    *,
    agent_ids: list[str],
    command_name: str,
    confirm: Literal[True],
) -> WriteResult:
    session = current_session()
    write_allow = write_allowlist_policy(session)
    if write_allow is not None and "write.run_active_response" not in write_allow:
        raise WazuhError("forbidden", reason="not_in_tenant_write_allowlist")
    ar_allowed = ar_allowlist_policy(session)
    if command_name not in ar_allowed:
        raise WazuhError("forbidden", reason="ar_command_not_in_tenant_ar_allowlist")
    client = await server_api_pool.acquire(session.tenant_id)
    resp = await client.run_active_response(
        agent_ids=agent_ids,
        command_name=command_name,
        run_as=session.wazuh_user,
    )
    return WriteResult(
        ok=(len(resp.failed_items) == 0),
        affected_agents=[item.id for item in resp.affected_items],
        failed_agents=[FailedAgent(agent_id=item.id, reason=item.error.message)
                       for item in resp.failed_items],
        timestamp=now_utc(),
    )
```

The `write_allowlist_policy(session)` call replaces M4b's registration-time filter. Operator-visible delta: `tenant_cfg.write_allowlist=[]` (empty list) shifts from "tools not registered → not listed" to "tools registered → listed but call-denied". Documented in §6.

### 2.5 `write.restart_manager` shape

```python
class RestartManagerArgs(BaseModel):
    confirm: Annotated[Literal[True], Field(description=...)]
    scope: Literal["node", "cluster"] = "cluster"


class RestartManagerResult(BaseModel):
    ok: bool
    scope: Literal["node", "cluster"]
    affected_nodes: list[str]
    timestamp: datetime
```

Handler flow:

1. RBAC + rate-limit + write_allowlist gates (existing chokepoint + new resolver).
2. Pre-flight `cluster_status()` read → captures `affected_nodes` for the audit trail.
3. If `scope == "cluster"` and `pre_status.enabled is False` → raise `WazuhError("upstream_error", reason="cluster_scope_requires_clustering_enabled")` *before* issuing the restart.
4. `client.restart_cluster(scope=args.scope)`:
   - `scope="cluster"` → `PUT /cluster/restart`.
   - `scope="node"` → `PUT /manager/restart`.
5. Returns immediately on Wazuh's 200 ack (~200ms typical). No polling, no wait. Operators poll readiness via `cluster.status`.

### 2.6 `cluster.status` shape

Thin read tool, default RBAC `analyst.*`-readable.

```python
class ClusterStatusArgs(BaseModel):
    pass


class ClusterStatusResult(BaseModel):
    enabled: bool                 # is clustering configured at all
    running: bool                 # are all nodes in "running" state
    nodes: list[ClusterNode]


class ClusterNode(BaseModel):
    name: str
    type: Literal["master", "worker"]
    status: str                   # "running", "restarting", "disconnected", etc.
```

Wraps `GET /cluster/status` and (where needed) `GET /cluster/nodes`. Single audit event (no `write.` prefix → no audit pair).

### 2.7 Multi-agent AR shape

```python
_AR_AGENTS_MAX: Final = 50      # near-future per-tenant tuning point


class IsolateAgentArgs(BaseModel):
    confirm: Annotated[Literal[True], Field(description=...)]
    agent_ids: Annotated[
        list[str],
        Field(min_length=1, max_length=_AR_AGENTS_MAX),
    ]


class RunActiveResponseArgs(BaseModel):
    confirm: Annotated[Literal[True], Field(description=...)]
    command_name: str
    agent_ids: Annotated[
        list[str],
        Field(min_length=1, max_length=_AR_AGENTS_MAX),
    ]
    extra_args: list[str] = Field(default_factory=list)
```

`ServerApiClient.run_active_response(agent_ids: list[str], ...)` builds `agents_list=",".join(agent_ids)` and issues a single `PUT /active-response?agents_list=...`. Wazuh handles fan-out server-side. No deduplication of `agent_ids` at parse time — Wazuh dedupes natively, and the `failed_items` response reflects what Wazuh actually saw.

`WriteResult` extends:

```python
class FailedAgent(BaseModel):
    agent_id: str
    reason: str


class WriteResult(BaseModel):
    ok: bool
    affected_agents: list[str] = Field(default_factory=list)
    failed_agents: list[FailedAgent] = Field(default_factory=list)
    affected_files: list[str] = Field(default_factory=list)
    timestamp: datetime
```

### 2.8 Partial-failure semantics

`ok=True` iff every requested agent succeeded. `ok=False` with populated `failed_agents` indicates partial or total failure. **No exception raised** for partial failure — the tool returns successfully, and the LLM client sees the partial outcome in its trace and can decide whether to retry the failed agents.

`WazuhError` is still raised for catastrophic API errors (network failure, auth failure, malformed Wazuh response). M4b's binary contract is preserved for the catastrophic case; multi-agent partial-failure is the new third state.

Audit emission: `outcome="ok"` with `affected_count` and `failed_count` in the payload regardless of partial-failure mix. The audit pair (`write.requested → ok`) still fires once per call.

### 2.9 `confirm_required` cleanup

Removed from `wazuh/errors.py`'s `SAFE_CODES` frozenset. No code change beyond the constant. `docs/deploy/m4b-writes.md` updated to drop the "reserved code" line. If MCP elicitation lands in a future SDK, re-adding the code is one-line.

## 3. Architecture

### 3.1 Boot-time wiring (HTTP)

```
load_http_config(config_dir)
  ├─ YamlTenantRegistry(tenants.yaml)               ← built once
  ├─ IssuerIndex(all_tenants)
  └─ HttpAppConfig(... registry=registry, tenant=primary, ...)

build_http_app(http_cfg)
  ├─ rbac_policy   = make_rbac_policy(http_cfg.registry, audit_emitter)
  ├─ write_policy  = make_write_allowlist(http_cfg.registry, audit_emitter)
  ├─ ar_policy     = make_ar_allowlist(http_cfg.registry, audit_emitter)
  ├─ _register_everything(mcp_app, ..., write_allowlist_policy=write_policy,
  │                       ar_allowlist_policy=ar_policy)
  │     └─ all 8 writes + cluster.status registered unconditionally
  └─ _install_rbac_hooks(mcp_app, rbac_policy=rbac_policy, audit_emitter=...)
```

### 3.2 Boot-time wiring (stdio)

```
build_app(cfg)
  ├─ registry = SingleTenantRegistry(cfg.tenant)
  ├─ rbac_policy   = make_rbac_policy(registry, audit_emitter)
  ├─ write_policy  = make_write_allowlist(registry, audit_emitter)
  ├─ ar_policy     = make_ar_allowlist(registry, audit_emitter)
  └─ ... rest identical to HTTP path
```

Identical resolver wiring across modes. Only the registry impl differs.

### 3.3 Call-time flow (write tool, success path)

```
SessionMiddleware sets contextvar (session.tenant_id="tenant_b")
FastMCP.call_tool("write.run_active_response", {...})
  ├─ _install_rbac_hooks intercepts:
  │     policy = rbac_policy(session)               ← per-tenant resolved
  │     match against policy[session.rbac_role]
  │     no match → audit forbidden + raise
  ├─ @instrumented_tool wrapper:
  │     args = RunActiveResponseArgs(**kwargs)      ← Pydantic + Literal[True] gate
  │     limiter.acquire()
  │     audit emit "write.requested" (tool, tenant, agent_count, command)
  ├─ handler body:
  │     wlist = write_allowlist_policy(session)
  │     if wlist is not None and tool not in wlist → raise forbidden
  │     ar = ar_allowlist_policy(session)
  │     if command not in ar → raise forbidden
  │     resp = await client.run_active_response(...)
  │     return WriteResult(ok=(failed==0), affected, failed, ts)
  └─ @instrumented_tool wrapper:
        audit emit "ok" (or "error" if WazuhError raised)
```

Three resolver lookups per write call (cheap dict ops). Audit pair (`requested → ok/error`) preserved.

### 3.4 Call-time flow (unknown tenant_id)

```
session.tenant_id="phantom" (programming error or DB-driver lag)
  ├─ rbac_policy(session) → registry.get raises KeyError
  ├─ resolver catches → audit emit forbidden + tenant_not_registered → return {}
  ├─ _install_rbac_hooks: effective_allowlist_for({})[role] → empty list → no match
  └─ Tool denied. list_tools returns [] (no surface leak).
```

Symmetric across `list_tools` and `call_tool`. `forbidden` is in `SAFE_CODES`; no new error vocabulary.

### 3.5 Call-time flow (write.restart_manager, success path)

```
1-4. Same chokepoint as run_active_response.
5. Handler body:
     pre = await client.cluster_status()
     if args.scope == "cluster" and not pre.enabled:
         raise WazuhError("upstream_error", reason="cluster_scope_requires_clustering_enabled")
     await client.restart_cluster(scope=args.scope)
     return RestartManagerResult(
         ok=True,
         scope=args.scope,
         affected_nodes=[n.name for n in pre.nodes],
         timestamp=now_utc(),
     )
6. audit emit "ok" with scope, affected_nodes count.
```

## 4. Component file map

| Layer | File | Change |
|---|---|---|
| **New** | `src/wazuh_mcp/rbac/resolver.py` | Three factories + sentinel audit shape + KeyError safe-defaults. ~80 lines. |
| **New** | `src/wazuh_mcp/tenancy/registry.py` (additive) | `SingleTenantRegistry` 5-line class. |
| **Modified** | `src/wazuh_mcp/server.py:280-298` (stdio) | Replace inline `_rbac_policy` with three resolver closures from `make_*(SingleTenantRegistry(cfg.tenant), audit_emitter)`. Plumb new resolver kwargs to `_register_everything`. |
| **Modified** | `src/wazuh_mcp/server.py:333-393` (HttpAppConfig + load_http_config) | Add `registry: TenantRegistry \| None` field. `load_http_config` passes the already-built registry through. |
| **Modified** | `src/wazuh_mcp/server.py:396-445` (build_http_app) | Three resolver closures from `make_*(http_cfg.registry, audit_emitter)`. |
| **Modified** | `src/wazuh_mcp/server.py:480-1200` (`_register_everything` + handlers) | Drop `tenant_cfg=` filter parameter. Each write handler signature gains `write_allowlist_policy` + (where applicable) `ar_allowlist_policy` kwargs. Handler bodies invoke per-call. New `write.restart_manager` handler. New `cluster.status` registration. |
| **Modified** | `src/wazuh_mcp/observability/audit.py` | `MultiSinkAuditEmitter.emit(...)` gains `error_reason: str \| None = None` kwarg. Written directly to event dict (not hashed into `arg_hash`). Additive — existing callers untouched. |
| **Modified** | `src/wazuh_mcp/wazuh/server_api.py` | Add `restart_cluster(scope)`, `cluster_status()`. Refactor `run_active_response`/`isolate_agent` to `agent_ids: list[str]`. |
| **Modified** | `src/wazuh_mcp/tools/writes.py` (or wherever Args models live) | `IsolateAgentArgs`/`RunActiveResponseArgs` switch to `agent_ids`. New `RestartManagerArgs`/`RestartManagerResult`/`ClusterStatusArgs`/`ClusterStatusResult`. `WriteResult` adds `failed_agents`. `_AR_AGENTS_MAX` constant. |
| **Modified** | `src/wazuh_mcp/wazuh/errors.py` | Remove `confirm_required` from `SAFE_CODES`. |
| **Tests new** | `tests/unit/test_rbac_resolver.py` | Three factories, KeyError safe-defaults, audit-emit sentinel shape, override semantics. |
| **Tests new** | `tests/unit/test_single_tenant_registry.py` | Wrap-and-return; KeyError on mismatch. |
| **Tests new** | `tests/unit/test_server_api_restart.py` | `restart_cluster` scope routing; `cluster_status` parsed shape; pytest-httpx wire pinning. |
| **Tests new** | `tests/unit/test_multi_agent_ar.py` | Single-agent in list; comma-join; cap rejection; partial-failure plumbing; Hypothesis fuzz on agent-id list. |
| **Tests new** | `tests/unit/test_m4c_per_tenant_policy.py` | Two-tenant fixture: per-call resolution flips with session.tenant_id; closure-capture absent. |
| **Tests new** | `tests/integration/test_m4c_writes.py` | `write.restart_manager` (node scope on single-node CI stack); `cluster.status`; multi-agent isolate; `<rbac.resolve>` audit on unknown tenant. `@requires_manager`. |
| **Tests modified** | `tests/unit/test_instrumented_tool.py`, `tests/unit/test_server_registration.py`, `tests/unit/test_server_wiring_m4a.py`, `tests/unit/test_*_writes*.py`, `tests/integration/test_m4b_writes.py` | Update closures to resolver shape; migrate `agent_id` callers to `agent_ids`. |
| **Doc new** | `docs/deploy/m4c-multi-tenant.md` | Per-tenant resolver model; `write_allowlist=[]` delta; restart_manager + cluster.status guides; multi-agent AR migration; unknown-tenant audit shape. |
| **Doc modified** | `docs/deploy/m4b-writes.md` | Remove `confirm_required` "reserved code" line. Update single-agent AR examples to multi-agent. |
| **Doc modified** | `docs/security/threat-model.md` | Add per-tenant resolution to mitigation table. Document fail-closed unknown-tenant behavior. |
| **Doc modified** | `README.md` | Bump milestone table to include M4c headlines. |
| **Spec/plan/retro** | `docs/superpowers/specs/2026-04-27-wazuh-mcp-m4c-design.md` (this file), `docs/superpowers/plans/2026-04-27-wazuh-mcp-m4c-plan.md`, `docs/superpowers/retros/2026-04-27-m4c-retro.md` | Standard milestone artifacts. |

## 5. Error handling

### 5.1 Resolver KeyError (unknown tenant_id)

Each of the three resolvers catches `KeyError` independently, emits an audit event with sentinel `tool="<rbac.resolve>"`, `error_code="forbidden"`, `error_reason="tenant_not_registered"`, and returns its safe-default (`{}` for RBAC, `[]` for both allowlists). Up to 3× audit events per call on the rare unknown-tenant path; no deduplication.

### 5.2 Pydantic ValidationError (parse_error)

- `agent_ids=[]` → `min_length=1` violated
- `agent_ids` length 51+ → `max_length=50` violated
- `confirm` not literally `True`, `confirm` missing → `Literal[True]` violated
- `scope` not in `{"node", "cluster"}` → `Literal` violated

All surface as the existing `parse_error` outcome via the `@instrumented_tool` decorator. No new error vocabulary.

### 5.3 Wazuh API errors (existing vocabulary)

- `restart_cluster` 4xx (cluster scope on non-clustered manager, restart already in progress, etc.) → `upstream_error`
- `restart_cluster` connection failure / timeout → `upstream_timeout`
- `run_active_response` 4xx (invalid command_name, AR not configured) → `upstream_error`
- `cluster_status` 503 / 5xx → `upstream_error`
- All flow through the existing `@instrumented_tool` error path.

### 5.4 Multi-agent partial failure (new semantics)

- All requested agents succeeded → `ok=True, failed_agents=[]`. Audit `outcome="ok"`.
- Some succeeded, some failed → `ok=False, affected_agents=[…], failed_agents=[…]`. **No exception raised.** Audit `outcome="ok"` with `affected_count` + `failed_count` in payload.
- All requested failed → `ok=False, affected_agents=[], failed_agents=[…]`. No exception.
- Catastrophic API error (network, auth, malformed response) → still raises `WazuhError`, audit `outcome="error"`. M4b binary contract preserved for the catastrophic path.

### 5.5 Restart-manager pre-flight

- `cluster_status()` returns `enabled=False` AND `scope="cluster"` → raise `WazuhError("upstream_error", reason="cluster_scope_requires_clustering_enabled")` *before* issuing restart. Caller can retry with `scope="node"`.
- `cluster_status()` itself fails → propagate as `upstream_error`. Don't restart with unknown node count.

## 6. Operator-visible deltas

### 6.1 `write_allowlist=[]` (empty list) semantics shift

| | M4b behavior | M4c behavior |
|---|---|---|
| Tool registration | `write.*` not registered when `write_allowlist=[]` | All 8 writes registered unconditionally |
| `list_tools` output | Hides denied writes | Lists denied writes |
| `call_tool` denied write | `Unknown tool: ...` (FastMCP unregistered-tool path) | `forbidden` (per-tenant write_allowlist denies in handler body) |

There is **no exact analog** in M4c for the M4b "tools hidden" behavior. Closest: leave `write_allowlist` *unset* (None default) and rely on RBAC role to gate visibility — but RBAC controls match-list, not registration, so writes still appear in `list_tools`. This is an intentional tradeoff: multi-tenant integrity (uniform tool surface across tenants) over surface-narrowing.

### 6.2 `write.run_active_response` and `write.isolate_agent` Args breaking change

`agent_id: str` → `agent_ids: list[str]` (1≤len≤50). Single-agent callers update from `agent_id="001"` to `agent_ids=["001"]`. Wire shape preserved (Wazuh's `agents_list` query param).

### 6.3 New tools: `write.restart_manager`, `cluster.status`

- `write.restart_manager` requires explicit add to `tenant_cfg.write_allowlist` (if the tenant uses an explicit list). Default RBAC restricts to `admin`. Operator's Wazuh API user must have cluster-admin perms (Wazuh enforces independently).
- `cluster.status` defaults to analyst-readable. Operators with restrictive RBAC overrides may need to add `cluster.status` (or `cluster.*`) to the relevant role's allowlist.

### 6.4 Resolver-emit audit events

New audit events with sentinel `tool="<rbac.resolve>"` (event field `tool`, per audit.py:102) appear when an unknown tenant_id is presented. Wazuh Dashboards saved searches that filter on the `tool` field with regex `^[a-z_]+\.[a-z_]+$` need updating to include `<rbac.resolve>`.

### 6.5 `confirm_required` removed from SAFE_CODES

Operator dashboards / alerting that listed `confirm_required` as a possible MCP error code remove the entry. Runtime-observable: zero (it never fired).

## 7. Testing strategy

### 7.1 Unit-test coverage matrix

| Surface | Test file | Pinned invariants |
|---|---|---|
| `make_rbac_policy` | `test_rbac_resolver.py` | tenant lookup; absent override → DEFAULT; KeyError → audit + `{}`; sentinel `tool="<rbac.resolve>"` + `error_reason="tenant_not_registered"` |
| `make_write_allowlist` | `test_rbac_resolver.py` | None / `[]` / list semantics; KeyError → audit + `[]` |
| `make_ar_allowlist` | `test_rbac_resolver.py` | List passthrough; KeyError → audit + `[]` |
| `SingleTenantRegistry` | `test_single_tenant_registry.py` | Wrap; KeyError on mismatch |
| `ServerApiClient.restart_cluster` | `test_server_api_restart.py` | scope routing; 4xx upstream_error; pytest-httpx pinning |
| `ServerApiClient.cluster_status` | `test_server_api_restart.py` | Parsed shape; nodes; status enum |
| `ServerApiClient.run_active_response` | `test_multi_agent_ar.py` | comma-join; failed_items; partial-failure semantics |
| Multi-tenant per-call wiring | `test_m4c_per_tenant_policy.py` | Two-tenant fixture: session-A vs session-B see distinct allowlists; mid-fixture flip proves no closure-capture |
| `RestartManagerArgs`/`ClusterStatusArgs`/`WriteResult` | `test_writes_args_models.py` (extends) | Literal validation; failed_agents default |
| Decorator audit pair on restart_manager | `test_instrumented_tool.py` (extends) | requested+ok pair; cluster.status single event |

### 7.2 Hypothesis fuzz

`agent_ids` URL-injection invariant: `st.lists(st.from_regex(r"^[0-9]{1,8}$", fullmatch=True), min_size=1, max_size=50)` confirms no agent_id contains a comma. Pinned in `test_multi_agent_ar.py`.

### 7.3 Integration tests (`@requires_manager`, amd64 nightly + manual dispatch)

`tests/integration/test_m4c_writes.py`:

- `test_restart_manager_node_scope_completes` — pre cluster.status, `write.restart_manager(scope="node")`, post cluster.status (poll until ready, ≤60s). Single-node CI stack.
- `test_cluster_status_reads_node_metadata` — single read; assert nodes ≥1, status="running".
- `test_multi_agent_isolate_one_agent` — `write.run_active_response(agent_ids=["001"], ...)` exercises the URL builder via `["001"]` shape on the single-agent CI fixture.
- `test_unknown_tenant_audit_emits_sentinel` — mint session with unregistered tenant_id; call any read tool; assert `<rbac.resolve>` audit event with `forbidden` + `tenant_not_registered`.

Multi-tenant integration with two distinct Wazuh clusters is **out of scope for M4c** (M5 cross-tenant-leak tests own that). Per-tenant resolution is pinned at the unit level in `test_m4c_per_tenant_policy.py`.

### 7.4 Tier classification (review knob)

| Phase | Tasks | Tier | Review |
|---|---|---|---|
| 1 | `rbac/resolver.py` | A | Full dual review (novel security primitive) |
| 1 | `SingleTenantRegistry`, `HttpAppConfig` threading | B | Controller spot-check |
| 1 | Stdio + HTTP wiring rewires (resolver kwargs added) | B | Controller spot-check |
| 1 | `test_m4c_per_tenant_policy.py` | A | Co-reviewed with resolver in same dispatch |
| 2 | Decoupling: registration unconditional, filters call-time | B | Controller spot-check (mechanical refactor downstream of phase-1 reviewed primitive) |
| 2 | `ServerApiClient.restart_cluster` / `cluster_status` | B | Controller spot-check (Wazuh API additions, pytest-httpx pinning) |
| 2 | `write.restart_manager` + `cluster.status` registrations | B | Controller spot-check |
| 2 | Multi-agent AR refactor | B | Controller spot-check |
| 2 | `confirm_required` deletion | B | Inline (3-line diff) |
| 3 | Operator doc, retro, ship | B | Controller |

One full Tier-A review (phase 1 resolver primitive). Phase 2 is composition over phase-1 reviewed infra → spot-check.

### 7.5 Regression-pinning tests (must still pass)

- `test_indexer_client.py::test_bulk_posts_ndjson_to_bulk_endpoint`
- `test_instrumented_tool.py::test_args_model_surfaces_typed_fields_to_fastmcp_introspection`

Both untouched by M4c. Listed here as MUST-PASS so any wiring refactor that breaks them surfaces immediately.

## 8. Internal phasing

Single tag `v0.6.0-m4c`. Phasing is plan-level; tests stay green commit-by-commit; main builds throughout.

### Phase 1 — Foundation (Tier-A full review)

Per-tenant resolution working end-to-end with no behavioral change to single-tenant deployments.

1. `SingleTenantRegistry` in `tenancy/registry.py` + unit test.
2. `rbac/resolver.py` — three factories + sentinel audit + KeyError safe-defaults + unit test full coverage.
3. Thread `registry` through `HttpAppConfig`. `load_http_config` stops discarding it.
4. Replace stdio `_rbac_policy` with three resolver closures over `SingleTenantRegistry(cfg.tenant)`.
5. Replace HTTP `_rbac_policy` with three resolver closures over `http_cfg.registry`.
6. `_register_everything` accepts new `*_allowlist_policy` kwargs alongside existing `tenant_cfg=` until phase 2. Per-tenant resolution covers `role_tool_allowlist` + `active_response_allowlist`; `write_allowlist` still registration-filtered. Behavior delta-free for existing operators.
7. Multi-tenant per-call test (`test_m4c_per_tenant_policy.py`) — proves resolution flips per session for the two already-resolver-resolved allowlists.

Estimated dispatches: ~7 implementer + 1 tier-A full review + 0-1 fix-after-review.

### Phase 2 — Write surface extension + decoupling (Tier-A spot-check)

1. Decouple registration from `write_allowlist`. All 8 writes register unconditionally. Filter moves to handler-body call into `write_allowlist_policy(session)`. Drop `tenant_cfg=` kwarg.
2. `ServerApiClient.restart_cluster`, `cluster_status` — pytest-httpx wire pinning.
3. `RestartManagerArgs`/`ClusterStatusArgs`/`RestartManagerResult` Pydantic models + tests.
4. `write.restart_manager` handler (pre-flight, scope branch, audit pair).
5. `cluster.status` read tool registered in read block, default analyst RBAC.
6. Multi-agent AR refactor: `agent_ids: list[str]` everywhere. `WriteResult.failed_agents`. Hypothesis fuzz.
7. `confirm_required` removed from `SAFE_CODES`. Update doc references.
8. Integration tests `test_m4c_writes.py`.

Estimated dispatches: ~6-7 implementer + 0 (spot-check) + 0-1 fix-after-review.

### Phase 3 — Operator doc + retro + ship (Tier-B controller)

1. `docs/deploy/m4c-multi-tenant.md`.
2. Update `docs/deploy/m4b-writes.md`, `docs/security/threat-model.md`, `README.md`.
3. Bump `pyproject.toml` to `0.6.0`.
4. `ruff format` alignment commit.
5. `docs/superpowers/retros/2026-04-27-m4c-retro.md`.
6. Stage specific files, tag `v0.6.0-m4c`, push with `--tags`.

Estimated dispatches: 0. ~2-3 commits.

### Total milestone budget

| Phase | Implementers | Tier-A reviews | Fix-after-review | Total dispatches |
|---|---|---|---|---|
| 1 | 7 | 1 | 0-1 | 8-9 |
| 2 | 6-7 | 0 (spot-check) | 0-1 | 6-8 |
| 3 | 0 | 0 | 0 | 0 |
| **Total** | **13-14** | **1** | **0-2** | **14-17** |

Compares to M4a (19 dispatches, 28 tasks) and M4b (10 dispatches, 10 tasks). M4c lands in the middle.

## 9. Threat model framing

### 9.1 Multi-tenant integrity

Today (`v0.5.1`): a session minted for tenant B, authenticated correctly via OAuth or API key against tenant B's issuer/store, sees tenant A's `role_tool_allowlist`, `write_allowlist`, and `active_response_allowlist`. Any divergence between tenants' allowlists is silently broken. Concrete attacks this enables:

- Tenant B's analyst role gets tenant A's analyst role allowlist. If tenant A's role is more permissive, tenant B's analyst is over-privileged.
- Tenant B's `write_allowlist=["write.add_agent_to_group"]` is ignored; tenant B sessions can call any write tenant A allows.
- Tenant B's `active_response_allowlist=["isolate"]` is ignored; tenant B sessions can run any AR command tenant A's allowlist permits.

### 9.2 M4c mitigation

All three allowlists resolve per-call against the session's own tenant_id. Cross-tenant policy bleed is closed structurally — there is no path through `_rbac_policy` / write handler / AR handler that captures the wrong tenant's config.

### 9.3 Defense-in-depth: unknown tenant_id

If a session is somehow minted with a tenant_id not in the registry (programming error, DB-driver lag, future driver swap), the three resolvers fail-closed: empty role table for RBAC (every tool denies in both `list_tools` and `call_tool`), empty list for write_allowlist (every write denies), empty list for AR allowlist (every AR command denies). Audit events emit with `<rbac.resolve>` sentinel for retroactive review.

### 9.4 What M4c does NOT close

- **Per-tenant rate-limiter.** Today's `InProcessRateLimiter` is constructed from primary tenant's `rate_limit`. Multi-tenant rate limiting is M5 scope.
- **Per-tenant audit-sink fan-out.** `_build_sinks(http_cfg.tenant, ...)` uses primary tenant. Multi-tenant per-tenant sink routing is M5 scope.
- **Cross-tenant leak tests.** End-to-end "session for tenant A runs every read AND write tool, assert no tenant B data touched" suite is M5 scope.
- **Multi-manager integration fixture.** True multi-tenant with two distinct Wazuh clusters in CI is M5 scope.

## 10. Migration guidance (operator-facing)

### 10.1 `agent_id` → `agent_ids` migration

Single-agent callers update:

```python
# Before (M4b)
write.run_active_response(confirm=True, command_name="isolate", agent_id="001")
write.isolate_agent(confirm=True, agent_id="001")

# After (M4c)
write.run_active_response(confirm=True, command_name="isolate", agent_ids=["001"])
write.isolate_agent(confirm=True, agent_ids=["001"])
```

Wire shape unchanged (Wazuh's `agents_list` query param accepts the same comma-joined output for either).

### 10.2 `write_allowlist=[]` deployments

Single-tenant operators using `write_allowlist=[]` to hide all writes from `list_tools`:

- M4c lists the writes; calls deny with `forbidden`.
- To preserve hidden behavior: not possible in M4c. All writes are uniformly registered.
- Recommended: leave the `[]` setting (denial behavior preserved) and document the listing-but-denial in operator runbooks. The `forbidden` audit events on probe-attempts are useful operational signal, not noise.

### 10.3 `write.restart_manager` rollout

For operators who want the M4b out-of-band restart pattern preserved:
- Don't add `"write.restart_manager"` to `tenant_cfg.write_allowlist`. The tool is listed but call-denies.

For operators who want the new in-band pattern:
- Add `"write.restart_manager"` to `tenant_cfg.write_allowlist`.
- Verify Wazuh API user has cluster-admin perms (Wazuh enforces independently).
- Default scope is `cluster`; for single-node deployments it falls through to manager restart.
- Pair with `cluster.status` reads pre/post for readiness verification.

## 11. Out of scope (deferred to M4d / M5)

- Group-target (`group_id`) for `run_active_response`. TOCTOU semantics + post-resolution cap behavior need their own design pass.
- Per-tenant rate-limiter / audit-sink fan-out (M5 multi-tenant infra completion).
- Cross-tenant leak test suite (M5 ship-gate item).
- Multi-manager integration fixture (M5).
- MCP elicitation activation of `confirm_required` (gated on SDK release).
- Formal toolset SDK wiring (gated on `mcp` SDK shipping native support).
- Eval harness (M5 ship-gate item).
- Helm chart for k8s deploy (M5).
- `WazuhError.scope` field for rate-limit metrics (M4a nit, defer).
- `cancelled` outcome vocabulary (M4a addition, defer).
- Vault integration tests (M4a non-goal, defer).
