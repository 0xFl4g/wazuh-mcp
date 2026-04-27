# M4c — Per-tenant policy resolution + write-surface completion

## Overview

M4c closes the multi-tenant policy-bleed gap carried over from M4b and finishes the rule-activation flow inside MCP. Three changes operators will notice when upgrading from `v0.5.x` to `v0.6.0-m4c`:

1. **Per-tenant policy now resolves at call time.** Previously, a session minted for tenant B sees tenant A's `role_tool_allowlist`, `write_allowlist`, and `active_response_allowlist` — the *primary* tenant's overrides were captured at server-build time. M4c looks up `session.tenant_id → TenantRegistry.get(...) → effective_*` per call. Cross-tenant policy bleed is closed structurally; there is no path through RBAC, the write-allowlist filter, or the AR-allowlist filter that captures the wrong tenant's config.
2. **`write_allowlist=[]` semantics shift** (operator-visible delta). Previously, an empty list hid all `write.*` tools from `list_tools` — the registration-time filter never registered them. M4c registers all writes unconditionally and denies disallowed calls at handler-body time. Tools appear in `list_tools` but every call returns `forbidden`. See §3 for the migration tradeoff.
3. **New tools.** `write.restart_manager` (scope=cluster|node) restarts the Wazuh manager from inside MCP, completing the M4b rule-activation flow that previously required out-of-band `systemctl restart`. Paired read tool `cluster.status` exposes clustering state and per-node status for pre/post readiness checks.

Two minor cleanups also land:
- `write.run_active_response` and `write.isolate_agent` now accept `agent_ids: list[str]` (1≤N≤50). Single-agent calls become `agent_ids=["001"]`. Wazuh's wire shape (`agents_list=001,002`) is preserved.
- `confirm_required` is removed from `SAFE_CODES`. The Pydantic `confirm: Literal[True]` parse-time gate IS the confirm contract; the post-parse error code never fired.

Spec: `docs/superpowers/specs/2026-04-27-wazuh-mcp-m4c-design.md`. This doc walks the operator-facing pieces.

## 1. Per-tenant resolver model

Three resolver factories live in `src/wazuh_mcp/rbac/resolver.py`:

- `make_rbac_policy(registry, audit_emitter) -> Callable[[Session], dict[str, list[str]]]`
- `make_write_allowlist(registry, audit_emitter) -> Callable[[Session], list[str] | None]`
- `make_ar_allowlist(registry, audit_emitter) -> Callable[[Session], list[str]]`

Each takes a `TenantRegistry` and returns a session-keyed callable. The callable is wired once at server-build time; the per-tenant lookup happens on every call. Stdio uses a `SingleTenantRegistry({cfg.tenant})` adapter so both modes share the wiring.

When `registry.get(session.tenant_id)` raises `KeyError` (programming error or DB-driver lag), the resolver fails closed:
- RBAC returns `{}` (empty role table → every tool denies in both `list_tools` and `call_tool`).
- Write allowlist returns `[]` (every write denies at handler time).
- AR allowlist returns `[]` (every AR command denies at handler time).

Each KeyError emits an audit event with `tool="<rbac.resolve>"`, `error_code="forbidden"`, `error_reason="tenant_not_registered"` so the path is operator-visible. See §4.

## 2. Configuration — no schema change required

`TenantConfig` is unchanged. The three allowlist fields keep their existing types:

```yaml
tenants:
  - tenant_id: acme
    indexer_url: https://wazuh.acme.internal:9200
    default_rbac_role: analyst
    role_tool_allowlist:
      admin: ["*"]
      responder: ["alerts.*", "agents.*", "write.isolate_agent"]
    write_allowlist:
      - write.isolate_agent
      - write.restart_manager        # NEW in M4c
    active_response_allowlist:
      - isolate
      - restart_service
  - tenant_id: contoso
    indexer_url: https://wazuh.contoso.example:9200
    default_rbac_role: readonly
    # No overrides — uses defaults. Per-tenant resolution still applies;
    # this tenant simply gets the global defaults rather than tenant_a's.
```

Sessions for `acme` see acme's role/write/AR allowlists; sessions for `contoso` see contoso's. M4c resolves this per call against `session.tenant_id`.

## 3. `write_allowlist=[]` behavior change (operator-visible delta)

If your tenant config sets `write_allowlist: []` to hide all writes, the observable behavior changes:

| | M4b (v0.5.x) | M4c (v0.6.x) |
|---|---|---|
| Tool registration | `write.*` not registered when `write_allowlist=[]` | All 8 writes registered unconditionally |
| `list_tools` output | Hides denied writes | Lists denied writes |
| `call_tool` denied write | `Unknown tool: ...` (FastMCP unregistered-tool path) | `forbidden` (per-tenant `write_allowlist` denies in handler body) |

There is **no exact analog** in M4c for the M4b "tools hidden" behavior. Closest: leave `write_allowlist` *unset* (None default) and rely on RBAC role to gate visibility — but RBAC controls match-list, not registration, so writes still appear in `list_tools` for callers with insufficient role. **There is no way in M4c to hide `write.*` tools from `list_tools` per-tenant.** This is a deliberate tradeoff: multi-tenant integrity (uniform tool surface across tenants) over per-tenant surface narrowing.

**Recommended migration:** keep your `write_allowlist: []` config as-is. Calls still deny with `forbidden`; `list_tools` now shows the rejected tools but they cannot be invoked. The `forbidden` audit events on probe-attempts are useful operational signal, not noise.

## 4. `<rbac.resolve>` audit events (defense-in-depth)

When a session is minted with a `tenant_id` not in the registry (programming error, DB-driver lag, future driver swap), each of the three resolvers fires once and emits:

```json
{
  "timestamp": "2026-04-27T13:24:11.482Z",
  "tool": "<rbac.resolve>",
  "user": "alice@phantom-tenant",
  "tenant": "phantom",
  "rbac_role": "admin",
  "arg_hash": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "outcome": "error",
  "result_count": 0,
  "duration_ms": 0,
  "error_code": "forbidden",
  "error_reason": "tenant_not_registered"
}
```

Up to 3× these events per inbound call (RBAC + write + AR resolvers each fire independently); deduplication is intentionally not applied — 3× audit on a vanishingly-rare event is preferable to module-level memoization state.

**Wazuh Dashboards saved-search update.** If your existing dashboard filters on `tool` field with the regex `^[a-z_]+\.[a-z_]+$`, update to include the angle-bracket sentinel:

```
tool:/^[a-z_]+\.[a-z_]+$/ OR tool:"<rbac.resolve>"
```

Or filter on `outcome:error AND error_reason:tenant_not_registered` to surface just the unknown-tenant path.

## 5. `write.restart_manager` setup

**Add to `tenant_cfg.write_allowlist`** if the tenant uses an explicit list:

```yaml
write_allowlist:
  - write.isolate_agent
  - write.create_rule
  - write.update_rule
  - write.restart_manager        # opt-in
```

If `write_allowlist` is unset (None default), `write.restart_manager` is callable subject to RBAC.

**Wazuh API user permissions.** The user MCP authenticates as on Wazuh's Server API (typically `wazuh-wui`) must have cluster-admin permissions. Wazuh enforces this independently of MCP; an MCP-allowed call to `write.restart_manager` still fails at Wazuh's API if the user lacks the cluster role. Verify with:

```
curl -k -u wazuh-wui:<password> -X PUT 'https://wazuh.example:55000/security/user/run_as' -H 'Content-Type: application/json' -d '{}'
```

(See your Wazuh Server API user-and-role documentation for full setup.)

**Scope choice.** `scope=cluster` (default) issues `PUT /cluster/restart` — coordinator-driven full cluster cycle, ~30s-5min depending on node count. Use this for rule-file activation; rules upload to one node but every node must restart to load them. `scope=node` issues `PUT /manager/restart` — single-node restart, ~30s. Use this for narrower-blast-radius needs (stuck node, no rule changes).

**Pair with `cluster.status` for readiness verification.** `restart_manager` is fire-and-forget — it returns on Wazuh's 200 ack (~200ms), not on cluster ready. Poll `cluster.status` to confirm:

```
1. write.restart_manager(scope="cluster", confirm=true)
   → ok=True, scope="cluster", affected_nodes=["node-master","node-worker-1"]
2. (wait ~30s; poll cluster.status every few seconds)
3. cluster.status() → enabled=true, running=true, all nodes status="running"
```

## 6. `cluster.status` setup

Default RBAC: `analyst.*`-readable. Operators with restrictive RBAC overrides may need to explicitly add the tool:

```yaml
role_tool_allowlist:
  admin: ["*"]
  analyst: ["alerts.*", "agents.*", "vulnerabilities.*", "mitre.*", "hunt.*", "fim.*", "cluster.*"]
  readonly: ["alerts.*", "agents.get_agent", "agents.list_agents", "vulnerabilities.*", "mitre.*", "fim.*", "cluster.status"]
```

The default `analyst` and `readonly` roles already include `cluster.*` and `cluster.status` respectively if you keep the global defaults; only operators who override these roles per-tenant need to migrate.

`cluster.status` is a thin read returning:

```json
{
  "enabled": true,
  "running": true,
  "nodes": [
    {"name": "node-master", "type": "master", "status": "running"},
    {"name": "node-worker-1", "type": "worker", "status": "running"}
  ]
}
```

When clustering is disabled (single-node deployment), `enabled=false`, `running=false`, `nodes=[]`. The read still succeeds.

## 7. Multi-agent AR migration

`write.run_active_response` and `write.isolate_agent` swap `agent_id: str` for `agent_ids: list[str]` (1≤len≤50). Wazuh's `agents_list` query param accepts the same comma-joined output for either, so the wire shape is preserved.

```python
# Before (M4b)
write.run_active_response(confirm=True, command_name="isolate", agent_id="001")
write.isolate_agent(confirm=True, agent_id="001")

# After (M4c)
write.run_active_response(confirm=True, command_name="isolate", agent_ids=["001"])
write.isolate_agent(confirm=True, agent_ids=["001"])

# Multi-agent (new)
write.isolate_agent(confirm=True, agent_ids=["001", "002", "003"])
```

**Partial-failure semantics.** `WriteResult.failed_agents` carries the per-agent failure list:

```json
{
  "ok": false,
  "affected_agents": ["001", "002"],
  "failed_agents": [{"agent_id": "003", "reason": "agent offline"}],
  "failed_files": null,
  "timestamp": "2026-04-27T13:24:32.001Z"
}
```

`ok=true` iff every requested agent succeeded. `ok=false` with populated `failed_agents` indicates partial or total failure — **the tool returns successfully**, no exception is raised. The LLM client sees the partial outcome in its trace and can decide whether to retry the failed agents. `WazuhError` is still raised for catastrophic API errors (network failure, auth failure, malformed Wazuh response); M4b's binary contract is preserved for the catastrophic case.

**Hard cap.** `_AR_AGENTS_MAX = 50` per call. Hitting the cap parse-fails with `parse_error`. The cap is a near-future tuning point; it can move to per-tenant config in a follow-up release if 50 proves restrictive.

## 8. Cross-tenant isolation

All 8 write tools (and `cluster.status`) register **uniformly across all tenants** in M4c. Per-tenant denial is purely call-time. This differs from M4b's hidden-tools approach.

**Why:** Multi-tenant integrity over surface narrowing. With per-tenant registration, the FastMCP app served the union of all tenants' write_allowlists, which leaked information about other tenants' configurations. Uniform registration + call-time denial gives every tenant the same `list_tools` surface; only the per-call resolution determines what's actually invocable.

**What this means operationally.** A session for tenant B running `list_tools` sees the same set of tool names as a session for tenant A. Calling `write.create_rule` from a tenant B session still denies if tenant B's `write_allowlist` excludes it — the deny just happens at handler time instead of at registration time. The audit log records the call as `outcome=error, error_code=forbidden, error_reason="not in tenant write_allowlist"`.

## 9. Audit-shape examples

### Successful multi-agent isolate (3/3 succeeded)

```json
// Pre-call (write.requested)
{"tool": "write.isolate_agent", "user": "alice", "tenant": "acme", "rbac_role": "responder", "outcome": "write.requested", "result_count": 0, "duration_ms": 0, "arg_hash": "sha256:..."}

// Completion
{"tool": "write.isolate_agent", "user": "alice", "tenant": "acme", "rbac_role": "responder", "outcome": "ok", "result_count": 3, "duration_ms": 1183, "arg_hash": "sha256:..."}
```

### Partial-failure multi-agent (2/3 succeeded, 1 failed)

```json
// Pre-call (write.requested)
{"tool": "write.run_active_response", "tenant": "acme", "outcome": "write.requested", ...}

// Completion — note ok=false in result body, but outcome="ok" because no exception was raised.
// The audit's outcome reflects "the call completed without raising"; the WriteResult body
// (returned to the caller) carries the success/failure split.
{"tool": "write.run_active_response", "tenant": "acme", "outcome": "ok", "result_count": 2, "duration_ms": 4521, ...}
```

### Unknown-tenant resolver miss (defense-in-depth)

```json
// Three events emitted independently by the three resolvers, on a single
// inbound call from a session with an unregistered tenant_id.
{"tool": "<rbac.resolve>", "tenant": "phantom", "outcome": "error", "error_code": "forbidden", "error_reason": "tenant_not_registered", ...}
{"tool": "<rbac.resolve>", "tenant": "phantom", "outcome": "error", "error_code": "forbidden", "error_reason": "tenant_not_registered", ...}
{"tool": "<rbac.resolve>", "tenant": "phantom", "outcome": "error", "error_code": "forbidden", "error_reason": "tenant_not_registered", ...}

// Followed by the actual tool deny:
{"tool": "alerts.search_alerts", "tenant": "phantom", "outcome": "error", "error_code": "forbidden", "duration_ms": 0, ...}
```
