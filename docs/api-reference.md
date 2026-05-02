# wazuh-mcp API reference

Comprehensive reference for every MCP-surface element: 18 tools (17 reads + `cluster.status`), 9 write tools, 3 resources, 3 prompts. Per element: full args schema, full result schema, RBAC requirement, error codes (with the `scope` field), and audit-shape examples.

For the operator-facing topic guides, see `deploy/`. This document is the contract — argument validators, result-shape invariants, and error semantics are what the implementation actually enforces.

---

## 1. Conventions

### Call shape

All tools use the standard MCP `tools/call` shape:

```json
{
  "name": "alerts.search_alerts",
  "arguments": { "time_range": "1h", "size": 25 }
}
```

Every tool's `Args` model is strict Pydantic — `ConfigDict(extra="forbid", frozen=True)`. Unexpected arguments fail with `parse_error` at validation time.

### Result shape

Every tool returns a strict Pydantic result model. FastMCP promotes the model to `CallToolResult.structuredContent` directly; clients with `structuredContent` support get typed output, while older clients see the JSON serialization in the text content.

### RBAC

Each call is gated by `role_tool_allowlist` for the session's role. Default roles:

| Role | Pattern set | Notes |
|---|---|---|
| `admin` | `("*",)` | Every tool. |
| `analyst` | `alerts.*`, `agents.*`, `vulnerabilities.*`, `mitre.*`, `hunt.*`, `fim.*`, `cluster.*` | All reads. No writes. |
| `responder` | inherits `analyst` set + curated writes (operator-defined) | Custom role example in `deploy/writes.md`. |
| `readonly` | `alerts.*`, `agents.get_agent`, `agents.list_agents`, `vulnerabilities.*`, `mitre.*`, `fim.*`, `cluster.status` | Subset of reads. |

Sessions also enforce per-tenant `write_allowlist`, `active_response_allowlist`, `agent_group_allowlist` (writes only) and rate-limit buckets. See `deploy/multi-tenant.md`.

### Audit

Every tool call produces exactly one audit event on every exit path. Write tools produce TWO events — pre-call (`outcome="write.requested"`) plus completion. Schema:

```json
{
  "timestamp": "2026-05-01T10:23:11.482Z",
  "tool": "alerts.search_alerts",
  "user": "alice@example.com",
  "tenant": "acme",
  "rbac_role": "analyst",
  "arg_hash": "sha256:...",
  "outcome": "ok",
  "result_count": 25,
  "duration_ms": 142
}
```

On `outcome="error"`, additional fields appear:
- `error_code` — one of `SAFE_CODES` (see §6).
- `scope` — only when the underlying `WazuhError` carried a structured scope (rate-limit + allowlist denials).
- `error_reason` — only on the resolver-miss sentinel `<rbac.resolve>` events.

See `deploy/observability.md` for the full sink + fan-out model.

---

## 2. Read tools

### `alerts.search_alerts`

Search Wazuh alerts by time range + filters. Backed by Wazuh Indexer (`wazuh-alerts-*`).

**Args (`SearchAlertsArgs`):**

| Field | Type | Constraint | Default | Notes |
|---|---|---|---|---|
| `time_range` | `str` | `^\d+[mhd]$`, `[1m..30d]` | `"1h"` | |
| `min_level` | `int?` | 0..15 | `None` | |
| `agent_id` | `str?` | 1..16 | `None` | Literal `agent.id`. |
| `size` | `int` | 1..100 | `25` | |
| `cursor` | `list?` | — | `None` | Opaque `search_after` cursor. |

**Result (`SearchAlertsResult`):** `alerts: list[dict]`, `total: int`, `next_cursor: list | None`, `truncated: bool`.

**RBAC:** `agent:read`, indexer read on `wazuh-alerts-*`.

**Errors:** `upstream_error`, `upstream_timeout`, `auth_expired`, `rate_limited`.

### `alerts.get_alert`

**Args (`GetAlertArgs`):** `alert_id: str (1..128)`.

**Result (`GetAlertResult`):** `alert: dict`.

**RBAC:** `agent:read`, indexer read on `wazuh-alerts-*`.

**Errors:** `not_found`, plus standard upstream errors.

### `alerts.alerts_by_agent`

**Args (`AlertsByAgentArgs`):** `agent_id: str (1..16)`, `time_range: str = "24h"`, `size: int (1..100) = 25`, `cursor?`.

**Result:** `SearchAlertsResult`.

**RBAC:** `agent:read`, indexer read on `wazuh-alerts-*`.

### `alerts.alerts_by_mitre`

**Args (`AlertsByMitreArgs`):** `technique_id: str (4..16, ^T\d{4}(\.\d{3})?$)`, `time_range: str = "24h"`, `size: int (1..100) = 25`, `cursor?`.

**Result:** `SearchAlertsResult`.

**RBAC:** `agent:read`, indexer read on `wazuh-alerts-*`.

### `agents.list_agents`

**Args (`ListAgentsArgs`):**

| Field | Type | Constraint | Default |
|---|---|---|---|
| `status` | `str?` | `active \| disconnected \| pending \| never_connected` | `None` |
| `group` | `str?` | 1..64 | `None` |
| `size` | `int` | 1..500 | `100` |
| `offset` | `int` | 0..10000 | `0` |

**Result (`AgentsResult`):** `agents: list[dict]`, `total: int`, `truncated: bool`.

**RBAC:** `agent:read` (Wazuh Server API).

### `agents.get_agent`

**Args (`GetAgentArgs`):** `agent_id: str (1..16)`.

**Result (`AgentResult`):** `agent: dict`.

**Errors:** `not_found`, plus standard upstream.

### `agents.agent_processes` / `agents.agent_packages` / `agents.agent_ports`

**Args (`AgentSubquery`):** `agent_id: str (1..16)`, `size: int (1..500) = 100`, `offset: int (0..10000) = 0`.

**Result (`AgentInventoryResult`):** `agent_id: str`, `items: list[dict]`, `total: int`, `truncated: bool`.

**RBAC:** `agent:read` (syscollector inventory).

### `vulnerabilities.list_vulnerabilities_by_agent`

**Args (`ListVulnerabilitiesByAgentArgs`):** `agent_id: str (1..16)`, `min_severity: str? (Low|Medium|High|Critical)`, `size: int (1..100) = 25`, `cursor?`.

**Result (`VulnerabilitiesResult`):** `vulnerabilities: list[dict]`, `total: int`, `next_cursor: list | None`, `truncated: bool`.

**RBAC:** `agent:read`, indexer read on `wazuh-states-vulnerabilities-*`. Requires Wazuh ≥ 4.8.

### `vulnerabilities.search_vulnerabilities`

**Args (`SearchVulnerabilitiesArgs`):** `cve_id: str?`, `min_severity: str? (Low|Medium|High|Critical)`, `size: int (1..100) = 25`, `cursor?`.

**Result:** `VulnerabilitiesResult`.

### `mitre.get_mitre_technique`

**Args (`GetMitreTechniqueArgs`):** `technique_id: str (4..16, ^T\d{4}(\.\d{3})?$)`.

**Result (`MitreTechniqueResult`):** `technique: dict`.

**RBAC:** `mitre:read`.

**Errors:** `not_found`.

### `mitre.search_mitre`

**Args (`SearchMitreArgs`):** `q: str?`, `tactic: str? (1..64)`, `size: int (1..200) = 50`. At least one of `q` / `tactic` required (model validator).

**Result (`MitreSearchResult`):** `techniques: list[dict]`, `total: int`, `truncated: bool`.

### `hunt.hunt_query`

**Args (`HuntQueryArgs`):**

| Field | Type | Notes |
|---|---|---|
| `time_range` | `str` | `^\d+[mhd]$`, up to 30d. |
| `must` | `list[HuntClause]` | All clauses AND'd. |
| `must_not` | `list[HuntClause]` | Default `[]`. |
| `size` | `int` | 1..100. Default 25. |
| `cursor` | `list?` | `search_after` cursor. |

`HuntClause`: `{field: str, op: str, value: scalar | list | bool}`.

- `field` ∈ 23-entry `FIELD_ALLOWLIST` (`agent.id`, `rule.id`, `rule.level`, `rule.mitre.id`, `data.srcip`, `syscheck.path`, `syscheck.sha256_after`, `@timestamp`, etc.).
- `op` ∈ `eq | ne | gt | gte | lt | lte | in | exists | prefix`.
- `value`: scalar for most ops; `list` (1..100 items) for `in`; `true` for `exists`; `str` (len ≥ 3) for `prefix`.

Combined `must + must_not` cap: 20 clauses; at least one required.

The builder only emits `term` / `terms` / `range` / `exists` / `prefix` DSL fragments. No `script`, `runtime_mappings`, `script_score`, `painless`, or nested `bool.should`.

**Result (`HuntQueryResult`):** `alerts: list[dict]`, `total: int`, `next_cursor: list | None`, `truncated: bool`.

**Errors:** `invalid_query` for grammar violations, plus standard upstream.

### `hunt.pivot_by_ioc`

**Args (`PivotByIocArgs`):** `kind: "hash" | "ip" | "user" | "domain"`, `value: str (1..256)`, `time_range: str = "24h"`, `size: int (1..100) = 25`, `cursor?`.

Field map: `hash` → `syscheck.sha256_after`; `ip` → `data.srcip`; `user` → `data.srcuser`; `domain` → `data.hostname`.

**Result:** `HuntQueryResult`.

### `fim.fim_history_for_path`

**Args (`FimHistoryArgs`):** `path: str (1..1024)`, `time_range: str = "24h"`, `size: int (1..100) = 25`, `cursor?`.

**Result (`FimResult`):** `events: list[dict]`, `total: int`, `next_cursor: list | None`, `truncated: bool`.

### `fim.fim_changes_by_agent`

**Args (`FimChangesArgs`):** `agent_id: str (1..16)`, `time_range: str = "24h"`, `size: int (1..100) = 25`, `cursor?`.

**Result:** `FimResult`.

### `cluster.status`

Reads the Wazuh cluster's status — clustering enabled, running state, per-node name/type/status. Used to verify cluster readiness pre/post manager restart.

**Args (`ClusterStatusArgs`):** `{}` (no fields).

**Result (`ClusterStatusResult`):**

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

When clustering is disabled (single-node deploy), `enabled=false`, `running=false`, `nodes=[]`. The read still succeeds.

**RBAC:** Default `analyst.*` and `readonly.cluster.status` — see `deploy/tools.md` for role overrides.

---

## 3. Write tools

All write-tool args carry `confirm: Literal[True]`. Pydantic rejects any value that is not literally `true`. `WriteResult` is the standard envelope:

```python
class WriteResult(BaseModel):
    ok: bool
    affected_agents: list[str] | None = None
    failed_agents: list[FailedAgent] = []   # FailedAgent: {agent_id: str, reason: str}
    affected_files: list[str] | None = None
    timestamp: datetime
```

`ok=true` iff every targeted item succeeded. Partial failure populates `failed_agents` and returns the result successfully (no exception). `WazuhError` is raised for catastrophic API failures (network, auth, malformed Wazuh response).

### `write.isolate_agent`

**Args (`IsolateAgentArgs`):** `agent_ids: list[str] (1..50)`, `confirm: Literal[True]`.

**Result:** `WriteResult` — `affected_agents`, optional `failed_agents`.

**Allowlists:** `write_allowlist` (registration-time, defaults to all-callable). RBAC enforced.

**Errors:** `forbidden` (RBAC, write_allowlist), `parse_error` (missing/false `confirm`), upstream errors.

### `write.restart_agent`

**Args (`RestartAgentArgs`):** `agent_id: str (1..16)`, `confirm: Literal[True]`.

**Result:** `WriteResult` — `affected_agents`.

### `write.add_agent_to_group` / `write.remove_agent_from_group`

**Args (`AddAgentToGroupArgs` / `RemoveAgentFromGroupArgs`):** `agent_id: str (1..16)`, `group_id: str (1..128, ^[a-zA-Z0-9_-]+$)`, `confirm: Literal[True]`.

**Result:** `WriteResult`.

### `write.create_rule`

**Args (`CreateRuleArgs`):** `rule: RuleDefinition`, `confirm: Literal[True]`.

`RuleDefinition` (see `src/wazuh_mcp/wazuh/rule_render.py`): rule id `[100000, 999999]`, level, description, optional groups + match clauses.

**Result:** `WriteResult` — `affected_files: ["wazuh-mcp-<id>.xml"]`.

**Note:** Does NOT activate the rule. Pair with `write.restart_manager`. See `deploy/writes.md#rule-file-lifecycle`.

### `write.update_rule`

**Args (`UpdateRuleArgs`):** `rule_id: int [100000..999999]`, `rule: RuleDefinition`, `confirm: Literal[True]`. Model-validator: `rule_id` MUST equal `rule.id`.

**Result:** `WriteResult` — `affected_files`.

### `write.run_active_response`

**Args (`RunActiveResponseArgs`):** `agent_ids: list[str] (1..50)`, `command_name: str (1..128)`, `custom_args: dict?`, `confirm: Literal[True]`.

**Allowlists:** `write_allowlist` + `active_response_allowlist` (`command_name` must be listed). RBAC enforced.

**Result:** `WriteResult` — `affected_agents`, optional `failed_agents`.

**Errors:** `forbidden` (RBAC, write_allowlist OR ar_allowlist — see `scope` field), `parse_error`, upstream errors.

### `write.run_active_response_on_group` *(M5b)*

**Args (`RunActiveResponseOnGroupArgs`):** `group_name: str (1..128)`, `command_name: str (1..128)`, `custom_args: dict?`, `confirm: Literal[True]`.

**Allowlists:** Four-gate model:
1. `write.run_active_response_on_group` in `write_allowlist` (or `write_allowlist=null`).
2. RBAC role allows the tool.
3. `group_name` in `agent_group_allowlist`.
4. `command_name` in `active_response_allowlist`.

**Result:** `WriteResult`.

**Errors:** `forbidden` with `scope ∈ {write_allowlist, ar_allowlist, ar_group_allowlist}` to disambiguate the failing gate.

### `write.restart_manager`

**Args (`RestartManagerArgs`):** `scope: "node" | "cluster" = "cluster"`, `confirm: Literal[True]`.

**Result (`RestartManagerResult`):**

```python
{
  "ok": True,
  "scope": "cluster",
  "affected_nodes": ["node-master", "node-worker-1"],
  "timestamp": "..."
}
```

**Allowlists:** `write_allowlist`. RBAC enforced. Wazuh-side cluster-admin permission required.

**Errors:** `upstream_error` if `scope="cluster"` is requested but clustering is not enabled on the manager. Standard upstream errors otherwise.

**Note:** Fire-and-forget — returns on Wazuh's 200 ack (~200 ms), not on cluster ready. Pair with `cluster.status` polling for readiness verification.

---

## 4. Resources

All three are published via `resources/templates/list`. `resources/list` returns `[]`. Each read returns:

```json
{
  "contents": [{"mimeType": "application/json", "text": "<JSON>"}],
  "_meta": {"ttl_seconds": <int>}
}
```

### `wazuh://rules/{rule_id}`

Individual Wazuh detection rule (definition, groups, description). Backed by Server API `/rules`.

- `_meta.ttl_seconds`: **300** (5 min).
- Errors: `not_found` on unknown id.

### `wazuh://mitre/technique/{technique_id}`

Individual MITRE ATT&CK technique (`TXXXX` or `TXXXX.YYY`). Backed by the bundled MITRE dataset.

- `_meta.ttl_seconds`: **86400** (24 h). Stable public corpus — cache aggressively.
- Errors: `not_found` on unknown id.

### `wazuh://agents/{agent_id}/config`

Current agent configuration snapshot from the Server API.

- `_meta.ttl_seconds`: **300** (5 min).
- Errors: `not_found` on unknown agent id.

---

## 5. Prompts

Each prompt's handler pre-fetches context via nested tool calls (inheriting the session's `tenant_id` + `wazuh_user`) and returns a `user`-role message with the data JSON-embedded.

### `/wazuh:investigate-alert {alert_id}`

Pre-fetches: `alerts.get_alert(alert_id)`, `agents.get_agent(agent_id)`, `alerts.alerts_by_agent(time_range=1h, size=10)`. Asks Claude to summarise + recommend SOC actions.

### `/wazuh:triage-last-hour`

Pre-fetches: `alerts.search_alerts(time_range=1h, min_level=10, size=25)`. Asks Claude to summarise unique rules fired, top agents by count, ATT&CK clustering, and which alerts warrant deeper investigation.

### `/wazuh:agent-posture {agent_id}`

Pre-fetches: `agents.get_agent`, `alerts.alerts_by_agent(time_range=24h, size=25)`, `vulnerabilities.list_vulnerabilities_by_agent(size=25)`. Asks Claude to summarise the agent's security posture.

---

## 6. Error codes

`WazuhError` carries `code`, `message`, `status_code`, and an optional `scope`. The wire format only ever surfaces codes in `SAFE_CODES`:

```python
SAFE_CODES = {
    "auth_expired",
    "forbidden",
    "rate_limited",
    "invalid_query",
    "upstream_error",
    "not_found",
    "upstream_timeout",
}
```

Internal exceptions (validation errors, programming bugs, cancellations) map to additional outcome labels on `mcp_tool_calls_total`:

| Outcome | Cause |
|---|---|
| `parse_error` | Pydantic validation failed (missing `confirm`, schema mismatch, etc.). |
| `cancelled` | The handler was cancelled (client disconnect, shutdown). |
| `internal` | Unhandled exception (programming bug — operator alert). |

### `scope` field

When the underlying `WazuhError` carried a structured scope, it appears as a top-level field on `outcome=error` audit events:

| Scope | Source |
|---|---|
| `rate_limit:tenant` | Per-tenant rate-limit bucket exhausted. |
| `rate_limit:session` | Per-session rate-limit bucket exhausted. |
| `write_allowlist` | Tool not in tenant's `write_allowlist`. |
| `ar_allowlist` | `command_name` not in tenant's `active_response_allowlist`, OR AR not configured. |
| `ar_group_allowlist` | `group_name` not in tenant's `agent_group_allowlist`, OR group AR not configured. |

The `mcp_rate_limit_drops_total{tenant, scope}` Prometheus metric reads `err.scope` directly.

### HTTP status mapping

| `WazuhError.code` | `status_code` | Wire-side outcome label |
|---|---|---|
| `auth_expired` | 401 | `auth_expired` |
| `forbidden` | 403 | `forbidden` |
| `not_found` | 404 | `not_found` |
| `rate_limited` | 429 | `rate_limited` |
| `invalid_query` | 400 | `invalid_query` |
| `upstream_error` | 502 (typical) | `upstream_error` |
| `upstream_timeout` | 504 | `upstream_timeout` |

---

## 7. Audit-event shape

### Successful read

```json
{
  "timestamp": "2026-05-01T10:23:11.482Z",
  "tool": "alerts.search_alerts",
  "user": "alice@example.com",
  "tenant": "acme",
  "rbac_role": "analyst",
  "arg_hash": "sha256:1f3a...",
  "outcome": "ok",
  "result_count": 25,
  "duration_ms": 142
}
```

### Pre-call write event

```json
{
  "tool": "write.isolate_agent",
  "user": "alice@example.com",
  "tenant": "acme",
  "rbac_role": "responder",
  "arg_hash": "sha256:...",
  "outcome": "write.requested",
  "result_count": 0,
  "duration_ms": 0
}
```

### Successful multi-agent write (3/3 succeeded)

```json
{
  "tool": "write.isolate_agent",
  "tenant": "acme",
  "outcome": "ok",
  "result_count": 3,
  "duration_ms": 1183
}
```

### Partial-failure write (no exception raised — outcome stays `ok`)

```json
{
  "tool": "write.run_active_response",
  "tenant": "acme",
  "outcome": "ok",
  "result_count": 2,
  "duration_ms": 4521
}
```

(The WriteResult body returned to the caller carries `failed_agents`. The audit `outcome` only flips to `error` when an exception is raised.)

### Forbidden — write_allowlist denial

```json
{
  "tool": "write.create_rule",
  "tenant": "acme",
  "outcome": "error",
  "error_code": "forbidden",
  "scope": "write_allowlist",
  "duration_ms": 0
}
```

### Forbidden — AR allowlist denial

```json
{
  "tool": "write.run_active_response",
  "tenant": "acme",
  "outcome": "error",
  "error_code": "forbidden",
  "scope": "ar_allowlist",
  "duration_ms": 0
}
```

### Forbidden — AR group allowlist denial

```json
{
  "tool": "write.run_active_response_on_group",
  "tenant": "acme",
  "outcome": "error",
  "error_code": "forbidden",
  "scope": "ar_group_allowlist",
  "duration_ms": 0
}
```

### Rate-limited (per-tenant bucket)

```json
{
  "tool": "alerts.search_alerts",
  "tenant": "tenant_b",
  "outcome": "error",
  "error_code": "rate_limited",
  "scope": "rate_limit:tenant",
  "duration_ms": 0
}
```

### Confirm-missing (parse_error)

```json
{
  "tool": "write.isolate_agent",
  "tenant": "acme",
  "outcome": "error",
  "error_code": "parse_error",
  "duration_ms": 0
}
```

### Upstream error (Wazuh API failure)

```json
{
  "tool": "agents.get_agent",
  "tenant": "acme",
  "outcome": "error",
  "error_code": "upstream_error",
  "duration_ms": 320
}
```

### Resolver miss (defense-in-depth — `<rbac.resolve>` sentinel)

```json
{
  "tool": "<rbac.resolve>",
  "user": "alice@phantom-tenant",
  "tenant": "phantom",
  "rbac_role": "admin",
  "outcome": "error",
  "error_code": "forbidden",
  "error_reason": "tenant_not_registered",
  "duration_ms": 0
}
```

Up to 4× `<rbac.resolve>` events per inbound call from a session whose tenant is unknown (RBAC + write + AR + AR-group resolvers each fire independently). Followed by the actual tool deny (e.g., `outcome="error", error_code="forbidden"` on the requested tool).

---

## 8. Where to go next

- Operator install + first-run smoke — `deploy/install.md`.
- `TenantConfig` schema reference — `deploy/tenants.md`.
- OAuth + IssuerIndex + claim mapping — `deploy/oauth.md`.
- Read-tool operator guide — `deploy/tools.md`.
- Write-tool operator guide — `deploy/writes.md`.
- Multi-tenant guarantees + resolver model — `deploy/multi-tenant.md`.
- Observability + audit + metrics — `deploy/observability.md`.
- Quality gates — `deploy/quality-gates.md`.
- Helm chart — `deploy/helm.md`.
