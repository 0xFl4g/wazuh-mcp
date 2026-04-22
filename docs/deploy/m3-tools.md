# M3 tool reference

Per-tool reference for the full M3 surface: **17 tools** across six domains, **3 resources**, and **3 prompts**.

Tools use dotted names — `alerts.*`, `agents.*`, `vulnerabilities.*`, `mitre.*`, `hunt.*`, `fim.*` — registered on the MCP server with `meta={"toolset": <domain>}`. The toolset tag is inert today but future SDK filtering (RBAC-aware `list_tools`, Claude's toolset preference) will use it.

All tools return strict Pydantic models (`ConfigDict(extra="forbid", frozen=True)`) which FastMCP promotes to `CallToolResult.structuredContent` directly. There are no authored text summaries — Claude generates better summaries from structured data than hand-rolled strings.

Every tool call is audited on every exit path (`ok` or `error` with a safe error code). When the OAuth bearer carries the configured `wazuh_user_claim` (default `wazuh_user`), Server API calls are attributed via the `run_as` header for per-user `wazuh-audit` entries on the Wazuh manager. If the claim is absent, the call uses the tenant's Server API service account (fail-closed — no tool arg override, no config-path derivation).

All tools enforce Pydantic `extra="forbid"`, so unexpected arguments fail fast at validation.

---

## `alerts.*`

Backed by the Wazuh Indexer (`wazuh-alerts-*`).

### `alerts.search_alerts`

Search Wazuh alerts by time range + filters.

| Arg | Type | Notes |
|---|---|---|
| `time_range` | `str` | `<int><m\|h\|d>`, up to 30d. Default `1h`. |
| `min_level` | `int?` | 0..15. |
| `agent_id` | `str?` | Literal `agent.id`. |
| `size` | `int` | 1..100. Default 25. |
| `cursor` | `list?` | Opaque `search_after` cursor from a prior call. |

Returns: `SearchAlertsResult` — `alerts[]`, `total`, `next_cursor`, `truncated`.

Required Wazuh RBAC permission: `agent:read`, read access on `wazuh-alerts-*`.

### `alerts.get_alert`

Fetch a single alert by its document id.

| Arg | Type | Notes |
|---|---|---|
| `alert_id` | `str` | 1..128 chars. |

Returns: `GetAlertResult` — `alert`.

Raises `not_found` (404) if the id is unknown in `wazuh-alerts-*`.

Required Wazuh RBAC permission: `agent:read`, read access on `wazuh-alerts-*`.

### `alerts.alerts_by_agent`

Filter alerts by agent over a time range.

| Arg | Type | Notes |
|---|---|---|
| `agent_id` | `str` | 1..16 chars. Literal `agent.id`. |
| `time_range` | `str` | Default `24h`. |
| `size` | `int` | 1..100. Default 25. |
| `cursor` | `list?` | `search_after` cursor. |

Returns: `SearchAlertsResult`.

Required Wazuh RBAC permission: `agent:read`, read access on `wazuh-alerts-*`.

### `alerts.alerts_by_mitre`

Filter alerts by MITRE technique id.

| Arg | Type | Notes |
|---|---|---|
| `technique_id` | `str` | 4..16 chars, e.g. `T1110` or `T1110.001`. |
| `time_range` | `str` | Default `24h`. |
| `size` | `int` | 1..100. Default 25. |
| `cursor` | `list?` | `search_after` cursor. |

Returns: `SearchAlertsResult`.

Required Wazuh RBAC permission: `agent:read`, read access on `wazuh-alerts-*`.

---

## `agents.*`

Backed by the Wazuh Server API (port 55000). All calls pass `run_as` when the session carries `wazuh_user`.

### `agents.list_agents`

List Wazuh agents, optionally filtered by status or group.

| Arg | Type | Notes |
|---|---|---|
| `status` | `str?` | `active` / `disconnected` / `pending` / `never_connected`. |
| `group` | `str?` | Max 64 chars. |
| `size` | `int` | 1..500. Default 100. |
| `offset` | `int` | 0..10000. Default 0. |

Returns: `AgentsResult` — `agents[]`, `total`, `truncated`.

Required Wazuh RBAC permission: `agent:read`.

### `agents.get_agent`

Fetch a single agent by id.

| Arg | Type | Notes |
|---|---|---|
| `agent_id` | `str` | 1..16 chars. |

Returns: `AgentResult` — `agent`.

Raises `not_found` (404) if the id is unknown.

Required Wazuh RBAC permission: `agent:read`.

### `agents.agent_processes`

Process inventory for an agent (from syscollector).

| Arg | Type | Notes |
|---|---|---|
| `agent_id` | `str` | 1..16 chars. |
| `size` | `int` | 1..500. Default 100. |
| `offset` | `int` | 0..10000. Default 0. |

Returns: `AgentInventoryResult` — `agent_id`, `items[]`, `total`, `truncated`.

Required Wazuh RBAC permission: `agent:read`.

### `agents.agent_packages`

Installed-packages inventory for an agent (from syscollector).

| Arg | Type | Notes |
|---|---|---|
| `agent_id` | `str` | 1..16 chars. |
| `size` | `int` | 1..500. Default 100. |
| `offset` | `int` | 0..10000. Default 0. |

Returns: `AgentInventoryResult`.

Required Wazuh RBAC permission: `agent:read`.

### `agents.agent_ports`

Open-ports inventory for an agent (from syscollector).

| Arg | Type | Notes |
|---|---|---|
| `agent_id` | `str` | 1..16 chars. |
| `size` | `int` | 1..500. Default 100. |
| `offset` | `int` | 0..10000. Default 0. |

Returns: `AgentInventoryResult`.

Required Wazuh RBAC permission: `agent:read`.

---

## `vulnerabilities.*`

Backed by the Wazuh Indexer (`wazuh-states-vulnerabilities-*`). **Requires Wazuh ≥ 4.8** — that's when vulnerability state moved into the indexer.

### `vulnerabilities.list_vulnerabilities_by_agent`

List the vulnerability state for a specific agent.

| Arg | Type | Notes |
|---|---|---|
| `agent_id` | `str` | 1..16 chars. |
| `min_severity` | `str?` | `Low` / `Medium` / `High` / `Critical`. |
| `size` | `int` | 1..100. Default 25. |
| `cursor` | `list?` | `search_after` cursor. |

Returns: `VulnerabilitiesResult` — `vulnerabilities[]`, `total`, `next_cursor`, `truncated`.

Required Wazuh RBAC permission: `agent:read`, read access on `wazuh-states-vulnerabilities-*`.

### `vulnerabilities.search_vulnerabilities`

Search vulnerability state by CVE id or minimum severity.

| Arg | Type | Notes |
|---|---|---|
| `cve_id` | `str?` | e.g. `CVE-2024-1234`. |
| `min_severity` | `str?` | `Low` / `Medium` / `High` / `Critical`. |
| `size` | `int` | 1..100. Default 25. |
| `cursor` | `list?` | `search_after` cursor. |

Returns: `VulnerabilitiesResult`.

Required Wazuh RBAC permission: `agent:read`, read access on `wazuh-states-vulnerabilities-*`.

---

## `mitre.*`

Backed by the Wazuh Server API's bundled MITRE ATT&CK dataset (`/mitre/techniques`).

### `mitre.get_mitre_technique`

Look up a technique by id.

| Arg | Type | Notes |
|---|---|---|
| `technique_id` | `str` | 4..16 chars, matches `T[0-9]{4}(\.[0-9]{3})?` (e.g. `T1110`, `T1110.001`). |

Returns: `MitreTechniqueResult` — `technique`.

Raises `not_found` (404) if the id is unknown.

Required Wazuh RBAC permission: `mitre:read`.

### `mitre.search_mitre`

Search techniques by name substring or tactic. At least one of `q` or `tactic` is required.

| Arg | Type | Notes |
|---|---|---|
| `q` | `str?` | Substring matched against technique name. |
| `tactic` | `str?` | Max 64 chars; matched against tactics. |
| `size` | `int` | 1..200. Default 50. |

Returns: `MitreSearchResult` — `techniques[]`, `total`, `truncated`.

Required Wazuh RBAC permission: `mitre:read`.

---

## `hunt.*`

Backed by the Wazuh Indexer (`wazuh-alerts-*`).

### `hunt.hunt_query`

Constrained-grammar hunt over alerts. Accepts structured `{field, op, value}` clauses from an allowlist — never raw DSL.

| Arg | Type | Notes |
|---|---|---|
| `time_range` | `str` | `<int><m\|h\|d>`, up to 30d. Required. |
| `must` | `list[HuntClause]` | Required. All clauses AND'd. |
| `must_not` | `list[HuntClause]` | Defaults to `[]`. |
| `size` | `int` | 1..100. Default 25. |
| `cursor` | `list?` | `search_after` cursor. |

`HuntClause`: `{field, op, value}`.
- `field`: one of the 23-entry `FIELD_ALLOWLIST` (`agent.id`, `rule.id`, `rule.level`, `rule.mitre.id`, `data.srcip`, `syscheck.path`, `syscheck.sha256_after`, `@timestamp`, …).
- `op`: `eq` / `ne` / `gt` / `gte` / `lt` / `lte` / `in` / `exists` / `prefix`.
- `value`: scalar for most ops; `list` for `in` (1..100 items); `true` required for `exists`; `str` with len ≥ 3 for `prefix`.

Combined `must + must_not` clause count capped at 20; at least one clause required.

The builder only emits `term` / `terms` / `range` / `exists` / `prefix` DSL fragments. No `script`, `runtime_mappings`, `script_score`, `painless`, or nested `bool.should` can be constructed.

Returns: `HuntQueryResult` — `alerts[]`, `total`, `next_cursor`, `truncated`.

Required Wazuh RBAC permission: read access on `wazuh-alerts-*`.

### `hunt.pivot_by_ioc`

Preset IOC pivot over `hunt_query`. Runs against the primary field for the IOC kind; the secondary field (if any) must be probed via a follow-up call (OR is deliberately out of the grammar).

| Arg | Type | Notes |
|---|---|---|
| `kind` | `"hash" \| "ip" \| "user" \| "domain"` | IOC category. |
| `value` | `str` | 1..256 chars. |
| `time_range` | `str` | Default `24h`. |
| `size` | `int` | 1..100. Default 25. |
| `cursor` | `list?` | `search_after` cursor. |

Field map: `hash` → `syscheck.sha256_after`; `ip` → `data.srcip`; `user` → `data.srcuser`; `domain` → `data.hostname`.

Returns: `HuntQueryResult`.

Required Wazuh RBAC permission: read access on `wazuh-alerts-*`.

---

## `fim.*`

File-integrity-monitoring views over the alerts index. Backed by the Wazuh Indexer (`wazuh-alerts-*`).

### `fim.fim_history_for_path`

FIM event history for a specific path.

| Arg | Type | Notes |
|---|---|---|
| `path` | `str` | 1..1024 chars. |
| `time_range` | `str` | Default `24h`. |
| `size` | `int` | 1..100. Default 25. |
| `cursor` | `list?` | `search_after` cursor. |

Returns: `FimResult` — `events[]`, `total`, `next_cursor`, `truncated`.

Required Wazuh RBAC permission: read access on `wazuh-alerts-*`.

### `fim.fim_changes_by_agent`

Recent FIM changes on a specific agent.

| Arg | Type | Notes |
|---|---|---|
| `agent_id` | `str` | 1..16 chars. |
| `time_range` | `str` | Default `24h`. |
| `size` | `int` | 1..100. Default 25. |
| `cursor` | `list?` | `search_after` cursor. |

Returns: `FimResult`.

Required Wazuh RBAC permission: read access on `wazuh-alerts-*`.

---

## Resources (3)

All three are published via `resources/templates/list`. `resources/list` returns `[]` — we never enumerate rules, techniques, or agents (cardinality too large or corpus too public-domain to be useful). Reads are scoped to the session's tenant; URIs have no tenant segment.

Each read returns `{contents: [{mimeType: "application/json", text: <JSON>}], _meta: {ttl_seconds: <int>}}`. Compliant clients cache for `ttl_seconds`.

### `wazuh://rules/{id}`

Individual Wazuh detection rule — definition, groups, description. Pulls from the Server API's `/rules` endpoint.

- `_meta.ttl_seconds`: **300** (5 min).
- Raises `not_found` on unknown id.

### `wazuh://mitre/technique/{id}`

Individual MITRE ATT&CK technique (`TXXXX` or `TXXXX.YYY`). Pulls from the Server API's bundled MITRE dataset.

- `_meta.ttl_seconds`: **86400** (24 h). Stable public corpus — cache aggressively.
- Raises `not_found` on unknown id.

### `wazuh://agents/{id}/config`

Current agent configuration snapshot from the Server API.

- `_meta.ttl_seconds`: **300** (5 min).
- Raises `not_found` on unknown agent id.

---

## Prompts (3)

Published via `prompts/list`. Each prompt's handler pre-fetches context via nested tool calls (inheriting the session's `tenant_id` + `wazuh_user` — no privilege path beyond what the caller already has) and returns a `user` role message with the data JSON-embedded.

### `/wazuh:investigate-alert {alert_id}`

Pre-fetches: the alert (`alerts.get_alert`), its agent (`agents.get_agent`), and last-hour neighbors on the same agent (`alerts.alerts_by_agent(time_range=1h, size=10)`).

Asks Claude to: summarise the alert, note notable neighbor patterns, and recommend the next SOC actions — suggesting further tool calls for anything the pre-loaded context doesn't cover.

### `/wazuh:triage-last-hour`

Pre-fetches: `alerts.search_alerts(time_range=1h, min_level=10, size=25)`.

Asks Claude to: summarise unique rules fired, top agents by count, ATT&CK clustering, and which alerts warrant deeper investigation.

### `/wazuh:agent-posture {agent_id}`

Pre-fetches: the agent (`agents.get_agent`), last-24h alerts for that agent (`alerts.alerts_by_agent(time_range=24h, size=25)`), and its vulnerability state (`vulnerabilities.list_vulnerabilities_by_agent(size=25)`).

Asks Claude to: summarise the agent's security posture — recent alert patterns, unpatched critical vulns, and immediate follow-ups for the SOC.
