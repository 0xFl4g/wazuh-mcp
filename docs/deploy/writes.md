# Write tools

Nine write tools mutate Wazuh state: agent isolation/restart, group membership, rule-file lifecycle, active-response (single-agent + group-target), and manager restart. Every write tool enforces the same safety model — `confirm: Literal[True]`, two-layer allowlist, `run_as` attribution, and double-audit emission.

For per-tool argument schemas, see `docs/api-reference.md`. This file covers the operator-facing safety model.

## The nine write tools

| Tool | Mutates | Wazuh endpoint |
|---|---|---|
| `write.isolate_agent` | Agent network reachability (multi-agent, 1..50) | `PUT /active-response` (`isolate` command) |
| `write.restart_agent` | Single agent process | `PUT /agents/{id}/restart` |
| `write.add_agent_to_group` | Group membership | `PUT /agents/{id}/group/{group}` |
| `write.remove_agent_from_group` | Group membership | `DELETE /agents/{id}/group/{group}` |
| `write.create_rule` | Rule file (no activation) | `PUT /manager/files` |
| `write.update_rule` | Rule file (no activation) | `PUT /manager/files` |
| `write.run_active_response` | Per-agent AR command (multi-agent, 1..50) | `PUT /active-response` |
| `write.run_active_response_on_group` | Group-target AR command (M5b) | `PUT /active-response` (group fan-out) |
| `write.restart_manager` | Wazuh manager / cluster | `PUT /cluster/restart` or `PUT /manager/restart` |

## Two-layer allowlist

Two independent gates govern write access. A call must pass both.

### Layer 1: registration-time `write_allowlist` (per-tenant)

`TenantConfig.write_allowlist` controls which writes are *callable* for the tenant. Three states:

| State | Behavior |
|---|---|
| `None` (omitted) | All 9 writes are callable. RBAC still applies. |
| `[]` (empty list) | All 9 writes register but every call denies with `forbidden`. M4c-shifted from "tools hidden in `list_tools`" to "tools shown but uniformly denied". |
| `["write.isolate_agent", ...]` | Only listed names are callable. Unknown names fail config validation loudly at startup. |

```yaml
tenants:
  - tenant_id: acme
    write_allowlist:
      - write.isolate_agent
      - write.restart_agent
      - write.run_active_response
      - write.run_active_response_on_group
      - write.create_rule
      - write.update_rule
      - write.restart_manager
```

Valid names: `write.isolate_agent`, `write.restart_agent`, `write.add_agent_to_group`, `write.remove_agent_from_group`, `write.create_rule`, `write.update_rule`, `write.run_active_response`, `write.run_active_response_on_group`, `write.restart_manager`.

**Why writes always register.** M4c made tool registration uniform across tenants — `list_tools` returns the same tool set for every tenant, with per-tenant denial happening at handler-body time. This closed the cross-tenant configuration leak that the M4b hide-by-registration pattern caused. `forbidden` audit events on probe attempts are useful operational signal.

### Layer 2: per-tool gates

On top of `write_allowlist`, each write tool consults the per-call session for additional gates:

- **RBAC role.** Every tool checks `role_tool_allowlist` for the session's role. Default roles:
  - `admin`: `("*",)` — every write.
  - `analyst`: read-only — no write tools match the pattern set.
  - `readonly`: subset of reads — no writes.
- **AR command (`write.run_active_response`).** `command_name` must be in `tenant.active_response_allowlist`. Default is empty (deny-all).
- **AR command + group (`write.run_active_response_on_group`).** Both `command_name` (in `active_response_allowlist`) AND `group_name` (in `agent_group_allowlist`) must match. Both default to empty (deny-all).
- **Agent group (general).** No general agent allowlist — operators trust the Wazuh-side `agent:*` permissions. The MCP layer only constrains AR group fan-out via `agent_group_allowlist`.

A custom `responder` role example to give specific operators a curated write set:

```yaml
tenants:
  - tenant_id: acme
    role_tool_allowlist:
      admin: ["*"]
      responder:
        - alerts.*
        - agents.*
        - fim.*
        - write.isolate_agent
        - write.restart_agent
        - write.run_active_response
        - write.run_active_response_on_group
      analyst:
        - alerts.*
        - agents.*
        - vulnerabilities.*
        - mitre.*
        - hunt.*
        - fim.*
        - cluster.*
```

Operators carrying the `responder` role (claim-mapped from the OAuth IdP or assigned via API key) see those writes alongside the read tools.

## `active_response_allowlist` setup

Default is deny-all — `write.run_active_response` denies every call until the operator lists commands explicitly. List the exact command names the Wazuh manager is configured to run in `ossec.conf`:

```yaml
tenants:
  - tenant_id: acme
    active_response_allowlist:
      - firewall-drop
      - restart-wazuh
      - disable-account
      - isolate
```

The MCP allowlist does not teach Wazuh anything. Commands listed here MUST also be declared in `ossec.conf` under `<command>` and bound to an `<active-response>` block. If the MCP allowlist names a command Wazuh does not know, the call reaches Wazuh and Wazuh fails it upstream. Treat the MCP `active_response_allowlist` as the MCP-side mirror of the `ossec.conf` AR registry.

## `agent_group_allowlist` setup (M5b)

`write.run_active_response_on_group` adds a second deny-all allowlist on top of `active_response_allowlist`. Mirrors the AR allowlist precedent: empty by default, list explicit group names per tenant.

```yaml
tenants:
  - tenant_id: acme
    agent_group_allowlist:
      - linux-prod
      - windows-prod
      - dmz
```

Both gates apply for group-target AR calls:
1. `write.run_active_response_on_group` must be in `write_allowlist` (or `write_allowlist=null`).
2. The session's role must allow `write.run_active_response_on_group` per `role_tool_allowlist`.
3. `group_name` arg must be in `agent_group_allowlist`.
4. `command_name` arg must be in `active_response_allowlist`.

Group names follow Wazuh's pattern (`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`). The list itself is capped at 50 entries — typical deployments have far fewer groups.

Call shape:

```json
{
  "group_name": "linux-prod",
  "command_name": "isolate",
  "confirm": true
}
```

## Multi-agent AR migration (M4c)

`write.run_active_response` and `write.isolate_agent` take `agent_ids: list[str]` (1..50), not the M4b `agent_id: str`. Wazuh's `agents_list` query param accepts the comma-joined output, preserving the wire shape.

```python
# M4c +
write.isolate_agent(confirm=True, agent_ids=["001"])
write.isolate_agent(confirm=True, agent_ids=["001", "002", "003"])
write.run_active_response(confirm=True, command_name="isolate", agent_ids=["001"])
```

**Partial-failure semantics.** `WriteResult.failed_agents` carries per-agent failure detail:

```json
{
  "ok": false,
  "affected_agents": ["001", "002"],
  "failed_agents": [{"agent_id": "003", "reason": "agent offline"}],
  "affected_files": null,
  "timestamp": "2026-04-27T13:24:32.001Z"
}
```

`ok=true` iff every requested agent succeeded. Partial-failure returns the WriteResult successfully (no exception) — the LLM client sees the partial outcome in its trace and decides whether to retry. `WazuhError` is still raised for catastrophic API errors (network failure, auth failure, malformed Wazuh response).

**Hard cap.** `_AR_AGENTS_MAX = 50` per call. Hitting the cap fails parse-time with `parse_error`.

## `confirm: Literal[True]` UX

Every write tool's `Args` carries `confirm: Literal[True]`. Pydantic rejects any value that is not literally `true`. There is no "imply true" path, no default, no server-side bypass.

The intended UX, end-to-end:

1. Human asks Claude for something destructive ("isolate agent 007").
2. Claude reads its system prompt: writes require explicit human approval before `confirm:true`.
3. Claude asks the human out loud: "May I isolate agent 007? This will cut the agent off the network until reversed."
4. Human says yes.
5. Claude calls `write.isolate_agent` with `confirm:true`.
6. MCP emits `write.requested`, calls the Server API, emits the completion audit event.

If Claude sets `confirm:true` without asking, the call still goes through — there is no server-side way to prove intent. The signal operators get is indirect: every write-tool description prepends a `_write_desc_prefix` reminding Claude of the contract, and deviations show up in the trace of Claude's turn.

If the caller omits `confirm` or sets it to `false`, Pydantic validation fails. The decorator emits an audit event with `outcome=error`, `error_code=parse_error`; the metric `mcp_tool_calls_total{outcome="parse_error"}` increments. Alert on a rising rate of `parse_error` on `tool=~"write\..*"`:

```
sum(rate(mcp_tool_calls_total{tool=~"write\\..*", outcome="parse_error"}[5m])) by (tool) > 0
```

A non-zero rate is worth investigating — either the IDE/agent wiring is broken, or an automated caller is probing without approval.

## `run_as` attribution

Every write tool calls the Server API with `run_as=session.wazuh_user`. The session is populated from the OAuth bearer's `wazuh_user` claim (claim name configurable via `TenantConfig.wazuh_user_claim`, default `wazuh_user`). API-key sessions leave `wazuh_user` as `None`; Server API calls then run as the tenant's service account with no per-operator attribution.

Verify in Wazuh's own audit output (typically `/var/ossec/logs/api.log`):

```
$ grep 'run_as=alice' /var/ossec/logs/api.log
```

Cross-check against the MCP audit events for the same tool call — same tenant, same tool, same timestamp window. If the MCP event shows `user=alice@example.com` but the Wazuh log shows `run_as=` absent, the OAuth claim is not making it through — verify `wazuh_user_claim` and the IdP mapping. See `oauth.md` for the claim setup.

## Rule-file lifecycle

`write.create_rule` and `write.update_rule` upload a rule XML file to the manager. They do NOT activate rules — Wazuh only loads new rule files after the manager restarts. `write.restart_manager` (M4c) closes that gap from inside MCP; previously it required out-of-band `systemctl restart wazuh-manager`.

Filename convention: `wazuh-mcp-<rule_id>.xml`. Rule IDs must be in `[100000, 999999]` (six-digit private range, avoids collision with shipped rules). On `write.update_rule`, `rule_id` and the nested `rule.id` must match — a mismatch fails validation.

End-to-end flow:

1. **Upload.** `write.create_rule(confirm=true, rule={...})` (or `update_rule`). Tool POSTs the XML as `wazuh-mcp-<id>.xml`. Response's `affected_files` lists the filename.
2. **Verify file exists.** Wazuh UI: **Management → Rules → Custom rules**. Or SSH: `ls /var/ossec/etc/rules/wazuh-mcp-<id>.xml`.
3. **Pre-restart cluster check.** `cluster.status()` — confirm all nodes `running`.
4. **Restart.** `write.restart_manager(scope="cluster", confirm=true)` for rule-file activation across the cluster, or `scope="node"` for narrower-blast-radius (single-node use only).
5. **Wait + verify cluster.** Poll `cluster.status()` every few seconds. Restart takes ~30 s for a single node, up to several minutes for larger clusters.
6. **Confirm rule loaded.** Wazuh UI: **Management → Rules** filtered by rule id. If the rule is parseable, it appears with the groups and description set in the upload. If the restart fails, Wazuh logs the parse error under `/var/ossec/logs/ossec.log`; remove the offending file and restart.

## `write.restart_manager` setup

Required Wazuh-side: the user MCP authenticates as on the Wazuh Server API (typically `wazuh-wui`) must have cluster-admin permissions. Wazuh enforces this independently — an MCP-allowed call to `write.restart_manager` still fails at Wazuh's API if the user lacks the cluster role.

Verify Wazuh-side permissions:

```
curl -k -u wazuh-wui:<password> -X PUT 'https://wazuh.example:55000/security/user/run_as' \
    -H 'Content-Type: application/json' -d '{}'
```

**Scope choice.**
- `scope="cluster"` (default) — `PUT /cluster/restart`. Coordinator-driven full cluster cycle, ~30 s to several minutes depending on node count. Use for rule-file activation; rules upload to one node but every node must restart to load them.
- `scope="node"` — `PUT /manager/restart`. Single-node restart, ~30 s. Use for narrower-blast-radius needs (stuck node, no rule changes).

`restart_manager` is fire-and-forget — it returns on Wazuh's 200 ack (~200 ms), not on cluster ready. Pair with `cluster.status` polling for readiness verification.

If `scope="cluster"` is requested but clustering is not enabled on the manager, the call fails with `upstream_error` (the precondition check returns 400).

## Audit shape

Every write emits TWO audit events. The pre-call event records intent (runs before Pydantic validation, handler execution, or any upstream call). The post-call event is the same per-exit-path event every read tool emits.

### Pre-call event

```json
{
  "tool": "write.isolate_agent",
  "user": "alice",
  "tenant": "acme",
  "rbac_role": "responder",
  "outcome": "write.requested",
  "result_count": 0,
  "duration_ms": 0,
  "arg_hash": "sha256:..."
}
```

`outcome="write.requested"`, `result_count=0`, `duration_ms=0`, no `error_code`. Emitted unconditionally at the start of every `write.*` call — the point is to record that somebody asked, even if everything downstream fails.

### Completion event

Successful multi-agent isolate (3/3 succeeded):

```json
{
  "tool": "write.isolate_agent",
  "user": "alice",
  "tenant": "acme",
  "rbac_role": "responder",
  "outcome": "ok",
  "result_count": 3,
  "duration_ms": 1183,
  "arg_hash": "sha256:..."
}
```

Partial-failure multi-agent (2/3 succeeded, 1 failed) — `outcome="ok"` because no exception was raised; the WriteResult body carries the success/failure split:

```json
{
  "tool": "write.run_active_response",
  "tenant": "acme",
  "outcome": "ok",
  "result_count": 2,
  "duration_ms": 4521
}
```

Forbidden (RBAC, write_allowlist, AR allowlist, AR group allowlist):

```json
{
  "tool": "write.run_active_response_on_group",
  "tenant": "acme",
  "outcome": "error",
  "error_code": "forbidden",
  "duration_ms": 0
}
```

Confirm-missing:

```json
{
  "tool": "write.isolate_agent",
  "tenant": "acme",
  "outcome": "error",
  "error_code": "parse_error",
  "duration_ms": 0
}
```

### Wazuh Dashboards saved searches

Assuming the tenant's `wazuh_indexer` audit sink is configured per `observability.md` with the default `index_prefix: wazuh-mcp-audit`:

- **Attempted writes** — `tool:write.* AND outcome:"write.requested"`.
- **Completed writes** — `tool:write.* AND outcome:ok`.
- **Failed writes** — `tool:write.* AND outcome:error` — group by `error_code`.
- **AR allowlist denials** — `tool:write.* AND error_code:forbidden` — surface `scope=ar_allowlist` / `scope=ar_group_allowlist` / `scope=write_allowlist` to disambiguate.
- **Confirm-missing rate** — `tool:write.* AND error_code:parse_error` — anomalous if non-zero.
- **Per-operator writes** — `tool:write.* AND user:"alice"` sorted by `timestamp` desc.

Diffing `attempted - completed - failed` at rate level should be near zero; a sustained gap means the handler is being cancelled mid-call (long upstream timeouts, client disconnects).

## Related docs

- `secrets.md` — how the tenant's Server API service-account credentials are stored and rotated.
- `observability.md` — OTel traces, Prometheus metrics (incl. `mcp_rate_limit_drops_total{tenant, scope}`), audit emitter and sink fan-out.
- `multi-tenant.md` — per-tenant resolver model, `agent_group_allowlist` placement, multi-tenant integration fixture.
- `api-reference.md` — full per-tool argument and result schema.
