# M4b — Write tools

> **M4c update (v0.6.0-m4c, 2026-04-27).** The M4b two-layer allowlist model below is preserved — but three operator-visible details have shifted in M4c:
>
> 1. `write.run_active_response` and `write.isolate_agent` now take `agent_ids: list[str]` (1-50) instead of `agent_id: str`. Existing single-agent callers update from `agent_id="001"` to `agent_ids=["001"]`. Wazuh's `agents_list` wire shape is preserved.
> 2. `write_allowlist=[]` no longer hides write tools from `list_tools` — all writes register unconditionally and per-tenant denial happens at handler time. The behavior previously described as "Disable all writes — no write tool registers" is now "all writes registered but every call denies with `forbidden`".
> 3. `confirm_required` is removed from `SAFE_CODES` (it never fired at runtime; the `confirm: Literal[True]` parse gate IS the confirm contract).
>
> A new tool `write.restart_manager` ships in M4c plus a paired read tool `cluster.status`. Per-tenant policy now resolves at call time against `session.tenant_id` — closing the multi-tenant policy-bleed gap. See `m4c-multi-tenant.md` for the full migration guide.

## Overview

M4b adds seven `write.*` tools that mutate Wazuh state: agent isolation, agent restart, group membership (add/remove), rule-file upload (create/update), and active-response dispatch. Every write tool enforces the same safety model — a `confirm: Literal[True]` argument the caller MUST set, a two-layer allowlist (per-tenant `write_allowlist` gates which writes register on the MCP surface at all, and `role_tool_allowlist` gates which roles see them), and `run_as` attribution threaded from the OAuth `wazuh_user` claim into every Server API call. Every write produces exactly two audit events — one `write.requested` pre-call, one completion — so operators see intent even when the handler fails, is cancelled, or is rejected for missing confirm. Active-response is locked down harder than the rest: `active_response_allowlist` defaults to empty, which means `write.run_active_response` denies every command until the operator explicitly lists the ones their Wazuh deployment is configured to run.

## Enable writes for a tenant

`TenantConfig.write_allowlist` has three meaningful states. Pick one per tenant.

### No filter (all writes register)

Omit the field or set it to `null`. Every M4b write tool registers on the MCP surface for this tenant. RBAC still applies on top — a `readonly` session still cannot call them.

```yaml
tenants:
  - tenant_id: acme
    indexer_url: https://wazuh.acme.internal:9200
    default_rbac_role: analyst
    # write_allowlist omitted: all seven write.* tools register.
```

### Disable all writes

Set to an empty list. No write tool registers; the MCP surface for this tenant is read-only.

```yaml
tenants:
  - tenant_id: readonly-msp-customer
    indexer_url: https://wazuh.customer.example:9200
    default_rbac_role: analyst
    write_allowlist: []
```

### Register a specific subset

List exact tool names. Only listed names register. Entries must be under the `write.*` namespace and must match a known tool name; unknown names fail config validation loudly at startup.

```yaml
tenants:
  - tenant_id: soc
    indexer_url: https://wazuh.soc.internal:9200
    default_rbac_role: analyst
    write_allowlist:
      - write.isolate_agent
      - write.restart_agent
      - write.run_active_response
```

Valid names: `write.isolate_agent`, `write.restart_agent`, `write.add_agent_to_group`, `write.remove_agent_from_group`, `write.create_rule`, `write.update_rule`, `write.run_active_response`.

See `src/wazuh_mcp/tenancy/config.py` and `src/wazuh_mcp/tenancy/m4_config.py` for the authoritative field definitions.

## Configure `active_response_allowlist`

`write.run_active_response` is the only write tool whose arguments can name an arbitrary Wazuh active-response command by string. To prevent a session from invoking an AR command the operator never intended to expose, the handler enforces a per-tenant deny-all allowlist.

### Default is deny-all

`active_response_allowlist` defaults to an empty list. With the default, every call to `write.run_active_response` returns `forbidden` (code `forbidden`, HTTP 403) regardless of RBAC — the tool registers but refuses to execute.

### List commands explicitly

List the exact command names your Wazuh manager is configured to run in `ossec.conf`. The allowlist is matched against the tool argument `command_name`.

```yaml
tenants:
  - tenant_id: acme
    indexer_url: https://wazuh.acme.internal:9200
    default_rbac_role: analyst
    active_response_allowlist:
      - firewall-drop
      - restart-wazuh
      - disable-account
```

### Correlate with `ossec.conf`

The MCP allowlist does not teach Wazuh anything. Commands listed here MUST also be declared in the Wazuh manager's `ossec.conf` under `<command>` and bound to an `<active-response>` block. If the MCP allowlist names a command Wazuh does not know, the Server API call will reach Wazuh and Wazuh will fail it upstream. Keep the two lists in lockstep — treat the MCP `active_response_allowlist` as the MCP-side mirror of the `ossec.conf` AR registry.

See `src/wazuh_mcp/tools/write.py::run_active_response`.

## Configure roles for write access

The three shipped roles treat writes as admin-only by default.

| Role | Allowlist | Writes? |
|---|---|---|
| `admin` | `("*",)` | Yes — matches every `write.*` tool. |
| `analyst` | `alerts.*`, `agents.*`, `vulnerabilities.*`, `mitre.*`, `hunt.*`, `fim.*` | No — `write.*` is not in the pattern set. |
| `readonly` | subset of reads | No. |

To let non-admin operators run a curated set of writes, define a custom role in the tenant's `role_tool_allowlist`. The map is `role -> list[pattern]`; patterns use the same glob shape as the defaults.

```yaml
tenants:
  - tenant_id: acme
    indexer_url: https://wazuh.acme.internal:9200
    default_rbac_role: analyst
    role_tool_allowlist:
      responder:
        - alerts.*
        - agents.*
        - fim.*
        - write.isolate_agent
        - write.restart_agent
        - write.run_active_response
```

Operators carrying the `responder` role (claim-mapped from the OAuth IdP or assigned via API key) now see those three writes alongside the read tools. `role_tool_allowlist` replaces the default per-role entry; absent roles fall through to the shipped defaults. See `src/wazuh_mcp/rbac/policy.py`.

## Verify `run_as` attribution

Every write tool calls the Server API with `run_as=session.wazuh_user`. The session is populated from the OAuth bearer's `wazuh_user` claim (claim name configurable via `TenantConfig.wazuh_user_claim`, default `wazuh_user`). API-key sessions leave `wazuh_user` as `None`; Server API calls then run as the tenant's service account with no per-operator attribution.

### Map the OAuth claim

Configure your IdP to emit the operator's Wazuh username as a custom claim on the access token. Example claim mapping (IdP-specific):

```
sub: alice@example.com
wazuh_user: alice
```

At session setup, `Session.wazuh_user` is set to `"alice"`. Every Server API call the write tool issues sends `?run_as=alice` as a query parameter.

### Verify in Wazuh's own audit output

Wazuh's API audit log (by default `/var/ossec/logs/api.log` on the manager) records the effective user on each authenticated request. Look for `run_as=<operator>` next to each write:

```
grep 'run_as=alice' /var/ossec/logs/api.log
```

Cross-check against the MCP audit events for the same tool call — same tenant, same tool, same timestamp window. If the MCP event shows `user=alice@example.com` but the Wazuh log shows `run_as=` absent, the OAuth claim is not making it through — check `wazuh_user_claim` and the IdP mapping.

See `src/wazuh_mcp/auth/session.py` and `src/wazuh_mcp/wazuh/server_api.py`.

## Understand the confirm flow

Every write tool's `Args` carries `confirm: Literal[True]`. Pydantic rejects any value that is not literally `true`; Literal typing in the tool schema tells Claude that the caller must set it explicitly. There is no "imply true" path, no default, no server-side bypass.

The intended UX, end-to-end:

1. Human asks Claude for something destructive ("isolate agent 007").
2. Claude reads its system prompt: writes require explicit human approval before `confirm:true`.
3. Claude asks the human out loud: "May I isolate agent 007? This will cut the agent off the network until reversed."
4. Human says yes.
5. Claude calls `write.isolate_agent` with `confirm:true`.
6. MCP emits `write.requested`, calls the Server API, emits the completion audit event.

If Claude sets `confirm:true` without asking, the call still goes through — there is no server-side way to prove intent. The signal operators get is indirect: the MCP system prompt attached to every write tool description makes the expectation explicit, and deviations show up in the trace of Claude's turn.

If the caller omits `confirm` or sets it to `false`, Pydantic validation fails. The decorator emits an audit event with `outcome=error`, `error_code=parse_error`; the metric `mcp_tool_calls_total{outcome="parse_error"}` increments. Alert on a rising rate of `parse_error` on `tool=~"write\..*"`:

```
sum(rate(mcp_tool_calls_total{tool=~"write\\..*", outcome="parse_error"}[5m])) by (tool) > 0
```

A non-zero rate is worth investigating — either your IdE/agent wiring is broken, or an automated caller is probing without approval.

See `src/wazuh_mcp/tools/write.py` (every `Args` class) and `src/wazuh_mcp/server.py` (the `_write_desc_prefix` attached to every write-tool registration).

## Run the rule-file lifecycle

`write.create_rule` and `write.update_rule` upload a rule XML file to the manager. They do NOT activate rules. Wazuh only loads new rule files after the manager restarts — this is a Wazuh invariant, not an MCP choice.

Filename convention: `wazuh-mcp-<rule_id>.xml`. Rule IDs must be in `[100000, 999999]` (six-digit private range to avoid collision with shipped rules). On `write.update_rule`, `rule_id` and the nested `rule.id` must match — a mismatch fails validation.

### Upload, verify, restart, confirm

1. **Upload.** Call `write.create_rule` (or `update_rule`) with the rule. The tool POSTs the XML as `wazuh-mcp-<id>.xml` via the Server API's rule-file upload endpoint. On success, the response's `affected_files` lists the filename.
2. **Verify file exists.** In the Wazuh UI, go to **Management → Rules → Custom rules** and confirm `wazuh-mcp-<id>.xml` is in the list. Alternatively, SSH to the manager: `ls /var/ossec/etc/rules/wazuh-mcp-<id>.xml`.
3. **Restart the manager.** Out of band — by operator choice, not by MCP. Either `systemctl restart wazuh-manager` or click **Management → Restart manager** in the UI. MCP deliberately does not restart the manager from a tool call; that is a production-impacting action with its own change-control cadence.
4. **Confirm rule loads.** After restart, check **Management → Rules** and filter by rule id. If the rule is parseable and the restart succeeded, it appears there with the groups and description you set. If the restart fails, Wazuh logs the parse error under `/var/ossec/logs/ossec.log`; remove the offending file and restart.

See `src/wazuh_mcp/tools/write.py` (`create_rule`, `update_rule`) and `src/wazuh_mcp/wazuh/rule_render.py`.

## Read the audit-event shape for writes

Every write emits TWO audit events. The pre-call event is keyed to intent and runs before the handler body; the post-call event is the same per-exit-path event every read tool emits.

### Pre-call event

- `outcome: "write.requested"`
- `result_count: 0`
- `duration_ms: 0`
- `error_code` absent

Emitted unconditionally at the start of every `write.*` tool call, before Pydantic validation, handler execution, or any upstream call. The point is to record that somebody asked, even if everything downstream fails.

### Completion event

Exactly one of:

- `outcome: "ok"`, `duration_ms: <measured>`, `result_count: <len(affected_agents or affected_files)>`, `error_code` absent.
- `outcome: "error"`, `error_code: <code>` — `forbidden` (AR command not allowlisted, RBAC deny), `parse_error` (missing or false `confirm`, schema mismatch), `rate_limited`, `auth_expired`, `upstream_error`, `upstream_timeout`, `not_found`, `invalid_query`, `cancelled`, `internal`.

### Wazuh Dashboards saved searches

Assuming the tenant's `wazuh_indexer` audit sink is configured per `m4a-audit.md` with the default `index_prefix: wazuh-mcp-audit`:

- **Attempted writes** — `tool:write.* AND outcome:"write.requested"` — intent to write, regardless of outcome.
- **Completed writes** — `tool:write.* AND outcome:ok` — writes that actually landed.
- **Failed writes** — `tool:write.* AND outcome:error` — group by `error_code` to separate allowlist denials (`forbidden`), missing confirm (`parse_error`), and upstream failures (`upstream_error`, `upstream_timeout`).
- **Confirm-missing rate** — `tool:write.* AND outcome:error AND error_code:parse_error` — anomalous if non-zero; see the confirm-flow section above for the alert rule.
- **Per-operator writes** — `tool:write.* AND user:"alice"` sorted by `timestamp` descending — per-operator activity.

Diffing `attempted - completed - failed` at rate level should be near zero; a sustained gap means the handler is being cancelled mid-call (long upstream timeouts, client disconnects).

See `src/wazuh_mcp/observability/decorators.py` and `src/wazuh_mcp/observability/audit.py`.

## Related docs

- `m4a-secrets.md` — how the tenant's Server API service-account credentials are stored and rotated. Writes inherit the same credential path reads use.
- `m4a-observability.md` — OTel traces and Prometheus metrics. Every write tool shows up under `mcp_tool_calls_total{tool=~"write\\..*"}` and opens a `mcp.tool.call` span identical in shape to reads.
- `m4a-audit.md` — audit sink configuration, queue sizing, drop detection. Write events are emitted through the same `AuditEmitter` as reads and land on the same sinks.
