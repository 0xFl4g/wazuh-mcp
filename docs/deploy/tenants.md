# `TenantConfig` reference

Authoritative per-field reference for `TenantConfig` (`src/wazuh_mcp/tenancy/config.py`). Every field, its type, default, validator, and operational semantics.

`TenantConfig` is a strict Pydantic model — `model_config = ConfigDict(extra="forbid", frozen=True)`. Unknown fields fail config validation loudly at startup; instances are immutable post-construction.

## Identity + transport

### `tenant_id` *(required)*

| | |
|---|---|
| Type | `str` |
| Pattern | `^[a-z0-9][a-z0-9_-]{0,62}$` |
| Validator | Pydantic regex (1..63 chars, lowercase + `_-`, must start alphanumeric) |

Stable identifier the operator picks per tenant. Used as the routing key everywhere — pool acquisition, RBAC resolution, rate-limit bucket key, audit-sink fan-out, secret-store path component. Renaming a tenant requires re-issuing tokens and re-keying secrets.

### `indexer_url` *(required)*

| | |
|---|---|
| Type | `HttpUrl` |
| Validator | Pydantic `HttpUrl` (must parse, scheme + host required) |

Wazuh Indexer base URL (typically `https://wazuh.<tenant>.example:9200`). The Server API URL is derived from this by substituting port 9200 → 55000, unless `server_api_url` overrides it.

### `server_api_url` *(optional, M5b T-C1)*

| | |
|---|---|
| Type | `HttpUrl \| None` |
| Default | `None` |

Explicit Wazuh Server API base URL. When unset, the pool derives it from `indexer_url` (port 9200 → 55000 substitution). M5b added this so multi-manager fixtures can point distinct tenants at distinct manager clusters without colliding on the derived URL.

Set this when the tenant's manager cluster lives on a non-default port, on a different host than its indexer, or when running federation-style deployments where multiple tenants must each target a distinct manager.

### `verify_tls`

| | |
|---|---|
| Type | `bool` |
| Default | `True` |

TLS-verify upstream Wazuh calls. Set `False` only for local dev with self-signed certs.

### `ca_bundle_path`

| | |
|---|---|
| Type | `Path \| None` |
| Default | `None` |

Path to a CA bundle the indexer + Server API pools use for TLS verification. Required when `verify_tls=True` and the upstream uses a private CA. Owned by the MCP service user, mode 0644.

## RBAC + role mapping

### `default_rbac_role` *(required)*

| | |
|---|---|
| Type | `str` |
| Validator | None — free-form string |

Role assigned when the OAuth bearer carries no claim from `oauth.rbac_claims`. Typical values: `analyst`, `responder`, `readonly`, `admin`. Must match a key in the effective `role_tool_allowlist` (or one of the shipped defaults).

### `role_tool_allowlist`

| | |
|---|---|
| Type | `dict[str, list[str]] \| None` |
| Default | `None` (use shipped defaults) |

Per-role tool pattern allowlist. Patterns use the same glob shape as the shipped defaults:

```yaml
role_tool_allowlist:
  admin: ["*"]
  responder: ["alerts.*", "agents.*", "fim.*", "write.isolate_agent"]
  analyst: ["alerts.*", "agents.*", "vulnerabilities.*", "mitre.*", "hunt.*", "fim.*", "cluster.*"]
  readonly: ["alerts.*", "agents.get_agent", "agents.list_agents", "vulnerabilities.*", "mitre.*", "fim.*", "cluster.status"]
```

Absent roles fall through to the shipped defaults. `None` means use defaults entirely.

## OAuth (per-tenant overrides)

### `oauth_issuer`

| | |
|---|---|
| Type | `HttpUrl \| None` |
| Default | `None` (inherit `server.yaml`'s `oauth.issuer`) |

OAuth issuer URL for tokens scoped to this tenant. Used by `IssuerIndex` to map verified `iss` claims back to tenants. Multiple tenants MAY share an issuer URL (multi-tenant Keycloak realms distinguished only by `tenant_id` claim) — see `oauth.md` for the IssuerIndex semantics.

### `oauth_audience`

| | |
|---|---|
| Type | `str \| None` |
| Default | `None` (inherit `server.yaml`'s `oauth.audience`) |

Expected `aud` claim on tokens for this tenant.

### `wazuh_user_claim`

| | |
|---|---|
| Type | `str` |
| Default | `"wazuh_user"` |

Name of the OAuth claim that carries the Wazuh user identity for `run_as` attribution. When the claim is present in a verified bearer, `Session.wazuh_user` is populated and Server API calls pass `?run_as=<value>`. When absent, calls run as the tenant's service account with no per-operator attribution.

## Secret prefix

### `secret_prefix`

| | |
|---|---|
| Type | `str \| None` |
| Default | `None` (use the secret driver's default `wazuh-mcp/`) |

Override the default secret-path prefix for this tenant. Resolves to `{secret_prefix}{tenant_id}/{key}` in the backing store. Use this when one tenant lives in an existing secret namespace (acquired customer, separate AWS account using a shared MCP deploy via cross-account IAM) and the rest follow the default.

See `secrets.md` for driver-specific path semantics.

## Rate limits

### `rate_limit`

| | |
|---|---|
| Type | `RateLimitConfig` |
| Default | `tenant: capacity=250, refill_per_sec=4.17 / session: capacity=60, refill_per_sec=1.0` |

Two token buckets per tenant:

```yaml
rate_limit:
  tenant:
    capacity: 100
    refill_per_sec: 10.0
  session:
    capacity: 10
    refill_per_sec: 1.0
```

`BucketConfig`:
- `capacity`: `int` in `(0, 100_000]`. Bucket size — burst budget.
- `refill_per_sec`: `float` in `(0.0, 1000.0]`. Refill rate.

The tenant bucket is shared across every session for the tenant; the session bucket is per-session. A call must successfully acquire from BOTH buckets. Denials surface as `WazuhError("rate_limited", ..., scope="rate_limit:tenant" | "rate_limit:session")` and increment `mcp_rate_limit_drops_total{tenant, scope}` (see `observability.md`).

The defaults are tuned for ~50 tenants on one MCP deploy with light query volume. Heavy-traffic tenants should override upward; locked-down tenants (e.g. `readonly` MSP customers) downward.

## Audit sinks

### `audit_sinks`

| | |
|---|---|
| Type | `list[AuditSinkConfig]` |
| Default | `[]` (the global stderr sink covers; no per-tenant sinks) |

Discriminated-union list. Each entry's `kind` field picks the variant:

- `kind: stderr` — no fields.
- `kind: stdout` — no fields. **HTTP-only**; under stdio it corrupts the JSON-RPC wire.
- `kind: file` — `path` (`Path`, required), `rotate_size_mb` (default 100, 1..10000), `keep` (default 5, 0..100).
- `kind: http` — `url` (`HttpUrl`, required), `batch` (default 50), `flush_ms` (default 500), `max_attempts` (default 5).
- `kind: wazuh_indexer` — `index_prefix` (default `wazuh-mcp-audit`), `batch` (default 100), `flush_ms` (default 1000), `max_attempts` (default 5).

See `observability.md` for sink semantics, the `MultiSinkAuditEmitter` dual-track model, and Wazuh Dashboards setup.

## Write surface

### `write_allowlist`

| | |
|---|---|
| Type | `list[str] \| None` |
| Default | `None` (no filter — all writes callable) |
| Validator | `_validate_write_allowlist_entry` — must start with `write.`, must be in the known-tool set |

Three meaningful states:

- `None` — no filter. All 9 writes callable. RBAC still applies on top.
- `[]` — empty list. All 9 writes register but every call denies with `forbidden`. M4c-shifted from "tools hidden in `list_tools`" to "tools shown but uniformly denied".
- `["write.isolate_agent", ...]` — only listed names callable. Unknown names fail config validation loudly at startup.

Valid names: `write.isolate_agent`, `write.restart_agent`, `write.add_agent_to_group`, `write.remove_agent_from_group`, `write.create_rule`, `write.update_rule`, `write.run_active_response`, `write.run_active_response_on_group`, `write.restart_manager`.

See `writes.md` for the full two-layer allowlist model.

### `active_response_allowlist`

| | |
|---|---|
| Type | `list[str]` |
| Default | `[]` (deny-all) |
| Validator | `_validate_ar_command_name` — must be non-empty after strip |

Allowed `command_name` values for `write.run_active_response` and `write.run_active_response_on_group`. Default is empty — every AR command denies until the operator lists commands explicitly.

The MCP allowlist does not teach Wazuh anything. Commands listed here MUST also be declared in the Wazuh manager's `ossec.conf` under `<command>` and bound to an `<active-response>` block. If the MCP allowlist names a command Wazuh does not know, the Server API call reaches Wazuh and Wazuh fails it upstream.

### `agent_group_allowlist` *(M5b T-A1)*

| | |
|---|---|
| Type | `list[str]` |
| Default | `[]` (deny-all) |
| Validator | `_validate_ar_group_name` — pattern `^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`, length 1..128 |
| Max length | 50 entries |

Allowed `group_name` values for `write.run_active_response_on_group`. Mirrors the `active_response_allowlist` precedent: empty by default, list explicit group names per tenant.

Both gates apply for group-target AR calls:
1. `write.run_active_response_on_group` must be in `write_allowlist` (or `write_allowlist=null`).
2. The session's role must allow `write.run_active_response_on_group` per `role_tool_allowlist`.
3. `group_name` arg must be in `agent_group_allowlist`.
4. `command_name` arg must be in `active_response_allowlist`.

See `writes.md` for the full group-target AR setup.

## Worked example

Multi-tenant config with one strict + one open tenant:

```yaml
tenants:
  - tenant_id: acme
    indexer_url: https://wazuh.acme.internal:9200
    server_api_url: https://wazuh-api.acme.internal:55000   # M5b — explicit override
    verify_tls: true
    ca_bundle_path: /etc/wazuh-mcp/ca/acme.pem
    default_rbac_role: analyst
    oauth_issuer: https://idp.example.com/realms/msp
    oauth_audience: wazuh-mcp-api
    wazuh_user_claim: wazuh_user
    secret_prefix: "prod/soc/wazuh-mcp/"
    role_tool_allowlist:
      admin: ["*"]
      responder: ["alerts.*", "agents.*", "fim.*", "write.isolate_agent", "write.run_active_response_on_group"]
      analyst: ["alerts.*", "agents.*", "vulnerabilities.*", "mitre.*", "hunt.*", "fim.*", "cluster.*"]
    rate_limit:
      tenant: { capacity: 500, refill_per_sec: 25.0 }
      session: { capacity: 50, refill_per_sec: 5.0 }
    audit_sinks:
      - kind: wazuh_indexer
        index_prefix: acme-audit
      - kind: file
        path: /var/log/wazuh-mcp/acme.jsonl
    write_allowlist:
      - write.isolate_agent
      - write.restart_agent
      - write.run_active_response
      - write.run_active_response_on_group
      - write.create_rule
      - write.update_rule
      - write.restart_manager
    active_response_allowlist:
      - isolate
      - firewall-drop
      - disable-account
    agent_group_allowlist:
      - linux-prod
      - windows-prod
      - dmz

  - tenant_id: contoso
    indexer_url: https://wazuh.contoso.example:9200
    default_rbac_role: readonly
    rate_limit:
      tenant: { capacity: 25, refill_per_sec: 1.0 }
      session: { capacity: 5, refill_per_sec: 0.2 }
    audit_sinks:
      - kind: wazuh_indexer
        index_prefix: contoso-audit
    # No write_allowlist override — defaults to None (all writes callable, but
    # readonly role's allowlist denies them all anyway).
    # No active_response_allowlist / agent_group_allowlist — empty defaults
    # mean any AR call denies even if RBAC permitted it.
```

## Related

- `install.md` — where this file lives + the surrounding `server.yaml` and `secrets.yaml`.
- `oauth.md` — `oauth_issuer` + `oauth_audience` + `wazuh_user_claim` semantics.
- `writes.md` — `write_allowlist` + `active_response_allowlist` + `agent_group_allowlist` operational model.
- `multi-tenant.md` — per-tenant resolver model + structural isolation guarantees.
- `observability.md` — `rate_limit` + `audit_sinks` runtime behavior.
- `secrets.md` — `secret_prefix` + driver-specific path resolution.
