# M3 — Full Tool Surface (Design)

**Status:** Approved for planning (2026-04-22)
**Predecessors:** `2026-04-20-wazuh-mcp-design.md` (v1 spec), `2026-04-21-wazuh-mcp-m2-design.md` (M2)
**Planned tag:** `v0.3.0-m3`

## 1. Purpose & Scope

M3 delivers the full v1 read-path tool surface and a Wazuh Server API client, closing the gap between the M2 auth-and-transport foundation and the MCP-visible capability promised in the v1 spec. No write-tools; no metrics/rate-limits (M4); no evals (M5).

**In scope:**
- Wazuh Server API client on port 55000 with JWT lifecycle and `run_as` support, plus a per-tenant pool mirroring `IndexerClientPool`.
- 13 new read-only tools across six domains (`alerts.*`, `agents.*`, `vulnerabilities.*`, `mitre.*`, `hunt.*`, `fim.*`). The existing `search_alerts` is renamed and folded into the dotted scheme.
- 3 resources (`wazuh://rules/{id}`, `wazuh://mitre/technique/{id}`, `wazuh://agents/{id}/config`) — templates-only; no enumeration.
- 3 prompts (`/wazuh:investigate-alert`, `/wazuh:triage-last-hour`, `/wazuh:agent-posture`) — context-loaded.
- Tool-result shape flattened (breaking change for the one existing tool `search_alerts`).
- All Task-20 carryover cleanups.
- Integration fixture extended with a real Wazuh manager container.

**Explicitly out of scope** (M4 or later):
- Write tools, RBAC-aware `list_tools`, per-tenant rate limits, OpenTelemetry / Prometheus / audit-sink plumbing.
- Real `SecretStore` drivers (AWS SM, Vault, sqlite_age).
- Evaluation harness.
- Wazuh < 4.8 support.
- Formal MCP toolset SDK support (deferred pending Python SDK catching up to the 2025-06-18 spec).

## 2. Product Decisions (from brainstorming)

Thirteen decisions locked before planning. All inform downstream design.

1. **One tag.** M3 ships as a single tag; no sub-milestone decomposition despite its size being roughly 2× M2.
2. **`run_as` via explicit claim.** The OAuth token must carry a dedicated `wazuh_user` claim (claim name configurable per-tenant, defaulting to `wazuh_user`) for Wazuh-audit attribution. Absent claim → request runs as the tenant's service account. No guessing from `preferred_username`.
3. **Flat tool returns, no authored summary.** Tools return a Pydantic model (or TypedDict) directly; FastMCP auto-promotes to `CallToolResult.structuredContent`. Authored `text` summaries (the M1 `_summarise` helper) are dropped — Claude generates better summaries from structured data than we do, and the double-wrap goes away.
4. **Wazuh 4.8+ only.** Documented floor; vulnerability state always read from the indexer; no runtime version probe, no dispatch branch.
5. **Dotted tool names.** `alerts.search_alerts`, `agents.list_agents`, etc. Rename the existing `search_alerts` in M3's first commit.
6. **`hunt_query` grammar** — constrained `{field, op, value}` clauses with a strict field + op allowlist; flat `must` + `must_not`, no nested bool, no `should`. Details in §4.
7. **Resources = templates-only.** `resources/list` returns empty; `resources/templates/list` publishes three URI templates. Per-resource TTL via `_meta.ttl_seconds` hints; no server-side cache.
8. **All three prompts in M3.**
9. **Context-loaded prompts.** Each prompt handler pre-fetches the obvious Wazuh queries server-side at invocation time and returns a user message with context already populated.
10. **Meta-annotated toolsets.** Each tool registration carries `meta={"toolset": "<domain>"}`; audit logs and `list_tools` responses key on it. Formal MCP toolsets (client-enabled subsets) deferred.
11. **Server API client shape** — mint via basic auth, decode `exp`, refresh at 80% lifetime, retry-once on 401 then fail with `auth_expired`. `run_as` passed per-request as a URL query parameter. No retry-with-backoff, no 429 auto-sleep, no client-side JWT signature verification.
12. **Integration fixture gains a real Wazuh manager container.** `wazuh/wazuh-manager:4.9.0`. Bootstrap time rises to ~3-4 min.
13. **All 8 carryover + testing additions in M3.** Includes the 5 Task-20 follow-ups plus hunt-query hypothesis fuzz, per-tool integration tests, and Server API security-negatives.

## 3. Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│ Starlette ASGI (transport/http.py — M2, minor patches in M3)    │
│  • WWW-Authenticate now emits resource_metadata=<url>           │
│  • SessionMiddleware unchanged                                  │
└──────────────────────┬──────────────────────────────────────────┘
                       │
       ┌───────────────┴───────────────┐
       │ SessionFactory (M2, unchanged)│
       │   resolves bearer → Session    │
       │   Session now carries          │
       │   .wazuh_user: str | None      │ ← NEW in M3
       └───────────────┬───────────────┘
                       │
             ┌─────────┴─────────────┐
             │  Tool / Resource /    │
             │  Prompt handlers      │
             └──┬──────────┬─────────┘
                │          │
   ┌────────────┴──┐   ┌───┴──────────────┐
   │ IndexerClient │   │ ServerApiClient  │ ← NEW in M3
   │  (M1 + M2)    │   │  JWT lifecycle   │
   │  port 9200    │   │  run_as per-call │
   └───────────────┘   │  port 55000      │
          ▲            └──────────────────┘
          │                     ▲
   ┌──────┴────────────┐   ┌────┴─────────────┐
   │ IndexerClientPool │   │ ServerApiClient  │ ← NEW in M3
   │  per-tenant lazy  │   │ Pool             │
   │  (M2)             │   │  per-tenant lazy │
   └───────────────────┘   │  mirrors indexer │
                           │  pool            │
                           └──────────────────┘
```

**Key invariant preserved from M2:** tenant is resolved from the `Session` at bearer-validation time. No tool takes a tenant argument. `run_as` is per-request and does NOT participate in client caching.

## 4. Components

### 4.1 `wazuh/server_api.py` (NEW)

Async `httpx` client for port 55000.

```python
class ServerApiClient:
    """Wazuh Server API client with JWT lifecycle and per-request run_as.

    Concurrency: the class is safe for concurrent use across a single tenant's
    request pipeline. JWT mint/refresh is serialized via an asyncio.Lock to
    prevent mint stampedes.
    """

    async def get(self, path: str, *, params: dict | None = None,
                  run_as: str | None = None) -> dict[str, Any]: ...
    async def post(self, path: str, *, json: dict, params: dict | None = None,
                   run_as: str | None = None) -> dict[str, Any]: ...
    async def aclose(self) -> None: ...

    # Internal
    async def _ensure_jwt(self) -> str: ...   # mint or refresh
    async def _mint_jwt(self) -> str: ...     # POST /security/user/authenticate
```

**JWT lifecycle details:**
- Mint: `POST /security/user/authenticate` with HTTP basic auth using `(server_api_user, server_api_password)` secrets.
- Decode `exp` client-side (base64url, no signature check) to compute refresh deadline.
- Refresh trigger: either elapsed ≥ 80% of lifetime, OR a 401 response from the Server API.
- Retry-once on 401: mint → replay the request. A second 401 raises `auth_expired` — no further retries.
- Mint itself 401 (bad secrets) or non-200: raises `upstream_error`, never leaks the basic-auth credentials.

**`run_as` handling:**
- Per-request argument; when present, appended as a URL query parameter (e.g. `?run_as=alice`) per Wazuh's documented contract.
- URL-encoded. Callers pass the value verbatim from the session's `wazuh_user` field (see §4.6).

**Timeouts:** `connect=5s, read=30s, write=10s, pool=5s` (identical to `IndexerClient`).

### 4.2 `wazuh/server_api_pool.py` (NEW)

```python
class ServerApiClientPool:
    """Per-tenant lazy pool. Mirrors IndexerClientPool.

    Pool entries are keyed by tenant_id and created on first .acquire().
    server-lifetime; closed en-masse via aclose().
    """
    def __init__(self, *, registry: TenantRegistry, secrets: SecretStore) -> None: ...
    async def acquire(self, tenant_id: str) -> ServerApiClient: ...
    async def aclose(self) -> None: ...
```

Same structural invariants as `IndexerClientPool` — idempotent close, asyncio.Lock-guarded lazy init, returns the shared client (not a new one).

### 4.3 `wazuh/models.py` (extended)

Current shape: `Alert`, `Agent` (new), `Vulnerability` (new), `FimEvent` (new), `MitreTechnique` (new). All Pydantic v2, `extra="forbid"`, `frozen=True`.

No runtime version dispatch. Models are shaped for Wazuh 4.8+ only. Field names:
- Vulnerability uses `vulnerability.id` (the 4.8+ name), never `vulnerability.cve`.
- All timestamps strict ISO-8601 with UTC.

### 4.4 `tools/` (domain-grouped)

Six files; 13 new tools + 1 existing rename:

```
tools/
  alerts.py      alerts.search_alerts (rename from search_alerts)
                 alerts.get_alert
                 alerts.alerts_by_agent
                 alerts.alerts_by_mitre
  agents.py      agents.list_agents
                 agents.get_agent
                 agents.agent_processes
                 agents.agent_packages
                 agents.agent_ports
  vulns.py       vulnerabilities.list_vulnerabilities_by_agent
                 vulnerabilities.search_vulnerabilities
  mitre.py       mitre.get_mitre_technique
                 mitre.search_mitre
  hunt.py        hunt.hunt_query
                 hunt.pivot_by_ioc
  fim.py         fim.fim_history_for_path
                 fim.fim_changes_by_agent
```

**Uniform contract:**
- Input: strict Pydantic model (`extra="forbid"`).
- Output: Pydantic model returned directly (FastMCP promotes to `structuredContent`). No authored `text` field.
- Every handler takes `(args, session, indexer | server_api, audit)` and emits one audit event per call.
- `meta={"toolset": "<domain>"}` on registration — `alerts`, `agents`, `vulns`, `mitre`, `hunt`, `fim`.

**`hunt.hunt_query` specifics:**

```python
FIELD_ALLOWLIST = frozenset([
    # agent identity
    "agent.id", "agent.name", "agent.ip",
    # rule
    "rule.id", "rule.level", "rule.groups",
    "rule.mitre.id", "rule.mitre.tactic",
    # common fields hunters actually use
    "location", "decoder.name", "full_log",
    "data.srcip", "data.dstip", "data.srcuser", "data.dstuser",
    "data.srcport", "data.dstport", "data.url", "data.hostname",
    # syscheck
    "syscheck.path", "syscheck.sha256_after", "syscheck.md5_after",
    # timestamps
    "timestamp", "@timestamp",
])

OP_ALLOWLIST = {"eq", "ne", "gt", "gte", "lt", "lte", "in", "exists", "prefix"}

class HuntClause(BaseModel, extra="forbid"):
    field: str                       # ∈ FIELD_ALLOWLIST
    op: Literal[*OP_ALLOWLIST]
    value: str | int | float | bool | list[str | int | float]

class HuntQueryArgs(BaseModel, extra="forbid"):
    time_range: str                  # same regex + 30d cap as search_alerts
    must: list[HuntClause]           # implicit AND
    must_not: list[HuntClause] = []  # NOT
    size: int = 25                   # clamped [1, 100]
    cursor: list[Any] | None = None
```

**Enforcement constraints:**
- Total clause count (`must + must_not`) ≤ 20.
- `in` op value-list length ≤ 100. DSL rendering: `in` → `terms` (`{"terms": {field: [values…]}}`); all other ops → `term` / `range` / `exists` / `prefix` as appropriate.
- `prefix` op value ≥ 3 chars.
- No nested `bool`, no `should`, no script/runtime_mappings reachable by construction.
- Same 30-day lookback cap and `size ≤ 100 / terminate_after: 10_000` as `search_alerts`.

**`hunt.pivot_by_ioc`** is a thin preset: `(kind: "hash"|"ip"|"user"|"domain", value)` → constructs the appropriate `must` clauses internally and delegates to `hunt_query`'s query builder. Not a second code path.

### 4.5 `resources/` (NEW)

```
resources/
  rules.py            wazuh://rules/{id}              ttl=300  (5 min)
  mitre.py            wazuh://mitre/technique/{id}    ttl=86400 (24h)
  agent_config.py     wazuh://agents/{id}/config      ttl=300  (5 min)
```

- `resources/list` returns `[]` — nothing to enumerate.
- `resources/templates/list` publishes the three URI templates above.
- Each `resources/read` response carries `_meta: {"ttl_seconds": N}` so compliant clients cache appropriately. Server does not cache.
- Tenant scoping: the URI has no tenant segment; the session-bound tenant is the sole source of truth. Resource handlers pass `session.tenant_id` to the client pool — same pattern as tools.

### 4.6 `prompts/` (NEW)

```
prompts/
  investigate_alert.py    /wazuh:investigate-alert {alert_id}
  triage_last_hour.py     /wazuh:triage-last-hour
  agent_posture.py        /wazuh:agent-posture {agent_id}
```

**Context-loaded shape.** Each handler pre-fetches on invocation and returns a single user message whose text embeds the pre-loaded context. Example for `investigate-alert`:

1. Validate `alert_id` (regex, not found → error message as the returned content).
2. Fetch the alert (`indexer.get`), the agent (`server_api` if needed), and the last-hour neighbors on the same agent.
3. Compose user content: "Investigating alert {id}. Alert: <data>. Agent: <data>. Nearby events: <summary>. Recommend next steps."
4. Audit: one event per prompt invocation (`tool=prompt.investigate_alert`) PLUS the usual per-tool events for each nested fetch.

Prompts execute under the session's identity (including `run_as`) exactly as if the user invoked the tools directly — no identity inversion.

### 4.7 `auth/session.py` (extended)

`Session` gains a new field:

```python
@dataclass(frozen=True, slots=True)
class Session:
    user_id: str
    tenant_id: str
    rbac_role: str
    auth_method: Literal["config", "oauth", "api_key"]
    wazuh_user: str | None = None   # ← NEW in M3
```

- `OAuthSessionFactory` reads `claims[tenant.wazuh_user_claim or "wazuh_user"]` and assigns `Session.wazuh_user` accordingly. Absent claim → `None`.
- `ApiKeySessionFactory` and `ConfigSessionFactory` always set `wazuh_user=None`. API-key sessions can't carry per-user identity by construction; config-driven sessions are admin/local anyway.
- All Wazuh Server API calls pass `run_as=session.wazuh_user` (which may be `None`).

### 4.8 `tenancy/config.py` (extended)

`TenantConfig` gains `wazuh_user_claim: str = "wazuh_user"`. Lets operators point at a differently-named claim emitted by their IdP without code changes.

### 4.9 `wazuh/errors.py` (extended)

Additions to `SAFE_CODES`:
- `not_found` — explicit 404 from either indexer (agent-doc) or Server API (agent/rule/technique missing).
- `upstream_timeout` — connect or read timeout bubbling from `httpx`.

`map_http_error()` gains branches for 404 (→ `not_found`) and `httpx.TimeoutException` (→ `upstream_timeout`).

### 4.10 Carryover patches (all small)

| Area | Change |
|---|---|
| `transport/http.py` `SessionMiddleware` | `WWW-Authenticate` gets `resource_metadata="<public_url>/.well-known/oauth-protected-resource"` appended to the Bearer challenge per MCP 2025-06-18. |
| `docker/seed_alerts.py` | Emit alerts at fixed offsets (`0, -1h, -2h, …, -23h`) rather than `datetime.now()`-relative. Integration tests query `time_range="24h"` so they survive clock drift. |
| `tests/unit/test_asgi_composition.py` | Rewrite the dummy MCP sub-app to mirror real FastMCP's shape: expose `/mcp` internally, provide a working `router.lifespan_context`. Add a regression test that `build_asgi_app`'s outer lifespan-forwarding actually runs. |
| `tests/integration/test_oauth_e2e.py` | Migrate to `streamable_http_client` — caller-supplied `httpx.AsyncClient` with `Authorization` header set. |
| `tools/alerts.py` | Drop `_summarise` and the `text` field from the return. Update fixtures accordingly. |

## 5. Data Flow: `hunt.hunt_query`

Worked example — Claude asks for a hunt.

```
1. Tool call arrives
   hunt.hunt_query(time_range="24h",
                   must=[{field:"data.srcip", op:"eq", value:"10.0.0.5"},
                         {field:"rule.level", op:"gte", value:10}],
                   must_not=[{field:"agent.id", op:"eq", value:"000"}])
2. SessionMiddleware already set CURRENT_SESSION from the bearer.
3. Pydantic strict-validates HuntQueryArgs.
   - field allowlist enforced
   - op allowlist enforced
   - clause count ≤ 20
   - in/prefix constraints checked
4. Audit event opens: arg_hash=sha256(canonicalised-args).
5. Query built server-side:
   bool{must: [{range:{"@timestamp":"gte":"now-24h"}},
               {term:{"data.srcip":"10.0.0.5"}},
               {range:{"rule.level":{"gte":10}}}],
        must_not:[{term:{"agent.id":"000"}}]}
6. IndexerClient.search(index="wazuh-alerts-*", query=<above>)
7. Pydantic-shape the hits into HuntQueryResult.
8. Audit event closes: outcome=ok, result_count=N, duration_ms=...
9. Return HuntQueryResult → FastMCP → structuredContent.
```

**Invariants reinforced:**
- Field names never flow through from caller to DSL untransformed. Every field name is checked against the allowlist, then rendered into the DSL by the server.
- No path to `script`, `runtime_mappings`, or `painless` — those aren't ops.
- No nested `bool`; flattening enforced at the type level.

## 6. Security Model — additions

### 6.1 Server API JWT hygiene

- `server_api_user` and `server_api_password` are pulled from `SecretStore` at mint time; never logged, never in error paths. `SecretValue` hardening from M1 carries through.
- Token itself is held in-memory on the `ServerApiClient` instance. Pool close zeroes references.
- `exp` is decoded but not signature-validated; we don't care whether our own token is valid, only when it expires. Wazuh validates on use.
- Mint stampedes prevented via per-client `asyncio.Lock`.

### 6.2 `run_as` policy

- `run_as` is ONLY set from `Session.wazuh_user`, which is ONLY populated from the OAuth bearer's claim. No tool argument, no config path, no derivation from `preferred_username`. A compromised tool could not cause a Wazuh call to run as a different user than the session's bearer attested.
- Absent claim → `run_as=None` → service account. Fail-closed.

### 6.3 `hunt.hunt_query` grammar

Addressed in §4.4. Key properties:
- Every dangerous OpenSearch feature (`script`, `runtime_mappings`, nested `bool`, `should`) is unreachable by construction, not by validation.
- Field allowlist is enforced at the Pydantic level; the DSL builder only renders what passed.
- Hypothesis property tests (§7) assert "no allowlist bypass" against arbitrary inputs.

### 6.4 Resources and prompts

- Resources run under the session's tenant scope; URI has no tenant segment so there's no cross-tenant URI confusion.
- Prompt handlers execute nested tool calls under the same session — identity, tenant, `run_as` all inherited. No elevation path.

## 7. Testing Strategy

Preserves M1/M2 pattern (unit + integration + security-negatives). M3 adds:

### 7.1 Per-tool integration tests

Every new tool gets at least one integration test hitting the real upstream. Docker-compose stack grows from `indexer + keycloak` to `indexer + keycloak + manager + agent-seed`. Expected bootstrap time rises to ~3-4 min.

### 7.2 `hunt_query` hypothesis fuzz

Property tests using `hypothesis` asserting:
- Random field names outside the allowlist always raise `ValidationError`.
- Random op names outside the allowlist always raise `ValidationError`.
- Arbitrary combinations of valid clauses produce a DSL dict containing only `term`, `range`, `exists`, `prefix`, `terms`, `bool.must`, `bool.must_not` keys — never `script`, `runtime_mappings`, `script_score`, or unbounded `wildcard`.
- Size clamping: any `size ∈ int` is clamped to `[1, 100]`.
- Clause-count cap: any input with >20 clauses rejected before reaching the builder.

### 7.3 Server API security-negatives

Dedicated test file:
- 401-twice (both the real request and the retry fail): surfaces `auth_expired`, not a credential leak.
- 429 (rate-limited): surfaces `rate_limited` with `Retry-After` passed through.
- Expired-JWT race: two concurrent requests, both see the token expired; mint is serialized (one lock-holder refreshes, other waits).
- Basic-auth creds never appear in any raised exception's `str()` or `__repr__()`.

### 7.4 Integration fixture

`docker/integration-compose.yml` grows to include `wazuh/wazuh-manager:4.9.0`. `bootstrap.sh` learns to:
- Wait for the manager's `/security/user/authenticate` to respond.
- Seed 1-2 agents via `wazuh-agent` containers OR via the manager's registration endpoint.
- Optional: seed a custom test rule so `mitre.search_mitre` has non-trivial data.

## 8. Breaking Changes

### 8.1 Tool name rename

`search_alerts` → `alerts.search_alerts`. No external consumers yet (we have no public customers on M1/M2), so the blast radius is internal tests + docs.

### 8.2 Tool-result shape flatten

`search_alerts` previously returned `{"structuredContent": {...}, "text": "..."}`. In M3 it returns a Pydantic model whose fields ARE the structured content. Effect on clients: flatter navigation. Effect on tests: ~5 assertion updates in existing integration tests.

### 8.3 Wazuh 4.8+ floor

Documented in deploy docs. Operators on 4.7 cannot upgrade to M3.

## 9. Deferred to M4+ (explicit)

- Write tools (`isolate_agent`, `add_agent_to_group`, `restart_agent`, `create_rule`, `run_active_response`, etc.) — scaffolding unchanged from v1 plan; per-tenant `write_allowlist` gates them, empty in M3.
- RBAC-aware `list_tools` filtering by `Session.rbac_role`.
- Per-tenant + per-session rate limits.
- OpenTelemetry spans, Prometheus metrics, audit-sink plumbing.
- Real `SecretStore` drivers (AWS SM, Vault, sqlite_age).
- Formal MCP toolset support (pending SDK).
- Wazuh < 4.8 support.
- Evaluation harness (M5).

## 10. Non-goals (M3 won't touch)

- `Session`, `SecretValue`, `SessionFactory` protocol — architecture survivors from M2.
- `IndexerClient` / `IndexerClientPool` internals — add-only (new index queries, no new client features).
- `AuditEmitter` sinks — stays stderr-default until M4.
- Transport layer structure — only the tiny `resource_metadata=<url>` patch lands.

## 11. References

- `2026-04-20-wazuh-mcp-design.md` — v1 full design.
- `2026-04-21-wazuh-mcp-m2-design.md` — M2 decisions that M3 builds on.
- `2026-04-21-m2-retro.md` — includes the Task 20 closure note and the transport bugs M3 preserves fixes for.
- [Wazuh Server API reference (v4.9)](https://documentation.wazuh.com/current/user-manual/api/reference.html) — `/security/user/authenticate`, `run_as`, rate limits.
- [MCP 2025-06-18 spec](https://modelcontextprotocol.io/specification/2025-06-18) — resources, prompts, toolsets, `WWW-Authenticate resource_metadata`.
