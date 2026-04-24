# wazuh-mcp M4b — Write-tool surface + toolset SDK

Status: Design approved 2026-04-24. Successor to `2026-04-23-wazuh-mcp-m4a-hardening-design.md`. Ship target `v0.5.0-m4b`.

## 0. Scope

M4b is the second half of the original M4 punch list — the write-tool surface deferred by the M4a split. It adds seven `write.*` tools plus formal MCP toolset SDK support (contingent on SDK availability). The hardening M4b rides on (RBAC, rate limits, audit fan-out, OTel, `@instrumented_tool`) was all delivered in M4a (`v0.4.0-m4a`).

### 0.1 Write-tool surface

Seven tools across four operational domains:

- Agent lifecycle (reversible within seconds): `write.isolate_agent`, `write.restart_agent`.
- Agent grouping (reversible, metadata-only): `write.add_agent_to_group`, `write.remove_agent_from_group`.
- Ruleset mutation (permanent until edited; activation requires manager restart): `write.create_rule`, `write.update_rule`.
- Remediation execution (arbitrary command surface, scoped to operator-configured AR commands): `write.run_active_response`.

### 0.2 Non-goals

- **No `write.restart_manager` tool.** Rule activation requires a manager restart; the operator runs it out-of-band (systemctl or Wazuh's own restart endpoint). An auto-restart tool is considered but deferred to M4c at earliest.
- **No multi-agent scope for `run_active_response`.** Single-agent per call. Batched remediation is a future milestone.
- **No rollback semantics beyond Wazuh's own behaviour.** If `create_rule` uploads a malformed file, Wazuh's ruleset loader rejects on restart; MCP surfaces the upstream error but does not attempt file-level recovery.
- **No structured preview/two-phase confirmation.** Confirmation flow is description-level guidance + `confirm: Literal[True]` arg + audit-grade enforcement of `confirm_required` (see §2.1).
- **No Helm chart, eval harness, or cross-tenant leak tests.** Those remain M5 scope.

## 1. Goals and non-goals

### Goals

1. Introduce seven `write.*` tools with a uniform safety flow: `confirm: Literal[True]` arg, pre+post audit, RBAC at list-time and call-time, rate-limit at call-time, `run_as=session.wazuh_user` attribution to Wazuh's own audit log.
2. Activate `TenantConfig.write_allowlist` (introduced in M4a as an unused placeholder) as a registration-time filter — a tenant can opt out of specific write tools entirely. Layered with the call-time RBAC check, this gives two independent gates per write.
3. Introduce `TenantConfig.active_response_allowlist: list[str]` (deny-all-by-default). Only allowlisted AR command names are invokable via `write.run_active_response`. Empty or missing → every call rejected.
4. Surface a new client-visible error code `confirm_required` in `SAFE_CODES` so Claude's error-handling can pattern-match on it and prompt the human user.
5. Probe MCP 1.28+ (or whichever release ships toolset client-enablement) for formal `meta={"toolset": ...}` support. If available, wire it; if not, document the gap and leave `meta` as the M3 placeholder.
6. Keep the M4a `@instrumented_tool` chokepoint as the sole audit/metric emit point for every tool — including writes. The write-specific double-audit fires from the handler body (pre) and the decorator (post).

### Non-goals

- Changing the M4a RBAC default roles (admin/analyst/readonly) or adding new default roles. Operators create a `responder` or similar role per-tenant via `role_tool_allowlist` overrides.
- Changing the audit-emit contract. Writes emit one `write.requested` event and one regular completion event — shape otherwise unchanged.
- Claude Desktop tool-selection ergonomics. Still M5 eval scope.
- Dockerised Vault integration (M4a non-goal, still out of scope).

## 2. Locked design decisions

### 2.1 Confirmation flow — description-level + audit-grade enforcement

Every write tool's Args includes:

```python
confirm: Annotated[
    Literal[True],
    Field(description=(
        "Must be set to true by a human user. Setting this from an automated "
        "agent without explicit human instruction violates the tool's safety "
        "contract and is recorded in the audit log."
    )),
]
```

Pydantic rejects every call where `confirm` is missing OR set to anything other than the Python literal `True` (`False`, `"true"`, `1` all fail). The resulting `ValidationError` surfaces as `parse_error` per the M4a decorator's existing branch.

Each write tool's `description=` string leads with:

> WRITE tool. Destructive side effects. Before calling, explicitly confirm with the human user what action they want taken and that they approve. Only set confirm:true after the human has explicitly approved the specific call.

**`confirm_required` is NOT primarily a Pydantic-level rejection** (that's `parse_error`). It is a handler-level check that short-circuits BEFORE the Server API call if, somehow, an older client bypasses Pydantic and hits the handler with a falsy `confirm`. This covers:

- The defensive case where a future tool surface (MCP elicitation, streaming) bypasses the standard Args parse.
- Explicit audit-log signaling that `confirm_required` is a distinct outcome from `parse_error`.

Practically, the decorator's per-call contract becomes:

```
handler runs →
  if not hasattr(args, "confirm") or args.confirm is not True:
      raise WazuhError("confirm_required", "human confirmation required", 403)
  audit.emit(outcome="write.requested", ...)
  <Server API call>
  # @instrumented_tool's per-call completion audit is the "completed" event
```

`confirm_required` joins `SAFE_CODES`. Client implementations (Claude, others) pattern-match on it to re-prompt the human.

### 2.2 Namespace and RBAC defaults — `write.*` + admin-only

All write tools live under `write.*`:

- `write.isolate_agent`
- `write.restart_agent`
- `write.add_agent_to_group`
- `write.remove_agent_from_group`
- `write.create_rule`
- `write.update_rule`
- `write.run_active_response`

**Default roles (unchanged from M4a):**

- `admin` → `"*"` — includes every `write.*` tool.
- `analyst` → `alerts.*`, `agents.*`, `vulnerabilities.*`, `mitre.*`, `hunt.*`, `fim.*`. No write access.
- `readonly` → subset of analyst, no hunt. No write access.

Operators who want a "responder" role (analyst + low-risk writes) configure it per-tenant:

```yaml
tenants:
  acme:
    role_tool_allowlist:
      responder:
        - alerts.*
        - agents.list_agents
        - agents.get_agent
        - write.isolate_agent
        - write.restart_agent
        - write.add_agent_to_group
        - write.remove_agent_from_group
```

Rationale: adding a fourth default role in M4b expands the role vocabulary and creates migration cost for every existing operator. Keeping defaults stable and letting operators opt-in per tenant preserves a predictable "what does analyst mean?" across milestones.

### 2.3 Two-layer allowlist — `write_allowlist` at registration + RBAC at list/call

**Layer 1 — Registration-time (`TenantConfig.write_allowlist: list[str] | None`):**

- `None` (default) → every `write.*` tool is registered. Back-compat with the "admin can use everything" pattern.
- Non-empty list → only names in the list are registered. Tools not in the list are never available on that tenant's MCP app — they don't exist from the wire's perspective.
- Empty list `[]` → no write tools registered on that tenant. Stricter than `None`.

Validation at registration time is a substring check against the canonical 7-tool set; operator typos fail fast with a YAML-load error, not silently at first call.

**Layer 2 — Call-time RBAC:** the M4a mechanism. A session role that doesn't match the tool's RBAC policy gets `forbidden` at call time (with the info-hiding "Unknown tool" message) AND `list_tools` hides the tool for that session.

Example: a tenant registers all 7 writes (`write_allowlist=None`), but only grants the `admin` role calls to `write.run_active_response`. An analyst session sees 6 writes, not 7. If the analyst session somehow calls `write.run_active_response` directly, it's rejected at the call-time RBAC guard.

### 2.4 `run_active_response` — deny-all-by-default allowlist, single-agent scope, always-run_as

**`TenantConfig.active_response_allowlist: list[str] = []`** (empty default).

- Empty/missing → every call to `write.run_active_response` rejected with `forbidden, "no active-response commands allowed for this tenant"`. Operators explicitly enumerate:

```yaml
active_response_allowlist:
  - block-ip
  - disable-account
  - restart-sshd
```

- The handler validates at runtime (can't be a `Literal[...]` on Args because the allowlist is per-tenant config, not static).

**Single-agent scope.** `agent_id: str`, not `agent_ids: list[str]` or `group_id`. Ten agents affected = ten audit events. A Claude-driven response-storm runs into M4a's rate limiter (tenant 250/60s, session 60/60s) plus the audit-volume signal operators alert on.

**`run_as` attribution.** Every write-tool Server API call passes `run_as=session.wazuh_user` when present, falls back to the service account otherwise. Each write-tool audit event records the effective `run_as` so operators can correlate MCP audit with Wazuh's internal audit.

### 2.5 Rule input shape — structured Pydantic only, no raw XML

Matches M3's "NO raw DSL" query-builder pattern. `write.create_rule` / `write.update_rule` take a `RuleDefinition` Pydantic model; a pure renderer produces the minimal well-formed XML.

```python
class RuleDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: Annotated[int, Field(ge=100_000, le=999_999)]   # custom rule ID range
    level: Annotated[int, Field(ge=0, le=15)]
    description: Annotated[str, Field(min_length=1, max_length=512)]

    if_sid: list[int] | None = None               # parent rule id(s)
    if_matched_sid: int | None = None
    match: str | None = None                      # plain-text substring match
    regex: str | None = None                      # PCRE; validated via re.compile at Args parse time
    decoded_as: str | None = None                 # decoder name
    field: dict[str, str] | None = None           # {"field_name": "regex"}
    srcip: str | None = None                      # IP or CIDR
    program_name: str | None = None
    groups: list[str] | None = None               # tags like ["authentication_failed"]
    options: list[Literal["no_log", "alert_by_email"]] | None = None
```

Renderer contract:

```python
def render_rule_xml(rule: RuleDefinition) -> str:
    """Produce a minimal well-formed <rule>...</rule> XML block.

    Every user-controlled string value is XML-escaped via xml.sax.saxutils.escape
    so no tool call can inject sibling elements or disable detection via
    `<ignore>*</ignore>` tricks."""
```

Unit tests + hypothesis fuzz: no generated RuleDefinition produces XML that Wazuh's rule parser rejects as malformed, and no generated RuleDefinition produces XML containing sibling elements outside the `<rule>` block.

**Field set is provisional.** Plan-time research against the installed Wazuh 4.9 rule grammar may add fields (or mark some as Wazuh-version-conditional). Fields NOT in this initial set are not expressible via MCP — operators edit `ossec.conf` directly for them.

### 2.6 Rule file lifecycle — per-rule files, no auto-restart

`write.create_rule(rule: RuleDefinition)` uploads a file named `wazuh-mcp-{rule.id}.xml` containing the single rule's XML, via Wazuh's `POST /manager/files/rules/...` endpoint (exact path is a plan-time research item — Wazuh's rule-file API surface has shifted across 4.x releases).

`write.update_rule(rule_id: int, rule: RuleDefinition)` re-uploads the same file, overwriting.

**No auto-restart.** Rule activation requires a manager restart, which is a brief outage. The operator triggers it out-of-band (`systemctl restart wazuh-manager` or Wazuh's own restart endpoint). This is intentional: auto-restart on every rule upload would surprise operators who want to stage changes. A `write.restart_manager` tool is considered for M4c.

The write-tool audit event records both the upload succeeded AND that activation is pending operator restart — so operators can close the loop via their existing change-management process.

### 2.7 `ServerApiClient` additions

New methods on `src/wazuh_mcp/wazuh/server_api.py` (or a sibling module `server_api_writes.py` if file-size discipline argues for split; plan decides):

- `async isolate_agent(agent_id: str, run_as: str | None) -> dict` — internally calls `POST /active-response` with the hardcoded `isolate` command (Wazuh ships this AR command by default).
- `async restart_agent(agent_id: str, run_as: str | None) -> dict` — `PUT /agents/{id}/restart`.
- `async add_agent_to_group(agent_id: str, group_id: str, run_as: str | None) -> dict` — `PUT /agents/{id}/group/{group_id}`.
- `async remove_agent_from_group(agent_id: str, group_id: str, run_as: str | None) -> dict` — `DELETE /agents/{id}/group/{group_id}`.
- `async upload_rule_file(filename: str, xml: str, run_as: str | None) -> dict` — the rule-file upload endpoint.
- `async run_active_response(agent_id: str, command: str, custom_args: dict | None, run_as: str | None) -> dict` — `POST /active-response`.

Each method plumbs `run_as` through the existing URL-param mechanism already used by M3's read methods.

### 2.8 Double-audit — `write.requested` before call, completion event after

For every write tool, emit TWO audit events per call:

1. **`write.requested`** (emitted from handler body BEFORE the Server API call). Captures intent: tool, args (hashed), confirm value, effective run_as, requested-at timestamp. `outcome="requested"` (new outcome label value; not in SAFE_CODES — audit-only).
2. **Completion event** (emitted by `@instrumented_tool` on exit). This is the M4a standard event: `outcome="ok"` on success, or `outcome="error"` with `error_code=<code>` on any failure.

Net: **exactly two audit events per write call**, regardless of success/failure. Even a failed Server API call leaves a `requested` + `error` pair.

Rationale: "someone asked for action X" is a distinct operational signal from "action X succeeded." The pre+post pairing lets operators detect:
- High `requested` / low `completed` ratio → upstream health issues or RBAC denials.
- Any `requested` event for a sensitive action → escalation trigger regardless of outcome.
- `requested` event where Claude set `confirm:true` without matching human prompt → potential prompt-injection (correlate with human-facing logs).

Implementation option (plan picks):

- **A. Handler emits requested, decorator emits completion.** Handler body calls `audit.emit(outcome="write.requested", ...)` directly before the Server API call. Decorator continues as M4a.
- **B. Decorator emits both if tool name starts with `write.`.** Decorator special-cases write tools, emitting `write.requested` at the top of the span, completion as today. Keeps tool bodies cleaner but couples decorator to naming convention.

Tradeoff: A is more flexible (each tool can enrich the requested event with tool-specific metadata pre-call — e.g. the resolved agent's IP, the group name). B is more consistent (less chance a tool forgets to emit the request event). Plan decides; I'd lean A for flexibility.

### 2.9 Toolset SDK — probe first, wire if available

The plan's first task probes the installed `mcp` SDK for formal toolset client-enablement support:

- Version check: `mcp == 1.27.x` today. If 1.28+ lands a `tools/list` filter by toolset membership OR a `/tools/enable`-style API, wire `meta={"toolset": "<domain>"}` to drive it.
- If not available: document the gap in `docs/superpowers/notes/2026-04-XX-toolset-sdk-probe.md` (same pattern as M4a's T14 `list_tools` probe); leave `meta` as the M3 placeholder; M4b ships without toolset SDK wiring. Revisit in M4c.

Probe outcome is binary; it doesn't change M4b's write-tool scope.

### 2.10 Error mapping

| Condition | Code | In `SAFE_CODES`? |
|---|---|---|
| `confirm` arg missing or not exactly `True` | `parse_error` (Pydantic rejection) | No (handled by decorator) |
| Post-parse `confirm` check fails (defensive) | `confirm_required` | **New; add to `SAFE_CODES`** |
| RBAC deny | `forbidden` | Yes |
| `run_active_response` command not in tenant allowlist | `forbidden` | Yes |
| Write tool not in `write_allowlist` | Tool not registered — caller sees "Unknown tool" | N/A |
| Rate limit exhausted | `rate_limited` | Yes |
| Wazuh upstream down / 5xx | `upstream_error` | Yes |
| Wazuh 401 (service account expired) | `auth_expired` | Yes |
| Agent unknown | `not_found` | Yes |

Only `confirm_required` is new. All others reuse the M4a `SAFE_CODES` frozenset.

## 3. Module layout

```
src/wazuh_mcp/
  tools/
    write.py                   # NEW — all 7 write tool handlers + Args
  wazuh/
    rule_render.py             # NEW — RuleDefinition → XML (pure, fuzz-tested)
    server_api.py              # EDIT — 7 new write methods; plan decides split vs inline
    errors.py                  # EDIT — confirm_required added to SAFE_CODES
  tenancy/
    m4_config.py               # EDIT — TenantConfig.write_allowlist (activate); .active_response_allowlist (new)
  server.py                    # EDIT — _register_everything registers write.* tools per write_allowlist
  observability/
    decorators.py              # EDIT (conditional on option A/B) — double-audit mechanics
```

## 4. Request flow (write.isolate_agent, HTTP)

```
incoming MCP tools/call for write.isolate_agent with {agent_id: "003", confirm: true}
  → SessionMiddleware populates CURRENT_SESSION
  → starlette auto-instrumentation span opens
  → FastMCP dispatches to @instrumented_tool-wrapped handler
      1. RBAC guard (@instrumented_tool) — is_allowed(session, "write.isolate_agent", policy).
         If deny → WazuhError(forbidden) + audit + metric (as M4a).
      2. RateLimiter.acquire(tenant, session) — as M4a.
      3. tracer.start_span("mcp.tool.call") with attrs.
      4. Handler body:
         a. Pydantic Args parse (IsolateAgentArgs). confirm: Literal[True] enforced here.
         b. (defensive) Post-parse confirm check.
         c. Emit audit: outcome="write.requested", tool="write.isolate_agent",
            args_hash=..., run_as=session.wazuh_user, agent_id="003".
         d. Call server_api.isolate_agent(agent_id="003", run_as=session.wazuh_user).
            This internally POSTs /active-response with command=isolate, agents=["003"].
         e. Return IsolateAgentResult(ok=True, timestamp=...).
      5. @instrumented_tool's completion branch:
         - span.set_attribute("mcp.outcome", "ok")
         - metric bumps
         - audit: outcome="ok", tool="write.isolate_agent", args_hash=..., duration_ms=...
  → response flows out.
```

On an `upstream_error`, the Server API call raises WazuhError — decorator's `except WazuhError` branch emits the error completion audit. Handler's pre-call `write.requested` already fired, so operators see one `requested` + one `error` event.

## 5. Config shape (TenantConfig additions)

```yaml
tenants:
  acme:
    # ... existing M4a fields (tenant_id, indexer_url, default_rbac_role, oauth_*, wazuh_user_claim,
    #      secret_prefix, role_tool_allowlist, rate_limit, audit_sinks) ...

    # Registration-time filter. None -> all writes registered. List -> only these registered.
    # Empty list -> no writes registered.
    write_allowlist:
      - write.isolate_agent
      - write.restart_agent
      - write.add_agent_to_group
      - write.remove_agent_from_group
      # Omitting write.create_rule/update_rule/run_active_response -> NOT registered for acme.

    # Deny-all-by-default. Empty/missing -> every run_active_response call rejected.
    active_response_allowlist:
      - block-ip
      - disable-account

    # Example custom role that includes writes. Per-tenant override of default roles.
    role_tool_allowlist:
      responder:
        - alerts.*
        - agents.list_agents
        - agents.get_agent
        - write.isolate_agent
        - write.restart_agent
      admin:
        - "*"
```

All M4b fields optional. Omission preserves M4a behaviour: no writes restricted at registration (but RBAC default-denies `write.*` for analyst/readonly anyway, so the effective user-visible behaviour is "admin-only writes").

## 6. Testing strategy

### 6.1 Unit tests (fast, no docker)

- **`render_rule_xml`** with hypothesis fuzz: random valid `RuleDefinition` → XML that parses via `xml.etree.ElementTree.fromstring` without errors. All user-controlled strings are escaped (assert no `<`/`>`/`&`/`"`/`'` in attribute values unless HTML-encoded).
- **Every write tool handler.** For each of the 7:
  - Missing `confirm` → `parse_error`.
  - `confirm=True`, RBAC allow, rate limit OK → Server API mock receives the expected call with correct `run_as`.
  - Post-parse defensive confirm check (inject an Args subclass that bypasses Pydantic) → `confirm_required`.
  - Double-audit: exactly one `write.requested` emitted BEFORE the mock API call; exactly one completion emitted AFTER. Use a sequential in-memory `AuditSink` subclass to assert ordering.
  - Upstream Wazuh error → `upstream_error`; decorator emits error completion.
- **`TenantConfig.write_allowlist` validation.** Typo in tool name fails at YAML load. Non-empty list → only named tools registered (assert via `mcp_app.list_tools()` after build).
- **`active_response_allowlist` enforcement.** Empty → `forbidden` on every `write.run_active_response` call. Non-empty missing command → `forbidden`. Allowlisted → handler proceeds.
- **Hypothesis fuzz on `write_allowlist`.** Random non-empty subsets of the 7-tool set → `list_tools` returns exactly that subset; every non-subset call gets "Unknown tool" (M4a info-hiding).

### 6.2 Integration tests (amd64 CI)

Dedicated `write_allowlist` tenant fixture against the real Wazuh 4.9 manager. For each of the 7 writes, exercise the happy path + one upstream-error path. Audit event roundtrip via `WazuhIndexerSink` confirms both pre+post events land in `wazuh-mcp-audit-YYYY.MM.DD`. All tests carry `@pytest.mark.requires_manager`; skip on arm64+darwin; run on amd64 CI via `.github/workflows/integration.yml`.

### 6.3 Out of scope

- Claude Desktop write-tool ergonomics (manual smoke, M5).
- Multi-tenant isolation tests for writes (M5 cross-tenant leak suite).
- Real Vault integration (M4a non-goal, still out of scope).
- Load tests against the rate limiter with write-tool workloads (M5 performance envelope).

## 7. Dependencies

No new runtime dependencies. Possible new dev-deps if the rule-XML fuzz needs a Wazuh-rule-parser harness (unlikely — `xml.etree` well-formedness check plus targeted assertions is sufficient).

## 8. Risk tiers

Per M3/M4a methodology. Tier A full dual-review; Tier B implementer-only + spot-check, batched adjacent.

**Tier A (security-critical):**

1. **Write-flow decorator mechanics.** Whichever of Option A/B for double-audit lands — the handler-body vs decorator-emit seam for `write.requested` must be consistent with M4a's `@instrumented_tool` invariants (single-chokepoint, never-blocks-hot-path, always-emits-on-error).
2. **`confirm_required` audit + RBAC integration.** The defensive post-parse check and its audit emission must not accidentally bypass the RBAC guard on error paths.
3. **`run_active_response` command allowlist enforcement.** Per-tenant allowlist; runtime check; forbidden-emit on mismatch.
4. **Rule XML renderer.** Fuzz-tested; NO raw user strings in XML; escape every attribute value.
5. **`write_allowlist` registration-time enforcement.** YAML validation; typo surfaces at load; unregistered tools truly don't exist.

**Tier B (batched):**

- 7 `ServerApiClient` method additions.
- 7 `tools/write.py` handler bodies (mostly mechanical once the first lands).
- `TenantConfig` field additions.
- Integration tests.
- Toolset SDK probe note.

## 9. Deliverables

- All unit tests green: `uv run pytest -q -m "not integration"`.
- All lint green: `uv run ruff check . && uv run ruff format --check . && uv run ty check .`.
- Integration suite green on amd64 CI on the ship commit.
- `pyproject.toml` at `0.5.0`, tagged `v0.5.0-m4b`, pushed with `--tags`.
- Retro at `docs/superpowers/retros/2026-04-XX-m4b-retro.md` before M4c / M5 scope work begins.
- Operator docs updated: new `docs/deploy/m4b-writes.md` covering write-tool setup, `write_allowlist` semantics, `active_response_allowlist`, responder-role example, confirm-flow guidance for operators-of-Claude.
- Toolset SDK probe note at `docs/superpowers/notes/2026-04-XX-toolset-sdk-probe.md`.

## 10. Deferred to M4c / M5

- `write.restart_manager` tool (ops ergonomics for rule activation).
- Multi-agent scope for `run_active_response`.
- MCP elicitation-based confirm flow (if SDK surface stabilises).
- Formal toolset SDK wiring if the probe comes back negative.
- Claude Desktop manual smoke against writes (M5).
- Cross-tenant leak tests exercising writes (M5).

M4b leaves hooks in place: every write tool audit event names the effective `run_as` and the tenant's allowlist config, so cross-tenant leak tests (M5) can correlate against those fields directly.
