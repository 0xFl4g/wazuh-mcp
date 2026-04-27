# wazuh-mcp M5a — Quality Gates Design

**Goal:** Ship `v0.8.0-m5a`. The four quality-gate workstreams that prove correctness before deployment readiness (M5b ships v1.0.0). Public-OSS scope: ship-gate is "would I be embarrassed if a stranger deployed this in prod?"

**Spec date:** 2026-04-27

**Predecessor:** `v0.7.5` (integration GREEN, M4d shipped + 5 patches landed). All M4c integration tests pass; the destructive `test_restart_manager_node_scope_completes` is `pytest.skip`-marked.

**Successor:** M5b (deployment readiness — Wazuh LTS matrix, Helm, multi-manager fixture, docs completion, `v1.0.0` tag).

---

## 0. Scope

**M5a delivers four workstreams:**

1. **Eval harness** — automated correctness gate proving Claude picks the right wazuh-mcp tools for representative security-ops prompts.
2. **Cross-tenant leak suite** — fills in the M4d skip-stubs and adds negative tests proving tenant isolation.
3. **Security CI** — `pip-audit` / `safety` / secret-leak scanning on every PR + nightly.
4. **Destructive-test isolation** — separate workflow for tests that mutate shared docker state, unblocking the v0.7.5 skip.

**Explicit non-goals (M5b or v1.1):**
- Wazuh LTS + latest matrix CI (M5b)
- Multi-manager integration fixture (M5b)
- Helm chart for k8s deploy (M5b)
- Docs completion (M5b)
- Vault integration tests (M5b carry-forward)
- `WazuhError.scope` field (M5b carry-forward)
- **Group-target `run_active_response`** — deferred to v1.1. Single-agent works; group is feature expansion, not a quality gate.
- MCP elicitation activation (gated on SDK)
- External (Redis) rate-limiter (gated on multi-instance deployment)

**Tag:** `v0.8.0-m5a` on ship.

**Estimated scope:** 12-15 tasks across 4 phases. 8-13 implementer dispatches expected (per M4c/M4d profile).

---

## 1. Eval harness — Claude Code slash command (no CI gate)

### 1.1 Constraint-driven design

The maintainer cannot afford an `ANTHROPIC_API_KEY` for CI. The eval harness ships as a *manually-invoked* Claude Code slash command, using the maintainer's existing Claude Code subscription. The eval is a **release-time gate**, not a regression detector. The corpus + scoring script are framework-agnostic so a v1.x community contributor with their own API key can wrap them in CI later.

### 1.2 Architecture — two-phase

**Phase 1 (LLM, in Claude Code session):** the slash command instructs Claude to read each prompt + the wazuh-mcp tool catalog, decide what tool it would call, and write the decision to a raw-results JSON file. Claude does NOT execute the tool — just records the intended call.

**Phase 2 (pure-Python scoring, no API needed):** `tools/eval/score.py` loads raw-results + corpus, asserts per-tier (selection / args / sequence), computes per-category accuracy, and writes a final `results.json` against `thresholds.yaml`. Exit code 1 if accuracy below gate.

**Cheating mitigation:** the slash command instructs Claude to read prompts WITHOUT viewing `expected_tool`. Phase 2 reads expected_tool but only after Phase 1's choices are committed to the raw file. Honor system + git-blame review.

### 1.3 Repo layout

```
.claude/commands/
└── eval-wazuh-mcp.md             # slash command markdown — drives Phase 1
docs/eval/
├── README.md                     # corpus authoring + run procedure
└── corpus/
    ├── selection_only.yaml       # 30 entries
    ├── with_args.yaml            # 10 entries
    └── multi_step.yaml           # 5 entries
tools/eval/
├── score.py                      # Phase 2: load raw results + corpus, assert
├── thresholds.yaml               # per-model accuracy gates
└── README.md                     # operator-facing run + interpretation guide
docs/eval-history/
└── YYYY-MM-DD-<model>-results.json   # committed audit trail (git history is the regression record)
```

### 1.4 Corpus shape

**Three tiers, one YAML schema per tier.**

`selection_only.yaml` (30 entries):
```yaml
- id: triage_alerts_recent_high
  prompt: "Show me the recent high-severity alerts from the last hour"
  expected_tool: alerts.search_alerts
  category: triage
- id: hunt_failed_logins_agent_001
  prompt: "Search for failed login events on agent 001"
  expected_tool: hunt.hunt_query
  category: hunt
```

`with_args.yaml` (10 entries; subset semantics — `expected_args` keys MUST match, extra args from Claude are OK):
```yaml
- id: write_isolate_with_confirm
  prompt: "Isolate agent 001 from the network. I'm sure."
  expected_tool: write.isolate_agent
  expected_args:
    agent_ids: ["001"]
    confirm: true
  category: writes
```

`multi_step.yaml` (5 entries; each step asserts tool name + optional args; the slash command instructs Claude to record the sequence as a JSON list including the stub `tool_result` it would have received between steps):
```yaml
- id: cluster_restart_flow
  prompt: "Restart the Wazuh manager cluster and tell me when it's back."
  expected_sequence:
    - tool: cluster.status
      stub_result: {"enabled": true, "running": true, "nodes": [{"name": "n1", "type": "master", "status": "running"}]}
    - tool: write.restart_manager
      args: {scope: "cluster", confirm: true}
      stub_result: {"ok": true, "scope": "cluster", "affected_nodes": ["n1"], "timestamp": "2026-04-27T00:00:00Z"}
    - tool: cluster.status
      stub_result: {"enabled": true, "running": true, "nodes": [{"name": "n1", "type": "master", "status": "running"}]}
  category: triage
```

**Categories:** `triage`, `hunt`, `writes`, `inventory`, `mitre`, `fim`, `vulns`. Authored by hand; ~6-7 prompts per category in selection_only.

### 1.5 Slash command (`.claude/commands/eval-wazuh-mcp.md`)

The command's markdown body instructs the live Claude Code session to:

1. **Pre-flight:** verify wazuh-mcp is connected as an MCP server in the current Claude Code session. If not, abort with an operator message pointing at `docs/eval/README.md`.
2. **Phase 1a — selection_only:** for each entry in `docs/eval/corpus/selection_only.yaml`:
   - Read just `id` + `prompt`. Do NOT read `expected_tool`.
   - With the wazuh-mcp tool catalog attached to the conversation, decide what tool you'd call for this prompt.
   - **Don't actually invoke it.** Write to `docs/eval-history/<today>-<model>-results-raw.json`: `{tier: "selection_only", id, picked_tool, picked_args}`.
3. **Phase 1b — with_args:** same, but also record `picked_args`.
4. **Phase 1c — multi_step:** drive a simulated multi-turn loop. For each step, decide the tool, record it, then read the corpus entry's `stub_result` for that step as if it were returned, decide the next step, and repeat. Record the full picked sequence.
5. **Phase 2:** invoke `uv run python tools/eval/score.py docs/eval-history/<today>-<model>-results-raw.json`. The script writes `<today>-<model>-results.json` and prints summary.
6. **Print final summary:** per-category accuracy + any failures + path to results.json.
7. **Operator next step:** "review `<today>-<model>-results.json`, commit it (`git add docs/eval-history/...`), and decide whether to ship."

**Filename convention:** `<today>-<model>-results-raw.json` and `<today>-<model>-results.json`. Model name is read from the slash command's instruction set ("which model are you currently running?") OR taken from a `--model` arg passed to the slash command. The slash command writes the model name into both files. This lets the maintainer run the eval against multiple models on different days and accumulate an audit trail.

### 1.6 Scoring script (`tools/eval/score.py`)

Pure-Python, no API access, ~150 LoC.

**Inputs:** raw results JSON + the three corpus files + `thresholds.yaml`.

**Per-tier scoring:**
- selection_only: `picked_tool == expected_tool`.
- with_args: `picked_tool == expected_tool` AND `all(picked_args.get(k) == v for k, v in expected_args.items())`. Subset semantics — extra picked_args keys are OK.
- multi_step: `len(picked_sequence) == len(expected_sequence)` AND each step's tool name matches AND if `args` is specified for a step, subset-match the picked args.

**Output:** `results.json` shape:
```json
{
  "model": "claude-opus-4-7",
  "run_date": "2026-04-27",
  "overall": {"accuracy": 0.91, "passed": 41, "failed": 4, "total": 45},
  "by_tier": {
    "selection_only": {"accuracy": 0.93, "passed": 28, "failed": 2, "total": 30},
    "with_args": {"accuracy": 0.90, "passed": 9, "failed": 1, "total": 10},
    "multi_step": {"accuracy": 0.80, "passed": 4, "failed": 1, "total": 5}
  },
  "by_category": {
    "triage": {"accuracy": 0.95, ...},
    ...
  },
  "failures": [
    {"id": "...", "tier": "selection_only", "expected": "alerts.search_alerts", "picked": "agents.list_agents"}
  ],
  "thresholds_met": true
}
```

**Thresholds (`tools/eval/thresholds.yaml`):**
```yaml
default:
  selection_only: 0.85
  with_args: 0.90
  multi_step: 0.80
  overall: 0.85
per_model:
  claude-opus-4-7:
    overall: 0.90   # higher bar for top-tier model
  claude-haiku-4-5:
    overall: 0.75   # lower bar for cheap-tier (if maintainer ever runs against it)
```

`thresholds_met` in results.json is `true` iff every applicable threshold is met. Script exits 0 if met, 1 if not. Maintainer uses exit code as the release-gate signal.

### 1.7 Audit trail

`docs/eval-history/` is committed to the repo. Every eval run produces a results.json (and a raw-results.json for debugging — also committed). Git history shows accuracy trends across releases. README.md in that directory explains:
- "results-raw.json is what Claude saw + decided" (Phase 1 output, debugging)
- "results.json is the scored report" (Phase 2 output, ship-gate)
- "review failures with `jq '.failures' <file>`"

### 1.8 Forward extensibility

- Adding a prompt = appending one YAML entry. No script changes.
- Adding a model to thresholds = one entry under `per_model:`. The maintainer just runs the eval in a Claude Code session of that model.
- Wrapping in CI (v1.x community contribution): `tools/eval/score.py` is framework-agnostic. A `tools/eval/run_via_api.py` wrapper would loop the corpus, call `anthropic.Anthropic` directly, write the raw-results, and invoke score.py — same interface, automated. The corpus + thresholds + scoring don't change.

---

## 2. Cross-tenant leak suite

### 2.1 Keycloak setup change

Single realm `wazuh-mcp`, two service-account clients. Bootstrap the second client in `docker/bootstrap.sh` alongside the existing `wazuh-mcp-client`:

```bash
# After existing wazuh-mcp-client creation:
./kcadm.sh create clients -r wazuh-mcp -s clientId=wazuh-mcp-client-tenant-b \
  -s serviceAccountsEnabled=true -s publicClient=false -s standardFlowEnabled=false

# Add tenant_id claim mapper for wazuh-mcp-client (existing) → "local"
# Add tenant_id claim mapper for wazuh-mcp-client-tenant-b → "tenant_b"
./kcadm.sh create clients/{client-uuid}/protocol-mappers/models -r wazuh-mcp \
  -s name=tenant_id-mapper \
  -s protocol=openid-connect \
  -s protocolMapper=oidc-hardcoded-claim-mapper \
  -s 'config."claim.name"=tenant_id' \
  -s 'config."claim.value"=local' \
  -s 'config."access.token.claim"=true'
```

**Verify against existing OAuth chain:** `OAuthSessionFactory` reads the `tenant_id` claim per `rbac_claims` in `server.yaml` if present (`auth/oauth.py`). The claim path needs verification at plan-time — grep for the actual extraction site. If the current chain only reads role claims and resolves tenant_id from the `IssuerIndex` (URL-path), we add a small claim-extraction step. Plan task explicitly verifies this and adapts.

### 2.2 Conftest changes

`tests/integration/conftest.py`:
- Add `KEYCLOAK_CLIENT_ID_TENANT_B = "wazuh-mcp-client-tenant-b"` and `KEYCLOAK_CLIENT_SECRET_TENANT_B` from env.
- Update `tenants.yaml` `tenant_b` block: `oauth_issuer: http://localhost:8080/realms/wazuh-mcp` (replacing v0.7.1 phantom URL — both tenants now share the issuer, distinguished by `tenant_id` claim).
- New fixture `keycloak_token_tenant_b()` mirroring `keycloak_token()` but using `KEYCLOAK_CLIENT_ID_TENANT_B` + `KEYCLOAK_CLIENT_SECRET_TENANT_B`.
- The `secrets.yaml` `tenant_b:` block already exists from M4d T10 — no change.

### 2.3 Test additions

`tests/integration/test_m4d_multi_tenant.py` — replace skip-stubs:

**Test 1: `test_per_tenant_rate_limit_isolation`.** Burns tenant_b's bucket (capacity=2 per conftest), asserts tenant_b is rate-limited. Then opens a `local` session (capacity=100), asserts unaffected.

**Test 2: `test_per_tenant_audit_routing`.** Per-test config-dir override that adds `audit_sinks: [{kind: wazuh_indexer, index_prefix: local-audit}]` to local AND `audit_sinks: [{kind: wazuh_indexer, index_prefix: tenant-b-audit}]` to tenant_b. Mints tenant_b token, calls `alerts.search_alerts` (a read tool, allowed for analyst). Queries the indexer directly: tenant-b-audit-* has the event; local-audit-* does not. Then mirror with local token; verify local-audit-* has the event, tenant-b-audit-* does not.

**Test 3: `test_tenant_a_session_does_not_use_tenant_b_indexer_pool`.** Hooks the `IndexerClientPool.acquire` call (via a debug counter or direct fixture) to assert that local's tool calls never trigger acquire("tenant_b"). End-to-end pinning of M4c per-tenant resolver wiring.

**Test 4: `test_tenant_a_session_does_not_use_tenant_b_server_api_pool`.** Mirror of test 3 for `ServerApiClientPool`.

**Test 5: `test_resolver_miss_audit_routes_to_globals_only`.** Synthesizes an unknown-tenant session (e.g., a token with `tenant_id: "phantom"` claim — requires a third Keycloak client OR the test mints a hand-crafted JWT). Triggers a tool call. Asserts the `<rbac.resolve>` audit event lands on global sinks only, not on either tenant's per-tenant sinks. Pins M4d's defense-in-depth path.

### 2.4 Audit-sinks restoration approach

v0.7.4 dropped `audit_sinks` from conftest tenants. Tests 2 + 5 need them back. Per-test override approach:

```python
@pytest.fixture
def audit_sinks_config_dir(tmp_path) -> Path:
    """Returns a config_dir with audit_sinks added to both tenants."""
    cfg_dir = tmp_path / "wm-audit-test"
    # render tenants.yaml + secrets.yaml + server.yaml with audit_sinks blocks
    # spawn a fresh wazuh-mcp subprocess pointing at this dir
    ...
```

Tests 2 + 5 use this fixture; tests 1, 3, 4 use the existing `mcp_http_server`. Keeps the main fixture lean.

**Alternative:** if per-test config-dir override is too heavy in practice, the simpler path is a dedicated `mcp_http_server_with_indexer_audit` fixture (port 8773) — same shape as `mcp_http_server_m4c` but with audit_sinks blocks. The plan picks one based on what comes out cleaner.

### 2.5 Total test count

5 tests in `test_m4d_multi_tenant.py`. The 2 existing skip-stubs (`test_per_tenant_rate_limit_isolation`, `test_per_tenant_audit_routing`) get filled in. 3 new tests added.

---

## 3. Security CI

### 3.1 New workflow

`.github/workflows/security.yml`:

```yaml
name: security
on:
  pull_request:
  schedule:
    - cron: "27 4 * * *"
  workflow_dispatch:

jobs:
  dependency-audit:
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/checkout@v6
      - uses: astral-sh/setup-uv@v7
      - run: uv sync --frozen
      - run: uv export --no-emit-project --frozen > requirements.txt
      - run: uv run pip-audit --strict --requirement requirements.txt
      - run: uv run safety check --full-report --file requirements.txt

  secret-leak-scan:
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/checkout@v6
        with: { fetch-depth: 0 }   # gitleaks needs history
      - uses: gitleaks/gitleaks-action@v2
        env:
          GITLEAKS_CONFIG: .gitleaks.toml
```

### 3.2 Dependency audit

- `pip-audit --strict` queries OSV/PyPA databases for CVEs in locked deps. Exit-non-zero on any vuln.
- `safety check` is redundant defense (different DB; occasionally catches what pip-audit misses).
- Both run against the `uv export`-rendered requirements file (uv.lock → pip-style).

**Suppression:** new `.github/security-ignores.yaml`:
```yaml
ignores:
  - id: GHSA-xxxx-yyyy
    reason: "False positive — vuln applies to flask handler we don't use"
    expires: 2026-10-27
    reviewer: 0xFl4g
```
Pre-commit hook validates schema. Each entry MUST have all three fields.

**Forward maintenance:** new `.github/workflows/security-ignores-expiry.yml` — separate weekly cron that opens an issue for any `expires:` past today.

### 3.3 Gitleaks config

`.gitleaks.toml` extends the default ruleset with Wazuh-specific patterns:
```toml
[[rules]]
id = "wazuh-api-token"
description = "Wazuh JWT-style API token"
regex = '''wazuh_(api_)?token\s*[:=]\s*["']?eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'''

[[rules]]
id = "keycloak-client-secret"
description = "Keycloak client_secret in URL or env"
regex = '''client_secret\s*[:=]\s*["']?[A-Za-z0-9]{32,}'''
```

`.gitleaksallow` lists known-safe test fixtures (e.g., `MCPmcp12345!`).

### 3.4 Integration log secret scan

**Deferred to v0.8.1 patch.** Wraps gitleaks on the integration test logs themselves; needs the integration workflow to upload its log as an artifact first, then a chained workflow consumes the artifact and scans. The chaining is its own design pass; fold it in post-v0.8.0 if the basic security CI shows value.

The 3-job design from the brainstorm is reduced to 2 jobs in v0.8.0; the 3rd (integration-log-scan) lives on the carry-forward list.

---

## 4. Destructive-test isolation

### 4.1 New workflow

`.github/workflows/destructive-integration.yml`:

```yaml
name: destructive-integration
on:
  schedule:
    - cron: "13 5 * * 0"   # weekly Sunday 05:13 UTC
  workflow_dispatch:

jobs:
  destructive:
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/checkout@v6
      - uses: astral-sh/setup-uv@v7
      - run: uv sync --frozen
      - run: bash docker/bootstrap.sh
      - run: uv run pytest tests/integration -m "destructive" -v --tb=short
```

### 4.2 Pytest mark

Register `destructive` mark in `pyproject.toml`:
```toml
[tool.pytest.ini_options]
markers = [
    "integration: requires Wazuh + Keycloak docker stack",
    "requires_manager: needs Wazuh manager + agent (auto-skips on darwin/arm64)",
    "destructive: mutates shared docker state — runs in destructive-integration.yml only",
]
```

### 4.3 Test relocation

`tests/integration/test_m4c_writes.py::test_restart_manager_node_scope_completes`:
- Replace `pytest.skip(...)` with `@pytest.mark.destructive` decorator (in addition to the existing `pytestmark = [..., requires_manager]`).
- Restore the test body that v0.7.5 stripped (the poll loop, structuredContent assertions).

### 4.4 Main integration workflow filter

`integration.yml` filter changes from:
```yaml
- run: uv run pytest tests/integration -m "integration" -v
```
to:
```yaml
- run: uv run pytest tests/integration -m "integration and not destructive" -v
```

Keeps the main nightly clean; destructive tests routed to the weekly workflow.

### 4.5 Forward extensibility

Any future destructive test (e.g., `test_create_rule_uploads_then_restart_activates`, `test_isolate_then_recover_full_loop`) gets the `destructive` mark. The weekly workflow scales to N destructive tests sharing one container lifecycle; per-test container restart is unnecessary at v1.0 cardinality.

---

## 5. Phasing & dispatch profile

**Phase 1 — eval harness (T1-T6).** Maintainer-run via Claude Code slash command; no CI gate.
- T1: corpus authoring (selection_only.yaml — 30 entries) [tier-B, batched authoring]
- T2: corpus authoring (with_args.yaml — 10 entries) [tier-B]
- T3: corpus authoring (multi_step.yaml — 5 entries) [tier-B]
- T4: `tools/eval/score.py` scoring script + `thresholds.yaml` + tools/eval/README.md [tier-B — pure-Python, no API]
- T5: `.claude/commands/eval-wazuh-mcp.md` slash command + docs/eval/README.md [tier-B — markdown procedure]
- T6: maintainer-runs slash command against current Claude Code model, commits initial baseline `docs/eval-history/<today>-<model>-results.json` so M5a ship inherits a real audit trail (NOT a shipping gate task — confirms harness works end-to-end before tagging) [controller inline]

**Phase 2 — cross-tenant leak suite (T7-T9).**
- T7: Keycloak claim-mapper bootstrap + conftest fixtures [tier-A — auth/security primitive]
- T8: 5 cross-tenant tests in test_m4d_multi_tenant.py [tier-B]
- T9: audit-sinks per-test config-dir override [tier-B]

**Phase 3 — security CI (T10-T11).**
- T10: security.yml workflow + .gitleaks.toml + .gitleaksallow + security-ignores.yaml schema [tier-B]
- T11: security-ignores-expiry weekly cron workflow [tier-B]

**Phase 4 — destructive isolation + ship (T12-T15).**
- T12: pytest mark registration + destructive-integration.yml workflow [tier-B]
- T13: relocate test_restart_manager_node_scope_completes (un-skip, add mark) [tier-B]
- T14: docs/deploy/m5a-quality-gates.md operator doc [controller inline]
- T15: bump 0.8.0, retro, tag v0.8.0-m5a, push [controller inline]

**Total:** 15 tasks. 8-13 implementer dispatches expected. T7 (Keycloak claim mapper) is the only tier-A task — auth/security primitive. Rest are tier-B or controller-inline. The slash-command redesign drops the original tier-A T4 (the pytest+API runner) — the new T4 (`score.py`) is mechanical Python with no security surface.

---

## 6. Open questions resolved during brainstorm

- **Eval target shape:** Hybrid 30+10+5 (selection-only + with-args + multi-step). Pure-tier corpus rejected as too narrow.
- **Eval execution model:** Maintainer-run Claude Code slash command (option C). Constraint-driven — maintainer cannot afford a CI `ANTHROPIC_API_KEY`. Earlier brainstorm proposed nightly CI with Sonnet+Opus matrix (~$100-150/month) but that's incompatible with the cost constraint. Pytest+CI runner rejected; promptfoo/Anthropic Evals SDK rejected as adding deps for no gain. The slash command uses the maintainer's existing Claude Code subscription. Whatever model the Claude Code session runs against (typically Opus 4.7) is what the eval scores — recorded in the results filename + JSON. Multi-model eval = run the slash command from a Sonnet session and an Opus session on different days; both results land in `docs/eval-history/`. Per-model thresholds preserved in `tools/eval/thresholds.yaml`.
- **Cross-tenant token mint:** Claim mapper in single Keycloak realm (B). Multi-realm (A) rejected as rare in real deployments; hand-minted JWTs (C) rejected as bypassing OAuth chain.
- **M5a vs M5b boundary:** M5a = quality gates only. Group-target AR moves to v1.1 (feature, not gate). Helm + LTS matrix + docs + Vault integration → M5b.
- **CI eval as v1.x community contribution:** the corpus + scoring script are framework-agnostic. A future contributor with a paid API key can write a `tools/eval/run_via_api.py` that loops the corpus → calls `anthropic.Anthropic` → writes raw-results → invokes `score.py`. The corpus + thresholds + scoring don't change. Tracked as a v1.x carry-forward, not blocking v1.0.

---

## 7. Carry-forward to M5b

Items deferred from this spec to M5b:
- Wazuh LTS + latest matrix CI
- Multi-manager integration fixture (two distinct Wazuh clusters)
- Helm chart for k8s deploy
- Docs completion (README polish, deploy guide consolidation, API reference)
- Vault integration tests (currently unit-mocked)
- `WazuhError.scope` field (rate-limit metrics nit)
- Integration log secret-scan (post-v0.8.0 chained-workflow design)
- v1.0.0 tag

---

## 8. Success criteria

M5a ships when:
1. `/eval-wazuh-mcp` slash command exists and runs end-to-end against a live Claude Code session with wazuh-mcp connected. T6 produces an initial baseline `docs/eval-history/<today>-<model>-results.json` against the maintainer's current Claude Code model. Phase 2 scoring exits 0 against `tools/eval/thresholds.yaml` (i.e. the corpus is well-calibrated AND the model meets bar). Threshold tuning is part of T6 — if first run scores below threshold, decide: (a) lower threshold, (b) fix corpus prompt that's ambiguous, (c) accept fail and document. NOT a "make it pass at any cost" exercise.
2. `tests/integration/test_m4d_multi_tenant.py` has 5 passing tests (no skip-stubs); the cross-tenant negatives all pass.
3. `security.yml` workflow runs on PR with green dependency audit + secret scan.
4. `destructive-integration.yml` workflow runs on weekly schedule + manual dispatch; `test_restart_manager_node_scope_completes` is un-skipped and passes there.
5. `integration.yml` (the main nightly) filters out destructive tests cleanly. Expected count: 34+ passed, 0 skipped (v0.7.5 baseline 30 passed + 3 skipped → minus 1 destructive relocation + 2 M4d skip-stubs filled in + 3 new cross-tenant tests = 34 passed, 0 skipped).
6. Unit suite stays green at 506+ passed.
7. `pyproject.toml` at `0.8.0`. Tag `v0.8.0-m5a` on the ship commit.

**Exit:** M5b brainstorm picks up from this state with all quality gates in place.
