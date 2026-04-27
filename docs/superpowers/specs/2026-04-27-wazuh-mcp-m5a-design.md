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

## 1. Eval harness

### 1.1 Architecture

Layout under `tests/eval/`:

```
tests/eval/
├── __init__.py
├── conftest.py             # pytest fixtures: anthropic client, tool catalog
├── corpus/
│   ├── selection_only.yaml # 30 prompts → expected tool name
│   ├── with_args.yaml      # 10 prompts → expected tool name + key arg subset
│   └── multi_step.yaml     # 5 prompts → expected tool sequence
├── runner.py               # corpus loader + pytest test generation
├── thresholds.yaml         # per-model accuracy gates
└── report.py               # session-end aggregator + JSON dump
```

### 1.2 Corpus shape

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

`multi_step.yaml` (5 entries; each step asserts tool name + optional args; the runner replays a stub `tool_result` to drive the next turn):
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

**Categories** (used for failure-grouping in reports): `triage`, `hunt`, `writes`, `inventory`, `mitre`, `fim`, `vulns`. Authored by hand; ~6-7 prompts per category in selection_only.

### 1.3 Runner mechanism

`runner.py`:
1. Loads each YAML corpus file at module import.
2. Generates one pytest test function per entry via `pytest_generate_tests` hook (parametrized by entry).
3. Each test ID is the YAML `id` field — clean failure reports.
4. Tests parametrized over `[("claude-sonnet-4-6", 0.85), ("claude-opus-4-7", 0.95)]` via `@pytest.mark.parametrize` outer-loop.

**Per-test execution:**
- Instantiate `Anthropic` client with API key from `ANTHROPIC_API_KEY` env.
- Build `tools` parameter from `mcp_app.list_tools()` JSON-Schema (the wazuh-mcp tool catalog produced by `_register_everything`).
- Call `client.messages.create(model=model, max_tokens=4096, tools=tools, messages=[{"role": "user", "content": prompt}])`.
- For selection_only: scan response `content` for the first `tool_use` block; assert `block.name == expected_tool`.
- For with_args: scan for `tool_use`; assert name match AND `all(input.get(k) == v for k, v in expected_args.items())`.
- For multi_step: drive multi-turn loop. After Claude emits a `tool_use`, append `{"role": "assistant", "content": [response]}` + `{"role": "user", "content": [{"type": "tool_result", "tool_use_id": ..., "content": json.dumps(stub_result)}]}` and re-call. Assert each step's tool name (and args if specified). Sequence must match in order.

**Per-eval failure surfaces** the prompt, expected, and what Claude actually picked. Pytest's verbose output at INFO level.

### 1.4 Aggregator + accuracy gates

Session-end (pytest `pytest_sessionfinish` hook in `report.py`):
- Collect per-model pass/fail counts.
- Compute accuracy = passed / total per model.
- Compare against `thresholds.yaml`:
  ```yaml
  models:
    claude-sonnet-4-6: 0.85
    claude-opus-4-7: 0.95
  ```
- If any model below threshold → exit code 1 (workflow fails).
- Write `eval-report.json` artifact: `{model: {accuracy, passed, failed, by_category: {...}}}`.

### 1.5 CI workflow

New `.github/workflows/eval.yml`:

```yaml
name: eval
on:
  schedule:
    - cron: "47 3 * * *"   # nightly UTC, off-peak, off-minute
  workflow_dispatch:

jobs:
  eval:
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/checkout@v6
      - uses: astral-sh/setup-uv@v7
      - run: uv sync --frozen
      - run: uv run pytest tests/eval -m eval -v --tb=short
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: eval-report
          path: eval-report.json
      - run: cat eval-report.json >> $GITHUB_STEP_SUMMARY
```

**Pytest mark:** `@pytest.mark.eval` registered in `pyproject.toml` `[tool.pytest.ini_options].markers`. `eval` and `integration` are separate marks — eval runs do NOT spin up the Wazuh docker stack.

**Cost projection:** ~45 evals × 2 models × ~1500 input + 200 output tokens (selection-only) to ~5000 input + 1500 output (multi-step). Approximate monthly cost: $100-150.

### 1.6 Forward extensibility

- Adding a prompt = appending one YAML entry. No runner changes.
- Adding a new model to the matrix = adding one `thresholds.yaml` entry.
- Switching corpora to JSONL or another format = swap the corpus loader; runner + thresholds unchanged.
- Web UI / fancy reporting deferred to v1.x — text + JSON artifact is sufficient for v0.8.0.

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
    "eval: requires ANTHROPIC_API_KEY; runs in eval.yml workflow",
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

**Phase 1 — eval harness (T1-T6).** Largest workstream, most novel.
- T1: corpus authoring (selection_only.yaml — 30 entries) [tier-B, batched authoring]
- T2: corpus authoring (with_args.yaml — 10 entries) [tier-B]
- T3: corpus authoring (multi_step.yaml — 5 entries) [tier-B]
- T4: runner.py + report.py [tier-A — novel runner, multi-turn replay]
- T5: thresholds.yaml + pytest mark + accuracy aggregator wiring [tier-B]
- T6: eval.yml workflow + ANTHROPIC_API_KEY secret docs [tier-B]

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

**Total:** 15 tasks. 8-13 implementer dispatches expected. T4 (runner) + T7 (Keycloak claim mapper) are tier-A — full review or close spot-check. Rest are tier-B.

---

## 6. Open questions resolved during brainstorm

- **Eval target shape:** Hybrid 30+10+5 (selection-only + with-args + multi-step). Pure-tier corpus rejected as too narrow.
- **Eval models:** Sonnet 4.6 + Opus 4.7 matrix with per-model bars (≥85% / ≥95%). Single-model rejected as risk of model-overfit; Haiku addition deferred to v1.x.
- **Eval CI cadence:** Nightly only. PR-smoke deferred (cost / fork-PR-secret friction).
- **Eval framework:** Pytest + YAML corpus (D). Hand-rolled runner ~150 LoC; promptfoo / Anthropic Evals SDK rejected as adding deps for marginal gain.
- **Cross-tenant token mint:** Claim mapper in single Keycloak realm (B). Multi-realm (A) rejected as rare in real deployments; hand-minted JWTs (C) rejected as bypassing OAuth chain.
- **M5a vs M5b boundary:** M5a = quality gates only. Group-target AR moves to v1.1 (feature, not gate). Helm + LTS matrix + docs + Vault integration → M5b.

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
1. `tests/eval` runs in nightly CI with both Sonnet 4.6 + Opus 4.7 above their thresholds.
2. `tests/integration/test_m4d_multi_tenant.py` has 5 passing tests (no skip-stubs); the cross-tenant negatives all pass.
3. `security.yml` workflow runs on PR with green dependency audit + secret scan.
4. `destructive-integration.yml` workflow runs on weekly schedule + manual dispatch; `test_restart_manager_node_scope_completes` is un-skipped and passes there.
5. `integration.yml` (the main nightly) filters out destructive tests cleanly: 32+ passed, 2 skipped (M4d skip-stubs filled in by §2.3 above).
6. Unit suite stays green at 506+ passed.
7. `pyproject.toml` at `0.8.0`. Tag `v0.8.0-m5a` on the ship commit.

**Exit:** M5b brainstorm picks up from this state with all quality gates in place.
