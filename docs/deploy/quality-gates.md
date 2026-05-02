# Quality gates

wazuh-mcp v1.0.0 ships with eight quality gates: an eval harness, a cross-tenant leak suite, security CI, destructive-test isolation, Wazuh version matrix CI, multi-manager weekly workflow, real Vault container in integration, and integration-log secret scanning. This document covers what each gate exists for, how it runs, and how to interpret its outputs.

These gates are CI-and-test-side — there is no operator migration. Deployments built from `v1.0.0` carry no code-level breaking changes vs `v0.7.5`.

## 1. Eval harness (M5a)

### Run

In a Claude Code session with wazuh-mcp connected as an MCP server:

```
/eval-wazuh-mcp
```

The slash command runs Phases 1a–1c (~5–10 minutes) and invokes Phase 2 scoring. Output:
- `docs/eval-history/<today>-<model>-results-raw.json` — Phase 1 raw decisions.
- `docs/eval-history/<today>-<model>-results.json` — scored report.

Exit code 0 if `thresholds_met`. The maintainer reviews the report and commits both files for the audit trail.

No CI-attached `ANTHROPIC_API_KEY` required — the eval runs against the maintainer's existing Claude Code subscription.

### Corpus

`docs/eval/corpus/`:
- `selection_only.yaml` (30 entries) — asserts tool name only.
- `with_args.yaml` (10 entries) — asserts tool name + key arg subset.
- `multi_step.yaml` (5 entries) — asserts a sequence of tool calls for multi-turn flows.

Add prompts by appending YAML entries. The slash command + scoring script are corpus-agnostic.

### Thresholds

`tools/eval/thresholds.yaml`. Defaults: selection_only ≥0.85, with_args ≥0.90, multi_step ≥0.80, overall ≥0.85. Per-model overrides for higher-tier models.

### Three-tier scoring + ladder rule

Each prompt scores 0/1 against its tier's correctness predicate. Per-tier accuracy must clear its threshold; overall accuracy must clear the overall threshold. The "ladder rule": multi-step thresholds are deliberately loosest (multi-turn variance is higher), with_args strictest (assertion is the most specific).

### Forward path (paid API)

A v1.x community contributor with a paid `ANTHROPIC_API_KEY` can wrap the corpus + scoring script in CI by writing `tools/eval/run_via_api.py` (loops corpus → calls `anthropic.Anthropic` → writes raw-results → invokes `score.py`). Corpus + thresholds + scoring don't change.

## 2. Cross-tenant leak suite (M5a)

`tests/integration/test_m4d_multi_tenant.py` pins five invariants end-to-end:

1. **Per-tenant rate-limit isolation** — tenant_b's bucket exhaustion does not affect local.
2. **Per-tenant audit routing** — tenant_b session's audit lands in `tenant-b-audit-*`, NOT `local-audit-*`. Un-skipped after M5b T-G5b fixed the index template patterns.
3. **Local session's tools do not query tenant_b's IndexerClient** — pool isolation.
4. **Unknown-tenant token routes to globals only** — phantom-token defense-in-depth. Un-skipped after M5b T-G4 wired the JWKS plumbing.
5. **tenant_b token cannot resolve to local** — claim-precedence end-to-end.

Per-tenant token mint: Keycloak protocol-mapper hardcodes `tenant_id` per service-account. Both tenants share the realm + audience; distinguished by claim. See `docker/config/keycloak-realm.json` for the two service-account clients.

`IssuerIndex` (`src/wazuh_mcp/tenancy/issuer_index.py`) returns `None` for issuers shared by multiple tenants. The OAuthSessionFactory then routes by the `tenant_id` claim alone; a token without a `tenant_id` claim hitting an ambiguous issuer fails closed with `MissingClaim`.

## 3. Security CI (M5a)

`.github/workflows/security.yml` runs on PR + nightly + manual dispatch.

### dependency-audit job

- `pip-audit --strict` against `uv export --no-emit-project --frozen` output.
- `safety check --full-report` (defense-in-depth — different DB).
- Pre-step: `uv run python tools/check_security_ignores.py` validates `.github/security-ignores.yaml` schema + expiry.

Adding a suppression:

```yaml
# .github/security-ignores.yaml
ignores:
  - id: GHSA-xxxx-yyyy
    reason: "Vuln applies to a flask handler we don't use; verified."
    expires: "2026-10-27"
    reviewer: 0xFl4g
```

All four fields required (`id`, `reason`, `expires`, `reviewer`). The weekly `security-ignores-expiry.yml` workflow opens a GitHub issue if any entry's `expires` is past today.

### secret-leak-scan job

`gitleaks-action@v2` with custom `.gitleaks.toml` (extends defaults; adds Wazuh JWT + Keycloak secret + Wazuh manager password patterns). Allowlist for known-safe test fixtures in `.gitleaksallow`.

## 4. Destructive-test isolation (M5a)

`.github/workflows/destructive-integration.yml` runs on:
- `cron: "13 5 * * 0"` (weekly Sunday 05:13 UTC).
- `workflow_dispatch`.

Uses `pytest -m "destructive"` filter. Tests marked `@pytest.mark.destructive` mutate shared Wazuh state (e.g., manager restart) — they run in this workflow's isolated docker-compose stack, not the main nightly's.

Currently 1 destructive test: `tests/integration/test_m4c_writes.py::test_restart_manager_node_scope_completes`. Future destructive tests get the mark; the workflow scales to N tests sharing one container lifecycle.

Main `integration.yml` filter is `-m "integration and not destructive"`.

## 5. Wazuh version matrix CI (M5b T-B1)

Nightly workflow runs the full integration suite against both Wazuh LTS and latest:

- LTS: `4.9.0` — long-term operator path; conservative deploys pin to LTS.
- Latest: `4.14.5` — current release; surfaces upstream regressions before they hit the LTS branch.

The matrix job parametrises `docker/integration-compose.yml` via env vars (`WAZUH_VERSION` selects the manager + indexer image tags). Both versions must pass for the nightly to be green.

A version-specific failure is an early-warning signal: either the LTS surface diverged from latest in a way wazuh-mcp depends on, or latest introduced a breaking change that needs a compat shim before the next Wazuh GA.

## 6. Multi-manager weekly workflow (M5b T-C2)

Federation-style deployments — one MCP server fronting multiple distinct Wazuh manager clusters — are tested via a separate weekly cron. The workflow brings up two distinct Wazuh stacks (independent indexer + manager + dashboard per stack) and asserts cross-manager isolation:

- A tenant_a tool call must not reach tenant_b's manager cluster.
- A tenant_b token must not be able to query tenant_a's indexer.
- Per-manager pools (indexer + server API) are independent — one manager going down does not block the other tenant's calls.

The fixture relies on `TenantConfig.server_api_url` (added in M5b T-C1) so each tenant explicitly targets its own manager. Without the override, both tenants would derive the Server API URL from `indexer_url` and collide on the shared port.

See `tests/integration/conftest.py` for the `multi_manager` parametrization.

## 7. Real Vault container in integration tests (M5b T-D1)

`docker/integration-compose.yml` ships a real Vault dev container on port 8200. `tests/integration/test_vault_secret_store.py` exercises the full Vault read path end-to-end:

1. Bootstrap Vault dev container with a known root token.
2. `vault kv put` a fixture secret.
3. `await store.get(tenant, key)` via `VaultSecretStore`.
4. Assert the `SecretValue` round-trip.

Replaces the prior `hvac.Client` mock-only coverage. Operators running the integration suite locally pick up the Vault container automatically via `docker/bootstrap.sh`. No additional config — the test container is gated to `pytest -m integration` runs and does not affect production deployments.

See `secrets.md` for the Vault driver reference.

## 8. Integration log secret-scan (M5b T-G2)

A chained gitleaks workflow runs against the always-uploaded integration log artifacts. Catches the case where a test failure dumps tokens, passwords, or other sensitive material into `pytest -ra` output that then ships to GitHub Actions artifacts.

Workflow chain:
1. Main `integration.yml` always uploads its log directory as a workflow artifact (success or failure).
2. `integration-log-scan.yml` triggers on the artifact upload, pulls the artifact, and runs gitleaks against it.
3. If gitleaks finds anything, the chained workflow fails and surfaces the leak to the maintainer.

The same `.gitleaks.toml` + `.gitleaksallow` from §3 apply, so test-fixture allowlists carry through.

## Migration

There is no operator migration. All quality gates are CI-and-test-side. Deployments built from `v1.0.0` carry no code-level breaking changes vs `v0.7.5`.

## Specs

- M5a: `docs/superpowers/specs/2026-04-27-wazuh-mcp-m5a-design.md`.
- M5a plan: `docs/superpowers/plans/2026-04-28-wazuh-mcp-m5a-plan.md`.
- M5b: `docs/superpowers/specs/2026-04-29-wazuh-mcp-m5b-design.md`.
