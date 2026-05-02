# M5a — Quality Gates

## Overview

M5a adds four quality gates to the wazuh-mcp build:

1. **Eval harness** — maintainer-run via `/eval-wazuh-mcp` slash command in Claude Code. Asserts Claude picks the right tool for each of 45 representative security-ops prompts. No CI-attached `ANTHROPIC_API_KEY` required; runs against the maintainer's existing Claude Code subscription.
2. **Cross-tenant leak suite** — five integration tests (in `tests/integration/test_m4d_multi_tenant.py`) pinning per-tenant rate-limit + audit-routing + claim-precedence invariants end-to-end.
3. **Security CI** — `pip-audit` + `safety check` + `gitleaks` on every PR + nightly. Suppression schema in `.github/security-ignores.yaml` with weekly-cron expiry checker.
4. **Destructive-test isolation** — destructive tests (currently `test_restart_manager_node_scope_completes`) run in a separate weekly workflow, not the main nightly. Lifted v0.7.5's skip-mark.

This is the first half of v1.0.0; M5b ships deployment readiness (Wazuh LTS matrix, multi-manager fixture, Helm chart, docs completion) and the v1.0.0 tag.

Spec: `docs/superpowers/specs/2026-04-27-wazuh-mcp-m5a-design.md`. Plan: `docs/superpowers/plans/2026-04-28-wazuh-mcp-m5a-plan.md`.

## 1. Eval harness

### Run

In a Claude Code session with wazuh-mcp connected as an MCP server:

    /eval-wazuh-mcp

The slash command runs Phases 1a-1c (~5-10 minutes) and invokes Phase 2 scoring. Output:
- `docs/eval-history/<today>-<model>-results-raw.json` (Phase 1 raw decisions)
- `docs/eval-history/<today>-<model>-results.json` (scored report)

Exit code 0 if `thresholds_met`. The maintainer reviews the report + commits both files for the audit trail.

### Corpus

`docs/eval/corpus/` holds three YAMLs:
- `selection_only.yaml` (30 entries) — asserts tool name only.
- `with_args.yaml` (10 entries) — asserts tool name + key arg subset.
- `multi_step.yaml` (5 entries) — asserts a sequence of tool calls for multi-turn flows.

Add prompts by appending YAML entries. The slash command + scoring script are corpus-agnostic.

### Thresholds

`tools/eval/thresholds.yaml`. Default: selection_only ≥0.85, with_args ≥0.90, multi_step ≥0.80, overall ≥0.85. Per-model overrides for higher-tier models.

### Forward path

A v1.x community contributor with a paid `ANTHROPIC_API_KEY` can wrap the corpus + scoring script in CI by writing `tools/eval/run_via_api.py` (loops corpus → calls `anthropic.Anthropic` → writes raw-results → invokes `score.py`). Corpus + thresholds + scoring don't change.

## 2. Cross-tenant leak suite

`tests/integration/test_m4d_multi_tenant.py` pins five invariants:

1. Per-tenant rate-limit isolation (tenant_b's bucket exhaustion does not affect local).
2. Per-tenant audit routing (tenant_b session's audit lands in `tenant-b-audit-*`, NOT `local-audit-*`).
3. Local session's tools do not query tenant_b's IndexerClient.
4. Unknown-tenant token routes to globals only (skip-marked pending v1.x JWKS plumbing).
5. tenant_b token cannot resolve to local — claim-precedence end-to-end.

Per-tenant token mint: Keycloak protocol-mapper hardcodes `tenant_id` per service-account. Both tenants share the realm + audience; distinguished by claim. See `docker/config/keycloak-realm.json` for the two service-account clients.

`IssuerIndex` (`src/wazuh_mcp/tenancy/issuer_index.py`) returns `None` for issuers shared by multiple tenants. The OAuthSessionFactory then routes by the `tenant_id` claim alone (oauth.py:125-126); a token without a `tenant_id` claim hitting an ambiguous issuer fails closed with `MissingClaim`.

## 3. Security CI

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

All four fields required. The weekly `security-ignores-expiry.yml` workflow opens a GitHub issue if any entry's `expires` is past today.

### secret-leak-scan job

`gitleaks-action@v2` with custom `.gitleaks.toml` (extends defaults; adds Wazuh JWT + Keycloak secret + Wazuh manager password patterns). Allowlist for known-safe test fixtures in `.gitleaksallow`.

## 4. Destructive-test isolation

`.github/workflows/destructive-integration.yml` runs on:
- `cron: "13 5 * * 0"` (weekly Sunday 05:13 UTC)
- `workflow_dispatch`

Uses `pytest -m "destructive"` filter. Tests marked `@pytest.mark.destructive` mutate shared Wazuh state (e.g., manager restart) — they run in this workflow's isolated docker-compose stack, not the main nightly's.

Currently 1 destructive test: `tests/integration/test_m4c_writes.py::test_restart_manager_node_scope_completes`. Future destructive tests get the mark; the workflow scales to N tests sharing one container lifecycle.

Main `integration.yml` filter is now `-m "integration and not destructive"`.

## Migration

There is no operator migration. All M5a additions are CI-and-test-side. Deployments built from `v0.8.0-m5a` artifact carry no code-level breaking changes vs `v0.7.5`.
