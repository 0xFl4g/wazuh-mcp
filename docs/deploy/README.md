# Deploying wazuh-mcp

Operator-facing deployment guides, organized by topic.

## Recommended reading order

For a fresh install:

1. [install.md](install.md) — three install paths (uv, Docker, Helm), config layout, stdio vs HTTP transport, first-run smoke.
2. [tenants.md](tenants.md) — full `TenantConfig` schema reference (every field, validator, semantics).
3. [oauth.md](oauth.md) — OIDC discovery + JWKS + token validation, IssuerIndex semantics, `wazuh_user` claim mapping for `run_as`.
4. [oauth-setup/](oauth-setup/) — IdP-specific setup:
   - [keycloak.md](oauth-setup/keycloak.md)
   - [okta.md](oauth-setup/okta.md)
   - [entra.md](oauth-setup/entra.md)
   - [auth0.md](oauth-setup/auth0.md)
5. [api-keys.md](api-keys.md) — alternative to OAuth for service-to-service auth.
6. [secrets.md](secrets.md) — SecretStore drivers (YAML, AWS Secrets Manager, Vault, SQLite + age) + caching wrapper.
7. [tools.md](tools.md) — read-tool surface (17 read tools across 6 domains, plus `cluster.status`, 3 resources, 3 prompts).
8. [writes.md](writes.md) — 9 write tools, two-layer allowlist, `confirm` UX, `run_as` flow, rule-file lifecycle, group-target AR.
9. [multi-tenant.md](multi-tenant.md) — per-tenant resolver model, rate-limit + audit-sink fan-out, cross-tenant isolation, multi-manager fixture.
10. [observability.md](observability.md) — OpenTelemetry traces, Prometheus metrics, audit emitter + sinks, `WazuhError.scope`.
11. [quality-gates.md](quality-gates.md) — eval harness, cross-tenant leak suite, security CI, destructive-test isolation, Wazuh version matrix CI, multi-manager weekly workflow, real Vault container, integration-log secret-scan.
12. [helm.md](helm.md) — Kubernetes deployment via the v1.0.0 Helm chart.

For the comprehensive per-tool argument + result schema (every tool, every field, every error code), see [`../api-reference.md`](../api-reference.md).

## v1.0.0 (M5b) additions

- [helm.md](helm.md) — `charts/wazuh-mcp/` production-baseline single-replica chart with HA caveat, opt-in NetworkPolicy / ServiceMonitor / Ingress.
- New `write.run_active_response_on_group` tool — group-target active-response with `agent_group_allowlist` per-tenant gate. See [writes.md](writes.md#agent_group_allowlist-setup-m5b).
- `WazuhError.scope` structured field — rate-limit and allowlist-deny errors carry a structured `scope` (e.g., `rate_limit:tenant`, `ar_group_allowlist`). Replaces the brittle substring-match in metrics. The `mcp_rate_limit_drops_total{tenant, scope}` Prometheus metric reads the field directly. See [observability.md](observability.md#wazuherrorscope-v100).
- Wazuh version matrix CI — nightly runs against both Wazuh LTS (`4.9.0`) and latest (`4.14.5`).
- Multi-manager weekly workflow — federation tested on a separate cron against two distinct Wazuh clusters.
- Real Vault container in integration tests — replaces `hvac.Client` mock-only coverage for `VaultSecretStore`.
- Integration log secret-scan — chained gitleaks workflow runs against the always-uploaded integration log artifacts.
- `TenantConfig.server_api_url` (T-C1) — explicit override for the derived port-55000 Server API URL; required for multi-manager deployments where each tenant targets a distinct manager cluster.

## Per-milestone archive

The pre-v1.0.0 deploy guides (m2 → m5a) are preserved at [`_archive/`](_archive/) for git-history archeology and v0.x.y → v1.0.0 diffs. They are not maintained — for current deployment docs, use the topic-organized files above.
