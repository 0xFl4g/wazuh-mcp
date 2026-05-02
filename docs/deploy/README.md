# Deploying wazuh-mcp

This directory holds operator-facing deployment guides. Each milestone in the v0.x development series shipped its own deploy notes (`m{2,3,4a,4b,4c,4d,5a}-*.md`); those remain in place and are factually correct at their respective milestone tags. v1.0.0 adds the Helm chart guide and the M5b additions.

## Recommended reading order

For a fresh install, read in roughly this order:

1. [m2-http.md](m2-http.md) — base HTTP transport + OAuth setup.
2. [oauth-setup/](oauth-setup/) — IDP-specific configuration:
   - [keycloak.md](oauth-setup/keycloak.md)
   - [okta.md](oauth-setup/okta.md)
   - [entra.md](oauth-setup/entra.md)
   - [auth0.md](oauth-setup/auth0.md)
3. [api-keys.md](api-keys.md) — alternative to OAuth for service-to-service auth.
4. [m3-tools.md](m3-tools.md) — read-tool surface (17 tools + resources + prompts).
5. [m4a-secrets.md](m4a-secrets.md) — SecretStore drivers (YAML, AWS Secrets Manager, Vault, SQLite+age) + caching wrapper.
6. [m4a-observability.md](m4a-observability.md) + [m4a-audit.md](m4a-audit.md) — OTel, Prometheus metrics, audit emitter, sink fan-out.
7. [m4b-writes.md](m4b-writes.md) — first 7 write tools + run_as + two-layer allowlist.
8. [m4c-multi-tenant.md](m4c-multi-tenant.md) — per-tenant policy resolvers, multi-agent AR, `restart_manager`, `cluster.status`.
9. [m4d-multi-tenant-runtime.md](m4d-multi-tenant-runtime.md) — per-tenant rate-limit + per-tenant audit-sink fan-out.
10. [m5a-quality-gates.md](m5a-quality-gates.md) — eval harness, security CI, destructive-test isolation.
11. [helm.md](helm.md) — Kubernetes deployment via the v1.0.0 Helm chart.

## v1.0.0 (M5b) additions

- [helm.md](helm.md) — `charts/wazuh-mcp/` production-baseline single-replica chart with HA caveat, opt-in NetworkPolicy / ServiceMonitor / Ingress.
- New `write.run_active_response_on_group` tool — group-target active-response with `agent_group_allowlist` per-tenant gate. Quick reference:
  - Add `agent_group_allowlist: ["<group>"]` to the tenant's config in `tenants.yaml`.
  - The session must also be allowed `write.run_active_response_on_group` via tenant `write_allowlist` (or `null` to register all writes).
  - Call shape: `{"group_name": "<group>", "command_name": "<allowlisted-command>", "confirm": true}`.
- `WazuhError.scope` structured field — rate-limit and allowlist-deny errors now carry a structured `scope` value (e.g., `rate_limit:tenant`, `ar_group_allowlist`). Replaces the brittle substring-match in metrics. The `mcp_rate_limit_drops_total{tenant, scope}` Prometheus metric reads the field directly; existing operator dashboards continue to work without changes (label set is unchanged).
- Wazuh version matrix CI — nightly runs against both Wazuh LTS (`4.9.0`) and latest (`4.14.5`).
- Multi-manager weekly workflow — federation tested on a separate cron against two distinct Wazuh clusters.
- Real Vault container in integration tests — replaces hvac.Client mock-only coverage for `VaultSecretStore`.
- Integration log secret-scan — chained gitleaks workflow runs against the always-uploaded integration log artifacts.

## Topic-organized restructure (planned)

A topic-organized reorganization of these per-milestone files (single `secrets.md`, `oauth.md`, `tools.md`, `writes.md`, `observability.md`, `multi-tenant.md`, `quality-gates.md`) is queued for a v1.0.x patch. The per-milestone files will then move to `_archive/` with a redirect banner. v1.0.0 ships with the per-milestone organization for honesty: each file is accurate at the milestone tag it was written against, and the deltas land in this README's "v1.0.0 (M5b) additions" section above.

If you find a documented surface that's been superseded by a later milestone, the per-milestone file's first paragraph notes the milestone tag — cross-reference against the latest milestone's notes for the current state.
