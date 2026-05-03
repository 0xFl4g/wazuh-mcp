# Security Policy

## Reporting a Vulnerability

If you've found a security issue in wazuh-mcp, **please do not open a public GitHub issue.** Report it privately so it can be triaged and fixed before disclosure.

Use GitHub's [private vulnerability reporting](https://github.com/0xFl4g/wazuh-mcp/security/advisories/new) (preferred), or email the maintainer at the address shown on the GitHub profile.

Include:
- A description of the issue and the impact you observed.
- A minimal reproduction (commands, config, or code snippet).
- The wazuh-mcp version (`v1.x.y` tag or commit SHA) and the Wazuh version it was running against.
- Whether the issue affects the stdio transport, the HTTP transport, or both.

You can expect:
- Acknowledgement within 5 business days.
- A coordinated fix and disclosure timeline once the issue is confirmed.
- Credit in the release notes (or an alias of your choice).

## Supported Versions

| Version | Supported |
|---|---|
| 1.1.x | ✅ active |
| 1.0.x | ✅ security fixes only |
| < 1.0 | ❌ unsupported |

## What's in scope

- Authentication and authorization paths (OAuth chain, API key, RBAC at list+call time).
- Tenant isolation guarantees (cross-tenant policy bleed, cross-tenant audit leak, cross-tenant rate-limit budget bleed).
- Write-tool safety contract (`confirm: Literal[True]`, two-layer allowlist, `agent_group_allowlist`).
- Secret backends (AWS SM, Vault, SQLite+age) — credential exposure or improper rotation.
- Rate-limiter and circuit-breaker correctness when backed by Redis.
- Audit-emitter correctness — dropped, duplicated, or attributed-incorrectly events.

## What's out of scope

- Vulnerabilities in upstream Wazuh, Keycloak, OpenSearch, or other backing services. Report those upstream.
- Issues that require an attacker to already have administrator access to the K8s cluster, the host running wazuh-mcp, or the Wazuh manager.
- Theoretical attacks on the test fixtures (`docker/integration-compose.yml`, fake JWKS issuers, fixture passwords). Test creds like `MCPmcp12345!` are intentionally non-secret and documented as such.

## Security testing

Every push runs:
- `gitleaks` against the source tree (`security` workflow).
- `pip-audit` and `safety` against the locked dependency graph.
- Integration logs are scanned with `gitleaks` post-run.

CI exemptions for known-safe test fixtures are documented in `.gitleaks.toml`.
