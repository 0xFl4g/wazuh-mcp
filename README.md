# wazuh-mcp

[![CI](https://github.com/0xFl4g/wazuh-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/0xFl4g/wazuh-mcp/actions/workflows/ci.yml)
[![Integration](https://github.com/0xFl4g/wazuh-mcp/actions/workflows/integration.yml/badge.svg)](https://github.com/0xFl4g/wazuh-mcp/actions/workflows/integration.yml)
[![Security](https://github.com/0xFl4g/wazuh-mcp/actions/workflows/security.yml/badge.svg)](https://github.com/0xFl4g/wazuh-mcp/actions/workflows/security.yml)
[![Release](https://img.shields.io/badge/release-v1.2.0-blue)](https://github.com/0xFl4g/wazuh-mcp/releases/tag/v1.2.0)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)

Model Context Protocol server for Wazuh SIEM/XDR.

**Status:** v1.2.0. Production-ready release: multi-tenant policy resolution, full read+write tool surface (18 reads + 9 writes including group-target active-response), real secret backends, RBAC + rate-limit + audit chokepoint, OTel + Prom metrics, OAuth 2.1 + API-key auth, stdio + Streamable HTTP transports, Helm chart for Kubernetes deploy, opt-in Redis-backed RateLimiter + audit-emitter dedup for true multi-replica HA. **Tested against Wazuh 4.9 LTS** — expected compatible with newer 4.x via documented API compat (file an issue if you find a regression; matrix-test against 4.14+ deferred pending larger CI runners). See [`docs/deploy/README.md`](docs/deploy/README.md) for the topic-organized deployment guide, [`docs/api-reference.md`](docs/api-reference.md) for the comprehensive per-tool API reference, and `docs/superpowers/specs/` for design specs per milestone.

## Tools (17)

### `alerts.*`
- `alerts.search_alerts` — Search alerts by time range + filters
- `alerts.get_alert` — Fetch a single alert by id
- `alerts.alerts_by_agent` — Filter alerts by agent
- `alerts.alerts_by_mitre` — Filter alerts by MITRE technique

### `agents.*`
- `agents.list_agents`
- `agents.get_agent`
- `agents.agent_processes`
- `agents.agent_packages`
- `agents.agent_ports`

### `vulnerabilities.*`
- `vulnerabilities.list_vulnerabilities_by_agent`
- `vulnerabilities.search_vulnerabilities`

### `mitre.*`
- `mitre.get_mitre_technique`
- `mitre.search_mitre`

### `hunt.*`
- `hunt.hunt_query` — constrained-grammar hunt over alerts
- `hunt.pivot_by_ioc` — hash/ip/user/domain preset

### `fim.*`
- `fim.fim_history_for_path`
- `fim.fim_changes_by_agent`

## Resources (3)
- `wazuh://rules/{id}` (5 min TTL hint)
- `wazuh://mitre/technique/{id}` (24 h TTL hint)
- `wazuh://agents/{id}/config` (5 min TTL hint)

## Prompts (3)
- `/wazuh:investigate-alert {alert_id}` — pre-loaded alert + agent + neighbors context
- `/wazuh:triage-last-hour` — pre-loaded recent high-severity alerts
- `/wazuh:agent-posture {agent_id}` — pre-loaded agent + alerts + vulns context

**Requires Wazuh ≥ 4.8** for `vulnerabilities.*` (state lives in the indexer as of 4.8).

See [`docs/deploy/tools.md`](docs/deploy/tools.md) for the read-tool operator guide and [`docs/api-reference.md`](docs/api-reference.md) for the comprehensive per-tool API. M5b adds `write.run_active_response_on_group` — group-target AR with per-tenant `agent_group_allowlist` gate; see [`docs/deploy/writes.md`](docs/deploy/writes.md) for the full write-tool guide.

## Deploy

- **stdio** — `uv run wazuh-mcp` after creating a `config/` directory (see "Configure" below).
- **HTTP** — `uv run wazuh-mcp serve` for the Streamable HTTP transport. See [`docs/deploy/install.md`](docs/deploy/install.md).
- **Kubernetes (Helm)** — `helm install wazuh-mcp ./charts/wazuh-mcp` with bring-your-own Secret. See [`docs/deploy/helm.md`](docs/deploy/helm.md) for the full guide and HA caveat.

## Requirements

- Python 3.12+
- `uv` — https://docs.astral.sh/uv/
- A Wazuh Indexer endpoint (for integration tests: Docker + Docker Compose)

## Install

    uv sync

## Configure

Create a `config/` directory with three files:

**`config/tenants.yaml`**

    tenants:
      - tenant_id: local
        indexer_url: https://localhost:9200
        verify_tls: false
        ca_bundle_path: null
        default_rbac_role: soc_analyst

**`config/secrets.yaml`**

    local:
      indexer_user: admin
      indexer_password: SecretPassword

**`config/server.yaml`**

    active_tenant: local
    user_id: alice

## Run

    WAZUH_MCP_CONFIG_DIR=./config uv run wazuh-mcp

The server speaks MCP over stdio. Add it to Claude Desktop's config:

    {
      "mcpServers": {
        "wazuh": {
          "command": "uv",
          "args": ["run", "--project", "/abs/path/to/wazuh-mcp", "wazuh-mcp"],
          "env": { "WAZUH_MCP_CONFIG_DIR": "/abs/path/to/wazuh-mcp/config" }
        }
      }
    }

## Develop

Unit tests (fast, no network):

    uv run pytest

Lint + format:

    uv run ruff check .
    uv run ruff format .

Integration tests (docker compose required):

    docker/bootstrap.sh        # up, security-init, seed
    uv run pytest -m integration
    docker compose -f docker/integration-compose.yml down -v

## Milestones

- **M1 (v0.1.0-m1)** — walking skeleton: stdio, single tenant, one tool.
- **M2 (v0.2.0-m2)** — Streamable HTTP transport, OAuth 2.1 + API-key auth, multi-tenant session routing, per-tenant IndexerClient pool.
- **M3 (v0.3.0-m3)** — full read tool surface (17 tools across 6 domains, 3 resources, 3 prompts), Server API client, hunt-query grammar.
- **M4a (v0.4.0-m4a)** — production hardening: real secret backends (AWS SM / Vault / SQLite+age), RBAC at list+call time, per-tenant + session token-bucket rate limits, OTel + Prom metrics, multi-sink audit emitter, `@instrumented_tool` chokepoint.
- **M4b (v0.5.0-m4b)** — write-tool surface: 7 `write.*` tools (agent isolate/restart, group add/remove, rule create/update, active-response), `confirm: Literal[True]` safety contract, two-layer per-tenant allowlist, `run_as` attribution, double-audit emit.
- **v0.5.1** — integration-restoration patch: 9 latent bugs fixed after the never-running integration suite was made to run (decorator schema collapse, missing IndexerClient methods, wrong rule-upload + active-response wire shapes).
- **M4c (v0.6.0-m4c)** — per-tenant policy resolution (closes the multi-tenant policy-bleed gap), `write.restart_manager` + `cluster.status` (rule-activation flow inside MCP), multi-agent `run_active_response` (`agent_ids: list[str]`), `confirm_required` cleanup. See `docs/deploy/m4c-multi-tenant.md`.
- **M4d (v0.7.0-m4d)** — multi-tenant runtime isolation completion: per-tenant rate-limit budgets (closes cross-tenant DOS), per-tenant audit-sink fan-out (closes cross-tenant audit leak). No new operator-config surface. See `docs/deploy/m4d-multi-tenant-runtime.md`.
- **M5 (planned)** — ship-gate: eval harness, Wazuh LTS matrix CI, cross-tenant leak suite, multi-manager integration fixture, Helm chart, full docs.
- **v1.1** — multi-replica HA opt-in: `RedisRateLimiter` shares the rate budget across replicas via Lua-scripted token buckets; per-process circuit breaker falls back to v1.0 in-process behavior on Redis outage. See [`docs/deploy/redis.md`](docs/deploy/redis.md).
- **v1.2** — multi-replica HA completion: audit-emitter cross-replica dedup via per-emit `event_id` (used as OpenSearch `_id`) + queryable `request_id` correlation. Closes the second half of the v1.0 HA caveat. See [`docs/deploy/observability.md`](docs/deploy/observability.md).

See `docs/superpowers/specs/` for full specs per milestone.

## Deploying

Topic-organized deploy guides:

- [Install + first-run](docs/deploy/install.md) — three install paths, config layout, stdio vs HTTP.
- [TenantConfig reference](docs/deploy/tenants.md) — every per-tenant field, validator, and semantics.
- [OAuth 2.1](docs/deploy/oauth.md) — JWKS, IssuerIndex semantics, `wazuh_user` claim mapping.
- [Secrets](docs/deploy/secrets.md) — YAML / AWS / Vault / SQLite+age drivers + caching wrapper.
- [Read tools](docs/deploy/tools.md) — 17 reads + `cluster.status` + 3 resources + 3 prompts.
- [Write tools](docs/deploy/writes.md) — 9 writes, two-layer allowlist, `confirm` UX, rule-file lifecycle.
- [Multi-tenant](docs/deploy/multi-tenant.md) — per-tenant resolvers, rate-limit, audit fan-out.
- [Observability](docs/deploy/observability.md) — OTel, Prometheus, audit emitter + sinks, `WazuhError.scope`.
- [Quality gates](docs/deploy/quality-gates.md) — eval harness, security CI, multi-manager workflow.
- [Helm chart](docs/deploy/helm.md) — Kubernetes deployment with bring-your-own Secret.
- [Redis rate limiter](docs/deploy/redis.md) — opt-in v1.1 backend for multi-replica deployments.
- [API reference](docs/api-reference.md) — comprehensive per-tool args/result/RBAC/audit reference.

The pre-v1.0.0 per-milestone deploy notes are preserved at [`docs/deploy/_archive/`](docs/deploy/_archive/) for git-history archeology.
