# wazuh-mcp

Model Context Protocol server for Wazuh SIEM/XDR.

**Status:** M3 in progress. Multi-tenant, OAuth 2.1 + API-key auth, stdio + Streamable HTTP transports. Full tool surface (17 tools across 6 domains, 3 resources, 3 prompts). See `docs/superpowers/specs/` for design specs per milestone.

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

See `docs/deploy/m3-tools.md` for the per-tool argument reference.

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
- **M2 (v0.2.0-m2)** — this release. Adds Streamable HTTP transport, OAuth 2.1 + API-key auth, multi-tenant session routing, per-tenant IndexerClient pool. Tool surface unchanged.
- **M3 (planned)** — full tool surface (~14 tools), Server API client, resources, prompts.
- **M4 (planned)** — production hardening: real secret backends, RBAC-aware tools, rate limits, OTel, write-tool scaffolding.
- **M5 (planned)** — ship-gate: eval harness, Wazuh LTS matrix CI, cross-tenant leak suite, full docs.

See `docs/superpowers/specs/` for full specs per milestone.

## Deploying M2

See `docs/deploy/m2-http.md` for the full remote-deployment guide (uvicorn + Caddy + OAuth IdP).
