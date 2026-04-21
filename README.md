# wazuh-mcp

Model Context Protocol server for Wazuh SIEM/XDR.

**Status:** M1 (walking skeleton). Single tenant, single tool (`search_alerts`),
stdio transport. See `docs/superpowers/specs/2026-04-20-wazuh-mcp-design.md`
for the full v1 design and `docs/superpowers/plans/` for the milestone
roadmap.

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
