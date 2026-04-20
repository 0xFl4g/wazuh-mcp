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

    docker compose -f docker/integration-compose.yml up -d
    # wait for wazuh-indexer healthcheck
    uv run python docker/seed_alerts.py
    uv run pytest -m integration
    docker compose -f docker/integration-compose.yml down -v

## M1 scope

One tool, `search_alerts`, with filters: `time_range` (required, `1m` to `30d`), `min_level`, `agent_id`, `size` (hard-capped at 100), `cursor` for pagination. Results include `structuredContent` (alerts, total, next_cursor, truncated) and a short text summary.

## Roadmap

See `docs/superpowers/specs/2026-04-20-wazuh-mcp-design.md` §9.
