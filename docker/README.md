# Integration fixtures

## Start the stack

    docker compose -f docker/integration-compose.yml up -d
    # wait for wazuh-indexer to pass healthcheck (~60-120s on first boot)

## Seed synthetic alerts

    uv run python docker/seed_alerts.py

## Tear down

    docker compose -f docker/integration-compose.yml down -v
