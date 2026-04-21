# Integration fixtures

The stack is a single-node Wazuh indexer plus a one-shot certificate generator.
We only run the indexer because M1's client only uses port 9200 (OpenSearch
REST, basic auth). The Wazuh manager service is added back in M3 when the
Server API client lands.

## Platform note

The Wazuh images are linux/amd64. On arm64 hosts they run under emulation
(about 2x slower to boot). The healthcheck allows up to 90s of initialisation
plus 60 retries at 10s, so the first boot on arm64 can take 2–3 minutes.

## Start

    docker compose -f docker/integration-compose.yml up -d

The `generator` service runs once, writes certs under
`docker/config/wazuh_indexer_ssl_certs/` (gitignored), and exits. The
`wazuh-indexer` then boots using those certs.

Wait for `docker compose ... ps` to show `wazuh-indexer` as `healthy`.

## Seed

    uv run python docker/seed_alerts.py

## Run tests

    uv run pytest -m integration

## Tear down

    docker compose -f docker/integration-compose.yml down -v

## Reset certs

    rm -rf docker/config/wazuh_indexer_ssl_certs
