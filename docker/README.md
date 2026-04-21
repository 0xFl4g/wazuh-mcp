# Integration fixtures

The stack is a single-node Wazuh indexer plus a one-shot certificate generator.
We only run the indexer because M1's client only uses port 9200 (OpenSearch
REST, basic auth). The Wazuh manager service is added back in M3 when the
Server API client lands.

## Platform note

The Wazuh images are linux/amd64. On arm64 hosts they run under emulation
(about 2x slower to boot). The healthcheck allows up to 90s of initialisation
plus 60 retries at 10s, so the first boot on arm64 can take 2–3 minutes.

## Bootstrap (recommended)

    docker/bootstrap.sh

One command: starts compose, initialises the OpenSearch security plugin
(required on every fresh boot — the Wazuh 4.9 image does not auto-init
it), waits for the cluster to go green, and seeds 20 synthetic alerts.

## Start manually (advanced)

    docker compose -f docker/integration-compose.yml up -d

The `generator` service runs once, writes certs under
`docker/config/wazuh_indexer_ssl_certs/` (gitignored), and exits. The
`wazuh-indexer` then boots using those certs.

After it's up, run `securityadmin.sh` inside the container to initialise
the security plugin, then seed:

    docker exec docker-wazuh-indexer-1 bash -c '
      /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
        -cd /usr/share/wazuh-indexer/opensearch-security/ -nhnv \
        -cacert /usr/share/wazuh-indexer/certs/root-ca.pem \
        -cert /usr/share/wazuh-indexer/certs/admin.pem \
        -key /usr/share/wazuh-indexer/certs/admin-key.pem \
        -h localhost'
    uv run python docker/seed_alerts.py

## Run tests

    uv run pytest -m integration

## Tear down

    docker compose -f docker/integration-compose.yml down -v

## Reset certs

    rm -rf docker/config/wazuh_indexer_ssl_certs
