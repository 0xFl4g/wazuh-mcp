#!/usr/bin/env bash
# One-shot bootstrap for the integration fixture.
#
# Brings up Wazuh + Keycloak, initialises OpenSearch security, seeds alerts.
# Keycloak imports its realm from docker/config/keycloak-realm.json at startup.
#
# Usage: docker/bootstrap.sh
# Teardown: docker compose -f docker/integration-compose.yml down -v
set -euo pipefail

COMPOSE_FILE="$(dirname "$0")/integration-compose.yml"
INDEXER_CONTAINER="${COMPOSE_PROJECT_NAME:-docker}-wazuh-indexer-1"
KEYCLOAK_URL="http://localhost:8080"
INDEXER_URL="https://localhost:9200"
ADMIN_AUTH="admin:admin"

echo "[bootstrap] bringing up compose stack..."
docker compose -f "$COMPOSE_FILE" up -d

echo "[bootstrap] waiting for wazuh-indexer to accept connections..."
for _ in $(seq 1 60); do
    if docker exec "$INDEXER_CONTAINER" curl -sk -o /dev/null -w '%{http_code}' \
        "$INDEXER_URL/_cluster/health" 2>/dev/null | grep -qE '^(200|401|503)$'; then
        break
    fi
    sleep 5
done

echo "[bootstrap] initialising OpenSearch security plugin..."
docker exec "$INDEXER_CONTAINER" bash -c '
    export JAVA_HOME=/usr/share/wazuh-indexer/jdk
    /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
        -cd /usr/share/wazuh-indexer/opensearch-security/ \
        -nhnv \
        -cacert /usr/share/wazuh-indexer/certs/root-ca.pem \
        -cert /usr/share/wazuh-indexer/certs/admin.pem \
        -key /usr/share/wazuh-indexer/certs/admin-key.pem \
        -h localhost
' > /dev/null

echo "[bootstrap] waiting for cluster to go green..."
for _ in $(seq 1 30); do
    status=$(curl -sk -u "$ADMIN_AUTH" "$INDEXER_URL/_cluster/health" 2>/dev/null \
        | grep -oE '"status":"[^"]+"' || true)
    case "$status" in
        *green*|*yellow*) break ;;
    esac
    sleep 2
done

echo "[bootstrap] seeding synthetic alerts..."
uv run python "$(dirname "$0")/seed_alerts.py"

echo "[bootstrap] waiting for Keycloak realm..."
for _ in $(seq 1 60); do
    if curl -sf "$KEYCLOAK_URL/realms/wazuh-mcp/.well-known/openid-configuration" \
        > /dev/null 2>&1; then
        echo "[bootstrap] Keycloak realm ready."
        break
    fi
    sleep 5
done

echo "[bootstrap] waiting for wazuh-manager Server API..."
for _ in $(seq 1 40); do
    if curl -sfku wazuh-wui:MCPmcp12345! \
        "https://localhost:55000/security/user/authenticate?raw=true" \
        > /dev/null 2>&1; then
        echo "[bootstrap] wazuh-manager API ready."
        break
    fi
    sleep 10
done

# wazuh-agent container auto-enrols against the manager via authd; wait
# until the manager reports it as active so M4b active-response/restart
# tests have a connected peer. ~2 min cap — failure surfaces in CI as a
# clear "agent never went active" rather than a flaky stall.
echo "[bootstrap] waiting for wazuh-agent to enrol + connect..."
TOKEN=$(curl -sku wazuh-wui:MCPmcp12345! \
    "https://localhost:55000/security/user/authenticate?raw=true" 2>/dev/null || true)
for _ in $(seq 1 40); do
    if [ -n "$TOKEN" ] && curl -sk -H "Authorization: Bearer $TOKEN" \
        "https://localhost:55000/agents?status=active" 2>/dev/null \
        | grep -q '"id":"001"'; then
        echo "[bootstrap] wazuh-agent connected as id=001."
        break
    fi
    sleep 5
done

echo "[bootstrap] ready. Run: uv run pytest -m integration"
