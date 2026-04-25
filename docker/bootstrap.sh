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

# ---------- TEMPORARY: probe Wazuh 4.9 API for skip-marked tests ----------
# Remove these probes once the create_rule + MITRE endpoints are mapped.
TOKEN=$(curl -sku wazuh-wui:MCPmcp12345! \
    "https://localhost:55000/security/user/authenticate?raw=true" 2>/dev/null || true)
if [ -n "$TOKEN" ]; then
    echo "[probe] === MITRE: GET /mitre/techniques (no filter, limit=3) ==="
    curl -sk -H "Authorization: Bearer $TOKEN" \
        "https://localhost:55000/mitre/techniques?limit=3" | head -c 1500
    echo
    echo "[probe] === MITRE: GET /mitre/techniques?q=external_id=T1110 ==="
    curl -sk -H "Authorization: Bearer $TOKEN" \
        "https://localhost:55000/mitre/techniques?q=external_id=T1110" | head -c 1500
    echo
    echo "[probe] === MITRE: GET /mitre/techniques?external_id=T1110 (param not q) ==="
    curl -sk -H "Authorization: Bearer $TOKEN" \
        "https://localhost:55000/mitre/techniques?external_id=T1110" | head -c 1500
    echo
    echo "[probe] === MITRE: GET /mitre/metadata ==="
    curl -sk -H "Authorization: Bearer $TOKEN" \
        "https://localhost:55000/mitre/metadata" | head -c 1500
    echo

    XML='<group name="wazuh-mcp"><rule id="100100" level="5"><description>probe</description></rule></group>'
    echo "[probe] === RULE: PUT /manager/files?path=etc/rules/probe.xml&overwrite=true ==="
    curl -sk -w "\n[probe] http=%{http_code}\n" -X PUT \
        -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/xml" \
        --data-raw "$XML" \
        "https://localhost:55000/manager/files?path=etc/rules/probe.xml&overwrite=true" \
        | head -c 1500
    echo
    echo "[probe] === RULE: PUT /manager/files?path=ruleset/rules/probe.xml&overwrite=true ==="
    curl -sk -w "\n[probe] http=%{http_code}\n" -X PUT \
        -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/xml" \
        --data-raw "$XML" \
        "https://localhost:55000/manager/files?path=ruleset/rules/probe.xml&overwrite=true" \
        | head -c 1500
    echo
    echo "[probe] === RULE: PUT /manager/files/etc/rules/probe.xml?overwrite=true ==="
    curl -sk -w "\n[probe] http=%{http_code}\n" -X PUT \
        -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/xml" \
        --data-raw "$XML" \
        "https://localhost:55000/manager/files/etc/rules/probe.xml?overwrite=true" \
        | head -c 1500
    echo
    echo "[probe] === RULE: PUT /manager/files/rules/probe.xml?overwrite=true (legacy) ==="
    curl -sk -w "\n[probe] http=%{http_code}\n" -X PUT \
        -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/xml" \
        --data-raw "$XML" \
        "https://localhost:55000/manager/files/rules/probe.xml?overwrite=true" \
        | head -c 1500
    echo
fi
# ---------- END TEMPORARY PROBES ----------

echo "[bootstrap] ready. Run: uv run pytest -m integration"
