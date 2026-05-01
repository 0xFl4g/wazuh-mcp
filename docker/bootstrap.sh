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
MULTI_MANAGER_FILE="$(dirname "$0")/multi-manager-compose.yml"
INDEXER_CONTAINER="${COMPOSE_PROJECT_NAME:-docker}-wazuh-indexer-1"
INDEXER_2_CONTAINER="${COMPOSE_PROJECT_NAME:-docker}-wazuh-indexer-2-1"
KEYCLOAK_URL="http://localhost:8080"
INDEXER_URL="https://localhost:9200"
INDEXER_2_URL="https://localhost:9201"
MANAGER_2_URL="https://localhost:55001"
ADMIN_AUTH="admin:admin"

# M5b T-C1. MULTI_MANAGER=1 layers docker/multi-manager-compose.yml on top
# of the base stack (adds wazuh-indexer-2 + wazuh-manager-2 on shifted host
# ports 9201/55001). Wait-for-cluster-2 logic mirrors the cluster-1 path.
COMPOSE_ARGS=("-f" "$COMPOSE_FILE")
if [ "${MULTI_MANAGER:-0}" = "1" ]; then
    COMPOSE_ARGS+=("-f" "$MULTI_MANAGER_FILE")
fi

echo "[bootstrap] bringing up compose stack..."
docker compose "${COMPOSE_ARGS[@]}" up -d

echo "[bootstrap] waiting for wazuh-indexer to accept connections..."
for _ in $(seq 1 60); do
    if docker exec "$INDEXER_CONTAINER" curl -sk -o /dev/null -w '%{http_code}' \
        "$INDEXER_URL/_cluster/health" 2>/dev/null | grep -qE '^(200|401|503)$'; then
        break
    fi
    sleep 5
done

echo "[bootstrap] initialising OpenSearch security plugin..."
# securityadmin.sh exits 255 if the cluster isn't fully formed yet, even
# when the HTTP probe above accepted a 401/503 response. Retry a few
# times before giving up — observed flake on GH Actions runners.
sec_init_ok="no"
for attempt in 1 2 3 4; do
    if docker exec "$INDEXER_CONTAINER" bash -c '
        export JAVA_HOME=/usr/share/wazuh-indexer/jdk
        /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
            -cd /usr/share/wazuh-indexer/opensearch-security/ \
            -nhnv \
            -cacert /usr/share/wazuh-indexer/certs/root-ca.pem \
            -cert /usr/share/wazuh-indexer/certs/admin.pem \
            -key /usr/share/wazuh-indexer/certs/admin-key.pem \
            -h localhost
    ' > /dev/null 2>&1; then
        sec_init_ok="yes"
        break
    fi
    echo "[bootstrap] securityadmin.sh attempt $attempt failed, retrying in 10s..."
    sleep 10
done
if [ "$sec_init_ok" != "yes" ]; then
    echo "[bootstrap] securityadmin.sh failed after 4 attempts" >&2
    exit 1
fi

# CI runners frequently sit above OpenSearch's default flood-stage disk
# watermark (95%), which makes every index read-only-allow-delete. For
# the integration fixture this is a hard blocker — relax thresholds and
# clear any block that a prior run already set on the daily alerts
# index. Test-fixture only; no production impact.
echo "[bootstrap] relaxing disk watermarks for CI test cluster..."
curl -sk -u "$ADMIN_AUTH" -X PUT "$INDEXER_URL/_cluster/settings" \
    -H "Content-Type: application/json" \
    -d '{"transient": {"cluster.routing.allocation.disk.watermark.low": "97%", "cluster.routing.allocation.disk.watermark.high": "98%", "cluster.routing.allocation.disk.watermark.flood_stage": "99%"}}' \
    > /dev/null
curl -sk -u "$ADMIN_AUTH" -X PUT "$INDEXER_URL/_all/_settings" \
    -H "Content-Type: application/json" \
    -d '{"index.blocks.read_only_allow_delete": null}' \
    > /dev/null

echo "[bootstrap] waiting for cluster to go green..."
for _ in $(seq 1 30); do
    status=$(curl -sk -u "$ADMIN_AUTH" "$INDEXER_URL/_cluster/health" 2>/dev/null \
        | grep -oE '"status":"[^"]+"' || true)
    case "$status" in
        *green*|*yellow*) break ;;
    esac
    sleep 2
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

# seed_alerts.py registers agent 001 + creates test-group via the
# manager API, so it must run AFTER the manager API responds. Pre-this
# move it ran during the manager's first ~30s of boot and the
# /agents POST timed out under load.
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

# wazuh-agent container auto-enrols against the manager via authd; wait
# until the manager reports it as active so M4b active-response/restart
# tests have a connected peer. Bounded at ~2 min; if it never goes
# active, downstream tests that need a connected agent will surface
# specific errors rather than just stalling.
echo "[bootstrap] waiting for wazuh-agent to enrol + connect..."
TOKEN=$(curl -sku wazuh-wui:MCPmcp12345! \
    "https://localhost:55000/security/user/authenticate?raw=true" 2>/dev/null || true)
agent_connected="no"
for _ in $(seq 1 40); do
    if [ -n "$TOKEN" ]; then
        # Use python to parse the JSON properly — Wazuh's response
        # interleaves whitespace inconsistently so a static grep is
        # fragile. ``status=active`` with ``agents_list=001`` returns
        # ``total_affected_items: 1`` only if 001 is actually active.
        active=$(curl -sk -H "Authorization: Bearer $TOKEN" \
            "https://localhost:55000/agents?agents_list=001&status=active" 2>/dev/null \
            | python3 -c "import sys, json; d=json.load(sys.stdin); print((d.get('data') or {}).get('total_affected_items', 0))" \
            2>/dev/null || echo 0)
        if [ "$active" = "1" ]; then
            echo "[bootstrap] wazuh-agent connected as id=001."
            agent_connected="yes"
            break
        fi
    fi
    sleep 5
done
if [ "$agent_connected" != "yes" ]; then
    echo "[bootstrap] wazuh-agent did NOT report as active within timeout — active-response/restart tests will likely fail."
fi

# M5b T-C1. When MULTI_MANAGER=1, mirror the securityadmin + manager-API
# wait for cluster 2. seed_alerts.py is NOT re-run against cluster 2 — the
# multi_manager federation tests deliberately assert that tenant_b sees
# NO seeded agent 001 (which only exists on cluster 1). Cluster 2 is left
# in its post-securityadmin "empty" state.
if [ "${MULTI_MANAGER:-0}" = "1" ]; then
    echo "[bootstrap] (multi-manager) waiting for wazuh-indexer-2 to accept connections..."
    for _ in $(seq 1 60); do
        if docker exec "$INDEXER_2_CONTAINER" curl -sk -o /dev/null -w '%{http_code}' \
            "$INDEXER_URL/_cluster/health" 2>/dev/null | grep -qE '^(200|401|503)$'; then
            break
        fi
        sleep 5
    done

    echo "[bootstrap] (multi-manager) initialising OpenSearch security plugin on cluster 2..."
    sec_init_ok="no"
    for attempt in 1 2 3 4; do
        if docker exec "$INDEXER_2_CONTAINER" bash -c '
            export JAVA_HOME=/usr/share/wazuh-indexer/jdk
            /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
                -cd /usr/share/wazuh-indexer/opensearch-security/ \
                -nhnv \
                -cacert /usr/share/wazuh-indexer/certs/root-ca.pem \
                -cert /usr/share/wazuh-indexer/certs/admin.pem \
                -key /usr/share/wazuh-indexer/certs/admin-key.pem \
                -h localhost
        ' > /dev/null 2>&1; then
            sec_init_ok="yes"
            break
        fi
        echo "[bootstrap] (multi-manager) cluster-2 securityadmin.sh attempt $attempt failed, retrying in 10s..."
        sleep 10
    done
    if [ "$sec_init_ok" != "yes" ]; then
        echo "[bootstrap] (multi-manager) cluster-2 securityadmin.sh failed after 4 attempts" >&2
        exit 1
    fi

    echo "[bootstrap] (multi-manager) relaxing disk watermarks for cluster 2..."
    curl -sk -u "$ADMIN_AUTH" -X PUT "$INDEXER_2_URL/_cluster/settings" \
        -H "Content-Type: application/json" \
        -d '{"transient": {"cluster.routing.allocation.disk.watermark.low": "97%", "cluster.routing.allocation.disk.watermark.high": "98%", "cluster.routing.allocation.disk.watermark.flood_stage": "99%"}}' \
        > /dev/null
    curl -sk -u "$ADMIN_AUTH" -X PUT "$INDEXER_2_URL/_all/_settings" \
        -H "Content-Type: application/json" \
        -d '{"index.blocks.read_only_allow_delete": null}' \
        > /dev/null

    echo "[bootstrap] (multi-manager) waiting for wazuh-manager-2 Server API..."
    for _ in $(seq 1 40); do
        if curl -sfku wazuh-wui:MCPmcp12345! \
            "$MANAGER_2_URL/security/user/authenticate?raw=true" \
            > /dev/null 2>&1; then
            echo "[bootstrap] (multi-manager) wazuh-manager-2 API ready."
            break
        fi
        sleep 10
    done
fi

echo "[bootstrap] ready. Run: uv run pytest -m integration"
