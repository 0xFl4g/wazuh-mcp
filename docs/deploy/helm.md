# Deploying wazuh-mcp on Kubernetes via Helm

`charts/wazuh-mcp/` ships a production-baseline single-replica Helm chart suitable for v1.0.0 deployments. This guide covers install, upgrade, and the deliberately scoped HA caveat.

## Prerequisites

- Kubernetes 1.26+ (any conformant distribution).
- Helm 3.16+.
- A reachable Wazuh manager (port 55000) and Wazuh indexer (port 9200) — either in-cluster or via egress.
- An OIDC issuer (Keycloak, Okta, Entra, Auth0) for OAuth-based MCP client auth, OR API-key tenant config.
- A container image of wazuh-mcp. v1.0.0 ships the chart only; bring your own image (operator builds from source or pulls from a registry — see "Image" below).

## Quick install

Bring-your-own Secret pattern (recommended for production):

```bash
# 1. Create the Secret out-of-band.
kubectl create secret generic wazuh-mcp-secrets \
  --from-literal=secrets.yaml="$(cat <<'EOF'
default:
  oauth_client_secret: <your-oauth-client-secret>
  wazuh_api_password: <your-wazuh-api-password>
  indexer_admin_password: <your-indexer-password>
EOF
)"

# 2. Override values to point at the existing Secret.
helm install wazuh-mcp ./charts/wazuh-mcp \
  --set image.repository=ghcr.io/<your-org>/wazuh-mcp \
  --set image.tag=1.0.0 \
  --set secrets.existingSecret=wazuh-mcp-secrets \
  --set 'tenants.yaml=<your-tenants-yaml-content>'
```

Stub-Secret pattern (dev/test only — secrets land in a chart-managed Kubernetes Secret):

```bash
helm install wazuh-mcp ./charts/wazuh-mcp \
  --set image.repository=ghcr.io/<your-org>/wazuh-mcp \
  --set image.tag=1.0.0 \
  --set secrets.create=true \
  --set-file secrets.yaml=./local-secrets.yaml
```

## Configuration

`values.yaml` exposes:

| Key | Default | Notes |
|-----|---------|-------|
| `image.repository` | `ghcr.io/0xfl4g/wazuh-mcp` | Override to your registry path. |
| `image.tag` | `""` (resolves to `.Chart.AppVersion`) | Pin a specific image tag. |
| `image.pullPolicy` | `IfNotPresent` | Standard Kubernetes semantics. |
| `replicaCount` | `1` | **Do not raise** — see HA caveat below. |
| `resources.requests.cpu` | `100m` | |
| `resources.requests.memory` | `128Mi` | |
| `resources.limits.cpu` | `500m` | |
| `resources.limits.memory` | `512Mi` | |
| `tenants.yaml` | minimal default | Inlined into a ConfigMap mounted at `/config/tenants.yaml`. |
| `server.yaml` | `bind: 0.0.0.0:8080` | Inlined into the same ConfigMap. |
| `secrets.create` | `false` | When true, chart templates a stub Secret. Set false for production. |
| `secrets.existingSecret` | `""` | Name of an existing Kubernetes Secret. Required when `create: false`. |
| `secrets.yaml` | `""` | Full secrets.yaml document (used only when `create: true`). |
| `probes.readiness.path` | `/readyz` | Wazuh-MCP's readiness endpoint. |
| `probes.liveness.path` | `/healthz` | Wazuh-MCP's liveness endpoint. |
| `service.type` | `ClusterIP` | Override to `LoadBalancer` or `NodePort` if exposing externally without Ingress. |
| `service.port` | `8080` | Matches the `bind` port in server.yaml. |
| `networkPolicy.enabled` | `false` | Opt-in NetworkPolicy. See "NetworkPolicy" below. |
| `serviceMonitor.enabled` | `false` | Opt-in Prometheus Operator ServiceMonitor on `/metrics`. |
| `ingress.enabled` | `false` | Opt-in nginx-class Ingress with cert-manager TLS. |

### Configuration model

wazuh-mcp loads its full config from a directory pointed at by `WAZUH_MCP_CONFIG_DIR` (the chart sets it to `/config`). The directory contains:

- `server.yaml` — HTTP transport config (bind address, OAuth defaults, etc.).
- `tenants.yaml` — per-tenant routing, RBAC, secret mappings, allowlists.
- `secrets.yaml` — per-tenant credentials (OAuth client secrets, Wazuh API password, indexer creds).

The chart mounts `server.yaml` + `tenants.yaml` from the ConfigMap and `secrets.yaml` from the Secret, both into `/config`. All three files end up in the same directory at runtime.

### tenants.yaml

Pass via `--set-file 'tenants.yaml=./tenants.yaml'` for clean multi-line override, or inline via `--set 'tenants.yaml=<...>'`. Schema reference is at the top-level wazuh-mcp docs; the M5b release adds the new `agent_group_allowlist` field for `write.run_active_response_on_group`.

## Opt-in extras

### NetworkPolicy

```bash
helm upgrade wazuh-mcp ./charts/wazuh-mcp \
  --set networkPolicy.enabled=true \
  --set networkPolicy.ingressFromNamespaces='{claude-clients}' \
  --set networkPolicy.egressTo.wazuhManager.host=wazuh-manager.security.svc \
  --set networkPolicy.egressTo.wazuhIndexer.host=wazuh-indexer.security.svc \
  --set networkPolicy.egressTo.oidcIssuer.host=keycloak.identity.svc
```

The chart's NetworkPolicy template uses `0.0.0.0/0` placeholders for the egress CIDRs by default. **Operators MUST narrow these** to the actual Wazuh manager / indexer / OIDC issuer IPs in their environment, otherwise the NetworkPolicy provides no actual egress isolation. Edit `values.yaml` directly or override per-key.

### ServiceMonitor (Prometheus Operator)

```bash
helm upgrade wazuh-mcp ./charts/wazuh-mcp \
  --set serviceMonitor.enabled=true \
  --set serviceMonitor.interval=30s
```

Targets the unauthenticated `/metrics` endpoint on the Service. Requires the Prometheus Operator CRDs installed in the cluster.

### Ingress

```bash
helm upgrade wazuh-mcp ./charts/wazuh-mcp \
  --set ingress.enabled=true \
  --set ingress.host=mcp.example.com \
  --set ingress.className=nginx \
  --set ingress.tls.enabled=true \
  --set ingress.tls.secretName=mcp-tls
```

Cert-manager users add the standard `cert-manager.io/cluster-issuer` annotation via `ingress.annotations`.

## HA caveat

**v1.2 closes the last v1.0 HA blocker.** Multi-replica deployments are now fully supported when both `redis.enabled=true` AND `replicaCount: 2+` are set. The audit emitter's cross-replica deduplication is solved at the OpenSearch index layer: every event carries a per-emit `event_id` (used as the `_id`) so retries from any replica's `QueuedSink` upsert idempotently. A queryable `request_id` field exposes the originating JSON-RPC request id for query-time correlation when needed. See [`docs/deploy/observability.md`](observability.md) for query examples.

Status of the original v1.0 blockers — **both closed:**

1. **Rate-limiter** — closed in v1.1. `RedisRateLimiter` (Lua-scripted token bucket, atomic refill+consume) shares the budget fleet-wide. On Redis outage, a per-process circuit breaker routes calls to a per-replica `InProcessRateLimiter` fallback, degrading to v1.0 behavior until Redis recovers. See [`docs/deploy/redis.md`](redis.md).
2. **Audit emitter dedup** — closed in v1.2. Per-emit `event_id` UUID + queryable `request_id`. Existing audit consumers parsing `local-audit-*` keep working — the new fields are additive.

The chart's default `replicaCount: 1` and `redis.enabled: false` stay. Bumping the default to multi-replica was rejected because it would force every existing operator to either provide a Redis Secret they may not have or explicitly pin `replicaCount: 1`. Operators who want HA opt in explicitly:

1. Stand up Redis (managed: ElastiCache, Memorystore, etc.; or self-hosted).
2. `kubectl create secret generic my-redis-creds --from-literal=redis-url=...`
3. Set `redis.enabled=true`, `redis.existingSecret=my-redis-creds`, AND `replicaCount: 2+` in Helm values.
4. Add a `rate_limiter:` block to your `.Values.server.yaml`.

Operators upgrading from v1.1 to v1.2 see no behavior change unless they explicitly bump `replicaCount`. Existing daily audit indices accept the new event fields on writes but won't field-index them until rollover; see [`docs/deploy/observability.md`](observability.md) for the manual `_rollover` step if you want immediate field-indexed visibility.

## Image

v1.0.0 does not ship a container image. The chart references `image.repository: ghcr.io/0xfl4g/wazuh-mcp` as a placeholder. Operator paths:

1. **Build from source.** Clone the repo, build a Python 3.12-based image with `uv sync` + `wazuh-mcp` entrypoint, push to your registry. Reference Dockerfile to be added in a v1.0.x patch.
2. **Wait for pre-built images.** A v1.0.x patch will publish images to GitHub Container Registry. Watch the repo releases page.

## Validating a deployment

After `helm install`:

```bash
kubectl get pods -l app.kubernetes.io/name=wazuh-mcp
kubectl logs -l app.kubernetes.io/name=wazuh-mcp -f

# helm test runs the bundled smoke pod that probes /readyz
helm test wazuh-mcp
```

The smoke pod uses `curlimages/curl:8.10.1` to GET `/readyz` against the in-cluster Service — verifies the pod is reachable and reports ready, but does NOT verify upstream Wazuh connectivity. End-to-end verification: invoke an MCP tool from a Claude Code client configured against the Service URL.

## Upgrade

```bash
helm upgrade wazuh-mcp ./charts/wazuh-mcp \
  --set image.tag=1.0.x \
  --reuse-values
```

The Deployment template includes `checksum/config` and `checksum/secret` annotations on the pod template, so updating tenants.yaml or secrets.yaml triggers a rolling restart on `helm upgrade`.

## Uninstall

```bash
helm uninstall wazuh-mcp
```

Removes Deployment, Service, ConfigMap, ServiceAccount, Role, RoleBinding, and (if `secrets.create=true`) the chart-managed Secret. Existing Secrets referenced via `existingSecret` are NOT removed (operator owns them).

## Source

Chart at `charts/wazuh-mcp/`. CI verifies `helm lint` + `helm template` (with both default values and all opt-ins enabled) on every PR touching `charts/**`. See `.github/workflows/helm-lint.yml`.
