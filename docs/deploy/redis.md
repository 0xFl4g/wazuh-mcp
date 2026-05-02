# Redis-backed rate limiter (v1.1+)

The `RateLimiter` Protocol has two backends: in-process (default, per-replica) and Redis (opt-in, shared across replicas). Use Redis when running `replicaCount > 1` so the configured rate budget is enforced fleet-wide instead of multiplied by replica count.

## Architecture

Two-tier token bucket: tenant + session. Both buckets live in Redis as hashes, keyed by `{prefix}:tenant:{tenant_id}` and `{prefix}:session:{tenant_id}:{session_id}`. Refill+consume happens atomically via a Lua script. The script is deterministic (caller-supplied wall clock, no `redis.call('TIME')`), so it's safe under Redis Cluster replication.

A per-process asyncio circuit breaker wraps every Redis call. On consecutive failures, the breaker opens and `acquire()` calls route to a per-replica in-process limiter for the duration of the outage. The breaker re-closes after Redis recovers. Effective fleet-wide rate during fallback is `replicas × configured_rate` — i.e. degrades to v1.0 behavior. This is the documented "degraded" mode.

## Configuration

`server.yaml` gains an optional `rate_limiter:` block:

```yaml
rate_limiter:
  backend: "redis"               # default "in_process"; only "redis" enables external store
  redis:
    key_prefix: "wazuhmcp:rl"     # default; lets multiple deployments share a Redis
    call_timeout_ms: 50           # per-Redis-call asyncio timeout
    circuit_breaker:
      error_threshold: 3          # consecutive failures before opening
      open_duration_sec: 5        # how long to stay open before half-open probe
      half_open_max_calls: 1      # probe with one call; success → closed, failure → re-open
```

URL via env var (Helm sources from a Secret):

```bash
WAZUH_MCP_REDIS_URL=rediss://default:hunter2@redis.svc:6380/0
```

URL syntax: `redis://`, `rediss://` (TLS), and `redis-sentinel://...` are all honored by `redis-py 5.x`'s `Redis.from_url`. For Redis Cluster, the `Redis.from_url` constructor handles cluster URLs transparently.

If `rate_limiter.backend == "redis"` but `WAZUH_MCP_REDIS_URL` is unset, the server fails to start with a clear error — no silent fallback to in-process for a deployment that asked for redis.

## Helm wiring

```yaml
# values.yaml
redis:
  enabled: true
  existingSecret: my-redis-creds   # K8s Secret with key 'redis-url'

server:
  yaml: |
    transport: http
    auth: oauth_chain
    # ... existing server config ...
    rate_limiter:
      backend: redis
      redis:
        key_prefix: "wazuhmcp:rl"
        call_timeout_ms: 50
```

Create the Secret separately:

```bash
kubectl create secret generic my-redis-creds \
  --from-literal=redis-url="rediss://default:hunter2@redis.svc:6380/0"
```

The chart does not ship a Redis subchart. BYO Redis (managed: ElastiCache, Memorystore, etc.; or self-hosted via the bitnami/redis Helm chart you maintain separately).

## Sizing

- Tenant bucket: ~200 bytes per tenant — negligible.
- Session bucket: ~250 bytes per active session. With TTL ≈ `2 × capacity / refill_per_sec`, abandoned sessions evict naturally.
- A 10K concurrent-session deployment: ~2.5 MB. Redis memory is not a concern at realistic v1.x scales.

## Observability

Three new metrics exported at `/metrics`:

| Metric | Type | Labels | Alert |
|---|---|---|---|
| `rate_limit_redis_state` | Gauge (0=closed, 1=half_open, 2=open) | `replica` | `>0` for >5 min |
| `rate_limit_redis_call_total` | Counter | `outcome=ok\|timeout\|error` | error rate >1% sustained |
| `rate_limit_fallback_total` | Counter | `tenant_id`, `scope=tenant\|session` | volume spikes during incidents |

`/healthz` reflects breaker state under `rate_limiter`:

```json
{
  "status": "ok",
  "rate_limiter": {"backend": "redis", "redis": "ok"}
}
```

`redis` field values: `"ok"` | `"degraded"` | `"disabled"`. `degraded` surfaces when the breaker is OPEN or HALF_OPEN.

The pre-existing `rate_limited_total{tenant,scope}` counter (counts user-facing 429s) keeps its meaning unchanged — it counts denials from either backend.

## Failure modes

- **Redis unreachable at startup** → server fails to start with a clear error. Fix the URL or unset `rate_limiter.backend = redis` to fall back to in-process.
- **Redis goes away mid-flight** → first failure increments the breaker counter; after `error_threshold` consecutive failures the breaker opens; `acquire()` calls then route to the per-replica in-process limiter. No user-visible errors during the outage. Once `open_duration_sec` elapses, a probe call retries Redis; success → re-closed.
- **Redis flushes the script cache** (e.g., after a restart) → first call detects `NOSCRIPT`, reloads the script, and retries transparently.
- **Replica clock skew** → the Lua script clamps negative elapsed time to 0 and refreshes `last_refill_ms` to the new wall-clock. Replicas with skewed clocks won't credit phantom refill.

## Migration from v1.0

None required. New optional config block. Existing v1.0 deployments without a `rate_limiter:` block in `server.yaml` are byte-for-byte unchanged. To opt in:

1. Stand up Redis (managed: ElastiCache, Memorystore, etc.; or self-hosted).
2. Create a K8s Secret with the URL: `kubectl create secret generic ... --from-literal=redis-url=...`
3. Set `redis.enabled=true` and `redis.existingSecret=<secret-name>` in Helm values.
4. Add a `rate_limiter:` block to your `.Values.server.yaml`.
5. (Eventually, post-v1.2) bump `replicaCount`.

## Trade-offs

- **Partial-credit during Redis flap.** If the tenant-bucket Redis call succeeds but the session-bucket call fails, the tenant token is "spent" without a corresponding session consume. Slight over-counting on flap, never under-counting against the upstream Wazuh API cap — safety-critical direction is correct.
- **Per-replica breaker decisions.** Each replica's breaker decides independently. A flapping Redis can have replica A in CLOSED and replica B in OPEN at the same instant — fine; each replica's fallback is per-replica anyway.
- **Two round-trips per `acquire()`.** Tenant + session buckets are two separate EVALSHA calls. Could be collapsed into a MULTI block to halve latency; deferred to a future optimization.
