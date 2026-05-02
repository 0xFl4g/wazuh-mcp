# v1.1 — Redis-backed RateLimiter

**Status:** approved (brainstorm 2026-05-02)
**Milestone:** v1.1
**Predecessor:** v1.0.10 (HEAD `b033615`)
**Scope:** rate limiter only. Audit-emitter dedup deferred to v1.2.

## Goal

Replace the per-replica in-memory `InProcessRateLimiter` with an external Redis-backed implementation so operators can run wazuh-mcp with `replicaCount > 1` without each replica independently enforcing its own rate budget. Today, two replicas with `tenant.capacity=250` give the fleet a 500-token effective budget — that violates Wazuh's 300/min Server API cap, which is the protected resource the limiter exists to defend.

## Non-goals (v1.1)

- Audit-emitter cross-replica dedup (deferred to v1.2; `MultiSinkAuditEmitter` keeps producing duplicate-keyed events when sessions hit different replicas).
- Bumping the Helm chart's `replicaCount` default (waits on the audit-dedup work).
- Changing the `RateLimiter` Protocol shape — stays `async def acquire(tenant_id, session_id) -> None`, fail-closed via `WazuhError(code="rate_limited", scope=...)`.
- Burst-window or fairness semantics — token bucket exactly as today, capacity + refill_per_sec.
- Redis Cluster manual slot routing. We use `redis-py >= 5.0`'s `Redis.from_url`, which transparently handles standalone, Sentinel, and Cluster URLs.
- Bundling a Redis subchart. BYO only.

## Decisions locked during brainstorm

| # | Decision | Rationale |
|---|---|---|
| 1 | **Failure mode = fall back to per-replica `InProcessRateLimiter`** when Redis is unhealthy. | Wazuh's 300/min cap is the protected resource (rules out fail-open); but a Redis outage shouldn't cascade into MCP outage (rules out fail-closed). Fallback degrades to v1.0 behavior — exactly the pre-acknowledged "degraded" mode in `docs/deploy/helm.md`. |
| 2 | **BYO Redis only.** Operator provides URL via env var. Chart ships no Redis subchart. | Realistic for production deployments (managed Redis: ElastiCache / Memorystore / etc.). Keeps chart upgrade story simple. Adding a bundled subchart later is non-breaking; removing one is breaking. |
| 3 | **Scope = rate limiter only.** Audit dedup deferred to v1.2. | Audit dedup is its own design problem (dedup key choice, write-time vs query-time, OpenSearch primitives). Bundling dilutes both. |
| 4 | **URL via env var, tunables in config file.** | Mirrors how `wazuh.api.password` already resolves (env-driven from `secrets.yaml` / K8s Secret at runtime). Clean separation: secrets in env, ops settings in config. |
| 5 | **Circuit breaker around Redis calls** (closed → open → half-open → closed). When OPEN, all `acquire()` calls go to per-replica `InProcessRateLimiter` without touching Redis. | Mirrors the existing `MultiSinkAuditEmitter` retry-with-fallback pattern. Avoids latency-pileup during Redis outages (each request would otherwise pay the per-call timeout). State + counters are observable. |

## Architecture

A new `RedisRateLimiter` implements the existing `RateLimiter` Protocol — semantically identical to `InProcessRateLimiter` (two-tier token bucket: tenant + session, fail-closed on budget exhaustion), but bucket state lives in Redis keyed by `(scope, id)` and refill+consume happens atomically via a Lua script.

A per-process asyncio circuit breaker wraps every Redis call. When OPEN, `acquire()` delegates to a per-replica `InProcessRateLimiter` instance held alongside the Redis client (lazy-constructed on first OPEN, kept warm). Each replica's breaker decides independently — flapping Redis can have replica A in CLOSED and replica B in OPEN at the same instant; safe because each replica's fallback is per-replica anyway.

The server-wiring code (`server.py:245` and `server.py:462`) gains one branch:
- `rate_limiter.backend == "redis"` *and* `WAZUH_MCP_REDIS_URL` set → build `RedisRateLimiter`.
- `rate_limiter.backend == "redis"` *and* `WAZUH_MCP_REDIS_URL` unset → fail at server start with a clear `ConfigError` (loud failure beats silent fallback to v1.0 behavior in a deployment that asked for redis).
- `rate_limiter.backend == "in_process"` or `rate_limiter:` block absent → build `InProcessRateLimiter`. Current v1.0 behavior, byte-for-byte.

## File layout

```
src/wazuh_mcp/rate_limit/
├── __init__.py            (unchanged)
├── token_bucket.py        (unchanged — in-process primitive)
├── limiter.py             (unchanged — RateLimiter Protocol + InProcessRateLimiter)
├── redis_limiter.py       (new — RedisRateLimiter + circuit breaker class)
└── lua/
    └── token_bucket.lua   (new — atomic refill+consume)
```

The circuit breaker primitive (~80 LOC: state enum, counters, asyncio lock, half-open probe) lives inside `redis_limiter.py` — small enough that a separate module would fragment cognition.

## Dependencies

- Runtime: `redis>=5.0` (async-capable; supports `redis://`, `rediss://`, Sentinel-flavored URLs via `Redis.from_url`).
- Dev: `fakeredis>=2.20` (Lua-capable variant, for unit tests).

No other new runtime deps.

## Configuration

### Config file (`tenants.yaml`)

New top-level block, optional. Absence = use `InProcessRateLimiter`.

```yaml
rate_limiter:
  backend: "redis"               # default "in_process"
  redis:
    key_prefix: "wazuhmcp:rl"     # all keys under this prefix; lets a shared Redis serve multiple deployments
    call_timeout_ms: 50           # per-Redis-call asyncio timeout
    circuit_breaker:
      error_threshold: 3          # consecutive failures before opening
      open_duration_sec: 5        # how long to stay open before half-open probe
      half_open_max_calls: 1      # probe with one call; success → closed, failure → re-open
```

Pydantic validation enforces ranges (timeouts > 0, error_threshold ≥ 1, etc.). Sibling module to `tenancy/m4_config.py` so the M4 config stays small.

### Secret (env var)

`WAZUH_MCP_REDIS_URL` — required when `backend: "redis"`. Server start fails with a clear error if backend is `redis` but the env var is unset.

Examples:
- `redis://default:hunter2@redis.svc:6379/0`
- `rediss://default:hunter2@redis.svc:6380/0`
- `redis-sentinel://default:hunter2@s1,s2,s3:26379/mymaster/0`

Helm chart wires this from a `Secret` named via `redis.existingSecret` (key: `redis-url`). New optional `redis-credentials` Secret manifest can be templated when the operator opts in via Helm values.

## Bucket key shape

| Bucket | Redis key | Hash fields |
|---|---|---|
| Tenant | `{key_prefix}:tenant:{tenant_id}` | `tokens` (float), `last_refill_ms` (int) |
| Session | `{key_prefix}:session:{tenant_id}:{session_id}` | `tokens` (float), `last_refill_ms` (int) |

TTL set on every write to `max(2 × full_refill_window_seconds, 60)` where `full_refill_window_seconds = capacity / refill_per_sec`. Survives idle gaps; abandoned sessions evict naturally.

## Lua script — atomic refill+consume

Loaded once via `SCRIPT LOAD` at limiter init, called via `EVALSHA`. Falls back to `EVAL` on `NOSCRIPT` (e.g. after a Redis restart that flushed the script cache).

```lua
-- KEYS[1] = bucket key
-- ARGV   = capacity, refill_per_sec, now_ms, n_tokens, ttl_sec
local h = redis.call('HMGET', KEYS[1], 'tokens', 'last_refill_ms')
local capacity = tonumber(ARGV[1])
local refill   = tonumber(ARGV[2])
local now_ms   = tonumber(ARGV[3])
local n        = tonumber(ARGV[4])
local ttl      = tonumber(ARGV[5])

local tokens = tonumber(h[1]) or capacity            -- new bucket = full
local last   = tonumber(h[2]) or now_ms
local elapsed_sec = math.max(0, (now_ms - last) / 1000)
tokens = math.min(capacity, tokens + elapsed_sec * refill)

if tokens < n then
  redis.call('HSET', KEYS[1], 'tokens', tokens, 'last_refill_ms', now_ms)
  redis.call('EXPIRE', KEYS[1], ttl)
  return 0    -- denied
end
redis.call('HSET', KEYS[1], 'tokens', tokens - n, 'last_refill_ms', now_ms)
redis.call('EXPIRE', KEYS[1], ttl)
return 1      -- granted
```

`now_ms` comes from the Python side (server time) for two reasons: (a) `redis.call('TIME', ...)` makes the script non-deterministic and breaks Redis Cluster replication if it ever runs there; (b) the existing in-process limiter accepts an injectable clock, and tests already exploit it — keeping clock-injection symmetric simplifies parity tests.

## Per-call sequencing

`acquire(tenant_id, session_id)` runs:

1. EVALSHA on tenant bucket → if denied, raise `WazuhError("rate_limited", "tenant rate limit exceeded", 429, scope="rate_limit:tenant")`.
2. EVALSHA on session bucket → if denied, raise `WazuhError("rate_limited", "session rate limit exceeded", 429, scope="rate_limit:session")`.

Two round-trips, same as the in-process limiter's two-bucket check. Both run inside the circuit breaker — a Redis call failure (timeout, ConnectionError, server error) increments the breaker's failure counter and the call falls through to the per-replica `InProcessRateLimiter` for *that call only* (caller doesn't see a failure).

**Partial-credit edge case:** if the tenant bucket succeeds but the session bucket Redis call fails, the tenant token is "spent" with no corresponding session consumption. Slight over-counting on Redis flap, never under-counting against Wazuh's API cap — safety-critical direction is correct.

## Circuit breaker

Three states; transitions logged at INFO with structured fields, state changes emit a metric.

```
        ┌──── error_threshold consecutive failures ────┐
        │                                              ▼
    [CLOSED] ─────────success─────────►  ◄────────  [OPEN]
        ▲                                              │
        │                                              │ open_duration_sec elapses
        │                                              ▼
        └──── probe success ──────────────────  [HALF_OPEN]
                                                        │
                                                        │ probe failure
                                                        ▼
                                                     [OPEN]
```

- **CLOSED:** Redis is the source of truth. Each Lua call wrapped in `asyncio.wait_for(..., call_timeout_ms/1000)`. Successes reset the failure counter; failures (timeout, connection error, redis-server error) increment it. `error_threshold` consecutive failures → OPEN.
- **OPEN:** All `acquire()` calls go straight to the per-replica `InProcessRateLimiter` (created lazily on first OPEN, kept warm). Zero Redis traffic. After `open_duration_sec`, transition to HALF_OPEN.
- **HALF_OPEN:** Next `half_open_max_calls` calls (default 1) try Redis; on success → CLOSED + reset failure counter; on failure → OPEN, restart the timer.

The fallback `InProcessRateLimiter` instance uses the *same* `RateLimitConfig` the Redis path was using, so OPEN-state behavior degrades to "each replica enforces own budget" (effective fleet rate = `replicas × configured_rate`). This is the pre-acknowledged degraded mode (decision 1).

Concurrency: a single `asyncio.Lock` around state mutations. Reads of state are unlocked (atomic-ish for asyncio purposes, no GIL contention worth caring about).

## Observability

Three new metrics, in the existing prometheus surface (`observability/metrics.py`):

| Metric | Type | Labels | Purpose |
|---|---|---|---|
| `wazuh_mcp_rate_limit_redis_state` | Gauge (0=closed, 1=half_open, 2=open) | `replica` (hostname from `socket.gethostname()`) | Breaker state per replica. Alert on `>0` for >5 min. |
| `wazuh_mcp_rate_limit_redis_call_total` | Counter | `outcome=ok\|timeout\|error` | Redis call health. Alert on error-rate > 1% sustained. |
| `wazuh_mcp_rate_limit_fallback_total` | Counter | `tenant_id`, `scope=tenant\|session` | OPEN-state fallback hits, per tenant. Operator visibility into who got served by degraded mode. |

The existing `wazuh_mcp_rate_limited_total{scope}` (already emitted by `instrumented_tool`) keeps its meaning unchanged — counts user-facing 429s from either backend.

**Health endpoint.** `/healthz` (existing) gains a non-fatal field:

```json
"rate_limiter": {"backend": "redis", "redis": "ok" | "degraded" | "disabled"}
```

`degraded` = breaker is OPEN. `disabled` = backend is `in_process`. Operators alert off the metric; the field is for incident-time eyeball checks.

**Logging.** State transitions log at INFO with structured fields:

```json
{"event": "rate_limit_breaker_transition",
 "from": "closed", "to": "open",
 "consecutive_errors": 3, "last_error": "ConnectionError: ..."}
```

Per-call errors at DEBUG only. Operators don't need the noise; the metric is the operational signal.

## Testing

Three layers.

### Unit — `tests/unit/test_redis_rate_limiter.py`

`fakeredis-py` (Lua-capable). Covers:
- Bucket math correctness against the same test cases as `test_rate_limiter.py`, parameterized over both backends — proves semantic equivalence.
- Lua edge cases: new (absent) bucket, empty bucket, partial refill across N seconds, boundary case where `tokens == n` exactly, capacity-clamp on long idle.
- `EVALSHA → NOSCRIPT → EVAL` fallback path.
- TTL applied on every write (verify via `fakeredis`'s TTL inspection).
- Key-prefix isolation: two `RedisRateLimiter` instances with different `key_prefix` don't interfere.

Goal: ~25 tests. Fully deterministic. No real Redis.

### Unit — `tests/unit/test_redis_circuit_breaker.py`

State machine in isolation, fake Redis client injectable to fail / timeout / recover on demand. Covers:
- All six transition edges.
- Concurrent `acquire()` calls under each state (no torn state).
- Lazy construction of fallback `InProcessRateLimiter` only on first OPEN.
- `half_open_max_calls > 1` semantics.
- Timer-based OPEN → HALF_OPEN transition (uses injected clock).

Goal: ~12 tests.

### Integration — `tests/integration/test_redis_limiter_real.py`

Marked `@pytest.mark.integration`. Real Redis 7 container via `docker/bootstrap.sh` (extends the existing compose with a `redis` service). Two scenarios:

1. **Multi-replica budget sharing.** Spin up two pretend-replicas (two `RedisRateLimiter` instances pointing at the same Redis). Hammer them in parallel; assert total successful `acquire()`s ≤ tenant capacity over a window. Proves the global budget enforcement.

2. **Fault injection.** Run a steady stream of `acquire()` calls. `docker pause` Redis mid-load. Assert: no individual `acquire()` raises, breaker metric flips from 0 to 2 within `open_duration_sec + epsilon`, fallback counter increments. `docker unpause`. Assert breaker returns to 0 (CLOSED) within one `half_open_max_calls` cycle.

Goal: 4 tests.

**CI cost:** integration matrix gains one extra container per matrix axis (~30s startup). `lint-and-unit` (the cheap path) gets unit + breaker tests, < 5s wall-clock added.

## Helm chart edits

`charts/wazuh-mcp/`:

- New `redis.enabled` value (default `false`). When `true`:
  - Expects `redis.existingSecret` referencing a `Secret` with key `redis-url`.
  - `templates/deployment.yaml` injects `WAZUH_MCP_REDIS_URL` from the Secret.
  - `tenants.yaml` ConfigMap gets the `rate_limiter:` block with `backend: "redis"` and the tunables from `redis.tunables.*` values.
- `replicaCount` default **stays at 1** — audit-dedup blocker still exists; raising the default is a v1.2 change.
- `values.schema.json` (if present) updated to validate new keys.
- New `templates/secret-redis.yaml` is **not** shipped — operators bring their own Secret. The chart references `existingSecret` only.

## Docs

- `docs/deploy/helm.md` "HA caveat" section edited:
  - Acknowledges rate-limiter blocker is solved in v1.1.
  - Audit-dedup blocker remains; operators wanting `replicaCount > 1` either tolerate audit duplicates or wait for v1.2.
  - Updated guidance: "for v1.1, multi-replica is supported with the Redis rate limiter, but operators querying `local-audit-*` will see duplicate-keyed events."
- New `docs/deploy/redis.md`:
  - Sizing guidance (~10 KB per active session × concurrent session count; tenant key is negligible).
  - URL syntax for standalone / TLS / Sentinel.
  - Observability/alert recipes off the three new metrics.
  - Fallback behavior expectations during Redis outages.
- `README.md` features matrix gains a row: "Multi-replica HA — opt-in via Redis-backed rate limiter (v1.1)."
- `docs/api-reference.md` — no changes (the protocol is unchanged).

## Migration

None required. New optional config block; existing v1.0 deployments untouched on upgrade. Operators who want multi-replica:

1. Stand up Redis (managed or self-hosted).
2. Create K8s Secret with `redis-url`.
3. Set `redis.enabled=true` and `redis.existingSecret=<secret-name>` in Helm values.
4. (Eventually, post-v1.2) bump `replicaCount`.

## Open implementation choices (deferred to plan phase)

- `redis-py` async surface: use `redis.asyncio.Redis` (the in-tree async client; `aioredis` was merged into redis-py 4.2 and is no longer maintained separately).
- Whether to wrap both Lua calls in a single MULTI block to halve round-trip latency. Adds ~30 LOC of script; saves one RTT. Defer to plan-phase benchmarking.
- Whether to expose `circuit_breaker.error_threshold` per-tenant or only globally. Default to global; revisit if ops feedback wants per-tenant.

## Acceptance criteria

1. `tests/unit/test_redis_rate_limiter.py` and `tests/unit/test_redis_circuit_breaker.py` exist and pass under `lint-and-unit`.
2. The integration test in `tests/integration/test_redis_limiter_real.py` passes against a real Redis 7 container in CI matrix.
3. With `rate_limiter.backend: "in_process"` (or block absent), `tests/unit/test_rate_limiter.py` continues to pass — proves backwards compat.
4. Helm chart with `redis.enabled=true` deploys cleanly and operates against an external Redis (validated by integration test or manual smoke).
5. New metrics `wazuh_mcp_rate_limit_redis_state`, `_redis_call_total`, `_fallback_total` appear at `/metrics`.
6. `/healthz` reflects breaker state.
7. `docs/deploy/redis.md` exists; `docs/deploy/helm.md` HA caveat updated.
8. `docs/api-reference.md` — unchanged (no Protocol changes).

## Risk register

| Risk | Severity | Mitigation |
|---|---|---|
| Lua-script bug → all rate-limit decisions wrong | High | Parameterized parity tests against in-process limiter, ~25 unit tests covering boundary math. |
| Circuit breaker thresholds wrong → flapping or slow detection | Medium | Defaults conservative (3 errors / 5s); configurable; metrics surface state for tuning. |
| Redis URL leaks to logs | Medium | URL only via env var, never in config files; structured logger redacts known credential-bearing keys; new test asserts URL not in any log emission. |
| Multi-replica budget over-counted on Redis flap | Low | Documented as the safety-critical direction (over-count never violates Wazuh cap). Operators see this in `_fallback_total` metric. |
| `fakeredis` Lua dialect drifts from real Redis | Medium | Real-Redis integration test catches dialect divergence. |
| Fault-injection test (`docker pause`) is flaky in CI | Medium | Fall back to `docker stop redis && docker start redis` if pause/unpause proves flaky. Already a CI pattern in this repo. |

## Estimate

| Phase | Tasks | Estimated effort |
|---|---|---|
| T-A: `RedisRateLimiter` + Lua + circuit breaker | 4 plans | medium |
| T-B: Server wiring + config schema | 2 plans | small |
| T-C: Unit + breaker tests | 2 plans | medium |
| T-D: Integration test + CI compose | 2 plans | medium |
| T-E: Helm chart edits | 1 plan | small |
| T-F: Docs + README features matrix | 1 plan | small |

Total: 12 plans across 6 phases. Methodology per project memory: brainstorm → spec → plan → subagent exec → retro. Tier-A cross-subsystem invariant grep at plan time (lessons from M5a Keycloak claim-mapper IssuerIndex incident). Per-plan low-risk task batching where the diff is small + isolated.
