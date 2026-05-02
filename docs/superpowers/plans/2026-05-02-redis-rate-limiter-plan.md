# wazuh-mcp v1.1 — Redis-backed RateLimiter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the per-replica in-memory `InProcessRateLimiter` with a Redis-backed implementation that shares a global rate budget across replicas, with circuit-breaker fallback to per-replica enforcement on Redis outage. Unblocks the rate-limiter half of the v1.0 HA caveat.

**Architecture:** Six phases. Phase 1 (T-A) lands the Lua-scripted token-bucket primitive against `fakeredis`. Phase 2 (T-B) adds the per-process asyncio circuit breaker. Phase 3 (T-C) composes those into a `RedisRateLimiter` class implementing the existing `RateLimiter` Protocol. Phase 4 (T-D) ships config schema + server wiring. Phase 5 (T-E) wires observability — three new metrics + `/healthz` field. Phase 6 (T-F) ships the real-Redis integration test, Helm chart edits, and docs. T-A ⊥ T-B (independent unit work). T-C depends on both. T-D depends on T-C. T-E ⊥ T-F can run after T-C.

**Tech Stack:** Python 3.12 + uv + redis-py 5.x (`redis.asyncio`) + fakeredis 2.x (Lua-capable) + Pydantic v2 + pytest + pytest-asyncio + asyncio + Helm 3 + Docker Compose + Lua 5.1 (Redis embedded).

**Predecessor:** `v1.0.10` at `b033615` + spec `8fa5659` (`docs/superpowers/specs/2026-05-02-redis-rate-limiter-design.md`). HEAD at plan-write time is `8fa5659` on `main`.

**Successor:** v1.2 (audit-emitter cross-replica dedup; Helm `replicaCount` default bump to ≥ 2).

**Total scope:** 15 tasks across 6 phases. ~12 dispatches expected (T-F batches 4 doc/chart tasks under one dispatch).

**Methodology in force** (from `feedback_methodology.md` + `feedback_subagent_patterns.md`):

- **No AI attribution in commits.** Never `Co-Authored-By: Claude` or "Generated with Claude" footer.
- **Full review** for the two novel primitives in this plan: T-A2 (Lua atomic refill+consume) and T-B2 (circuit-breaker state machine). Tier-A spot-check for composition tasks (T-C, T-D, T-E).
- **Plan-time signature grep** mandatory for tasks touching `server.py:245`/`server.py:462` (limiter wiring), `observability/metrics.py` (metric registry), `tenancy/m4_config.py` (config schema sibling).
- **Cross-subsystem invariant grep:** at T-D plan-time, grep all callers of `RateLimiter.acquire(...)` to confirm Protocol stability. The Protocol is unchanged, so this should be a no-op confirmation.
- **Code snippets must pass ruff (line-length 100):** no f-strings without placeholders (F541); use ASCII dashes; use `# ty: ignore` (ty syntax, not `# type: ignore`).
- **Don't stack spec→plan→execution in one session.** Plan ends at commit; execution happens in a fresh-context session.

---

## File Structure (all phases)

### New files

```
src/wazuh_mcp/rate_limit/                          # Phase 1, 2, 3
  redis_limiter.py                                 # T-C1 (new — RedisRateLimiter + breaker class)
  lua/
    token_bucket.lua                               # T-A2 (new — atomic refill+consume)

src/wazuh_mcp/                                     # Phase 4
  # No new top-level files; modifications only.

tests/unit/                                        # Phase 1, 2, 3, 4, 5
  test_redis_token_bucket_lua.py                   # T-A3 (new — Lua script unit tests via fakeredis)
  test_redis_circuit_breaker.py                    # T-B3 (new — breaker state machine unit tests)
  test_redis_rate_limiter.py                       # T-C2 (new — RedisRateLimiter integration with breaker)
  test_rate_limiter_config.py                      # T-D1 (new — pydantic config schema tests)
  test_redis_limiter_metrics.py                    # T-E2 (new — metric emission tests)

tests/integration/                                 # Phase 6
  test_redis_limiter_real.py                       # T-F1 (new — real Redis container)

docker/                                            # Phase 6
  integration-compose.yml                          # T-F1 (modified — add redis service)

charts/wazuh-mcp/                                  # Phase 6
  values.yaml                                      # T-F2 (modified — add redis.* values)
  templates/
    deployment.yaml                                # T-F2 (modified — wire WAZUH_MCP_REDIS_URL)
    configmap-server.yaml                          # T-F2 (modified — emit rate_limiter: block)

docs/                                              # Phase 6
  deploy/
    helm.md                                        # T-F3 (modified — update HA caveat)
    redis.md                                       # T-F3 (new — sizing, URL syntax, observability)
  api-reference.md                                 # T-F3 (no change — Protocol stable)
README.md                                          # T-F3 (modified — features matrix row)
```

### Modified files

```
pyproject.toml                                     # T-A1 (add redis>=5.0; dev fakeredis>=2.20)
uv.lock                                            # T-A1 (regenerate)

src/wazuh_mcp/tenancy/m4_config.py                 # T-D1 (add RateLimiterConfig + RedisRateLimiterConfig + CircuitBreakerConfig)
src/wazuh_mcp/server.py                            # T-D2 (wire backend selection at :245 stdio + :462 HTTP)
src/wazuh_mcp/observability/metrics.py             # T-E1 (register 3 new metrics)
src/wazuh_mcp/observability/healthz.py             # T-E3 (add rate_limiter field)  # if it exists; else server.py
```

---

## Phase 1: T-A — Lua-scripted token bucket primitive

**Goal:** Working `token_bucket.lua` script with full unit-test coverage via `fakeredis`. No production code touches Redis yet — this phase ships only the Lua script + a thin Python wrapper that loads/calls it.

**Goal-backward:** End of phase, `pytest tests/unit/test_redis_token_bucket_lua.py -v` passes ~11 tests covering: new bucket starts full, single acquire decrements, refill across N seconds, capacity clamp, exact-boundary case, exhaustion returns 0, NOSCRIPT-fallback path, TTL applied on every write.

### Task T-A1: Add redis + fakeredis deps

**Files:**
- Modify: `pyproject.toml`
- Modify: `uv.lock`

- [ ] **Step 1: Inspect current `[project.dependencies]` and `[dependency-groups.dev]` blocks**

```bash
sed -n '7,42p' pyproject.toml
```

Confirm `dependencies` ends with `"opentelemetry-instrumentation-starlette>=0.48b0,<1",` and `dev` ends with `"safety>=3.2,<4",`.

- [ ] **Step 2: Add runtime dep `redis>=5.0`**

Edit `pyproject.toml`. After the line `"opentelemetry-instrumentation-starlette>=0.48b0,<1",` (line ~23) and before the closing `]` of `dependencies`, add:

```toml
    "redis>=5.0,<6",
```

- [ ] **Step 3: Add dev dep `fakeredis>=2.20` with Lua extra**

In `[dependency-groups.dev]`, after `"safety>=3.2,<4",` add:

```toml
    "fakeredis[lua]>=2.20,<3",
```

The `[lua]` extra pulls in `lupa` so `fakeredis` can execute Lua scripts the same way real Redis does.

- [ ] **Step 4: Regenerate uv.lock**

```bash
uv lock
```

Expected output: lockfile updated, `redis` and `fakeredis` (+ `lupa` transitive) added.

- [ ] **Step 5: Verify install**

```bash
uv sync && uv run python -c "import redis.asyncio; import fakeredis; print(redis.__version__, fakeredis.__version__)"
```

Expected: prints two versions, no import errors.

- [ ] **Step 6: Commit**

```bash
git add pyproject.toml uv.lock
git commit -m "chore(deps): add redis>=5.0 + fakeredis[lua]>=2.20 (v1.1 T-A1)

v1.1 Redis-backed RateLimiter prerequisites. redis-py is the runtime
client (uses redis.asyncio); fakeredis with [lua] extra runs the
production Lua script in unit tests so test failures aren't fakeredis
dialect drift."
```

---

### Task T-A2: Write Lua token-bucket script

**Files:**
- Create: `src/wazuh_mcp/rate_limit/lua/token_bucket.lua`

This task introduces a **novel primitive** — the only piece of Lua in the project. Full review at task close.

- [ ] **Step 1: Create the lua directory**

```bash
mkdir -p src/wazuh_mcp/rate_limit/lua
```

- [ ] **Step 2: Write the script**

Create `src/wazuh_mcp/rate_limit/lua/token_bucket.lua` with this exact content:

```lua
-- Atomic token-bucket refill + consume.
-- KEYS[1] = bucket key (Redis hash)
-- ARGV[1] = capacity (integer, max tokens)
-- ARGV[2] = refill_per_sec (float)
-- ARGV[3] = now_ms (integer, server-supplied wall clock in ms)
-- ARGV[4] = n_tokens (integer, tokens to consume; usually 1)
-- ARGV[5] = ttl_sec (integer, key expiry to apply on every write)
--
-- Returns: 1 if granted, 0 if denied.
-- Side effect: hash fields {tokens, last_refill_ms} updated, key TTL refreshed.

local capacity = tonumber(ARGV[1])
local refill   = tonumber(ARGV[2])
local now_ms   = tonumber(ARGV[3])
local n        = tonumber(ARGV[4])
local ttl      = tonumber(ARGV[5])

local h = redis.call('HMGET', KEYS[1], 'tokens', 'last_refill_ms')
local tokens = tonumber(h[1])
local last   = tonumber(h[2])

if tokens == nil then
  -- New bucket: start full.
  tokens = capacity
  last   = now_ms
end

local elapsed_sec = (now_ms - last) / 1000.0
if elapsed_sec < 0 then
  -- Clock skew on caller side. Don't credit negative time; just refresh last_refill_ms.
  elapsed_sec = 0
end

tokens = math.min(capacity, tokens + elapsed_sec * refill)

if tokens < n then
  -- Denied. Persist the refill but not the consume, so retries see updated state.
  redis.call('HSET', KEYS[1], 'tokens', tokens, 'last_refill_ms', now_ms)
  redis.call('EXPIRE', KEYS[1], ttl)
  return 0
end

tokens = tokens - n
redis.call('HSET', KEYS[1], 'tokens', tokens, 'last_refill_ms', now_ms)
redis.call('EXPIRE', KEYS[1], ttl)
return 1
```

Design points worth understanding before reading the tests:
- `now_ms` is **caller-supplied** (server-side wall clock). NOT `redis.call('TIME', ...)`. Reasons: (a) script determinism (Redis Cluster + replication require deterministic scripts; `TIME` is non-deterministic); (b) symmetric clock injection with the in-process `TokenBucket` test suite.
- New bucket starts **full**, not empty. Matches `TokenBucket.__init__` behavior at `src/wazuh_mcp/rate_limit/token_bucket.py:29` (`self._tokens: float = float(capacity)`).
- On denial we still HSET — the refill happened conceptually; persisting it means a quick retry sees the new tokens, not stale state. Matches `_refresh()` semantics at `token_bucket.py:32-37`.
- Negative elapsed (clock-skew) clamped to 0. Defensive; in practice every caller uses `time.time()`-derived ms which is monotonic enough.

- [ ] **Step 3: Verify file structure**

```bash
ls src/wazuh_mcp/rate_limit/lua/
```

Expected output: `token_bucket.lua`

- [ ] **Step 4: Commit**

```bash
git add src/wazuh_mcp/rate_limit/lua/token_bucket.lua
git commit -m "feat(rate_limit): add token_bucket.lua (v1.1 T-A2)

Atomic refill+consume primitive for the Redis-backed RateLimiter.
Caller supplies now_ms (server wall clock) for script determinism — no
redis.call('TIME') so the script is safe under Cluster replication.
New bucket starts full, matching the in-process TokenBucket behavior.
Persists refill on both grant and deny paths so retry-after-deny sees
the most-recent state.

Tests land in T-A3."
```

**Full review note:** Reviewer must confirm: (a) deterministic (no `redis.call('TIME')`); (b) returns 0/1 not nil (for clean Python `bool(result)`); (c) HSET fields match what Python writer/reader expects in T-A3.

---

### Task T-A3: Unit tests for the Lua script via fakeredis

**Files:**
- Create: `tests/unit/test_redis_token_bucket_lua.py`

The tests use `script_load` + `evalsha` (production path) rather than direct script execution. This proves the production EVALSHA path end-to-end on every test, not just on a few "happy path" cases in T-C2.

- [ ] **Step 1: Write the failing test file**

Create `tests/unit/test_redis_token_bucket_lua.py` with this exact content:

```python
"""Lua token_bucket script unit tests via fakeredis (Lua-capable).

Mirrors the in-process TokenBucket test scenarios so semantic parity is
provable. Each test loads the production .lua file and runs it via
SCRIPT LOAD + EVALSHA — the same path the production limiter uses.
"""

from __future__ import annotations

from pathlib import Path

import fakeredis
import pytest

LUA_PATH = Path(__file__).parent.parent.parent / "src" / "wazuh_mcp" / "rate_limit" / "lua" / "token_bucket.lua"


@pytest.fixture
def lua_script() -> str:
    return LUA_PATH.read_text(encoding="utf-8")


@pytest.fixture
def fake_redis() -> fakeredis.FakeRedis:
    # Synchronous fakeredis is fine for Lua tests — we're testing the script,
    # not the async wrapper. T-C2 covers async integration.
    return fakeredis.FakeRedis()


@pytest.fixture
def script_sha(lua_script: str, fake_redis: fakeredis.FakeRedis) -> str:
    return fake_redis.script_load(lua_script)


def _run(redis: fakeredis.FakeRedis, sha: str, key: str, *, capacity: int, refill: float, now_ms: int, n: int = 1, ttl: int = 60) -> int:
    return int(redis.evalsha(sha, 1, key, capacity, refill, now_ms, n, ttl))


def test_new_bucket_starts_full_and_grants(fake_redis: fakeredis.FakeRedis, script_sha: str) -> None:
    result = _run(fake_redis, script_sha, "k", capacity=5, refill=1.0, now_ms=1_000_000)
    assert result == 1
    h = fake_redis.hgetall("k")
    assert float(h[b"tokens"]) == pytest.approx(4.0)
    assert int(h[b"last_refill_ms"]) == 1_000_000


def test_consume_to_exhaustion(fake_redis: fakeredis.FakeRedis, script_sha: str) -> None:
    for _ in range(5):
        assert _run(fake_redis, script_sha, "k", capacity=5, refill=0.0001, now_ms=1_000_000) == 1
    assert _run(fake_redis, script_sha, "k", capacity=5, refill=0.0001, now_ms=1_000_000) == 0


def test_refill_across_seconds(fake_redis: fakeredis.FakeRedis, script_sha: str) -> None:
    for _ in range(3):
        assert _run(fake_redis, script_sha, "k", capacity=3, refill=1.0, now_ms=1_000_000) == 1
    assert _run(fake_redis, script_sha, "k", capacity=3, refill=1.0, now_ms=1_000_000) == 0
    assert _run(fake_redis, script_sha, "k", capacity=3, refill=1.0, now_ms=1_002_000) == 1
    assert _run(fake_redis, script_sha, "k", capacity=3, refill=1.0, now_ms=1_002_000) == 1
    assert _run(fake_redis, script_sha, "k", capacity=3, refill=1.0, now_ms=1_002_000) == 0


def test_capacity_clamp_on_long_idle(fake_redis: fakeredis.FakeRedis, script_sha: str) -> None:
    _run(fake_redis, script_sha, "k", capacity=5, refill=1.0, now_ms=1_000_000)
    for _ in range(5):
        assert _run(fake_redis, script_sha, "k", capacity=5, refill=1.0, now_ms=2_000_000) == 1
    assert _run(fake_redis, script_sha, "k", capacity=5, refill=1.0, now_ms=2_000_000) == 0


def test_exact_boundary_grant(fake_redis: fakeredis.FakeRedis, script_sha: str) -> None:
    assert _run(fake_redis, script_sha, "k", capacity=1, refill=1.0, now_ms=0) == 1
    assert _run(fake_redis, script_sha, "k", capacity=1, refill=1.0, now_ms=1_000) == 1


def test_denial_persists_refill(fake_redis: fakeredis.FakeRedis, script_sha: str) -> None:
    assert _run(fake_redis, script_sha, "k", capacity=1, refill=0.5, now_ms=0) == 1
    assert _run(fake_redis, script_sha, "k", capacity=1, refill=0.5, now_ms=100) == 0
    h = fake_redis.hgetall("k")
    assert int(h[b"last_refill_ms"]) == 100
    assert float(h[b"tokens"]) == pytest.approx(0.05)


def test_clock_skew_negative_elapsed_clamped(fake_redis: fakeredis.FakeRedis, script_sha: str) -> None:
    assert _run(fake_redis, script_sha, "k", capacity=2, refill=1.0, now_ms=1000) == 1
    assert _run(fake_redis, script_sha, "k", capacity=2, refill=1.0, now_ms=500) == 1
    assert _run(fake_redis, script_sha, "k", capacity=2, refill=1.0, now_ms=500) == 0


def test_multi_token_consume(fake_redis: fakeredis.FakeRedis, script_sha: str) -> None:
    assert _run(fake_redis, script_sha, "k", capacity=5, refill=1.0, now_ms=0, n=3) == 1
    h = fake_redis.hgetall("k")
    assert float(h[b"tokens"]) == pytest.approx(2.0)
    assert _run(fake_redis, script_sha, "k", capacity=5, refill=1.0, now_ms=0, n=3) == 0


def test_ttl_applied_on_every_call(fake_redis: fakeredis.FakeRedis, script_sha: str) -> None:
    _run(fake_redis, script_sha, "k", capacity=3, refill=1.0, now_ms=0, ttl=120)
    assert 0 < fake_redis.ttl("k") <= 120
    _run(fake_redis, script_sha, "k", capacity=3, refill=1.0, now_ms=1000, ttl=180)
    assert 120 < fake_redis.ttl("k") <= 180


def test_distinct_keys_isolated(fake_redis: fakeredis.FakeRedis, script_sha: str) -> None:
    for _ in range(3):
        assert _run(fake_redis, script_sha, "ka", capacity=3, refill=0.0001, now_ms=0) == 1
    assert _run(fake_redis, script_sha, "ka", capacity=3, refill=0.0001, now_ms=0) == 0
    assert _run(fake_redis, script_sha, "kb", capacity=3, refill=0.0001, now_ms=0) == 1


def test_zero_refill_rate_supported(fake_redis: fakeredis.FakeRedis, script_sha: str) -> None:
    # Edge case — Pydantic schema enforces refill > 0 at config-load time, but
    # the script itself shouldn't crash on 0 (defensive).
    assert _run(fake_redis, script_sha, "k", capacity=2, refill=0.0, now_ms=0) == 1
    assert _run(fake_redis, script_sha, "k", capacity=2, refill=0.0, now_ms=10_000_000) == 1
    assert _run(fake_redis, script_sha, "k", capacity=2, refill=0.0, now_ms=10_000_000) == 0
```

- [ ] **Step 2: Run the tests**

```bash
uv run pytest tests/unit/test_redis_token_bucket_lua.py -v
```

Expected: 11 PASS.

If fewer than 11 pass, debug the script. Common issues:
- `nil` arithmetic on first-bucket case → check the `if tokens == nil then` guard.
- TTL not refreshed → confirm the EXPIRE call is on every code path.
- Boundary off-by-one → re-examine `if tokens < n`.

- [ ] **Step 3: Run ruff + ty on the test file**

```bash
uv run ruff check tests/unit/test_redis_token_bucket_lua.py
uv run ruff format --check tests/unit/test_redis_token_bucket_lua.py
uv run ty check tests/unit/test_redis_token_bucket_lua.py
```

Expected: no output (clean).

- [ ] **Step 4: Commit**

```bash
git add tests/unit/test_redis_token_bucket_lua.py
git commit -m "test(rate_limit): Lua token_bucket unit tests (v1.1 T-A3)

11 tests via fakeredis with [lua] extra. Covers: full-on-init,
exhaustion, refill-across-seconds, capacity-clamp on long idle,
exact-boundary grant, denial-persists-refill, clock-skew clamp,
multi-token consume, TTL refresh on every call, key isolation, zero
refill rate. All tests use SCRIPT LOAD + EVALSHA — same path the
production RedisRateLimiter uses, so dialect drift surfaces here."
```

**Full-review checkpoint after T-A3:** verify all 11 tests pass; verify Lua script and tests are byte-for-byte semantic-equivalent to the in-process TokenBucket where applicable.

---

## Phase 2: T-B — Circuit breaker primitive

**Goal:** A `_RedisCircuitBreaker` class with full state-machine coverage. No Redis touch — pure asyncio state machine driven by an injectable async-callable. Lives in `src/wazuh_mcp/rate_limit/redis_limiter.py` (the file gets created in T-B2; T-C1 fills out the rest).

### Task T-B1: Define breaker tests scaffold (test-first stub)

**Files:**
- Create: `tests/unit/test_redis_circuit_breaker.py`

This is a stub task that lays the test scaffolding. T-B2 implements the actual breaker.

- [ ] **Step 1: Write the failing test scaffolding**

Create `tests/unit/test_redis_circuit_breaker.py` with this exact content:

```python
"""_RedisCircuitBreaker state machine unit tests.

Pure asyncio state machine — no Redis. Tests inject an async callable
that can be flipped to succeed / fail / hang to drive transitions.
"""

from __future__ import annotations

import asyncio

import pytest

from wazuh_mcp.rate_limit.redis_limiter import (  # ty: ignore  (until T-B2)
    BreakerState,
    CircuitBreakerOpenError,
    _RedisCircuitBreaker,
)


def _bcfg(*, error_threshold: int = 3, open_duration_sec: float = 0.05, half_open_max_calls: int = 1, call_timeout_ms: int = 50) -> dict[str, object]:
    return {
        "error_threshold": error_threshold,
        "open_duration_sec": open_duration_sec,
        "half_open_max_calls": half_open_max_calls,
        "call_timeout_ms": call_timeout_ms,
    }


class _Counter:
    """Stateful test fixture: caller flips .should_fail to control behavior."""

    def __init__(self) -> None:
        self.calls = 0
        self.should_fail = False
        self.should_hang = False

    async def __call__(self) -> int:
        self.calls += 1
        if self.should_hang:
            await asyncio.sleep(10)
        if self.should_fail:
            raise RuntimeError("simulated failure")
        return 42


@pytest.mark.asyncio
async def test_closed_passes_call_through() -> None:
    breaker = _RedisCircuitBreaker(**_bcfg())  # ty: ignore
    counter = _Counter()
    assert await breaker.call(counter) == 42
    assert counter.calls == 1
    assert breaker.state == BreakerState.CLOSED


@pytest.mark.asyncio
async def test_closed_to_open_after_threshold_consecutive_failures() -> None:
    breaker = _RedisCircuitBreaker(**_bcfg(error_threshold=3))  # ty: ignore
    counter = _Counter()
    counter.should_fail = True
    for _ in range(3):
        with pytest.raises(RuntimeError):
            await breaker.call(counter)
    assert breaker.state == BreakerState.OPEN


@pytest.mark.asyncio
async def test_success_resets_failure_counter() -> None:
    breaker = _RedisCircuitBreaker(**_bcfg(error_threshold=3))  # ty: ignore
    counter = _Counter()
    counter.should_fail = True
    for _ in range(2):
        with pytest.raises(RuntimeError):
            await breaker.call(counter)
    counter.should_fail = False
    await breaker.call(counter)  # success resets counter
    counter.should_fail = True
    for _ in range(2):
        with pytest.raises(RuntimeError):
            await breaker.call(counter)
    assert breaker.state == BreakerState.CLOSED


@pytest.mark.asyncio
async def test_open_raises_circuit_open_without_calling() -> None:
    breaker = _RedisCircuitBreaker(**_bcfg(error_threshold=2))  # ty: ignore
    counter = _Counter()
    counter.should_fail = True
    for _ in range(2):
        with pytest.raises(RuntimeError):
            await breaker.call(counter)
    assert breaker.state == BreakerState.OPEN
    counter.calls = 0
    counter.should_fail = False
    with pytest.raises(CircuitBreakerOpenError):
        await breaker.call(counter)
    assert counter.calls == 0


@pytest.mark.asyncio
async def test_open_to_half_open_after_open_duration() -> None:
    breaker = _RedisCircuitBreaker(**_bcfg(error_threshold=2, open_duration_sec=0.05))  # ty: ignore
    counter = _Counter()
    counter.should_fail = True
    for _ in range(2):
        with pytest.raises(RuntimeError):
            await breaker.call(counter)
    assert breaker.state == BreakerState.OPEN
    await asyncio.sleep(0.06)
    counter.should_fail = False
    assert await breaker.call(counter) == 42
    assert breaker.state == BreakerState.CLOSED


@pytest.mark.asyncio
async def test_half_open_failure_reopens_breaker() -> None:
    breaker = _RedisCircuitBreaker(**_bcfg(error_threshold=2, open_duration_sec=0.05))  # ty: ignore
    counter = _Counter()
    counter.should_fail = True
    for _ in range(2):
        with pytest.raises(RuntimeError):
            await breaker.call(counter)
    await asyncio.sleep(0.06)
    with pytest.raises(RuntimeError):
        await breaker.call(counter)
    assert breaker.state == BreakerState.OPEN


@pytest.mark.asyncio
async def test_call_timeout_counts_as_failure() -> None:
    breaker = _RedisCircuitBreaker(**_bcfg(error_threshold=2, call_timeout_ms=20))  # ty: ignore
    counter = _Counter()
    counter.should_hang = True
    for _ in range(2):
        with pytest.raises(asyncio.TimeoutError):
            await breaker.call(counter)
    assert breaker.state == BreakerState.OPEN


@pytest.mark.asyncio
async def test_concurrent_calls_under_closed_state() -> None:
    breaker = _RedisCircuitBreaker(**_bcfg())  # ty: ignore
    counter = _Counter()
    results = await asyncio.gather(*(breaker.call(counter) for _ in range(10)))
    assert results == [42] * 10
    assert counter.calls == 10
    assert breaker.state == BreakerState.CLOSED


@pytest.mark.asyncio
async def test_state_transitions_recorded_for_observability() -> None:
    breaker = _RedisCircuitBreaker(**_bcfg(error_threshold=2))  # ty: ignore
    counter = _Counter()
    counter.should_fail = True
    for _ in range(2):
        with pytest.raises(RuntimeError):
            await breaker.call(counter)
    assert breaker.last_transition is not None
    from_state, to_state = breaker.last_transition
    assert from_state == BreakerState.CLOSED
    assert to_state == BreakerState.OPEN
```

- [ ] **Step 2: Run tests — expect ALL FAIL (import error)**

```bash
uv run pytest tests/unit/test_redis_circuit_breaker.py -v 2>&1 | head -10
```

Expected: `ImportError` or `ModuleNotFoundError: wazuh_mcp.rate_limit.redis_limiter`. Correct — T-B2 implements it.

- [ ] **Step 3: Commit (test-first scaffolding)**

```bash
git add tests/unit/test_redis_circuit_breaker.py
git commit -m "test(rate_limit): circuit breaker test scaffolding (v1.1 T-B1)

9 failing tests covering all six state transitions, threshold counter
reset on success, timeout-as-failure, concurrent calls, and the
last_transition observability hook. Imports fail until T-B2 ships
_RedisCircuitBreaker + BreakerState + CircuitBreakerOpenError."
```

---

### Task T-B2: Implement `_RedisCircuitBreaker`

**Files:**
- Create: `src/wazuh_mcp/rate_limit/redis_limiter.py` (initial scaffold — T-C1 fills out RedisRateLimiter)

This task introduces the second **novel primitive**. Full review at task close.

- [ ] **Step 1: Create `redis_limiter.py` with breaker scaffold**

Create `src/wazuh_mcp/rate_limit/redis_limiter.py` with this exact content:

```python
"""RedisRateLimiter and supporting circuit breaker.

The breaker is a per-process asyncio state machine that wraps every
Redis call. When OPEN, RedisRateLimiter.acquire() delegates to a
per-replica InProcessRateLimiter without touching Redis. T-C1 fills
out RedisRateLimiter; this file currently ships only the breaker.
"""

from __future__ import annotations

import asyncio
import enum
import logging
import time
from collections.abc import Awaitable, Callable
from typing import TypeVar

T = TypeVar("T")
_LOG = logging.getLogger(__name__)


class BreakerState(enum.IntEnum):
    CLOSED = 0
    HALF_OPEN = 1
    OPEN = 2


class CircuitBreakerOpenError(Exception):
    """Raised by _RedisCircuitBreaker.call() when the breaker is OPEN.

    Caller (RedisRateLimiter.acquire in T-C1) catches this and routes
    to the per-replica InProcessRateLimiter fallback.
    """


class _RedisCircuitBreaker:
    """Asyncio circuit breaker. Counts consecutive failures; opens on
    threshold; probes after open_duration_sec; closes on probe success.

    Per-process. One instance per RedisRateLimiter (one per replica).
    """

    def __init__(
        self,
        *,
        error_threshold: int,
        open_duration_sec: float,
        half_open_max_calls: int,
        call_timeout_ms: int,
        now: Callable[[], float] | None = None,
    ) -> None:
        if error_threshold < 1:
            raise ValueError("error_threshold must be >= 1")
        if open_duration_sec <= 0:
            raise ValueError("open_duration_sec must be > 0")
        if half_open_max_calls < 1:
            raise ValueError("half_open_max_calls must be >= 1")
        if call_timeout_ms <= 0:
            raise ValueError("call_timeout_ms must be > 0")
        self._error_threshold = error_threshold
        self._open_duration_sec = open_duration_sec
        self._half_open_max_calls = half_open_max_calls
        self._call_timeout = call_timeout_ms / 1000.0
        self._now = now or time.monotonic

        self._state: BreakerState = BreakerState.CLOSED
        self._consecutive_failures: int = 0
        self._opened_at: float | None = None
        self._half_open_in_flight: int = 0
        self._lock = asyncio.Lock()
        self.last_transition: tuple[BreakerState, BreakerState] | None = None

    @property
    def state(self) -> BreakerState:
        return self._state

    async def _transition(self, new_state: BreakerState) -> None:
        # Caller must hold self._lock.
        if new_state == self._state:
            return
        self.last_transition = (self._state, new_state)
        self._state = new_state
        if new_state == BreakerState.OPEN:
            self._opened_at = self._now()
            self._half_open_in_flight = 0
        elif new_state == BreakerState.CLOSED:
            self._consecutive_failures = 0
            self._opened_at = None
            self._half_open_in_flight = 0
        elif new_state == BreakerState.HALF_OPEN:
            self._half_open_in_flight = 0

    async def _maybe_promote_to_half_open(self) -> None:
        # Caller must hold self._lock.
        if self._state != BreakerState.OPEN:
            return
        if self._opened_at is None:
            return
        if self._now() - self._opened_at >= self._open_duration_sec:
            await self._transition(BreakerState.HALF_OPEN)

    async def call(self, fn: Callable[[], Awaitable[T]]) -> T:
        async with self._lock:
            await self._maybe_promote_to_half_open()
            current = self._state
            if current == BreakerState.OPEN:
                raise CircuitBreakerOpenError("breaker is OPEN")
            if current == BreakerState.HALF_OPEN:
                if self._half_open_in_flight >= self._half_open_max_calls:
                    raise CircuitBreakerOpenError("HALF_OPEN probe budget exhausted")
                self._half_open_in_flight += 1

        # Execute outside the lock so concurrent callers don't serialize on Redis I/O.
        try:
            result = await asyncio.wait_for(fn(), timeout=self._call_timeout)
        except Exception:  # noqa: BLE001  — every exception counts as a breaker failure
            await self._record_failure()
            raise

        await self._record_success()
        return result

    async def _record_success(self) -> None:
        async with self._lock:
            if self._state == BreakerState.HALF_OPEN:
                await self._transition(BreakerState.CLOSED)
            elif self._state == BreakerState.CLOSED:
                self._consecutive_failures = 0

    async def _record_failure(self) -> None:
        async with self._lock:
            if self._state == BreakerState.HALF_OPEN:
                await self._transition(BreakerState.OPEN)
                return
            if self._state == BreakerState.CLOSED:
                self._consecutive_failures += 1
                if self._consecutive_failures >= self._error_threshold:
                    await self._transition(BreakerState.OPEN)
```

Design notes:
- The `try/except ... raise` shape preserves the original exception type and traceback. `_record_failure` is called with the lock acquired anew — necessary because the work happened outside the lock.
- The lock is held for the state-decision phase (~microseconds) and released for the I/O phase (10s of ms). Standard pattern.
- `last_transition` is the cheapest possible observability hook for T-E1's metric. A real metric API would be observers/listeners, but that's overkill for two consumers.
- `BaseException` is excluded by `except Exception` — KeyboardInterrupt/SystemExit do not trip the breaker.

- [ ] **Step 2: Run the breaker tests**

```bash
uv run pytest tests/unit/test_redis_circuit_breaker.py -v
```

Expected: 9 PASS.

If `test_call_timeout_counts_as_failure` fails: confirm `asyncio.wait_for` is wrapping `fn()` and the TimeoutError flows into `_record_failure`.

If `test_concurrent_calls_under_closed_state` is slow or deadlocks: confirm the lock is released before `await asyncio.wait_for(fn(), ...)`.

- [ ] **Step 3: Run ruff + ty**

```bash
uv run ruff check src/wazuh_mcp/rate_limit/redis_limiter.py tests/unit/test_redis_circuit_breaker.py
uv run ruff format --check src/wazuh_mcp/rate_limit/redis_limiter.py tests/unit/test_redis_circuit_breaker.py
uv run ty check src/wazuh_mcp/rate_limit/redis_limiter.py
```

Expected: clean. The `# ty: ignore` comments in the test file are now resolvable; remove them in step 4.

- [ ] **Step 4: Remove the now-stale `# ty: ignore` lines from the test file**

Edit `tests/unit/test_redis_circuit_breaker.py`. Remove every `  # ty: ignore` and `  # ty: ignore  (until T-B2)` suffix.

- [ ] **Step 5: Re-run tests + linters**

```bash
uv run pytest tests/unit/test_redis_circuit_breaker.py -v
uv run ruff check tests/unit/test_redis_circuit_breaker.py
uv run ty check tests/unit/test_redis_circuit_breaker.py
```

Expected: 9 PASS, clean lint.

- [ ] **Step 6: Commit**

```bash
git add src/wazuh_mcp/rate_limit/redis_limiter.py tests/unit/test_redis_circuit_breaker.py
git commit -m "feat(rate_limit): _RedisCircuitBreaker (v1.1 T-B2)

Asyncio state machine: closed -> open after N consecutive failures ->
half-open after open_duration_sec -> closed on probe success or open
on probe failure. Lock held only for state decisions; released across
the wrapped I/O so concurrent calls don't serialize on Redis. Exposes
last_transition tuple for T-E1 metric emission.

9 unit tests covering all six edges + concurrency + threshold reset
on success + timeout-as-failure."
```

**Full-review checkpoint after T-B2:** verify (a) lock release happens before `asyncio.wait_for` to allow concurrent I/O; (b) `except Exception` excludes BaseException (KeyboardInterrupt should not trip breaker); (c) `last_transition` correctly tracks the most-recent transition.

---

## Phase 3: T-C — `RedisRateLimiter` composition

**Goal:** A `RedisRateLimiter` class implementing the existing `RateLimiter` Protocol. Owns: a `redis.asyncio.Redis` client, the SHA1 of the loaded Lua script, an `InProcessRateLimiter` fallback instance, and a `_RedisCircuitBreaker` per-process.

### Task T-C1: Implement `RedisRateLimiter`

**Files:**
- Modify: `src/wazuh_mcp/rate_limit/redis_limiter.py` (extend with the limiter class)

- [ ] **Step 1: Read the existing in-process limiter to confirm Protocol shape**

```bash
sed -n '25,35p' src/wazuh_mcp/rate_limit/limiter.py
```

Expected output (verbatim):

```python
class RateLimiter(Protocol):
    async def acquire(self, tenant_id: str, session_id: str) -> None: ...
```

Signature must match exactly.

- [ ] **Step 2: Update top-of-file imports**

Edit `src/wazuh_mcp/rate_limit/redis_limiter.py`. Replace the existing import block with the full set:

```python
from __future__ import annotations

import asyncio
import enum
import logging
import math
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import TypeVar

from redis.asyncio import Redis as AsyncRedis
from redis.exceptions import (
    ConnectionError as RedisConnectionError,
    NoScriptError,
    TimeoutError as RedisTimeoutError,
)

from wazuh_mcp.rate_limit.limiter import InProcessRateLimiter
from wazuh_mcp.tenancy.m4_config import RateLimitConfig
from wazuh_mcp.wazuh.errors import WazuhError

T = TypeVar("T")
_LOG = logging.getLogger(__name__)
_LUA_PATH = Path(__file__).parent / "lua" / "token_bucket.lua"
```

- [ ] **Step 3: Append the limiter class to `redis_limiter.py`**

After the existing breaker code (`_RedisCircuitBreaker`), append:

```python


def _ttl_for(cfg: RateLimitConfig) -> int:
    """TTL seconds = max(2 * full_refill_window, 60).

    full_refill_window = capacity / refill_per_sec. Use the longer of
    tenant and session refill windows so both buckets get a survivable TTL.
    """
    windows = [
        cfg.tenant.capacity / cfg.tenant.refill_per_sec,
        cfg.session.capacity / cfg.session.refill_per_sec,
    ]
    return max(int(math.ceil(2 * max(windows))), 60)


class RedisRateLimiter:
    """Two-tier token-bucket limiter backed by Redis with breaker fallback.

    Implements the RateLimiter Protocol. acquire() runs the Lua script
    against tenant + session bucket keys; raises WazuhError(rate_limited)
    on budget exhaustion (same behavior as InProcessRateLimiter).

    On Redis call failure (timeout, ConnectionError, server error), the
    circuit breaker counts the failure and routes the call to a
    per-process InProcessRateLimiter fallback that is lazy-constructed
    on first OPEN transition and kept warm.
    """

    def __init__(
        self,
        *,
        redis_client: AsyncRedis,
        default: RateLimitConfig,
        per_tenant: dict[str, RateLimitConfig] | None = None,
        key_prefix: str,
        breaker: _RedisCircuitBreaker,
        now_ms: Callable[[], int] | None = None,
    ) -> None:
        self._redis = redis_client
        self._default = default
        self._per_tenant = per_tenant or {}
        self._key_prefix = key_prefix
        self._breaker = breaker
        self._now_ms = now_ms or (lambda: int(time.time() * 1000))
        self._script_text = _LUA_PATH.read_text(encoding="utf-8")
        self._script_sha: str | None = None
        self._fallback: InProcessRateLimiter | None = None

    def _cfg(self, tenant_id: str) -> RateLimitConfig:
        return self._per_tenant.get(tenant_id, self._default)

    def _tenant_key(self, tenant_id: str) -> str:
        return f"{self._key_prefix}:tenant:{tenant_id}"

    def _session_key(self, tenant_id: str, session_id: str) -> str:
        return f"{self._key_prefix}:session:{tenant_id}:{session_id}"

    def _ensure_fallback(self) -> InProcessRateLimiter:
        if self._fallback is None:
            self._fallback = InProcessRateLimiter(
                default=self._default,
                per_tenant=self._per_tenant,
            )
        return self._fallback

    async def _run_script(self, key: str, capacity: int, refill: float, n: int, ttl: int) -> int:
        """EVALSHA the Lua script. Reload via EVAL on NOSCRIPT (e.g., Redis restart)."""
        if self._script_sha is None:
            self._script_sha = await self._redis.script_load(self._script_text)
        try:
            return int(await self._redis.evalsha(
                self._script_sha, 1, key, capacity, refill, self._now_ms(), n, ttl
            ))
        except NoScriptError:
            self._script_sha = await self._redis.script_load(self._script_text)
            return int(await self._redis.evalsha(
                self._script_sha, 1, key, capacity, refill, self._now_ms(), n, ttl
            ))

    async def _try_redis_acquire(self, key: str, cfg_bucket, ttl: int) -> bool:
        """Run the Lua script. True on grant, False on deny. Raises on Redis errors."""
        result = await self._run_script(
            key=key,
            capacity=cfg_bucket.capacity,
            refill=cfg_bucket.refill_per_sec,
            n=1,
            ttl=ttl,
        )
        return result == 1

    async def acquire(self, tenant_id: str, session_id: str) -> None:
        cfg = self._cfg(tenant_id)
        ttl = _ttl_for(cfg)
        tenant_key = self._tenant_key(tenant_id)
        session_key = self._session_key(tenant_id, session_id)

        try:
            granted = await self._breaker.call(
                lambda: self._try_redis_acquire(tenant_key, cfg.tenant, ttl)
            )
        except CircuitBreakerOpenError:
            await self._ensure_fallback().acquire(tenant_id, session_id)
            return
        except (RedisConnectionError, RedisTimeoutError, asyncio.TimeoutError, TimeoutError):
            _LOG.debug("rate_limit_redis_call_failed", exc_info=True)
            await self._ensure_fallback().acquire(tenant_id, session_id)
            return

        if not granted:
            raise WazuhError(
                "rate_limited",
                "tenant rate limit exceeded",
                429,
                scope="rate_limit:tenant",
            )

        try:
            granted = await self._breaker.call(
                lambda: self._try_redis_acquire(session_key, cfg.session, ttl)
            )
        except CircuitBreakerOpenError:
            await self._ensure_fallback().acquire(tenant_id, session_id)
            return
        except (RedisConnectionError, RedisTimeoutError, asyncio.TimeoutError, TimeoutError):
            _LOG.debug("rate_limit_redis_call_failed", exc_info=True)
            await self._ensure_fallback().acquire(tenant_id, session_id)
            return

        if not granted:
            raise WazuhError(
                "rate_limited",
                "session rate limit exceeded",
                429,
                scope="rate_limit:session",
            )
```

Design notes:
- `_now_ms` injectable for deterministic test clock control.
- Lazy `_fallback` instantiation defers `InProcessRateLimiter` allocation until the first actual fallback need.
- Both `CircuitBreakerOpenError` (breaker decision) and `RedisConnectionError`/`RedisTimeoutError` (raw call failure that hasn't tripped breaker yet) route to fallback.
- Partial-credit: if the tenant call succeeds but the session call fails, the tenant token is "spent" without a corresponding session consume. Documented in the spec as the safety-critical direction.

- [ ] **Step 4: Run breaker tests to confirm refactor didn't regress them**

```bash
uv run pytest tests/unit/test_redis_circuit_breaker.py -v
```

Expected: 9 PASS.

- [ ] **Step 5: Commit**

```bash
git add src/wazuh_mcp/rate_limit/redis_limiter.py
git commit -m "feat(rate_limit): RedisRateLimiter (v1.1 T-C1)

Implements the RateLimiter Protocol with two-tier token buckets in
Redis (tenant + session). EVALSHA with NOSCRIPT-EVAL fallback for
post-restart cache misses. Wraps every Redis call in
_RedisCircuitBreaker; on OPEN or transient Redis error, routes to a
lazily-constructed InProcessRateLimiter fallback that mirrors v1.0
per-replica enforcement. WazuhError(rate_limited, scope=...) raised
on budget exhaustion — identical contract to InProcessRateLimiter.

Tests land in T-C2."
```

---

### Task T-C2: Integration tests for `RedisRateLimiter`

**Files:**
- Create: `tests/unit/test_redis_rate_limiter.py`

- [ ] **Step 1: Write the test file**

Create `tests/unit/test_redis_rate_limiter.py`:

```python
"""RedisRateLimiter unit tests via fakeredis.aioredis.

End-to-end limiter behavior: Protocol conformance, two-bucket math,
WazuhError emission with correct scope, fallback routing on Redis
failure, per-tenant config overrides, NOSCRIPT recovery.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import fakeredis.aioredis
import pytest
from redis.exceptions import ConnectionError as RedisConnectionError

from wazuh_mcp.rate_limit.redis_limiter import (
    BreakerState,
    RedisRateLimiter,
    _RedisCircuitBreaker,
)
from wazuh_mcp.tenancy.m4_config import BucketConfig, RateLimitConfig
from wazuh_mcp.wazuh.errors import WazuhError


def _cfg(tenant_cap: int = 5, session_cap: int = 3, refill: float = 0.0001) -> RateLimitConfig:
    return RateLimitConfig(
        tenant=BucketConfig(capacity=tenant_cap, refill_per_sec=refill),
        session=BucketConfig(capacity=session_cap, refill_per_sec=refill),
    )


def _breaker() -> _RedisCircuitBreaker:
    return _RedisCircuitBreaker(
        error_threshold=3,
        open_duration_sec=0.05,
        half_open_max_calls=1,
        call_timeout_ms=200,
    )


@pytest.fixture
async def redis_client() -> AsyncIterator[fakeredis.aioredis.FakeRedis]:
    client = fakeredis.aioredis.FakeRedis()
    yield client
    await client.aclose()


@pytest.mark.asyncio
async def test_acquires_under_budget(redis_client: fakeredis.aioredis.FakeRedis) -> None:
    limiter = RedisRateLimiter(
        redis_client=redis_client,
        default=_cfg(),
        key_prefix="t",
        breaker=_breaker(),
    )
    await limiter.acquire("ten1", "sess1")
    await limiter.acquire("ten1", "sess1")
    await limiter.acquire("ten1", "sess1")


@pytest.mark.asyncio
async def test_session_exhaustion_raises_session_scope(redis_client: fakeredis.aioredis.FakeRedis) -> None:
    limiter = RedisRateLimiter(
        redis_client=redis_client,
        default=_cfg(tenant_cap=100, session_cap=2),
        key_prefix="t",
        breaker=_breaker(),
    )
    await limiter.acquire("ten1", "sess1")
    await limiter.acquire("ten1", "sess1")
    with pytest.raises(WazuhError) as exc:
        await limiter.acquire("ten1", "sess1")
    assert exc.value.code == "rate_limited"
    assert exc.value.scope == "rate_limit:session"


@pytest.mark.asyncio
async def test_tenant_exhaustion_raises_tenant_scope(redis_client: fakeredis.aioredis.FakeRedis) -> None:
    limiter = RedisRateLimiter(
        redis_client=redis_client,
        default=_cfg(tenant_cap=2, session_cap=100),
        key_prefix="t",
        breaker=_breaker(),
    )
    await limiter.acquire("ten1", "sess1")
    await limiter.acquire("ten1", "sess2")
    with pytest.raises(WazuhError) as exc:
        await limiter.acquire("ten1", "sess3")
    assert exc.value.scope == "rate_limit:tenant"


@pytest.mark.asyncio
async def test_distinct_tenants_distinct_budgets(redis_client: fakeredis.aioredis.FakeRedis) -> None:
    limiter = RedisRateLimiter(
        redis_client=redis_client,
        default=_cfg(tenant_cap=2),
        key_prefix="t",
        breaker=_breaker(),
    )
    await limiter.acquire("a", "s")
    await limiter.acquire("a", "s")
    await limiter.acquire("b", "s")
    await limiter.acquire("b", "s")


@pytest.mark.asyncio
async def test_per_tenant_override(redis_client: fakeredis.aioredis.FakeRedis) -> None:
    default = _cfg(tenant_cap=2)
    big = RateLimitConfig(
        tenant=BucketConfig(capacity=10, refill_per_sec=0.0001),
        session=BucketConfig(capacity=10, refill_per_sec=0.0001),
    )
    limiter = RedisRateLimiter(
        redis_client=redis_client,
        default=default,
        per_tenant={"vip": big},
        key_prefix="t",
        breaker=_breaker(),
    )
    for _ in range(10):
        await limiter.acquire("vip", "s")
    await limiter.acquire("plebs", "s")
    await limiter.acquire("plebs", "s")
    with pytest.raises(WazuhError):
        await limiter.acquire("plebs", "s")


@pytest.mark.asyncio
async def test_redis_connection_error_routes_to_fallback(redis_client: fakeredis.aioredis.FakeRedis) -> None:
    """Simulate Redis going away mid-call; first call should still succeed via fallback."""

    class FlakeyRedis:
        def __init__(self, real: fakeredis.aioredis.FakeRedis) -> None:
            self._real = real
            self.fail_next = True

        async def script_load(self, script: str) -> str:
            return await self._real.script_load(script)

        async def evalsha(self, *args, **kwargs):
            if self.fail_next:
                raise RedisConnectionError("simulated redis down")
            return await self._real.evalsha(*args, **kwargs)

    flakey = FlakeyRedis(redis_client)
    limiter = RedisRateLimiter(
        redis_client=flakey,
        default=_cfg(),
        key_prefix="t",
        breaker=_breaker(),
    )
    await limiter.acquire("ten1", "sess1")
    assert limiter._fallback is not None  # noqa: SLF001


@pytest.mark.asyncio
async def test_breaker_open_after_threshold_failures() -> None:
    class AlwaysFailRedis:
        async def script_load(self, script: str) -> str:
            return "fakesha"

        async def evalsha(self, *args, **kwargs):
            raise RedisConnectionError("nope")

    breaker = _RedisCircuitBreaker(
        error_threshold=3,
        open_duration_sec=10.0,
        half_open_max_calls=1,
        call_timeout_ms=200,
    )
    limiter = RedisRateLimiter(
        redis_client=AlwaysFailRedis(),
        default=_cfg(),
        key_prefix="t",
        breaker=breaker,
    )
    for _ in range(4):
        await limiter.acquire("ten1", "sess1")
    assert breaker.state == BreakerState.OPEN


@pytest.mark.asyncio
async def test_noscript_triggers_reload_and_succeeds(redis_client: fakeredis.aioredis.FakeRedis) -> None:
    limiter = RedisRateLimiter(
        redis_client=redis_client,
        default=_cfg(),
        key_prefix="t",
        breaker=_breaker(),
    )
    await limiter.acquire("ten1", "sess1")
    await redis_client.script_flush()
    await limiter.acquire("ten1", "sess1")


@pytest.mark.asyncio
async def test_key_prefix_isolation(redis_client: fakeredis.aioredis.FakeRedis) -> None:
    limiter_a = RedisRateLimiter(
        redis_client=redis_client,
        default=_cfg(tenant_cap=2),
        key_prefix="depA",
        breaker=_breaker(),
    )
    limiter_b = RedisRateLimiter(
        redis_client=redis_client,
        default=_cfg(tenant_cap=2),
        key_prefix="depB",
        breaker=_breaker(),
    )
    await limiter_a.acquire("ten", "s")
    await limiter_a.acquire("ten", "s")
    await limiter_b.acquire("ten", "s")
    await limiter_b.acquire("ten", "s")
```

- [ ] **Step 2: Run the tests**

```bash
uv run pytest tests/unit/test_redis_rate_limiter.py -v
```

Expected: 9 PASS.

- [ ] **Step 3: Run linters**

```bash
uv run ruff check src/wazuh_mcp/rate_limit/redis_limiter.py tests/unit/test_redis_rate_limiter.py
uv run ruff format --check src/wazuh_mcp/rate_limit/redis_limiter.py tests/unit/test_redis_rate_limiter.py
uv run ty check src/wazuh_mcp/rate_limit/redis_limiter.py
```

Expected: clean.

- [ ] **Step 4: Run the entire unit suite to confirm no regression**

```bash
uv run pytest tests/unit -q -m "not integration"
```

Expected: at least 544 + 9 + 9 + 11 = 573 PASS, 4 SKIP.

- [ ] **Step 5: Commit**

```bash
git add tests/unit/test_redis_rate_limiter.py
git commit -m "test(rate_limit): RedisRateLimiter unit tests (v1.1 T-C2)

9 tests via fakeredis.aioredis: protocol conformance, session/tenant
exhaustion (correct scope label), distinct-tenant budget isolation,
per-tenant override, ConnectionError fallback, breaker-open after
threshold, NOSCRIPT reload+retry, key-prefix isolation. All pass
without touching real Redis."
```

---

## Phase 4: T-D — Config schema + server wiring

**Goal:** Operators set `rate_limiter:` in `server.yaml` to pick the backend; `WAZUH_MCP_REDIS_URL` env var supplies the Redis URL when backend is `redis`. Server startup builds the right limiter.

### Task T-D1: Pydantic config schema

**Files:**
- Modify: `src/wazuh_mcp/tenancy/m4_config.py` (append new classes)
- Create: `tests/unit/test_rate_limiter_config.py`

- [ ] **Step 1: Verify the existing module's import block has `Literal`**

```bash
grep -n "^from typing\|Literal" src/wazuh_mcp/tenancy/m4_config.py | head -3
```

Expected: `from typing import Annotated, Literal` is already present (line 11). If not, add `Literal`.

- [ ] **Step 2: Append new classes to `m4_config.py`**

Append (do NOT replace) at the bottom of `src/wazuh_mcp/tenancy/m4_config.py`:

```python


# ---------------------------------------------------------------------------
# v1.1 — server-wide RateLimiter backend config (lives in server.yaml)
# ---------------------------------------------------------------------------


class CircuitBreakerConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    error_threshold: Annotated[int, Field(ge=1, le=100)] = 3
    open_duration_sec: Annotated[float, Field(gt=0.0, le=300.0)] = 5.0
    half_open_max_calls: Annotated[int, Field(ge=1, le=100)] = 1


class RedisRateLimiterConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    key_prefix: Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9:_-]+$")] = "wazuhmcp:rl"
    call_timeout_ms: Annotated[int, Field(ge=1, le=10_000)] = 50
    circuit_breaker: CircuitBreakerConfig = CircuitBreakerConfig()


class RateLimiterConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    backend: Literal["in_process", "redis"] = "in_process"
    redis: RedisRateLimiterConfig = RedisRateLimiterConfig()
```

- [ ] **Step 3: Write the config test file**

Create `tests/unit/test_rate_limiter_config.py`:

```python
"""RateLimiterConfig pydantic schema tests."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from wazuh_mcp.tenancy.m4_config import (
    CircuitBreakerConfig,
    RateLimiterConfig,
    RedisRateLimiterConfig,
)


def test_default_config_is_in_process() -> None:
    cfg = RateLimiterConfig()
    assert cfg.backend == "in_process"


def test_redis_backend_default_tunables() -> None:
    cfg = RateLimiterConfig.model_validate({"backend": "redis"})
    assert cfg.backend == "redis"
    assert cfg.redis.key_prefix == "wazuhmcp:rl"
    assert cfg.redis.call_timeout_ms == 50
    assert cfg.redis.circuit_breaker.error_threshold == 3
    assert cfg.redis.circuit_breaker.open_duration_sec == 5.0
    assert cfg.redis.circuit_breaker.half_open_max_calls == 1


def test_invalid_backend_rejected() -> None:
    with pytest.raises(ValidationError):
        RateLimiterConfig.model_validate({"backend": "memcached"})


def test_unknown_field_rejected() -> None:
    with pytest.raises(ValidationError):
        RateLimiterConfig.model_validate({"backend": "redis", "unknown": "x"})


def test_key_prefix_pattern() -> None:
    RedisRateLimiterConfig.model_validate({"key_prefix": "prod:rl"})
    RedisRateLimiterConfig.model_validate({"key_prefix": "rl-east-1"})
    with pytest.raises(ValidationError):
        RedisRateLimiterConfig.model_validate({"key_prefix": "has spaces"})
    with pytest.raises(ValidationError):
        RedisRateLimiterConfig.model_validate({"key_prefix": "no/slash"})


def test_call_timeout_bounds() -> None:
    with pytest.raises(ValidationError):
        RedisRateLimiterConfig.model_validate({"call_timeout_ms": 0})
    with pytest.raises(ValidationError):
        RedisRateLimiterConfig.model_validate({"call_timeout_ms": 100_000})


def test_circuit_breaker_bounds() -> None:
    with pytest.raises(ValidationError):
        CircuitBreakerConfig.model_validate({"error_threshold": 0})
    with pytest.raises(ValidationError):
        CircuitBreakerConfig.model_validate({"open_duration_sec": 0})
    with pytest.raises(ValidationError):
        CircuitBreakerConfig.model_validate({"half_open_max_calls": 0})


def test_full_config_round_trip() -> None:
    raw = {
        "backend": "redis",
        "redis": {
            "key_prefix": "custom:rl",
            "call_timeout_ms": 75,
            "circuit_breaker": {
                "error_threshold": 5,
                "open_duration_sec": 10.0,
                "half_open_max_calls": 2,
            },
        },
    }
    cfg = RateLimiterConfig.model_validate(raw)
    assert cfg.redis.key_prefix == "custom:rl"
    assert cfg.redis.call_timeout_ms == 75
    assert cfg.redis.circuit_breaker.error_threshold == 5
```

- [ ] **Step 4: Run the tests**

```bash
uv run pytest tests/unit/test_rate_limiter_config.py -v
```

Expected: 8 PASS.

- [ ] **Step 5: Run linters**

```bash
uv run ruff check src/wazuh_mcp/tenancy/m4_config.py tests/unit/test_rate_limiter_config.py
uv run ruff format --check src/wazuh_mcp/tenancy/m4_config.py tests/unit/test_rate_limiter_config.py
uv run ty check src/wazuh_mcp/tenancy/m4_config.py
```

Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add src/wazuh_mcp/tenancy/m4_config.py tests/unit/test_rate_limiter_config.py
git commit -m "feat(config): RateLimiterConfig schema for server.yaml (v1.1 T-D1)

Three new pydantic models (frozen, extra=forbid):
- CircuitBreakerConfig (error_threshold, open_duration_sec,
  half_open_max_calls — bounded ranges)
- RedisRateLimiterConfig (key_prefix pattern-validated, call_timeout_ms
  bounded, embeds CircuitBreakerConfig)
- RateLimiterConfig (backend Literal['in_process','redis'])

Default backend = in_process so v1.0 deployments are byte-for-byte
unchanged when this block is added to the schema. 8 unit tests cover
default values, invalid backends, unknown-field rejection, key_prefix
pattern, bounds, and full round-trip."
```

---

### Task T-D2: Server wiring — branch on `RateLimiterConfig.backend`

**Files:**
- Modify: `src/wazuh_mcp/server.py` (two limiter-construction sites)

- [ ] **Step 1: Plan-time signature grep — confirm the two construction sites**

```bash
grep -n "InProcessRateLimiter(" src/wazuh_mcp/server.py
```

Expected:
```
245:    limiter = cfg.limiter or InProcessRateLimiter(
246:        default=cfg.tenant.rate_limit,
247:        per_tenant={cfg.tenant.tenant_id: cfg.tenant.rate_limit},
248:    )
462:        limiter = InProcessRateLimiter(default=default_cfg, per_tenant=per_tenant_cfg)
```

Two sites confirmed: stdio-mode launcher (~line 245) and HTTP-mode launcher (~line 462).

- [ ] **Step 2: Read the surrounding context for both sites**

```bash
sed -n '240,255p' src/wazuh_mcp/server.py
sed -n '455,470p' src/wazuh_mcp/server.py
```

Confirm:
- `cfg` (stdio AppConfig) carries `tenant.rate_limit` and `secrets`.
- `http_cfg` (HTTP AppConfig) carries `all_tenants`, `default_cfg`, `per_tenant_cfg`.

- [ ] **Step 3: Add a helper that builds either backend**

Insert near other module-level helpers in `server.py` (around line 75, before `def load_config`):

```python
def _build_rate_limiter(
    *,
    cfg: RateLimiterConfig,
    default: RateLimitConfig,
    per_tenant: dict[str, RateLimitConfig],
) -> RateLimiter:
    """Build the configured rate-limiter backend.

    backend == "in_process" -> InProcessRateLimiter (v1.0 behavior).
    backend == "redis" -> RedisRateLimiter; requires WAZUH_MCP_REDIS_URL env var.
    """
    if cfg.backend == "in_process":
        return InProcessRateLimiter(default=default, per_tenant=per_tenant)

    redis_url = os.environ.get("WAZUH_MCP_REDIS_URL", "").strip()
    if not redis_url:
        raise RuntimeError(
            "rate_limiter.backend = 'redis' but WAZUH_MCP_REDIS_URL is not set; "
            "either unset rate_limiter or provide the URL via environment"
        )

    from redis.asyncio import Redis as AsyncRedis

    from wazuh_mcp.rate_limit.redis_limiter import (
        RedisRateLimiter,
        _RedisCircuitBreaker,
    )

    client = AsyncRedis.from_url(redis_url, decode_responses=False)
    breaker = _RedisCircuitBreaker(
        error_threshold=cfg.redis.circuit_breaker.error_threshold,
        open_duration_sec=cfg.redis.circuit_breaker.open_duration_sec,
        half_open_max_calls=cfg.redis.circuit_breaker.half_open_max_calls,
        call_timeout_ms=cfg.redis.call_timeout_ms,
    )
    return RedisRateLimiter(
        redis_client=client,
        default=default,
        per_tenant=per_tenant,
        key_prefix=cfg.redis.key_prefix,
        breaker=breaker,
    )
```

The Redis imports are deferred inline so `redis-py` is only imported when actually needed.

Add the imports needed at the top of `server.py`:

```python
import os  # if not already imported

from wazuh_mcp.tenancy.m4_config import (
    # ... existing imports ...
    RateLimiterConfig,  # add
)
```

- [ ] **Step 4: Wire the stdio-mode site**

Replace the existing block at `server.py:245-248`:

```python
    limiter = cfg.limiter or InProcessRateLimiter(
        default=cfg.tenant.rate_limit,
        per_tenant={cfg.tenant.tenant_id: cfg.tenant.rate_limit},
    )
```

with:

```python
    rl_cfg = RateLimiterConfig.model_validate(cfg.rate_limiter_raw or {})
    limiter = cfg.limiter or _build_rate_limiter(
        cfg=rl_cfg,
        default=cfg.tenant.rate_limit,
        per_tenant={cfg.tenant.tenant_id: cfg.tenant.rate_limit},
    )
```

- [ ] **Step 5: Make `AppConfig` carry the raw rate_limiter dict**

Find the stdio `AppConfig` dataclass at around `server.py:65-72`:

```python
@dataclass
class AppConfig:
    factory: ConfigSessionFactory
    tenant: TenantConfig
    secrets: YamlSecretStore
    limiter: RateLimiter | None = None
    audit: MultiSinkAuditEmitter | None = None
```

Add:

```python
    rate_limiter_raw: dict[str, object] | None = None
```

Then update `load_config` (around `server.py:75-84`):

```python
def load_config(config_dir: Path) -> AppConfig:
    server_cfg = yaml.safe_load((config_dir / "server.yaml").read_text()) or {}
    registry = YamlTenantRegistry(config_dir / "tenants.yaml")
    secrets = YamlSecretStore(config_dir / "secrets.yaml")

    tenant_id = server_cfg["active_tenant"]
    user_id = server_cfg.get("user_id", "local")
    tenant = registry.get(tenant_id)
    factory = ConfigSessionFactory(user_id=user_id, tenant=tenant)
    return AppConfig(
        factory=factory,
        tenant=tenant,
        secrets=secrets,
        rate_limiter_raw=server_cfg.get("rate_limiter") or None,
    )
```

- [ ] **Step 6: Wire the HTTP-mode site**

Find the HTTP-mode block at around `server.py:455-470` and replace:

```python
        limiter = InProcessRateLimiter(default=default_cfg, per_tenant=per_tenant_cfg)
```

with:

```python
        rl_cfg = RateLimiterConfig.model_validate(http_cfg.rate_limiter_raw or {})
        limiter = _build_rate_limiter(
            cfg=rl_cfg,
            default=default_cfg,
            per_tenant=per_tenant_cfg,
        )
```

Locate the HTTP `AppConfig`-equivalent:

```bash
grep -n "class.*AppConfig\|class HttpAppConfig\|HttpServerConfig" src/wazuh_mcp/server.py
```

Add a `rate_limiter_raw: dict[str, object] | None = None` field. Update its loader (around `server.py:534`) to read `server_cfg.get("rate_limiter")` and pass it through.

- [ ] **Step 7: Run unit suite to verify backwards-compat**

```bash
uv run pytest tests/unit -q -m "not integration"
```

Expected: PASS — no test should regress, since the default `RateLimiterConfig()` builds an `InProcessRateLimiter` exactly as before.

- [ ] **Step 8: Add an explicit test for the new wiring**

Append to `tests/unit/test_rate_limiter_config.py`:

```python


def test_build_rate_limiter_in_process_default(monkeypatch: pytest.MonkeyPatch) -> None:
    from wazuh_mcp.rate_limit.limiter import InProcessRateLimiter
    from wazuh_mcp.server import _build_rate_limiter
    from wazuh_mcp.tenancy.m4_config import RateLimitConfig

    rl = _build_rate_limiter(
        cfg=RateLimiterConfig(),
        default=RateLimitConfig(),
        per_tenant={},
    )
    assert isinstance(rl, InProcessRateLimiter)


def test_build_rate_limiter_redis_requires_url(monkeypatch: pytest.MonkeyPatch) -> None:
    from wazuh_mcp.server import _build_rate_limiter
    from wazuh_mcp.tenancy.m4_config import RateLimitConfig

    monkeypatch.delenv("WAZUH_MCP_REDIS_URL", raising=False)
    with pytest.raises(RuntimeError, match="WAZUH_MCP_REDIS_URL"):
        _build_rate_limiter(
            cfg=RateLimiterConfig.model_validate({"backend": "redis"}),
            default=RateLimitConfig(),
            per_tenant={},
        )


def test_build_rate_limiter_redis_constructs(monkeypatch: pytest.MonkeyPatch) -> None:
    from wazuh_mcp.rate_limit.redis_limiter import RedisRateLimiter
    from wazuh_mcp.server import _build_rate_limiter
    from wazuh_mcp.tenancy.m4_config import RateLimitConfig

    monkeypatch.setenv("WAZUH_MCP_REDIS_URL", "redis://localhost:6379/0")
    rl = _build_rate_limiter(
        cfg=RateLimiterConfig.model_validate({"backend": "redis"}),
        default=RateLimitConfig(),
        per_tenant={},
    )
    assert isinstance(rl, RedisRateLimiter)
```

- [ ] **Step 9: Run the new tests**

```bash
uv run pytest tests/unit/test_rate_limiter_config.py -v
```

Expected: 11 PASS (8 from T-D1 + 3 new).

- [ ] **Step 10: Run linters**

```bash
uv run ruff check src/wazuh_mcp/server.py tests/unit/test_rate_limiter_config.py
uv run ruff format --check src/wazuh_mcp/server.py tests/unit/test_rate_limiter_config.py
uv run ty check src/wazuh_mcp/server.py
```

Expected: clean.

- [ ] **Step 11: Commit**

```bash
git add src/wazuh_mcp/server.py tests/unit/test_rate_limiter_config.py
git commit -m "feat(server): wire RateLimiterConfig backend selection (v1.1 T-D2)

server.yaml gains an optional top-level rate_limiter: block. Both
the stdio and HTTP launchers now route through _build_rate_limiter,
which selects InProcessRateLimiter (default — byte-for-byte v1.0
behavior) or RedisRateLimiter when backend=redis. The Redis path
requires WAZUH_MCP_REDIS_URL — startup fails loudly if backend=redis
and the env var is unset (the alternative — silent fallback to
in-process — was rejected at spec time).

Redis imports are inline-deferred so the in_process path doesn't pay
the import cost. 3 new wiring tests confirm the branch."
```

---

## Phase 5: T-E — Observability

**Goal:** Three new prometheus metrics + a `/healthz` field that operators can wire alerts off of.

### Task T-E1: Register the three new metrics

**Files:**
- Modify: `src/wazuh_mcp/observability/metrics.py`

- [ ] **Step 1: Read the existing metric registry surface**

```bash
grep -n "^def \|^_\|create_gauge\|create_counter\|create_histogram\|RATE_LIMITED" src/wazuh_mcp/observability/metrics.py | head -30
```

Read enough of the file to understand the registration pattern. The existing `wazuh_mcp_rate_limited_total` is the closest analog — match its style exactly.

- [ ] **Step 2: Append three new metric registrations**

Locate the section that registers rate-limit-related metrics. After the existing `rate_limited_total` registration, add:

```python
# v1.1 — Redis-backed rate limiter observability.
RATE_LIMIT_REDIS_STATE = _meter.create_gauge(
    "wazuh_mcp_rate_limit_redis_state",
    description="Circuit breaker state for the Redis-backed rate limiter "
                "(0=closed, 1=half_open, 2=open). One time series per replica.",
    unit="1",
)
RATE_LIMIT_REDIS_CALL_TOTAL = _meter.create_counter(
    "wazuh_mcp_rate_limit_redis_call_total",
    description="Total Redis calls from the rate limiter, labeled by outcome.",
    unit="1",
)
RATE_LIMIT_FALLBACK_TOTAL = _meter.create_counter(
    "wazuh_mcp_rate_limit_fallback_total",
    description="Acquire calls served by the in-process fallback while the "
                "Redis backend is OPEN.",
    unit="1",
)
```

Adjust `_meter.create_*` to match the actual registration pattern in this file — the existing `rate_limited_total` is the reference.

- [ ] **Step 3: Run linters**

```bash
uv run ruff check src/wazuh_mcp/observability/metrics.py
uv run ty check src/wazuh_mcp/observability/metrics.py
```

Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add src/wazuh_mcp/observability/metrics.py
git commit -m "feat(observability): register 3 v1.1 rate-limiter metrics (v1.1 T-E1)

- wazuh_mcp_rate_limit_redis_state (gauge, 0/1/2 = closed/half_open/open)
- wazuh_mcp_rate_limit_redis_call_total (counter, labeled by outcome)
- wazuh_mcp_rate_limit_fallback_total (counter, labeled by tenant+scope)

Wired into RedisRateLimiter and _RedisCircuitBreaker in T-E2."
```

---

### Task T-E2: Wire metric emission

**Files:**
- Modify: `src/wazuh_mcp/rate_limit/redis_limiter.py`
- Create: `tests/unit/test_redis_limiter_metrics.py`

- [ ] **Step 1: Add metric imports to top of `redis_limiter.py`**

Add to the import block:

```python
import socket

from wazuh_mcp.observability.metrics import (
    RATE_LIMIT_FALLBACK_TOTAL,
    RATE_LIMIT_REDIS_CALL_TOTAL,
    RATE_LIMIT_REDIS_STATE,
)
```

- [ ] **Step 2: Wire breaker state metric**

In `_RedisCircuitBreaker._transition`, after `self._state = new_state`:

```python
        try:
            RATE_LIMIT_REDIS_STATE.set(int(new_state), {"replica": socket.gethostname()})
        except Exception:
            _LOG.debug("rate_limit_redis_state metric emission failed", exc_info=True)
```

- [ ] **Step 3: Wire call-outcome counter**

Replace `RedisRateLimiter._try_redis_acquire` body:

```python
    async def _try_redis_acquire(self, key: str, cfg_bucket, ttl: int) -> bool:
        try:
            result = await self._run_script(
                key=key,
                capacity=cfg_bucket.capacity,
                refill=cfg_bucket.refill_per_sec,
                n=1,
                ttl=ttl,
            )
            RATE_LIMIT_REDIS_CALL_TOTAL.add(1, {"outcome": "ok"})
            return result == 1
        except (RedisTimeoutError, asyncio.TimeoutError, TimeoutError):
            RATE_LIMIT_REDIS_CALL_TOTAL.add(1, {"outcome": "timeout"})
            raise
        except Exception:  # noqa: BLE001
            RATE_LIMIT_REDIS_CALL_TOTAL.add(1, {"outcome": "error"})
            raise
```

- [ ] **Step 4: Wire fallback counter**

In `RedisRateLimiter.acquire`, in each fallback path (CircuitBreakerOpenError + RedisConnectionError/TimeoutError), before the fallback call. The two fallback paths cover tenant-bucket and session-bucket failures; emit with the appropriate `scope` label.

For the tenant-bucket fallbacks:

```python
            RATE_LIMIT_FALLBACK_TOTAL.add(1, {"tenant_id": tenant_id, "scope": "tenant"})
            await self._ensure_fallback().acquire(tenant_id, session_id)
            return
```

For the session-bucket fallbacks:

```python
            RATE_LIMIT_FALLBACK_TOTAL.add(1, {"tenant_id": tenant_id, "scope": "session"})
            await self._ensure_fallback().acquire(tenant_id, session_id)
            return
```

- [ ] **Step 5: Write metric tests**

Create `tests/unit/test_redis_limiter_metrics.py`:

```python
"""Metric emission from RedisRateLimiter + breaker."""

from __future__ import annotations

import pytest

from wazuh_mcp.rate_limit.redis_limiter import (
    BreakerState,
    _RedisCircuitBreaker,
)


@pytest.mark.asyncio
async def test_breaker_transition_emits_state_metric(monkeypatch: pytest.MonkeyPatch) -> None:
    """The state metric must be set on every transition."""
    captured: list[tuple[int, dict[str, str]]] = []

    class FakeGauge:
        def set(self, value: int, labels: dict[str, str]) -> None:
            captured.append((value, labels))

    monkeypatch.setattr("wazuh_mcp.rate_limit.redis_limiter.RATE_LIMIT_REDIS_STATE", FakeGauge())

    breaker = _RedisCircuitBreaker(
        error_threshold=2,
        open_duration_sec=10.0,
        half_open_max_calls=1,
        call_timeout_ms=200,
    )

    async def fail() -> None:
        raise RuntimeError("boom")

    for _ in range(2):
        with pytest.raises(RuntimeError):
            await breaker.call(fail)

    assert breaker.state == BreakerState.OPEN
    open_emissions = [c for c in captured if c[0] == int(BreakerState.OPEN)]
    assert len(open_emissions) >= 1
    assert "replica" in open_emissions[0][1]
```

- [ ] **Step 6: Run tests**

```bash
uv run pytest tests/unit/test_redis_limiter_metrics.py tests/unit/test_redis_circuit_breaker.py tests/unit/test_redis_rate_limiter.py -v
```

Expected: all PASS.

- [ ] **Step 7: Commit**

```bash
git add src/wazuh_mcp/rate_limit/redis_limiter.py tests/unit/test_redis_limiter_metrics.py
git commit -m "feat(observability): wire 3 metrics into RedisRateLimiter (v1.1 T-E2)

- Breaker transitions set RATE_LIMIT_REDIS_STATE with replica label.
- Every Redis call adds to RATE_LIMIT_REDIS_CALL_TOTAL with outcome
  label (ok / timeout / error).
- Every fallback hit adds to RATE_LIMIT_FALLBACK_TOTAL with tenant_id
  + scope (tenant / session) labels.

Metric emission failures swallowed at DEBUG to keep business logic
robust. 1 representative metric test; the call paths are exercised by
existing T-B3 + T-C2 suites."
```

---

### Task T-E3: `/healthz` field

**Files:**
- Modify: `src/wazuh_mcp/server.py` or `src/wazuh_mcp/observability/healthz.py` (whichever owns /healthz)

- [ ] **Step 1: Locate the /healthz handler**

```bash
grep -rn "healthz\|/healthz\|health_check\|liveness" src/wazuh_mcp/ | head -10
```

Identify the handler module.

- [ ] **Step 2: Add a `rate_limiter` field to the response**

Add a helper function near the handler:

```python
def _rate_limiter_health(limiter: RateLimiter | None) -> dict[str, str]:
    if limiter is None:
        return {"backend": "none", "redis": "disabled"}
    from wazuh_mcp.rate_limit.redis_limiter import BreakerState, RedisRateLimiter
    if isinstance(limiter, RedisRateLimiter):
        state = limiter._breaker.state  # noqa: SLF001
        if state == BreakerState.CLOSED:
            return {"backend": "redis", "redis": "ok"}
        return {"backend": "redis", "redis": "degraded"}
    return {"backend": "in_process", "redis": "disabled"}
```

Wire it into the existing healthz JSON body under a `rate_limiter` key.

- [ ] **Step 3: Run unit suite to confirm no regression**

```bash
uv run pytest tests/unit -q -m "not integration"
```

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add src/wazuh_mcp/  # whichever files touched
git commit -m "feat(healthz): rate_limiter status field (v1.1 T-E3)

/healthz response gains a rate_limiter object:
  {\"backend\": \"redis\"|\"in_process\"|\"none\",
   \"redis\": \"ok\"|\"degraded\"|\"disabled\"}

\"degraded\" surfaces when the circuit breaker is OPEN or HALF_OPEN.
Operators alert off the metric (RATE_LIMIT_REDIS_STATE) for SLO
purposes; this field is for incident-time eyeball checks."
```

---

## Phase 6: T-F — Integration test, Helm, docs

**Goal:** Real-Redis integration coverage; Helm chart wiring; updated operator docs.

### Task T-F1: Real-Redis integration test

**Files:**
- Create: `tests/integration/test_redis_limiter_real.py`
- Modify: `docker/integration-compose.yml`

- [ ] **Step 1: Add redis to docker-compose**

Edit `docker/integration-compose.yml`. Add a service:

```yaml
  redis:
    image: redis:7-alpine
    container_name: wazuhmcp-redis-${COMPOSE_PROJECT_NAME:-test}
    ports:
      - "6379:6379"
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 2s
      timeout: 3s
      retries: 10
```

Confirm no port conflicts with existing services.

- [ ] **Step 2: Write the integration test**

Create `tests/integration/test_redis_limiter_real.py`:

```python
"""Real-Redis integration test for RedisRateLimiter.

Marked @pytest.mark.integration. Spun up via docker/bootstrap.sh which
starts the redis service from integration-compose.yml.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
from collections.abc import AsyncIterator

import pytest
from redis.asyncio import Redis as AsyncRedis

from wazuh_mcp.rate_limit.redis_limiter import (
    BreakerState,
    RedisRateLimiter,
    _RedisCircuitBreaker,
)
from wazuh_mcp.tenancy.m4_config import BucketConfig, RateLimitConfig
from wazuh_mcp.wazuh.errors import WazuhError

pytestmark = pytest.mark.integration

REDIS_URL = os.environ.get("WAZUH_MCP_REDIS_URL", "redis://localhost:6379/0")


def _cfg(tenant_cap: int = 5, session_cap: int = 5) -> RateLimitConfig:
    return RateLimitConfig(
        tenant=BucketConfig(capacity=tenant_cap, refill_per_sec=0.1),
        session=BucketConfig(capacity=session_cap, refill_per_sec=0.1),
    )


def _breaker() -> _RedisCircuitBreaker:
    return _RedisCircuitBreaker(
        error_threshold=3,
        open_duration_sec=2.0,
        half_open_max_calls=1,
        call_timeout_ms=500,
    )


@pytest.fixture
async def redis_clean() -> AsyncIterator[AsyncRedis]:
    client = AsyncRedis.from_url(REDIS_URL, decode_responses=False)
    await client.flushdb()
    yield client
    await client.flushdb()
    await client.aclose()


@pytest.mark.asyncio
async def test_real_redis_basic_acquire(redis_clean: AsyncRedis) -> None:
    limiter = RedisRateLimiter(
        redis_client=redis_clean,
        default=_cfg(tenant_cap=3, session_cap=3),
        key_prefix="itest:basic",
        breaker=_breaker(),
    )
    for _ in range(3):
        await limiter.acquire("ten1", "sess1")
    with pytest.raises(WazuhError):
        await limiter.acquire("ten1", "sess1")


@pytest.mark.asyncio
async def test_two_replicas_share_budget(redis_clean: AsyncRedis) -> None:
    """Two RedisRateLimiter instances against the same Redis enforce one global budget."""
    a = RedisRateLimiter(
        redis_client=redis_clean,
        default=_cfg(tenant_cap=4),
        key_prefix="itest:share",
        breaker=_breaker(),
    )
    b = RedisRateLimiter(
        redis_client=redis_clean,
        default=_cfg(tenant_cap=4),
        key_prefix="itest:share",
        breaker=_breaker(),
    )
    await a.acquire("ten", "s1")
    await b.acquire("ten", "s2")
    await a.acquire("ten", "s3")
    await b.acquire("ten", "s4")
    with pytest.raises(WazuhError):
        await a.acquire("ten", "s5")


@pytest.mark.asyncio
async def test_redis_stop_triggers_fallback(redis_clean: AsyncRedis) -> None:
    """docker stop redis mid-load -> breaker opens -> fallback serves; restart -> breaker closes."""
    if shutil.which("docker") is None:
        pytest.skip("docker CLI not available")

    container_name = f"wazuhmcp-redis-{os.environ.get('COMPOSE_PROJECT_NAME', 'test')}"

    limiter = RedisRateLimiter(
        redis_client=redis_clean,
        default=_cfg(tenant_cap=1000),
        key_prefix="itest:stop",
        breaker=_breaker(),
    )

    await limiter.acquire("ten", "sess")
    subprocess.run(["docker", "stop", container_name], check=True, timeout=15)
    try:
        for _ in range(5):
            await limiter.acquire("ten", "sess")
        assert limiter._breaker.state == BreakerState.OPEN  # noqa: SLF001
    finally:
        subprocess.run(["docker", "start", container_name], check=True, timeout=15)
        for _ in range(30):
            try:
                await redis_clean.ping()
                break
            except Exception:
                await asyncio.sleep(0.5)

    await asyncio.sleep(2.5)
    await limiter.acquire("ten", "sess")
    assert limiter._breaker.state == BreakerState.CLOSED  # noqa: SLF001


@pytest.mark.asyncio
async def test_real_redis_noscript_recovery(redis_clean: AsyncRedis) -> None:
    """SCRIPT FLUSH mid-run; next acquire reloads via NOSCRIPT path."""
    limiter = RedisRateLimiter(
        redis_client=redis_clean,
        default=_cfg(),
        key_prefix="itest:noscript",
        breaker=_breaker(),
    )
    await limiter.acquire("ten", "sess")
    await redis_clean.script_flush()
    await limiter.acquire("ten", "sess")
```

- [ ] **Step 3: Run the integration test**

```bash
docker compose -f docker/integration-compose.yml up -d redis
WAZUH_MCP_REDIS_URL=redis://localhost:6379/0 \
  uv run pytest tests/integration/test_redis_limiter_real.py -v -m integration
```

Expected: 4 PASS.

- [ ] **Step 4: Commit**

```bash
git add docker/integration-compose.yml tests/integration/test_redis_limiter_real.py
git commit -m "test(integration): real-Redis integration coverage (v1.1 T-F1)

Adds redis:7-alpine to integration-compose.yml. 4 integration tests:
- basic acquire end-to-end against real Redis
- two replicas (same Redis) enforce one global budget — proves the
  multi-replica HA guarantee
- docker-stop redis mid-load -> breaker opens -> fallback serves;
  restart -> breaker closes. Uses docker stop/start (not pause) per
  CI flake history with pause/unpause in this repo
- SCRIPT FLUSH mid-run triggers NOSCRIPT recovery"
```

---

### Task T-F2: Helm chart wiring

**Files:**
- Modify: `charts/wazuh-mcp/values.yaml`
- Modify: `charts/wazuh-mcp/templates/deployment.yaml`
- Modify: `charts/wazuh-mcp/templates/configmap-server.yaml` (or whichever templates server.yaml)

- [ ] **Step 1: Add redis values block to values.yaml**

In `charts/wazuh-mcp/values.yaml`, add (near `replicaCount: 1`):

```yaml
# v1.1 — opt-in Redis-backed rate limiter for multi-replica deployments.
# replicaCount > 1 is supported when redis.enabled=true, but operators querying
# local-audit-* will see duplicate-keyed events from sessions hitting different
# replicas. The audit-dedup blocker is closed in v1.2; until then, replicaCount
# default stays at 1.
redis:
  enabled: false
  # K8s Secret with key 'redis-url' (e.g. redis://default:hunter2@redis.svc:6379/0).
  existingSecret: ""
  tunables:
    keyPrefix: "wazuhmcp:rl"
    callTimeoutMs: 50
    circuitBreaker:
      errorThreshold: 3
      openDurationSec: 5
      halfOpenMaxCalls: 1
```

- [ ] **Step 2: Wire env var in deployment.yaml**

In `charts/wazuh-mcp/templates/deployment.yaml`, find the main container's `env:` block. Add:

```yaml
          {{- if .Values.redis.enabled }}
          - name: WAZUH_MCP_REDIS_URL
            valueFrom:
              secretKeyRef:
                name: {{ required "redis.existingSecret is required when redis.enabled" .Values.redis.existingSecret }}
                key: redis-url
          {{- end }}
```

- [ ] **Step 3: Emit the rate_limiter block in the server.yaml ConfigMap**

In `charts/wazuh-mcp/templates/configmap-server.yaml`, append to the `server.yaml` data:

```yaml
{{- if .Values.redis.enabled }}
    rate_limiter:
      backend: "redis"
      redis:
        key_prefix: {{ .Values.redis.tunables.keyPrefix | quote }}
        call_timeout_ms: {{ .Values.redis.tunables.callTimeoutMs }}
        circuit_breaker:
          error_threshold: {{ .Values.redis.tunables.circuitBreaker.errorThreshold }}
          open_duration_sec: {{ .Values.redis.tunables.circuitBreaker.openDurationSec }}
          half_open_max_calls: {{ .Values.redis.tunables.circuitBreaker.halfOpenMaxCalls }}
{{- end }}
```

- [ ] **Step 4: Lint the chart**

```bash
helm lint charts/wazuh-mcp/
helm template test charts/wazuh-mcp/ --set redis.enabled=true --set redis.existingSecret=my-secret | head -80
```

Expected: lint passes; rendered output shows the env var + ConfigMap block.

- [ ] **Step 5: Commit**

```bash
git add charts/wazuh-mcp/
git commit -m "feat(helm): redis.enabled wiring for v1.1 RateLimiter (v1.1 T-F2)

values.yaml gains a redis.* block (default disabled). When enabled:
- WAZUH_MCP_REDIS_URL env var sourced from the user-provided
  existingSecret (key: redis-url)
- server.yaml ConfigMap emits the rate_limiter: block with the user's
  configured tunables

replicaCount default stays at 1 — audit-dedup blocker (closed in v1.2)
still gates a default bump. Operators who want multi-replica today set
both redis.enabled=true and replicaCount: N explicitly."
```

---

### Task T-F3: Documentation

**Files:**
- Modify: `docs/deploy/helm.md`
- Create: `docs/deploy/redis.md`
- Modify: `README.md`

- [ ] **Step 1: Update HA caveat in helm.md**

Replace the HA-caveat section in `docs/deploy/helm.md` (around line 125) with:

```markdown
## HA caveat

**v1.1 lifts the rate-limiter blocker** — set `redis.enabled=true` to opt into
multi-replica deployments with a shared rate budget. The remaining blocker is
the **audit emitter**, which still buffers events in-memory before flushing to
the indexer. Operators querying `local-audit-*` will see duplicate-keyed events
for sessions that hit different replicas. The audit-dedup blocker is closed in
v1.2.

Until v1.2:

- For maximum HA today, set `redis.enabled=true` and `replicaCount: 2+`.
  Tolerate the audit duplication or query past it.
- For audit-quality-first, keep `replicaCount: 1`.

The chart's default `replicaCount: 1` reflects the conservative path. See
`docs/deploy/redis.md` for redis-side sizing and observability.
```

- [ ] **Step 2: Create redis.md**

Create `docs/deploy/redis.md`:

````markdown
# Redis-backed rate limiter (v1.1+)

The `RateLimiter` Protocol has two backends: in-process (default; per-replica)
and Redis (opt-in; shared across replicas). Use Redis when running
`replicaCount > 1` so the configured rate budget is enforced fleet-wide instead
of multiplied by replica count.

## Architecture

Two-tier token-bucket: tenant + session. Both buckets live in Redis as hashes,
keyed by `{prefix}:tenant:{tenant_id}` and `{prefix}:session:{tenant_id}:{session_id}`.
Refill+consume happens atomically via a Lua script (server-supplied wall clock,
deterministic under Redis Cluster replication).

A per-process asyncio circuit breaker wraps every Redis call. On consecutive
failures, the breaker opens and `acquire()` calls route to a per-replica
in-process limiter. The fleet temporarily degrades to per-replica enforcement
during the outage; the breaker re-closes after Redis recovers.

## Configuration

`server.yaml`:

```yaml
rate_limiter:
  backend: "redis"
  redis:
    key_prefix: "wazuhmcp:rl"     # default; lets multiple deployments share a Redis
    call_timeout_ms: 50
    circuit_breaker:
      error_threshold: 3
      open_duration_sec: 5
      half_open_max_calls: 1
```

URL via env var (Helm sources from a Secret):

```bash
WAZUH_MCP_REDIS_URL=rediss://default:hunter2@redis.svc:6380/0
```

URL syntax: `redis://`, `rediss://` (TLS), and `redis-sentinel://...` are all
honored by `redis-py 5.x`'s `Redis.from_url`.

## Sizing

- Tenant bucket: ~200 bytes per tenant — negligible.
- Session bucket: ~250 bytes per active session. With TTL ≈ `2 × capacity / refill_per_sec`,
  abandoned sessions evict naturally.
- A 10K concurrent-session deployment: ~2.5 MB. Redis memory is not a concern at
  realistic v1.x scales.

## Observability

Three new metrics exported at `/metrics`:

| Metric | Purpose | Alert |
|---|---|---|
| `wazuh_mcp_rate_limit_redis_state{replica}` | Breaker state per replica (0=closed, 1=half_open, 2=open). | `>0` for >5 min |
| `wazuh_mcp_rate_limit_redis_call_total{outcome}` | Redis call health. | Error rate >1% sustained |
| `wazuh_mcp_rate_limit_fallback_total{tenant_id,scope}` | Fallback hits per tenant. | Volume spikes during incidents |

`/healthz` reflects breaker state under `rate_limiter.redis`:
`"ok"` | `"degraded"` | `"disabled"`.

## Failure modes

- **Redis unreachable at startup** → server fails to start with a clear error.
  Fix the URL or unset `rate_limiter.backend = redis` to fall back to in-process.
- **Redis goes away mid-flight** → first failure increments the breaker counter;
  after `error_threshold` consecutive failures the breaker opens; `acquire()`
  calls then route to the per-replica in-process limiter. No user-visible
  errors during the outage. Once `open_duration_sec` elapses, a probe call
  retries Redis; success → re-closed.
- **Redis flushes the script cache** (e.g., after a restart) → first call
  detects `NOSCRIPT`, reloads the script, and retries transparently.

## Migration from v1.0

None required. New optional config block. Existing deployments are byte-for-byte
identical until `rate_limiter.backend: "redis"` is set.
````

- [ ] **Step 3: Update README features matrix**

In `README.md`, find the features table and add a row:

```markdown
| Multi-replica HA (Redis-backed rate limiter) | v1.1 | opt-in via `redis.enabled=true` |
```

- [ ] **Step 4: Commit**

```bash
git add docs/deploy/helm.md docs/deploy/redis.md README.md
git commit -m "docs(v1.1): redis rate-limiter operator guide (v1.1 T-F3)

- docs/deploy/redis.md (new): config, sizing, observability, failure modes
- docs/deploy/helm.md HA-caveat updated: rate-limiter blocker closed
  in v1.1; audit-dedup blocker remains; default replicaCount=1 stays
- README.md features matrix gains a multi-replica HA row"
```

---

## Phase close-out

### Task T-G1: Final verification + ship

- [ ] **Step 1: Run the full unit suite**

```bash
uv run pytest tests/unit -q -m "not integration"
```

Expected: all PASS, no skips beyond the v1.0 baseline of 4.

- [ ] **Step 2: Run the integration suite (requires docker stack)**

```bash
docker compose -f docker/integration-compose.yml up -d
WAZUH_MCP_REDIS_URL=redis://localhost:6379/0 \
  uv run pytest tests/integration -q -m integration
```

Expected: existing 39 + 4 new integration tests PASS.

- [ ] **Step 3: Lint + format + type-check the whole project**

```bash
uv run ruff check .
uv run ruff format --check .
uv run ty check src tests
```

Expected: clean.

- [ ] **Step 4: Verify v1.0 backwards compat**

```bash
uv run python -c "
from wazuh_mcp.tenancy.m4_config import RateLimiterConfig, RateLimitConfig
from wazuh_mcp.rate_limit.limiter import InProcessRateLimiter
from wazuh_mcp.server import _build_rate_limiter
rl = _build_rate_limiter(cfg=RateLimiterConfig(), default=RateLimitConfig(), per_tenant={})
assert isinstance(rl, InProcessRateLimiter), type(rl)
print('v1.0 backwards-compat verified')
"
```

Expected: `v1.0 backwards-compat verified`.

- [ ] **Step 5: Bump version**

Edit `pyproject.toml`. Change `version = "1.0.10"` to `version = "1.1.0"`. Run `uv lock`.

```bash
git add pyproject.toml uv.lock
git commit -m "chore: bump version 1.0.10 -> 1.1.0 for v1.1 ship"
```

- [ ] **Step 6: Tag and push**

```bash
git tag -a v1.1.0 -m "v1.1.0 — Redis-backed RateLimiter for multi-replica deployments

Closes the rate-limiter half of the v1.0 HA caveat. Multi-replica
deployments now share a global rate budget via Redis; on Redis outage,
each replica falls back to per-replica enforcement (v1.0 behavior)
under circuit-breaker control.

Audit-emitter cross-replica dedup remains the open HA blocker;
deferred to v1.2.

Backwards-compatible: v1.0 deployments without rate_limiter: in
server.yaml are byte-for-byte unchanged."

git push origin main v1.1.0
```

The release workflow at `.github/workflows/release.yml` builds + publishes the v1.1.0 GHCR image automatically.

---

## Self-review notes (for plan author)

Spec coverage check: every spec section traced to a task.
- Goal / non-goals → plan header.
- Decisions 1-5 → T-A through T-E (failure mode = T-C1, BYO Redis = T-D2 + T-F2, scope = whole plan, env+config split = T-D1 + T-D2, breaker = T-B).
- Architecture → T-C1.
- File layout → File Structure section.
- Dependencies → T-A1.
- Configuration (server.yaml + env) → T-D1, T-D2.
- Bucket key shape, TTL → T-C1 (`_ttl_for`, `_tenant_key`, `_session_key`).
- Lua script + per-call sequencing → T-A2, T-A3, T-C1, T-C2.
- Circuit breaker → T-B1, T-B2.
- Observability → T-E1, T-E2, T-E3.
- Testing (3 layers) → T-A3 (script), T-B (breaker), T-C2 (limiter), T-F1 (real redis).
- Helm chart edits → T-F2.
- Docs → T-F3.
- Migration / acceptance criteria → T-G1.

Type-consistency check passed: `RateLimiter` Protocol shape unchanged. `RedisRateLimiter` constructor params consistent across T-C1, T-D2, T-F1. Metric names identical across T-E1 (registration), T-E2 (emission), T-F3 (docs).

Placeholder scan: no "TBD" / "TODO" / "implement later" remain. Two intentional `# ty: ignore` comments removed in T-B2 step 4.

Scope check: single-feature milestone (rate limiter only). Audit dedup explicitly out of scope. ~12 dispatches across 6 phases — proportionate to past M5b (16 dispatches across 6 phases).
