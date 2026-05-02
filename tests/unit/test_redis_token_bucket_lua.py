"""Lua token_bucket script unit tests via fakeredis (Lua-capable).

Mirrors the in-process TokenBucket test scenarios so semantic parity is
provable. Each test loads the production .lua file and runs it via
SCRIPT LOAD + EVALSHA — the same path the production limiter uses.
"""

from __future__ import annotations

from pathlib import Path

import fakeredis
import pytest

LUA_PATH = (
    Path(__file__).parent.parent.parent
    / "src"
    / "wazuh_mcp"
    / "rate_limit"
    / "lua"
    / "token_bucket.lua"
)


@pytest.fixture
def lua_script() -> str:
    return LUA_PATH.read_text(encoding="utf-8")


@pytest.fixture
def fake_redis() -> fakeredis.FakeRedis[bytes]:
    return fakeredis.FakeRedis(decode_responses=False)


@pytest.fixture
def script_sha(lua_script: str, fake_redis: fakeredis.FakeRedis[bytes]) -> str:
    return fake_redis.script_load(lua_script)  # type: ignore[return-value]


def _run(
    redis: fakeredis.FakeRedis[bytes],
    sha: str,
    key: str,
    *,
    capacity: int,
    refill: float,
    now_ms: int,
    n: int = 1,
    ttl: int = 60,
) -> int:
    return int(redis.evalsha(sha, 1, key, capacity, refill, now_ms, n, ttl))  # type: ignore[arg-type]


def test_new_bucket_starts_full_and_grants(
    fake_redis: fakeredis.FakeRedis[bytes], script_sha: str
) -> None:
    result = _run(fake_redis, script_sha, "k", capacity=5, refill=1.0, now_ms=1_000_000)
    assert result == 1
    h = fake_redis.hgetall("k")
    assert float(h[b"tokens"]) == pytest.approx(4.0)
    assert int(h[b"last_refill_ms"]) == 1_000_000


def test_consume_to_exhaustion(fake_redis: fakeredis.FakeRedis[bytes], script_sha: str) -> None:
    for _ in range(5):
        assert _run(fake_redis, script_sha, "k", capacity=5, refill=0.0001, now_ms=1_000_000) == 1
    assert _run(fake_redis, script_sha, "k", capacity=5, refill=0.0001, now_ms=1_000_000) == 0


def test_refill_across_seconds(fake_redis: fakeredis.FakeRedis[bytes], script_sha: str) -> None:
    for _ in range(3):
        assert _run(fake_redis, script_sha, "k", capacity=3, refill=1.0, now_ms=1_000_000) == 1
    assert _run(fake_redis, script_sha, "k", capacity=3, refill=1.0, now_ms=1_000_000) == 0
    assert _run(fake_redis, script_sha, "k", capacity=3, refill=1.0, now_ms=1_002_000) == 1
    assert _run(fake_redis, script_sha, "k", capacity=3, refill=1.0, now_ms=1_002_000) == 1
    assert _run(fake_redis, script_sha, "k", capacity=3, refill=1.0, now_ms=1_002_000) == 0


def test_capacity_clamp_on_long_idle(
    fake_redis: fakeredis.FakeRedis[bytes], script_sha: str
) -> None:
    _run(fake_redis, script_sha, "k", capacity=5, refill=1.0, now_ms=1_000_000)
    for _ in range(5):
        assert _run(fake_redis, script_sha, "k", capacity=5, refill=1.0, now_ms=2_000_000) == 1
    assert _run(fake_redis, script_sha, "k", capacity=5, refill=1.0, now_ms=2_000_000) == 0


def test_exact_boundary_grant(fake_redis: fakeredis.FakeRedis[bytes], script_sha: str) -> None:
    assert _run(fake_redis, script_sha, "k", capacity=1, refill=1.0, now_ms=0) == 1
    assert _run(fake_redis, script_sha, "k", capacity=1, refill=1.0, now_ms=1_000) == 1


def test_denial_persists_refill(fake_redis: fakeredis.FakeRedis[bytes], script_sha: str) -> None:
    assert _run(fake_redis, script_sha, "k", capacity=1, refill=0.5, now_ms=0) == 1
    assert _run(fake_redis, script_sha, "k", capacity=1, refill=0.5, now_ms=100) == 0
    h = fake_redis.hgetall("k")
    assert int(h[b"last_refill_ms"]) == 100
    assert float(h[b"tokens"]) == pytest.approx(0.05)


def test_clock_skew_negative_elapsed_clamped(
    fake_redis: fakeredis.FakeRedis[bytes], script_sha: str
) -> None:
    assert _run(fake_redis, script_sha, "k", capacity=2, refill=1.0, now_ms=1000) == 1
    assert _run(fake_redis, script_sha, "k", capacity=2, refill=1.0, now_ms=500) == 1
    assert _run(fake_redis, script_sha, "k", capacity=2, refill=1.0, now_ms=500) == 0


def test_multi_token_consume(fake_redis: fakeredis.FakeRedis[bytes], script_sha: str) -> None:
    assert _run(fake_redis, script_sha, "k", capacity=5, refill=1.0, now_ms=0, n=3) == 1
    h = fake_redis.hgetall("k")
    assert float(h[b"tokens"]) == pytest.approx(2.0)
    assert _run(fake_redis, script_sha, "k", capacity=5, refill=1.0, now_ms=0, n=3) == 0


def test_ttl_applied_on_every_call(fake_redis: fakeredis.FakeRedis[bytes], script_sha: str) -> None:
    _run(fake_redis, script_sha, "k", capacity=3, refill=1.0, now_ms=0, ttl=120)
    assert 0 < fake_redis.ttl("k") <= 120
    _run(fake_redis, script_sha, "k", capacity=3, refill=1.0, now_ms=1000, ttl=180)
    assert 120 < fake_redis.ttl("k") <= 180


def test_distinct_keys_isolated(fake_redis: fakeredis.FakeRedis[bytes], script_sha: str) -> None:
    for _ in range(3):
        assert _run(fake_redis, script_sha, "ka", capacity=3, refill=0.0001, now_ms=0) == 1
    assert _run(fake_redis, script_sha, "ka", capacity=3, refill=0.0001, now_ms=0) == 0
    assert _run(fake_redis, script_sha, "kb", capacity=3, refill=0.0001, now_ms=0) == 1


def test_zero_refill_rate_supported(
    fake_redis: fakeredis.FakeRedis[bytes], script_sha: str
) -> None:
    # Edge case — Pydantic schema enforces refill > 0 at config-load time, but
    # the script itself shouldn't crash on 0 (defensive).
    assert _run(fake_redis, script_sha, "k", capacity=2, refill=0.0, now_ms=0) == 1
    assert _run(fake_redis, script_sha, "k", capacity=2, refill=0.0, now_ms=10_000_000) == 1
    assert _run(fake_redis, script_sha, "k", capacity=2, refill=0.0, now_ms=10_000_000) == 0
