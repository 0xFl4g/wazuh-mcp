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
