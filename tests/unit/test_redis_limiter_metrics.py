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

    fake_counters = {"rate_limit_redis_state": FakeGauge()}
    monkeypatch.setattr(
        "wazuh_mcp.observability.metrics.m4_counters",
        lambda: fake_counters,
    )

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
