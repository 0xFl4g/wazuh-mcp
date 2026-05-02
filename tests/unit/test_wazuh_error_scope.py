"""M5b T-G1. WazuhError.scope field tests.

Pins both the field plumbing and the actual raise sites so future
refactors that drop the kwarg get caught at the unit boundary.
"""

from __future__ import annotations

import asyncio

import pytest

from wazuh_mcp.rate_limit.limiter import InProcessRateLimiter
from wazuh_mcp.tenancy.m4_config import BucketConfig, RateLimitConfig
from wazuh_mcp.wazuh.errors import WazuhError


def test_scope_defaults_to_none():
    err = WazuhError("forbidden", "test message", 403)
    assert err.scope is None


def test_scope_can_be_set_via_kwarg():
    err = WazuhError("forbidden", "test message", 403, scope="rate_limit:tenant")
    assert err.scope == "rate_limit:tenant"


def test_scope_appears_in_repr():
    err = WazuhError("rate_limited", "exhausted", 429, scope="rate_limit:session")
    assert "rate_limit:session" in repr(err)


def test_existing_3_arg_callers_still_work():
    """Backwards compat: every M3-M5a positional caller continues to work
    without setting scope."""
    err = WazuhError("upstream_error", "msg", 500)
    assert err.code == "upstream_error"
    assert err.message == "msg"
    assert err.status_code == 500
    assert err.scope is None


def test_rate_limit_tenant_raise_pins_scope():
    """T-G1: limiter tenant-budget exhaustion sets scope='rate_limit:tenant'."""
    cfg = RateLimitConfig(
        tenant=BucketConfig(capacity=1, refill_per_sec=0.001),
        session=BucketConfig(capacity=10, refill_per_sec=10.0),
    )
    limiter = InProcessRateLimiter(default=cfg)

    async def _drive() -> WazuhError:
        await limiter.acquire("tenant-x", "session-x")
        try:
            await limiter.acquire("tenant-x", "session-x")
        except WazuhError as e:
            return e
        raise AssertionError("expected rate_limited")

    err = asyncio.run(_drive())
    assert err.code == "rate_limited"
    assert err.scope == "rate_limit:tenant"


def test_rate_limit_session_raise_pins_scope():
    """T-G1: limiter session-budget exhaustion sets scope='rate_limit:session'."""
    cfg = RateLimitConfig(
        tenant=BucketConfig(capacity=10, refill_per_sec=10.0),
        session=BucketConfig(capacity=1, refill_per_sec=0.001),
    )
    limiter = InProcessRateLimiter(default=cfg)

    async def _drive() -> WazuhError:
        await limiter.acquire("tenant-y", "session-y")
        try:
            await limiter.acquire("tenant-y", "session-y")
        except WazuhError as e:
            return e
        raise AssertionError("expected rate_limited")

    err = asyncio.run(_drive())
    assert err.code == "rate_limited"
    assert err.scope == "rate_limit:session"


def test_ar_command_deny_pins_scope():
    """T-G1: tools/write.run_active_response AR-command-deny raise sets
    scope='ar_allowlist'."""
    from datetime import UTC, datetime  # noqa: F401  (re-export check)

    from wazuh_mcp.tools.write import RunActiveResponseArgs, run_active_response

    args = RunActiveResponseArgs(
        agent_ids=["001"],
        command_name="not-allowlisted",
        custom_args=None,
        confirm=True,
    )

    class _DummySession:
        wazuh_user = "u"

    async def _drive() -> WazuhError:
        try:
            await run_active_response(
                args=args,
                session=_DummySession(),
                server_api=None,
                ar_allowlist=["other-cmd"],
            )
        except WazuhError as e:
            return e
        raise AssertionError("expected forbidden")

    err = asyncio.run(_drive())
    assert err.code == "forbidden"
    assert err.scope == "ar_allowlist"


def test_ar_group_deny_pins_scope():
    """T-G1: tools/write.run_active_response_on_group group-deny raise sets
    scope='ar_group_allowlist'."""
    from wazuh_mcp.tools.write import (
        RunActiveResponseOnGroupArgs,
        run_active_response_on_group,
    )

    args = RunActiveResponseOnGroupArgs(
        group_name="not-allowed-group",
        command_name="some-cmd",
        custom_args=None,
        confirm=True,
    )

    class _DummySession:
        wazuh_user = "u"

    async def _drive() -> WazuhError:
        try:
            await run_active_response_on_group(
                args=args,
                session=_DummySession(),
                server_api=None,
                ar_group_allowlist=["other-group"],
            )
        except WazuhError as e:
            return e
        raise AssertionError("expected forbidden")

    err = asyncio.run(_drive())
    assert err.code == "forbidden"
    assert err.scope == "ar_group_allowlist"


def test_pytest_module_imports():
    """Sanity: pytest import is used by upstream tooling that scans the suite."""
    assert pytest is not None
