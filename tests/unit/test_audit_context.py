"""audit_context.set/reset/get_request_id contextvar tests."""

from __future__ import annotations

import asyncio

import pytest

from wazuh_mcp.observability.audit_context import (
    get_request_id,
    reset_request_id,
    set_request_id,
)


def test_default_is_none() -> None:
    """No active request, no override → None."""
    assert get_request_id() is None


def test_set_then_get_returns_value() -> None:
    token = set_request_id("abc-123")
    try:
        assert get_request_id() == "abc-123"
    finally:
        reset_request_id(token)


def test_reset_returns_to_default() -> None:
    token = set_request_id("abc-123")
    reset_request_id(token)
    assert get_request_id() is None


def test_set_none_explicit() -> None:
    """Setting None explicitly is allowed and returns None."""
    token = set_request_id(None)
    try:
        assert get_request_id() is None
    finally:
        reset_request_id(token)


@pytest.mark.asyncio
async def test_concurrent_tasks_dont_leak_context() -> None:
    """Two concurrent tasks each set their own request_id; neither sees the other's."""
    seen: dict[str, str | None] = {}

    async def task(name: str, rid: str) -> None:
        token = set_request_id(rid)
        try:
            await asyncio.sleep(0)  # yield
            seen[name] = get_request_id()
        finally:
            reset_request_id(token)

    await asyncio.gather(
        task("a", "rid-A"),
        task("b", "rid-B"),
    )
    assert seen == {"a": "rid-A", "b": "rid-B"}


@pytest.mark.asyncio
async def test_create_task_inherits_parent_context() -> None:
    """A child task sees the parent's request_id at spawn time."""
    token = set_request_id("parent-rid")
    try:
        result_box: list[str | None] = []

        async def child() -> None:
            result_box.append(get_request_id())

        await asyncio.create_task(child())
        assert result_box == ["parent-rid"]
    finally:
        reset_request_id(token)


def test_falls_through_to_mcp_request_ctx_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    """When local contextvar is unset, get_request_id() reads MCP SDK's request_ctx."""

    class FakeRequestCtx:
        request_id = "mcp-rid-456"

    import contextvars

    fake_var: contextvars.ContextVar[FakeRequestCtx | None] = contextvars.ContextVar(
        "fake_request_ctx", default=None
    )
    fake_var.set(FakeRequestCtx())

    # Patch the import path used by audit_context.get_request_id().
    import mcp.server.lowlevel.server as mcp_server_mod

    monkeypatch.setattr(mcp_server_mod, "request_ctx", fake_var)
    assert get_request_id() == "mcp-rid-456"


def test_local_override_wins_over_mcp_request_ctx(monkeypatch: pytest.MonkeyPatch) -> None:
    """An explicit set_request_id wins over MCP's request_ctx."""

    class FakeRequestCtx:
        request_id = "mcp-rid-456"

    import contextvars

    fake_var: contextvars.ContextVar[FakeRequestCtx | None] = contextvars.ContextVar(
        "fake_request_ctx", default=None
    )
    fake_var.set(FakeRequestCtx())

    import mcp.server.lowlevel.server as mcp_server_mod

    monkeypatch.setattr(mcp_server_mod, "request_ctx", fake_var)

    token = set_request_id("local-override")
    try:
        assert get_request_id() == "local-override"
    finally:
        reset_request_id(token)


def test_handles_non_string_mcp_request_id(monkeypatch: pytest.MonkeyPatch) -> None:
    """JSON-RPC id can be int or null; we always return str."""

    class FakeRequestCtx:
        request_id = 42  # int — JSON-RPC permits this

    import contextvars

    fake_var: contextvars.ContextVar[FakeRequestCtx | None] = contextvars.ContextVar(
        "fake_request_ctx", default=None
    )
    fake_var.set(FakeRequestCtx())

    import mcp.server.lowlevel.server as mcp_server_mod

    monkeypatch.setattr(mcp_server_mod, "request_ctx", fake_var)
    assert get_request_id() == "42"
