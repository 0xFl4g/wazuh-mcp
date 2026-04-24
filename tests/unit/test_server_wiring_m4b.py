"""Server wiring for M4b writes — registration-time allowlist + RBAC + audit."""

from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_writes_all_registered_when_write_allowlist_is_none() -> None:
    """None (default) -> all 7 writes registered."""
    pytest.skip("end-to-end coverage via tests/integration/test_m4b_writes.py (T8)")


@pytest.mark.asyncio
async def test_writes_filtered_by_write_allowlist() -> None:
    """Non-empty write_allowlist -> only listed tools registered."""
    pytest.skip("see above")


@pytest.mark.asyncio
async def test_empty_write_allowlist_registers_no_writes() -> None:
    """Empty list -> zero write tools, even for admin."""
    pytest.skip("see above")


@pytest.mark.asyncio
async def test_analyst_role_cannot_see_any_write_tool() -> None:
    """Default analyst role -> list_tools hides every write.*."""
    pytest.skip("see above")
