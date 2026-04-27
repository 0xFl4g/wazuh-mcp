"""M4d integration tests — per-tenant rate-limit + audit routing.

Marked @requires_manager — runs nightly on amd64 CI. Multi-tenant
fixture (two-tenant tenants.yaml) is in place; per-tenant token mint
requires either (a) a second Keycloak realm, or (b) a tenant_id claim
mapper in the existing realm. Both are deferred to M5 cross-tenant
leak suite scope.

For now: tests skip with a clear message pointing at the fixture
prerequisite. Per-tenant fan-out is fully covered at the unit level
in test_per_tenant_sink_fanout.py and test_per_tenant_rate_limiter.py.
"""

from __future__ import annotations

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.requires_manager]


@pytest.mark.asyncio
async def test_per_tenant_rate_limit_isolation() -> None:
    pytest.skip(
        "requires per-tenant token mint — multi-realm Keycloak or "
        "tenant_id claim mapper. Deferred to M5 cross-tenant leak suite. "
        "Unit coverage in test_per_tenant_rate_limiter.py."
    )


@pytest.mark.asyncio
async def test_per_tenant_audit_routing() -> None:
    pytest.skip(
        "requires per-tenant token mint — multi-realm Keycloak or "
        "tenant_id claim mapper. Deferred to M5. "
        "Unit coverage in test_per_tenant_sink_fanout.py."
    )
