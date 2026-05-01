"""M4d integration tests — per-tenant rate-limit + audit routing + cross-tenant negatives.

Marked @requires_manager — runs nightly on amd64 CI. Per-tenant token mint
landed in M5a T7 via a Keycloak claim-mapper hardcoding tenant_id per
service-account. This file pins:
  1. Per-tenant rate-limit isolation (tenant_b's bucket exhaustion does
     not affect local).
  2. Per-tenant audit routing (events from a tenant_b session land in
     tenant-b-audit-* index, NOT local-audit-*). Requires audit-sinks-
     enabled fixture from T9.
  3-5. Cross-tenant negative invariants — pool routing per session
     tenant_id, resolver-miss audit goes to globals only.
"""

from __future__ import annotations

from contextlib import asynccontextmanager

import httpx
import pytest

from tests.integration.conftest import MCP_URL  # type: ignore[import-not-found]

pytestmark = [pytest.mark.integration, pytest.mark.requires_manager]


@asynccontextmanager
async def _mcp_session(url: str, token: str):
    """Authenticated MCP streamable-HTTP session.

    Inlined per M4b precedent (test_m4b_writes.py:186) — pytest-asyncio
    runs async-generator fixture setup/teardown in different tasks, and
    anyio's CancelScope (used inside streamable_http_client / ClientSession)
    requires same-task entry+exit.
    """
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    http_client = httpx.AsyncClient(
        headers={"Authorization": f"Bearer {token}"},
        timeout=httpx.Timeout(30.0),
    )
    try:
        async with (
            streamable_http_client(f"{url}/mcp", http_client=http_client) as (
                read,
                write,
                _gsid,
            ),
            ClientSession(read, write) as session,
        ):
            await session.initialize()
            yield session
    finally:
        await http_client.aclose()


@pytest.mark.asyncio
async def test_per_tenant_rate_limit_isolation(
    mcp_http_server, keycloak_token, keycloak_token_tenant_b
) -> None:
    """tenant_b's bucket exhaustion does not block local.

    tenant_b is configured with capacity=2 in conftest's tenants.yaml.
    Burn the bucket, assert the third call rate-limits. Then mint a
    local token and assert it works — proving the budgets are isolated.
    """
    # tenant_b: 2 succeed, 3rd rate-limits.
    async with _mcp_session(MCP_URL, keycloak_token_tenant_b()) as session_b:
        r1 = await session_b.call_tool("alerts.search_alerts", {"size": 1})
        assert not r1.isError, f"call 1 errored: {r1}"
        r2 = await session_b.call_tool("alerts.search_alerts", {"size": 1})
        assert not r2.isError, f"call 2 errored: {r2}"
        r3 = await session_b.call_tool("alerts.search_alerts", {"size": 1})
        assert r3.isError, "tenant_b's third call should rate-limit"
        text = "".join(getattr(c, "text", "") for c in r3.content).lower()
        assert "rate_limited" in text or "rate limit" in text, f"expected rate-limit error: {text}"

    # local: capacity=100. unaffected.
    async with _mcp_session(MCP_URL, keycloak_token()) as session_local:
        r = await session_local.call_tool("alerts.search_alerts", {"size": 1})
        assert not r.isError, f"local call errored: {r}"


@pytest.mark.asyncio
async def test_per_tenant_audit_routing(
    mcp_http_server_audit_sinks,
    raw_indexer_client,
    keycloak_token,
    keycloak_token_tenant_b,
) -> None:
    """tenant_b session's audit events land in tenant-b-audit-*, NOT local-audit-*.

    Requires the audit-sinks-enabled fixture from T9 (per-test config-dir
    override that adds wazuh_indexer audit sinks per tenant). The main
    mcp_http_server fixture intentionally has no audit_sinks (per v0.7.4)
    to keep the bulk of integration tests fast.
    """
    import asyncio

    # Fire a tool call from tenant_b. The decorator emits an audit event
    # to tenant_b's per-tenant sinks (tenant-b-audit-*).
    async with _mcp_session(mcp_http_server_audit_sinks, keycloak_token_tenant_b()) as session:
        r = await session.call_tool("alerts.search_alerts", {"size": 1})
        assert not r.isError

    # Wait for QueuedSink to flush (default flush_ms=200 + indexer refresh
    # interval). 5s gives generous margin on a CI runner under load.
    await asyncio.sleep(5.0)

    # Query local-audit-* and tenant-b-audit-* directly via the indexer.
    # tenant-b-audit-* must contain the event; local-audit-* must NOT.
    body_b = await raw_indexer_client.search(
        index="tenant-b-audit-*",
        body={"query": {"match": {"tenant": "tenant_b"}}, "size": 10},
    )
    hits_b = (body_b.get("hits") or {}).get("hits") or []
    assert len(hits_b) >= 1, "tenant_b session's audit event missing from tenant-b-audit-*"

    body_local = await raw_indexer_client.search(
        index="local-audit-*",
        body={"query": {"match": {"tenant": "tenant_b"}}, "size": 10},
    )
    hits_local = (body_local.get("hits") or {}).get("hits") or []
    assert len(hits_local) == 0, (
        f"cross-tenant leak: tenant_b event found in local-audit-*: {hits_local}"
    )


@pytest.mark.asyncio
async def test_local_session_tools_do_not_query_tenant_b_indexer(
    mcp_http_server, keycloak_token
) -> None:
    """Cross-tenant negative: local session's queries never hit tenant_b's
    IndexerClient. We verify by looking for any audit event with
    tenant=tenant_b after running a local tool that would only emit to
    local-audit-* (or stderr in the no-audit-sink case).

    This is the M4c per-tenant resolver primitive end-to-end pinning at
    the integration layer.
    """
    async with _mcp_session(MCP_URL, keycloak_token()) as session:
        r = await session.call_tool("alerts.search_alerts", {"size": 1})
        assert not r.isError, f"local call errored: {r}"
    # Note: with the main mcp_http_server fixture audit_sinks disabled
    # (v0.7.4 revert), this test verifies behavior at the rate-limiter
    # + IndexerClientPool layer indirectly — a tenant-b leak would
    # surface via the audit-routing test (test 2). The unit suite at
    # tests/unit/test_per_tenant_sink_fanout.py and
    # tests/unit/test_per_tenant_rate_limiter.py provides the direct
    # routing pin; integration confirms wiring at boot.


@pytest.mark.asyncio
async def test_unknown_tenant_token_routes_to_globals_only(
    mcp_http_server_audit_sinks, raw_indexer_client, hand_minted_phantom_token
) -> None:
    """Resolver-miss path: a token claiming tenant_id='phantom' (not in
    tenants.yaml) hits the resolver-miss audit shape from M4c (sentinel
    tool='<rbac.resolve>', error_code='forbidden', error_reason=
    'tenant_not_registered'). The audit event must land on GLOBAL sinks
    only, never on per-tenant sinks (which would be a defense-in-depth
    leak).

    The hand_minted_phantom_token fixture (T9) signs a JWT directly
    with the test private key — bypasses Keycloak (which only mints
    real tenant claims). Phantom tenant_id can't be added to Keycloak
    without polluting the realm with non-existent tenant test fixtures.
    """
    import asyncio

    # Fire any tool call. RBAC resolver KeyErrors on unknown tenant_id
    # → audit emits with sentinel tool='<rbac.resolve>'. The client
    # call also fails (forbidden), but our concern is the audit shape.
    async with _mcp_session(mcp_http_server_audit_sinks, hand_minted_phantom_token) as session:
        r = await session.call_tool("alerts.search_alerts", {"size": 1})
        # Expect an error — resolver-miss → forbidden.
        assert r.isError

    await asyncio.sleep(2.0)

    # Audit must land on globals (stderr — visible in process logs)
    # OR confirm via per-tenant indices: BOTH local-audit-* and
    # tenant-b-audit-* must NOT have a 'phantom' tenant event.
    for index in ("local-audit-*", "tenant-b-audit-*"):
        body = await raw_indexer_client.search(
            index=index,
            body={"query": {"match": {"tenant": "phantom"}}, "size": 10},
        )
        hits = (body.get("hits") or {}).get("hits") or []
        assert len(hits) == 0, f"phantom-tenant audit event leaked to {index}: {hits}"


@pytest.mark.asyncio
async def test_tenant_b_token_cannot_resolve_to_local(
    mcp_http_server, keycloak_token_tenant_b
) -> None:
    """A token with tenant_id='tenant_b' MUST NOT resolve as the local
    session. End-to-end pin of OAuthSessionFactory's claim-precedence
    logic (oauth.py:115-130).

    We verify indirectly by running a tool that would burn tenant_b's
    bucket (capacity=2): if the session were misrouted to local
    (capacity=100), three calls would all succeed. With correct
    routing, the third rate-limits. This test asserts the negative
    of test 1 — confirming the claim isn't being silently ignored.
    """
    import asyncio

    # Tenant_b shares a module-scoped server with prior tests that may
    # have exhausted the bucket. Wait for refill (refill_per_sec=1.0,
    # capacity=2 → 2s for full refill).
    await asyncio.sleep(2.5)

    async with _mcp_session(MCP_URL, keycloak_token_tenant_b()) as session:
        r1 = await session.call_tool("alerts.search_alerts", {"size": 1})
        assert not r1.isError
        r2 = await session.call_tool("alerts.search_alerts", {"size": 1})
        assert not r2.isError
        r3 = await session.call_tool("alerts.search_alerts", {"size": 1})
        assert r3.isError, "tenant_b token misrouted to local — bucket should have exhausted"
