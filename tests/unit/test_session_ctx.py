import asyncio

import pytest

from wazuh_mcp.auth.session import Session
from wazuh_mcp.transport.session_ctx import (
    CURRENT_SESSION,
    current_session,
    set_current_session,
)


def _session(user: str, tenant: str) -> Session:
    return Session(
        user_id=user, tenant_id=tenant, rbac_role="soc_analyst", auth_method="oauth"
    )


def test_current_session_raises_outside_context():
    with pytest.raises(LookupError):
        current_session()


def test_set_current_session_writes_contextvar():
    s = _session("alice", "acme")
    token = set_current_session(s)
    try:
        assert current_session() is s
    finally:
        CURRENT_SESSION.reset(token)
    with pytest.raises(LookupError):
        current_session()


async def test_concurrent_tasks_see_isolated_sessions():
    started = asyncio.Event()

    async def task_for(s: Session) -> str:
        token = set_current_session(s)
        try:
            started.set()
            await asyncio.sleep(0)
            return current_session().user_id
        finally:
            CURRENT_SESSION.reset(token)

    alice, bob = _session("alice", "acme"), _session("bob", "beta")
    results = await asyncio.gather(task_for(alice), task_for(bob))
    assert results == ["alice", "bob"]
