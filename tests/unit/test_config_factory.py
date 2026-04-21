from pathlib import Path
from typing import Any

import pytest

from wazuh_mcp.auth.config_factory import ConfigSessionFactory
from wazuh_mcp.auth.factory import RequestContext, SessionFactory
from wazuh_mcp.auth.session import Session
from wazuh_mcp.tenancy.config import TenantConfig


@pytest.fixture
def tenant() -> TenantConfig:
    return TenantConfig(
        tenant_id="acme",
        indexer_url="https://wazuh.acme.test:9200",
        verify_tls=False,
        ca_bundle_path=None,
        default_rbac_role="soc_analyst",
    )


async def test_config_factory_builds_session_from_fixed_config(tenant):
    factory = ConfigSessionFactory(user_id="alice", tenant=tenant)
    ctx: RequestContext = {}
    session = await factory.build(ctx)
    assert isinstance(session, Session)
    assert session.user_id == "alice"
    assert session.tenant_id == "acme"
    assert session.rbac_role == "soc_analyst"
    assert session.auth_method == "config"


async def test_config_factory_ignores_request_context(tenant):
    factory = ConfigSessionFactory(user_id="alice", tenant=tenant)
    ctx1: RequestContext = {"headers": {"Authorization": "Bearer whatever"}}
    ctx2: RequestContext = {}
    s1 = await factory.build(ctx1)
    s2 = await factory.build(ctx2)
    assert s1 == s2


def test_config_factory_is_a_session_factory(tenant):
    factory = ConfigSessionFactory(user_id="alice", tenant=tenant)
    assert isinstance(factory, SessionFactory)
