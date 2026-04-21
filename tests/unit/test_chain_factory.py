from dataclasses import dataclass, field

import pytest

from wazuh_mcp.auth.chain_factory import ChainSessionFactory
from wazuh_mcp.auth.errors import InvalidToken
from wazuh_mcp.auth.factory import RequestContext, SessionFactory
from wazuh_mcp.auth.session import Session


@dataclass
class _Recorder(SessionFactory):
    name: str
    calls: list[RequestContext] = field(default_factory=list)

    async def build(self, ctx: RequestContext) -> Session:
        self.calls.append(ctx)
        return Session(
            user_id=self.name, tenant_id="t", rbac_role="r", auth_method="oauth",
        )


async def test_routes_jwt_to_oauth_factory():
    oauth = _Recorder("oauth")
    apikey = _Recorder("apikey")
    chain = ChainSessionFactory(oauth=oauth, api_key=apikey)

    ctx = {"headers": {"Authorization": "Bearer aaa.bbb.ccc"}}
    session = await chain.build(ctx)
    assert session.user_id == "oauth"
    assert len(oauth.calls) == 1
    assert len(apikey.calls) == 0


async def test_routes_wzk_prefix_to_api_key_factory():
    oauth = _Recorder("oauth")
    apikey = _Recorder("apikey")
    chain = ChainSessionFactory(oauth=oauth, api_key=apikey)

    ctx = {"headers": {"Authorization": "Bearer wzk_acme_01.secret"}}
    session = await chain.build(ctx)
    assert session.user_id == "apikey"
    assert len(oauth.calls) == 0
    assert len(apikey.calls) == 1


async def test_unknown_token_shape_rejected():
    oauth = _Recorder("oauth")
    apikey = _Recorder("apikey")
    chain = ChainSessionFactory(oauth=oauth, api_key=apikey)

    for bad in ["Bearer abc", "Bearer ", "", "Basic xxx"]:
        with pytest.raises(InvalidToken):
            await chain.build({"headers": {"Authorization": bad}})
    assert oauth.calls == [] and apikey.calls == []


async def test_no_authorization_header_rejected():
    chain = ChainSessionFactory(
        oauth=_Recorder("oauth"),
        api_key=_Recorder("apikey"),
    )
    with pytest.raises(InvalidToken):
        await chain.build({"headers": {}})
