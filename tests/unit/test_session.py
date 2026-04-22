import pytest

from wazuh_mcp.auth.session import Session


def test_session_holds_identity_and_tenant():
    session = Session(
        user_id="alice",
        tenant_id="acme",
        rbac_role="soc_analyst",
        auth_method="config",
    )
    assert session.user_id == "alice"
    assert session.tenant_id == "acme"
    assert session.rbac_role == "soc_analyst"
    assert session.auth_method == "config"


def test_session_is_immutable():
    import dataclasses

    session = Session(
        user_id="alice",
        tenant_id="acme",
        rbac_role="soc_analyst",
        auth_method="config",
    )
    try:
        session.tenant_id = "hostile"  # type: ignore[misc]
    except dataclasses.FrozenInstanceError:
        return
    raise AssertionError("Session must be frozen to prevent mid-call tenant swap")


def test_session_wazuh_user_defaults_to_none():
    s = Session(
        user_id="u",
        tenant_id="t",
        rbac_role="r",
        auth_method="config",
    )
    assert s.wazuh_user is None


def test_session_wazuh_user_explicit():
    s = Session(
        user_id="u",
        tenant_id="t",
        rbac_role="r",
        auth_method="oauth",
        wazuh_user="alice",
    )
    assert s.wazuh_user == "alice"


def test_session_wazuh_user_frozen():
    s = Session(
        user_id="u",
        tenant_id="t",
        rbac_role="r",
        auth_method="oauth",
        wazuh_user="alice",
    )
    import dataclasses

    with pytest.raises(dataclasses.FrozenInstanceError):
        s.wazuh_user = "bob"  # type: ignore[misc]
