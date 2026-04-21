from wazuh_mcp.auth.errors import (
    ApiKeyRevoked,
    AuthError,
    ExpiredToken,
    InvalidToken,
    MissingClaim,
    UnknownIssuer,
)


def test_auth_errors_share_base_class():
    for cls in (InvalidToken, ExpiredToken, UnknownIssuer, MissingClaim, ApiKeyRevoked):
        assert issubclass(cls, AuthError)


def test_auth_error_has_http_status():
    assert InvalidToken().http_status == 401
    assert ExpiredToken().http_status == 401
    assert UnknownIssuer().http_status == 401
    assert MissingClaim("tenant_id").http_status == 403
    assert ApiKeyRevoked().http_status == 401


def test_missing_claim_carries_claim_name():
    e = MissingClaim("tenant_id")
    assert e.claim_name == "tenant_id"


def test_repr_does_not_leak_internal_detail():
    e = InvalidToken(detail="SECRET upstream detail")
    assert "SECRET" not in repr(e)


def test_auth_error_message_is_generic():
    e = InvalidToken(detail="SECRET")
    assert str(e) in {"unauthorized", "invalid_token"}
