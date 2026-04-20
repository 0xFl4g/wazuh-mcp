import httpx
import pytest

from wazuh_mcp.wazuh.errors import WazuhError, map_http_error


def _response(status: int, body: dict | str) -> httpx.Response:
    req = httpx.Request("GET", "https://example/9200/x/_search")
    return httpx.Response(
        status,
        json=body if isinstance(body, dict) else None,
        text=body if isinstance(body, str) else None,
        request=req,
    )


def test_401_maps_to_auth_expired():
    resp = _response(401, {"error": "token expired"})
    err = map_http_error(resp)
    assert isinstance(err, WazuhError)
    assert err.code == "auth_expired"


def test_403_maps_to_forbidden():
    resp = _response(403, {"error": "no permission"})
    err = map_http_error(resp)
    assert err.code == "forbidden"


def test_429_maps_to_rate_limited():
    resp = _response(429, {"error": "too many"})
    err = map_http_error(resp)
    assert err.code == "rate_limited"


def test_400_parse_error_maps_to_invalid_query_without_details():
    body = {
        "error": {
            "type": "parse_exception",
            "reason": "failed to parse at line 1: unknown field rule.badname",
            "stack_trace": "...deep internals...",
        }
    }
    resp = _response(400, body)
    err = map_http_error(resp)
    assert err.code == "invalid_query"
    # Internal details never surface:
    assert "stack_trace" not in err.message
    assert "...deep internals..." not in err.message
    assert "parse_exception" not in err.message


def test_5xx_maps_to_upstream_error():
    resp = _response(503, "<html>gateway</html>")
    err = map_http_error(resp)
    assert err.code == "upstream_error"


def test_error_repr_does_not_leak_body():
    resp = _response(500, {"error": {"reason": "secret internal message"}})
    err = map_http_error(resp)
    assert "secret internal message" not in repr(err)
    assert "secret internal message" not in str(err)


def test_unknown_status_is_upstream_error():
    resp = _response(418, {"error": "teapot"})
    err = map_http_error(resp)
    assert err.code == "upstream_error"


def test_safe_codes_enumerated():
    # A guard against accidental expansion of the safe-code set.
    from wazuh_mcp.wazuh.errors import SAFE_CODES

    assert (
        frozenset({"auth_expired", "forbidden", "rate_limited", "invalid_query", "upstream_error"})
        == SAFE_CODES
    )


def test_unsafe_code_rejected_at_construction():
    with pytest.raises(ValueError, match="unsafe error code"):
        WazuhError("leaked_detail", "x", 500)
