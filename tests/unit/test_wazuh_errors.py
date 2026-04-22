"""WazuhError + map_http_error + map_timeout tests."""

import httpx
import pytest

from wazuh_mcp.wazuh.errors import (
    SAFE_CODES,
    WazuhError,
    map_http_error,
    map_timeout,
)


def test_safe_codes_contains_new_m3_codes():
    assert "not_found" in SAFE_CODES
    assert "upstream_timeout" in SAFE_CODES


def test_map_http_error_404_is_not_found():
    resp = httpx.Response(status_code=404)
    err = map_http_error(resp)
    assert err.code == "not_found"
    assert err.status_code == 404


def test_map_timeout_is_upstream_timeout():
    err = map_timeout()
    assert err.code == "upstream_timeout"
    assert err.status_code == 504


def test_wazuh_error_rejects_unsafe_code():
    with pytest.raises(ValueError, match="unsafe error code"):
        WazuhError("internal_server_error", "leak me", 500)


def test_wazuh_error_repr_scrubs_message():
    err = WazuhError("not_found", "agent 999 missing", 404)
    # repr must not include the message (which could carry IDs or arbitrary upstream text).
    assert "agent 999" not in repr(err)
