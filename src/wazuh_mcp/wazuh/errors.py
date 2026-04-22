"""Upstream error → safe code mapping.

Any upstream response body/stacktrace/schema data is discarded at this
boundary. MCP clients only ever see the codes in SAFE_CODES.
"""

from __future__ import annotations

from typing import Final

import httpx

SAFE_CODES: Final[frozenset[str]] = frozenset(
    {
        "auth_expired",
        "forbidden",
        "rate_limited",
        "invalid_query",
        "upstream_error",
        "not_found",
        "upstream_timeout",
    }
)


class WazuhError(Exception):
    __slots__ = ("code", "message", "status_code")

    def __init__(self, code: str, message: str, status_code: int) -> None:
        if code not in SAFE_CODES:
            raise ValueError(f"unsafe error code: {code!r}")
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.status_code = status_code

    def __repr__(self) -> str:
        return f"WazuhError(code={self.code!r}, status={self.status_code})"


_INVALID_QUERY_GENERIC: Final[str] = "query was rejected by the backend"


def map_http_error(resp: httpx.Response) -> WazuhError:
    status = resp.status_code
    if status == 401:
        return WazuhError("auth_expired", "upstream authentication expired", status)
    if status == 403:
        return WazuhError("forbidden", "upstream denied the request", status)
    if status == 404:
        return WazuhError("not_found", "upstream resource not found", status)
    if status == 429:
        return WazuhError("rate_limited", "upstream rate limit exceeded", status)
    if status == 400:
        # Swallow upstream detail entirely; surface only a generic message.
        return WazuhError("invalid_query", _INVALID_QUERY_GENERIC, status)
    return WazuhError("upstream_error", "upstream returned an error", status)


def map_timeout() -> WazuhError:
    """Surface httpx.TimeoutException as a safe, scrubbed code.

    Called at catch sites that wrap httpx calls; httpx doesn't carry a
    response object for timeouts so this takes no arguments.
    """
    return WazuhError("upstream_timeout", "upstream request timed out", 504)
