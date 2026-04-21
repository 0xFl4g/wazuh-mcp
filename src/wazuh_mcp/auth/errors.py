"""Auth-layer exception types.

Every AuthError maps to a fixed HTTP status and a fixed client-facing
message. An optional `detail` is for internal logs only and never appears
in repr/str/wire output.
"""

from __future__ import annotations

from typing import ClassVar


class AuthError(Exception):
    http_status: ClassVar[int] = 401
    public_message: ClassVar[str] = "unauthorized"

    def __init__(self, *, detail: str | None = None) -> None:
        super().__init__(self.public_message)
        self._detail = detail  # redacted from repr/str

    def __repr__(self) -> str:
        return f"{type(self).__name__}(status={self.http_status})"

    def __str__(self) -> str:
        return self.public_message


class InvalidToken(AuthError):  # noqa: N818 - public auth error name, not *Error suffix
    http_status = 401
    public_message = "invalid_token"


class ExpiredToken(AuthError):  # noqa: N818 - public auth error name, not *Error suffix
    http_status = 401
    public_message = "invalid_token"


class UnknownIssuer(AuthError):  # noqa: N818 - public auth error name, not *Error suffix
    http_status = 401
    public_message = "unauthorized"


class MissingClaim(AuthError):  # noqa: N818 - public auth error name, not *Error suffix
    http_status = 403
    public_message = "forbidden"

    def __init__(self, claim_name: str, *, detail: str | None = None) -> None:
        super().__init__(detail=detail)
        self.claim_name = claim_name


class ApiKeyRevoked(AuthError):  # noqa: N818 - public auth error name, not *Error suffix
    http_status = 401
    public_message = "unauthorized"
