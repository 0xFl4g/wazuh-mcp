"""In-memory RSA keypair + JWT builder for OAuth tests.

Usage:
    from tests.fixtures.jwt_factory import JwtFactory

    factory = JwtFactory(issuer="https://idp.test", audience="wazuh-mcp-api")
    token = factory.make(sub="alice", extra={"tenant_id": "acme"})
    jwks = factory.jwks()
    oidc_discovery = factory.oidc_discovery("https://idp.test/jwks")
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from joserfc import jwt
from joserfc.jwk import RSAKey


@dataclass
class JwtFactory:
    issuer: str
    audience: str
    kid: str = "test-key"
    ttl_seconds: int = 300
    _key: RSAKey = field(init=False)

    def __post_init__(self) -> None:
        self._key = RSAKey.generate_key(2048, parameters={"kid": self.kid, "alg": "RS256"})

    def make(
        self,
        *,
        sub: str,
        extra: dict[str, Any] | None = None,
        now: int | None = None,
        exp_delta: int | None = None,
    ) -> str:
        ts = now if now is not None else int(time.time())
        exp = ts + (exp_delta if exp_delta is not None else self.ttl_seconds)
        claims: dict[str, Any] = {
            "iss": self.issuer,
            "sub": sub,
            "aud": self.audience,
            "iat": ts,
            "exp": exp,
            "nbf": ts,
        }
        if extra:
            claims.update(extra)
        header = {"alg": "RS256", "kid": self.kid, "typ": "JWT"}
        return jwt.encode(header, claims, self._key)

    def make_expired(self, *, sub: str, extra: dict[str, Any] | None = None) -> str:
        return self.make(sub=sub, extra=extra, exp_delta=-60)

    def make_with_header(
        self,
        *,
        sub: str,
        header: dict[str, Any],
        extra: dict[str, Any] | None = None,
    ) -> str:
        """Escape hatch for negative tests that need to tamper with the header."""
        ts = int(time.time())
        claims: dict[str, Any] = {
            "iss": self.issuer,
            "sub": sub,
            "aud": self.audience,
            "iat": ts,
            "exp": ts + self.ttl_seconds,
        }
        if extra:
            claims.update(extra)
        return jwt.encode(header, claims, self._key)

    def public_jwk(self) -> dict[str, Any]:
        return self._key.as_dict(private=False)

    def jwks(self) -> dict[str, Any]:
        return {"keys": [self.public_jwk()]}

    def oidc_discovery(self, jwks_uri: str) -> dict[str, Any]:
        return {"issuer": self.issuer, "jwks_uri": jwks_uri}
