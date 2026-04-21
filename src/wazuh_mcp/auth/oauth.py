"""OAuthSessionFactory - validates bearer JWTs and builds Session.

Uses joserfc for JWT decoding + signature verification. JWKS is cached via
JwksCache. Tenant resolution is hybrid: custom ``tenant_id`` claim first,
then iss -> IssuerIndex fallback. Claim/iss mismatch -> InvalidToken.
"""

from __future__ import annotations

import base64
import json
import time
from typing import Any

from joserfc import jwt
from joserfc.errors import BadSignatureError, ExpiredTokenError
from joserfc.jwk import JWKRegistry

from wazuh_mcp.auth.errors import (
    ExpiredToken,
    InvalidToken,
    MissingClaim,
)
from wazuh_mcp.auth.factory import RequestContext, SessionFactory
from wazuh_mcp.auth.jwks_cache import JwksCache
from wazuh_mcp.auth.session import Session
from wazuh_mcp.tenancy.issuer_index import IssuerIndex


class OAuthSessionFactory(SessionFactory):
    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        algorithms: list[str],
        rbac_claims: list[str],
        issuer_index: IssuerIndex,
        clock_skew_seconds: int = 30,
        jwks: JwksCache | None = None,
    ) -> None:
        # Structural invariant: 'none' is never a valid JWT signing algorithm,
        # even if an operator tries to configure it. joserfc's jwt.decode would
        # otherwise accept unsigned tokens when "none" is in the allowlist.
        if any(a.lower() == "none" for a in algorithms):
            raise ValueError("'none' algorithm is never permitted")
        if not algorithms:
            raise ValueError("at least one algorithm must be configured")
        self._issuer = issuer.rstrip("/")
        self._audience = audience
        self._algorithms = list(algorithms)
        self._rbac_claims = list(rbac_claims)
        self._index = issuer_index
        self._skew = clock_skew_seconds
        self._jwks = jwks or JwksCache(issuer=self._issuer)

    async def build(self, ctx: RequestContext) -> Session:
        token = _extract_bearer(ctx)
        header = _unverified_header(token)
        kid = header.get("kid")
        if not kid:
            raise InvalidToken(detail="missing kid")
        if header.get("alg") not in self._algorithms:
            raise InvalidToken(detail=f"disallowed alg {header.get('alg')!r}")

        jwk_dict = await self._jwks.get_key(kid)
        if jwk_dict is None:
            raise InvalidToken(detail=f"unknown kid {kid!r}")
        key = JWKRegistry.import_key(jwk_dict)

        try:
            decoded = jwt.decode(token, key, algorithms=self._algorithms)
        except ExpiredTokenError as e:
            raise ExpiredToken(detail=str(e)) from e
        except BadSignatureError as e:
            raise InvalidToken(detail="bad signature") from e
        except Exception as e:  # joserfc shape/parse errors
            raise InvalidToken(detail=str(e)) from e

        claims = decoded.claims
        self._validate_claims(claims)
        return self._build_session(claims)

    def _validate_claims(self, claims: dict[str, Any]) -> None:
        now = int(time.time())
        iss = claims.get("iss")
        if iss != self._issuer:
            raise InvalidToken(detail=f"issuer mismatch: {iss!r}")
        aud = claims.get("aud")
        if isinstance(aud, str):
            if aud != self._audience:
                raise InvalidToken(detail=f"audience mismatch: {aud!r}")
        elif isinstance(aud, list):
            if self._audience not in aud:
                raise InvalidToken(detail=f"audience mismatch: {aud!r}")
        else:
            raise InvalidToken(detail="aud claim missing")
        exp = claims.get("exp")
        if not isinstance(exp, int | float):
            raise InvalidToken(detail="exp missing")
        if exp < now - self._skew:
            raise ExpiredToken(detail="token expired")
        nbf = claims.get("nbf")
        if isinstance(nbf, int | float) and nbf > now + self._skew:
            raise InvalidToken(detail="not yet valid")
        iat = claims.get("iat")
        if isinstance(iat, int | float) and iat > now + self._skew:
            raise InvalidToken(detail="iat in future")

    def _build_session(self, claims: dict[str, Any]) -> Session:
        sub = claims.get("sub")
        if not sub:
            raise MissingClaim("sub", detail="no sub in token")

        claim_tenant = claims.get("tenant_id")
        iss_tenant_cfg = self._index.get(str(claims.get("iss", "")))

        if claim_tenant is not None and iss_tenant_cfg is not None:
            if claim_tenant != iss_tenant_cfg.tenant_id:
                raise InvalidToken(
                    detail=f"claim tenant {claim_tenant!r} != iss tenant "
                    f"{iss_tenant_cfg.tenant_id!r}"
                )
            tenant_id = str(claim_tenant)
        elif claim_tenant is not None:
            tenant_id = str(claim_tenant)
        elif iss_tenant_cfg is not None:
            tenant_id = iss_tenant_cfg.tenant_id
        else:
            raise MissingClaim("tenant_id", detail="no tenant resolution path")

        rbac = _pick_rbac(claims, self._rbac_claims)
        if rbac is None:
            if iss_tenant_cfg is not None:
                rbac = iss_tenant_cfg.default_rbac_role
            else:
                raise MissingClaim("rbac_role", detail="no rbac claim found")

        return Session(
            user_id=str(sub),
            tenant_id=tenant_id,
            rbac_role=rbac,
            auth_method="oauth",
        )

    async def aclose(self) -> None:
        await self._jwks.aclose()


def _extract_bearer(ctx: RequestContext) -> str:
    headers = ctx.get("headers", {})
    auth = headers.get("Authorization") or headers.get("authorization") or ""
    if not auth.startswith("Bearer "):
        raise InvalidToken(detail="missing bearer")
    return auth[len("Bearer ") :].strip()


def _unverified_header(token: str) -> dict[str, Any]:
    try:
        header_b64 = token.split(".", 1)[0]
        pad = "=" * (-len(header_b64) % 4)
        return json.loads(base64.urlsafe_b64decode(header_b64 + pad))
    except Exception as e:
        raise InvalidToken(detail="malformed JWT") from e


def _pick_rbac(claims: dict[str, Any], priority: list[str]) -> str | None:
    for key in priority:
        val = claims.get(key)
        if val is None:
            continue
        if isinstance(val, list):
            if val:
                return str(val[0])
            continue
        return str(val)
    return None
