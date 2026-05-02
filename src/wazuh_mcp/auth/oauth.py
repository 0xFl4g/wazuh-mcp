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
        # v1.0.4 (failure A): per-issuer JWKS caches. The "global" issuer
        # from server.yaml gets the supplied (or default) cache; each
        # tenant-configured issuer in IssuerIndex gets its own cache,
        # lazily created on first token from that issuer. This allows
        # tenants in tenants.yaml to declare their own oauth_issuer
        # (e.g. an in-process JWKS side-car or a partner IdP), with
        # signature validation routed to the correct JWKS endpoint.
        self._jwks_by_issuer: dict[str, JwksCache] = {
            self._issuer: jwks or JwksCache(issuer=self._issuer),
        }
        # Pre-register tenant-configured issuers so InvalidToken fires
        # at "issuer not trusted" rather than after a costly JWKS fetch.
        self._valid_issuers: set[str] = {self._issuer}
        for iss in issuer_index.known_issuers():
            self._valid_issuers.add(iss)

    async def build(self, ctx: RequestContext) -> Session:
        token = _extract_bearer(ctx)
        header = _unverified_header(token)
        kid = header.get("kid")
        if not kid:
            raise InvalidToken(detail="missing kid")
        if header.get("alg") not in self._algorithms:
            raise InvalidToken(detail=f"disallowed alg {header.get('alg')!r}")

        # v1.0.4 (failure A): peek at unverified iss to route to the
        # correct per-issuer JWKS cache. Issuer trust is enforced again
        # post-verification in _validate_claims (defense in depth).
        unverified_iss = _unverified_iss(token)
        if unverified_iss not in self._valid_issuers:
            raise InvalidToken(detail=f"issuer not trusted: {unverified_iss!r}")
        jwks_cache = self._jwks_for(unverified_iss)
        jwk_dict = await jwks_cache.get_key(kid)
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

    def _jwks_for(self, issuer: str) -> JwksCache:
        """Return (creating if needed) the per-issuer JWKS cache.

        v1.0.4 (failure A): tenants in tenants.yaml may declare their
        own oauth_issuer distinct from the global oauth.issuer.
        """
        cache = self._jwks_by_issuer.get(issuer)
        if cache is None:
            cache = JwksCache(issuer=issuer)
            self._jwks_by_issuer[issuer] = cache
        return cache

    def _validate_claims(self, claims: dict[str, Any]) -> None:
        now = int(time.time())
        iss = claims.get("iss")
        if iss not in self._valid_issuers:
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
                # Cross-tenant token theft prevention: a claim_tenant that
                # is REGISTERED under a different issuer is a forged-issuer
                # attempt. Reject hard.
                #
                # An UNREGISTERED claim_tenant (not in by_tenant_id) is the
                # M4c resolver-miss path: the issuer is trusted but the
                # claimed tenant_id has no config. We let it through so the
                # downstream RBAC resolver fires its KeyError + audit event
                # (sentinel tool='<rbac.resolve>', error_reason=
                # 'tenant_not_registered') on global sinks only — never
                # mounting on the iss-mapped tenant's per-tenant sinks.
                claim_tenant_cfg = self._index.get_by_tenant_id(str(claim_tenant))
                if claim_tenant_cfg is not None:
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

        # Resolve the tenant's config by id — covers the shared-issuer case
        # where iss_tenant_cfg is None but tenant_id was claim-resolved.
        # Falls back to iss_tenant_cfg for legacy single-tenant-per-issuer
        # configs where the by-id index entry equals the iss-mapped one.
        tenant_cfg = self._index.get_by_tenant_id(tenant_id) or iss_tenant_cfg

        rbac = _pick_rbac(claims, self._rbac_claims)
        if rbac is None:
            if tenant_cfg is not None:
                rbac = tenant_cfg.default_rbac_role
            else:
                raise MissingClaim("rbac_role", detail="no rbac claim found")

        wazuh_user = self._pick_wazuh_user(claims, tenant_cfg)

        return Session(
            user_id=str(sub),
            tenant_id=tenant_id,
            rbac_role=rbac,
            auth_method="oauth",
            wazuh_user=wazuh_user,
        )

    def _pick_wazuh_user(
        self,
        claims: dict[str, Any],
        iss_tenant_cfg: Any,
    ) -> str | None:
        """Extract wazuh_user from claims using the tenant's configured claim name.

        Tenant config defaults to `wazuh_user`. When the claim is absent or
        empty, returns None — the Server API request will run as the tenant's
        service account.
        """
        if iss_tenant_cfg is None:
            return None
        claim_name = getattr(iss_tenant_cfg, "wazuh_user_claim", "wazuh_user")
        val = claims.get(claim_name)
        if val is None:
            return None
        if isinstance(val, list):
            return str(val[0]) if val else None
        s = str(val).strip()
        return s or None

    async def aclose(self) -> None:
        for cache in self._jwks_by_issuer.values():
            await cache.aclose()


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


def _unverified_iss(token: str) -> str:
    """Peek at the JWT payload's `iss` claim WITHOUT verifying signature.

    Caller MUST treat the result as untrusted until the JWKS lookup
    succeeds (signature verifies) AND _validate_claims re-checks
    membership in self._valid_issuers.
    """
    try:
        parts = token.split(".")
        payload_b64 = parts[1]
        pad = "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + pad))
        iss = payload.get("iss")
        return str(iss) if iss is not None else ""
    except Exception as e:
        raise InvalidToken(detail="malformed JWT payload") from e


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
