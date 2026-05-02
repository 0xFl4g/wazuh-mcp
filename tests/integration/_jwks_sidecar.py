"""M5b T-G4a. In-process JWKS HTTP server + key-pair generator.

Used by the hand_minted_phantom_token fixture to mint JWTs signed
by a test private key whose public key is served at a side-car JWKS
endpoint. The wazuh-mcp server is configured to trust the side-car's
issuer URL via an extra tenant in mcp_http_server_audit_sinks's
tenants.yaml.

Plan-author deviation from spec § 7.4: Path C (side-car JWKS) was
adopted instead of Path A (Keycloak admin claim-injection) or Path B
(Keycloak admin REST private-key fetch). Path A doesn't support
arbitrary tenant_id claims; Path B doesn't work because Keycloak
does not expose realm signing private keys via admin API.

The side-car runs in a background thread so module-scoped sync
fixtures (mcp_http_server_audit_sinks) can call get-or-start without
needing an event loop, while async fixtures
(jwks_sidecar_issuer / hand_minted_phantom_token) can also reuse it.
"""

from __future__ import annotations

import socket
import threading
import time
from typing import Any

import uvicorn
from joserfc import jwt
from joserfc.jwk import RSAKey
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

# Module-level singletons. Test session reuses one key pair + one server.
_KEY: RSAKey | None = None
_SERVER: uvicorn.Server | None = None
_THREAD: threading.Thread | None = None
_ISSUER: str | None = None
_LOCK = threading.Lock()


def _key() -> RSAKey:
    global _KEY
    if _KEY is None:
        _KEY = RSAKey.generate_key(2048, parameters={"kid": "wazuh-mcp-phantom-test"})
    return _KEY


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _build_app(issuer: str) -> Starlette:
    async def jwks(_request: Any) -> JSONResponse:
        pub = _key().as_dict(private=False)
        # Advertise alg + use so JWKS consumers (joserfc-based) accept the key.
        pub.setdefault("alg", "RS256")
        pub.setdefault("use", "sig")
        return JSONResponse({"keys": [pub]})

    async def discovery(_request: Any) -> JSONResponse:
        return JSONResponse(
            {
                "issuer": issuer,
                "jwks_uri": f"{issuer}/.well-known/jwks.json",
            }
        )

    return Starlette(
        routes=[
            Route("/.well-known/openid-configuration", discovery),
            Route("/.well-known/jwks.json", jwks),
        ]
    )


def start_sidecar() -> str:
    """Idempotently start the side-car. Returns the issuer URL.

    Safe to call from sync (module-scoped) fixtures — uses a background
    thread running uvicorn's own event loop. Subsequent calls return
    the same URL without restarting.
    """
    global _SERVER, _THREAD, _ISSUER
    with _LOCK:
        if _ISSUER is not None and _SERVER is not None and _SERVER.started:
            return _ISSUER
        port = _free_port()
        issuer = f"http://127.0.0.1:{port}"
        app = _build_app(issuer)
        config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
        server = uvicorn.Server(config)

        def _run() -> None:
            server.run()

        thread = threading.Thread(target=_run, name="jwks-sidecar", daemon=True)
        thread.start()
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            if server.started:
                break
            time.sleep(0.05)
        else:
            raise RuntimeError("JWKS side-car failed to start within 5s")
        _SERVER = server
        _THREAD = thread
        _ISSUER = issuer
        return issuer


def stop_sidecar() -> None:
    """Tear down the side-car. Safe to call multiple times."""
    global _SERVER, _THREAD, _ISSUER
    with _LOCK:
        if _SERVER is None:
            return
        _SERVER.should_exit = True
        if _THREAD is not None:
            _THREAD.join(timeout=5.0)
        _SERVER = None
        _THREAD = None
        _ISSUER = None


def mint_phantom_token(
    *,
    issuer: str,
    audience: str,
    tenant_id: str = "phantom",
    sub: str = "phantom-user",
    extra_claims: dict[str, Any] | None = None,
) -> str:
    """Mint a JWT signed by the side-car private key.

    Default claims target the M4c resolver-miss path: tenant_id is set
    to a value NOT in tenants.yaml, so IssuerIndex / OAuthSessionFactory
    routes the request, but the per-tenant resolver KeyError fires.
    """
    now = int(time.time())
    claims = {
        "iss": issuer,
        "aud": audience,
        "sub": sub,
        "tenant_id": tenant_id,
        "rbac_role": "admin",
        "wazuh_user": "phantom-svc",
        "iat": now,
        "exp": now + 300,
    }
    if extra_claims:
        claims.update(extra_claims)
    header = {"alg": "RS256", "kid": "wazuh-mcp-phantom-test"}
    return jwt.encode(header, claims, _key())
