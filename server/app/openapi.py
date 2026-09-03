"""OpenAPI/Swagger metadata for the development environment.

Split out of ``main`` because it is documentation, not behaviour, and because it
is deliberately *not* served in production: publishing a schema for a service
whose whole premise is that it holds nothing readable buys developers a lot and
buys an attacker a free map of every route and payload shape. ``app_metadata``
below is the single place that decides which of the two you get.
"""

from __future__ import annotations

from typing import Any

from .config import Settings

API_TITLE = "zkvault blind sync"
API_VERSION = "1.0.0"

# Shown in production too (the /healthz body is the only thing served there), so
# keep it to the one sentence that matters.
SHORT_DESCRIPTION = (
    "Stores encrypted vault blobs. The server cannot decrypt them, cannot "
    "search them, and offers no password recovery."
)

DESCRIPTION = """
Blind sync for [zkvault](https://github.com/ahmedazizabbassi/pwd_manager). The
server stores an opaque ciphertext blob per account and arbitrates versions
between devices. It never receives the master passphrase, the vault key, or
anything that can derive either.

> **This page is a development-only affordance.** `/docs`, `/redoc` and
> `/openapi.json` are all disabled when `ZKVAULT_ENVIRONMENT` is `production`,
> `prod` or `staging`.

## What the client computes before it talks to this API

```
master = Argon2id(passphrase, salt, ops_limit, mem_limit_bytes)
auth   = BLAKE2b(master, "zkvault/v1/server-auth")   -> sent here, base64
KEK    = BLAKE2b(master, ...) -- wraps the vault key, never sent
```

`auth_secret` is therefore a base64 string that decodes to **exactly 32 bytes**.
The server rejects anything else at validation time, which turns "a client
accidentally POSTed the real passphrase" into a 422 rather than a breach. What
is stored is `Argon2id(auth_secret)`, so a database dump yields neither the
passphrase nor the key.

## Trying it out from this page

1. **POST `/api/v1/auth/register`** with an email, a base64 32-byte
   `auth_secret`, and your KDF parameters. For scratch testing,
   `python -c "import base64,os;print(base64.b64encode(os.urandom(32)).decode())"`
   produces both the secret and (at 16 bytes) a usable salt.
2. **POST `/api/v1/auth/login`** with the same email and secret. You get either
   a token pair, or — if TOTP is enabled — `{"mfa_required": true, "mfa_token":
   ...}`, which you exchange at `/api/v1/auth/mfa/verify`.
3. Click **Authorize** and paste the `access_token`. Swagger UI is configured
   with `persistAuthorization`, so it survives a page reload.
4. **PUT `/api/v1/vault`** with a base64 blob and `base_version: 0`.

Access tokens last 15 minutes by design (there is no server-side revocation
list; `POST /auth/logout` revokes refresh tokens only). Refresh tokens rotate on
every use and reuse of a spent token revokes the entire family.

## Conventions

* **Errors** are `{"detail": "..."}`, except `409` on vault upload, where
  `detail` is an object carrying `server_version` so the client can re-sync
  without a second round trip.
* **Concurrency** is optimistic. Send the version you edited as `base_version`
  (and optionally the same number as an `If-Match` header); a mismatch is a
  `409`, never a silent overwrite.
* **Rate limits** are per IP and per route class, and return `429` with a
  `Retry-After` header. The dev limiter is in-process, so it under-counts behind
  multiple workers.
* **`X-Request-ID`** is echoed on every response; send your own to correlate
  with the server's access log.
"""

TAGS_METADATA: list[dict[str, Any]] = [
    {
        "name": "health",
        "description": "Unauthenticated liveness probe. Reports the configured environment.",
    },
    {
        "name": "auth",
        "description": (
            "Registration, login, TOTP enrolment and rotating refresh tokens. "
            "Everything here authenticates a *derived* secret; the passphrase "
            "itself never reaches this process. Rate limited per IP at "
            "`ZKVAULT_RATE_LIMIT_AUTH_PER_MINUTE`."
        ),
    },
    {
        "name": "vault",
        "description": (
            "Blind storage. The blob is bytes to this service — no parsing, no "
            "indexing, no search, no recovery. Writes are version-checked; reads "
            "carry an `ETag`. Rate limited per IP at "
            "`ZKVAULT_RATE_LIMIT_SYNC_PER_MINUTE`."
        ),
    },
]

DEV_SERVERS: list[dict[str, str]] = [
    {"url": "http://127.0.0.1:8000", "description": "Local dev server (make serve)"},
]

# persistAuthorization is the one that matters: without it every reload of /docs
# throws away the bearer token you just pasted.
SWAGGER_UI_PARAMETERS: dict[str, Any] = {
    "persistAuthorization": True,
    "displayRequestDuration": True,
    "docExpansion": "none",
    "filter": True,
    "tryItOutEnabled": True,
    "syntaxHighlight.theme": "obsidian",
}


def app_metadata(settings: Settings) -> dict[str, Any]:
    """FastAPI constructor kwargs: a documented API in dev, a mute one elsewhere."""
    base: dict[str, Any] = {
        "title": API_TITLE,
        "version": API_VERSION,
        "description": SHORT_DESCRIPTION,
    }
    if settings.is_production:
        return {**base, "docs_url": None, "redoc_url": None, "openapi_url": None}
    return {
        **base,
        "summary": SHORT_DESCRIPTION,
        "description": DESCRIPTION,
        "openapi_tags": TAGS_METADATA,
        "servers": DEV_SERVERS,
        "docs_url": "/docs",
        "redoc_url": "/redoc",
        "openapi_url": "/openapi.json",
        "swagger_ui_parameters": SWAGGER_UI_PARAMETERS,
        "license_info": {"name": "MIT"},
        "contact": {
            "name": "zkvault",
            "url": "https://github.com/ahmedazizabbassi/pwd_manager",
        },
    }


# --- Content-Security-Policy for the docs routes ---------------------------
#
# The API's own CSP is `default-src 'none'`, which is right for a JSON service
# and fatal for Swagger UI: FastAPI's docs page pulls its bundle from a CDN and
# boots it from an inline script, so under that policy /docs renders blank. The
# exemption is scoped to these four paths and, like the docs themselves, never
# applies in production.
DOCS_PATHS = frozenset({"/docs", "/docs/oauth2-redirect", "/redoc", "/openapi.json"})

DOCS_CSP = (
    "default-src 'none'; "
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
    "font-src 'self' data: https://fonts.gstatic.com https://cdn.jsdelivr.net; "
    "img-src 'self' data: https://fastapi.tiangolo.com; "
    "connect-src 'self'; "
    "worker-src 'self' blob:; "  # ReDoc renders in a web worker
    "frame-ancestors 'none'"
)


# --- shared error responses ------------------------------------------------
#
# FastAPI documents the happy path from the return type and nothing else, so
# every failure a client must actually handle -- 401, 409, 413, 429 -- would be
# invisible in Swagger UI unless listed here.
from .schemas import ConflictOut, ErrorOut  # noqa: E402  (kept next to its use)

_ERROR_DESCRIPTIONS: dict[int, str] = {
    400: "Malformed request that passed schema validation.",
    401: "Missing, expired or rejected credentials.",
    403: "Authenticated, but not permitted.",
    404: "Nothing stored for this account.",
    409: "Conflicts with existing state.",
    413: "Blob exceeds ZKVAULT_MAX_BLOB_BYTES.",
    429: "Rate limit exceeded. Honour the Retry-After header.",
}


def errors(
    *codes: int,
    describe: dict[int, str] | None = None,
    models: dict[int, Any] | None = None,
) -> dict[int | str, dict[str, Any]]:
    """Response docs for the listed status codes, all shaped `{"detail": ...}`.

    ``describe`` replaces a generic description with the one a route actually
    returns; ``models`` swaps the body model, which only PUT /vault needs
    (``ConflictOut``, whose `detail` is an object rather than a string).
    """
    describe, models = describe or {}, models or {}
    return {
        code: {
            "model": models.get(code, ErrorOut),
            "description": describe.get(code, _ERROR_DESCRIPTIONS[code]),
        }
        for code in codes
    }
