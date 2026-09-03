"""Request-scoped middleware: correlation IDs, safe access logs, security headers."""

from __future__ import annotations

import logging
import time
import uuid

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response

from .config import get_settings
from .openapi import DOCS_CSP, DOCS_PATHS

log = logging.getLogger("zkvault.access")


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Logs method, path, status and latency. Never the body.

    Vault ciphertext and auth secrets both travel in request bodies, so body
    logging would undo the entire design. Query strings are dropped too -- an
    email in a `?email=` log line is exactly the leak we are avoiding elsewhere.
    """

    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("x-request-id", uuid.uuid4().hex[:16])[:32]
        request.state.request_id = request_id
        started = time.perf_counter()
        try:
            response: Response = await call_next(request)
        except Exception:
            log.exception("request_id=%s %s %s unhandled", request_id, request.method, request.url.path)
            return JSONResponse({"detail": "internal error"}, status_code=500)
        elapsed_ms = (time.perf_counter() - started) * 1000
        log.info(
            "request_id=%s %s %s -> %d in %.1fms",
            request_id, request.method, request.url.path, response.status_code, elapsed_ms,
        )
        response.headers["X-Request-ID"] = request_id
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        settings = get_settings()
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Cache-Control", "no-store")
        response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        # This API returns only JSON; a CSP this tight costs nothing and blocks
        # the rendered-error-page class of XSS outright. The docs routes are the
        # one exception -- they serve HTML that loads a CDN bundle -- and they
        # only exist outside production in the first place.
        is_docs = not settings.is_production and request.url.path in DOCS_PATHS
        response.headers.setdefault(
            "Content-Security-Policy",
            DOCS_CSP if is_docs else "default-src 'none'; frame-ancestors 'none'",
        )
        if settings.require_https and settings.is_production:
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload"
            )
        return response


class HTTPSRedirectGuard(BaseHTTPMiddleware):
    """Refuse plaintext requests in production rather than redirecting them.

    A redirect would still have carried the auth secret over cleartext once.
    """

    async def dispatch(self, request: Request, call_next):
        settings = get_settings()
        if settings.require_https and settings.is_production:
            proto = request.headers.get("x-forwarded-proto", request.url.scheme)
            if proto != "https":
                return JSONResponse({"detail": "HTTPS required"}, status_code=400)
        return await call_next(request)
