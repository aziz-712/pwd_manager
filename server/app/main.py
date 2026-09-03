"""FastAPI application factory.

Why FastAPI rather than Django: this service has four tables and no server-
rendered UI. Django's admin, ORM migrations, template engine, sessions and CSRF
machinery are the parts you would immediately have to disable -- an admin panel
that can browse user rows is a liability for a service whose selling point is
that operators cannot see anything useful. FastAPI keeps the attack surface to
the endpoints actually written here, and Pydantic gives strict request validation
at the boundary, which matters more than any of the batteries Django includes.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import get_settings
from .db import init_db
from .middleware import HTTPSRedirectGuard, RequestContextMiddleware, SecurityHeadersMiddleware
from .openapi import app_metadata
from .routers import auth, health, vault

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s"
)

API_PREFIX = "/api/v1"


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    init_db()
    if settings.is_production:
        # Fail at boot rather than serving with a per-process random JWT key,
        # which would silently log everyone out on every deploy.
        settings.resolved_jwt_secret()
        settings.resolved_enumeration_secret()
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    # Swagger UI, ReDoc and the schema itself are a development affordance:
    # app_metadata returns them wired up outside production and switched off
    # inside it, so the deployed service publishes no route map at all.
    app = FastAPI(lifespan=lifespan, **app_metadata(settings))

    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestContextMiddleware)
    app.add_middleware(HTTPSRedirectGuard)

    origins = [o.strip() for o in settings.cors_origins.split(",") if o.strip()]
    if origins:
        # Explicit origins only. A wildcard with credentials is both forbidden by
        # the spec and the classic way these APIs get read cross-origin.
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_credentials=True,
            allow_methods=["GET", "PUT", "POST", "DELETE"],
            allow_headers=["Authorization", "Content-Type", "If-Match", "X-Request-ID"],
            max_age=600,
        )

    app.include_router(health.router)
    app.include_router(auth.router, prefix=API_PREFIX)
    app.include_router(vault.router, prefix=API_PREFIX)

    return app


app = create_app()
