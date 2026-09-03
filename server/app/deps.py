"""Shared dependencies: DB session, current user, rate limiting."""

from __future__ import annotations

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from .config import get_settings
from .db import get_db
from .models import User
from .ratelimit import limiter
from .security import decode_token

bearer = HTTPBearer(auto_error=False)

UNAUTHORIZED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="not authenticated",
    headers={"WWW-Authenticate": "Bearer"},
)


def current_user(
    creds: HTTPAuthorizationCredentials | None = Depends(bearer),
    db: Session = Depends(get_db),
) -> User:
    if creds is None or not creds.credentials:
        raise UNAUTHORIZED
    claims = decode_token(creds.credentials, expected_type="access")
    if not claims:
        raise UNAUTHORIZED
    user = db.get(User, claims.get("sub"))
    if user is None or not user.is_active:
        raise UNAUTHORIZED
    return user


def rate_limit(bucket: str, per_minute_attr: str):
    """Per-IP limiter for one route class. IP-only by design: limiting by email
    would let an attacker lock a victim out by spending someone else's budget."""

    def _dep(request: Request) -> None:
        from .audit import client_ip

        limit = getattr(get_settings(), per_minute_attr)
        key = f"{bucket}:{client_ip(request) or 'unknown'}"
        allowed, remaining, retry_after = limiter.check(key, limit)
        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="rate limit exceeded",
                headers={"Retry-After": str(int(retry_after) + 1)},
            )
        request.state.rate_remaining = remaining

    return _dep


auth_rate_limit = rate_limit("auth", "rate_limit_auth_per_minute")
sync_rate_limit = rate_limit("sync", "rate_limit_sync_per_minute")
