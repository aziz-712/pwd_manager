"""Audit logging. Metadata only.

Rule enforced by review, not by the type system: nothing derived from a request
body may be passed as `detail`. The body is either the auth secret or ciphertext,
and neither belongs in a log that operators can read.
"""

from __future__ import annotations

import logging

from fastapi import Request
from sqlalchemy.orm import Session

from .models import AuditEvent

log = logging.getLogger("zkvault.audit")

# Events worth alerting on rather than merely storing.
SECURITY_EVENTS = {
    "login.failed",
    "login.mfa_failed",
    "refresh.reuse_detected",
    "vault.conflict",
    "vault.deleted",
    "ratelimit.exceeded",
}


def client_ip(request: Request) -> str | None:
    """Left-most X-Forwarded-For hop, else the socket peer.

    Only trust the header when a proxy you control sets it -- an unproxied
    deployment must ignore it, or every rate limit becomes bypassable.
    """
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()[:64]
    return request.client.host if request.client else None


def record(
    db: Session,
    request: Request,
    event: str,
    user_id: str | None = None,
    detail: str | None = None,
) -> None:
    entry = AuditEvent(
        user_id=user_id,
        event=event,
        ip=client_ip(request),
        user_agent=(request.headers.get("user-agent") or "")[:256] or None,
        detail=detail,
    )
    db.add(entry)
    db.commit()
    level = logging.WARNING if event in SECURITY_EVENTS else logging.INFO
    log.log(level, "audit event=%s user=%s ip=%s detail=%s", event, user_id, entry.ip, detail)
