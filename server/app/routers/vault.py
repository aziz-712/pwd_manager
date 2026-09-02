"""Blind sync endpoints.

Everything here treats the vault as bytes. There is no parsing, no indexing, no
search, and no recovery path -- by design, none of those are possible without the
master passphrase, which never reaches this process.
"""

from __future__ import annotations

import base64

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from .. import audit
from ..config import get_settings
from ..db import get_db
from ..deps import current_user, sync_rate_limit
from ..models import AuditEvent, User, VaultBlob
from ..schemas import AuditEventOut, VaultMetaOut, VaultOut, VaultPutIn

router = APIRouter(prefix="/vault", tags=["vault"], dependencies=[Depends(sync_rate_limit)])


def _meta(blob: VaultBlob) -> dict:
    return {
        "version": blob.version,
        "size_bytes": blob.size_bytes,
        "updated_at": blob.updated_at.isoformat() if blob.updated_at else None,
    }


@router.get("/meta", response_model=VaultMetaOut)
def vault_meta(user: User = Depends(current_user), db: Session = Depends(get_db)) -> VaultMetaOut:
    """Cheap version probe, so a client can skip downloading an unchanged vault."""
    blob = db.get(VaultBlob, user.id)
    if blob is None:
        return VaultMetaOut(version=0, size_bytes=0)
    return VaultMetaOut(**_meta(blob))


@router.get("", response_model=VaultOut)
def download(
    response: Response, user: User = Depends(current_user), db: Session = Depends(get_db)
) -> VaultOut:
    blob = db.get(VaultBlob, user.id)
    if blob is None:
        raise HTTPException(status_code=404, detail="no vault stored")
    response.headers["ETag"] = f'"{blob.version}"'
    return VaultOut(blob=base64.b64encode(blob.blob).decode(), **_meta(blob))


@router.put("", response_model=VaultMetaOut)
def upload(
    body: VaultPutIn,
    request: Request,
    response: Response,
    if_match: str | None = Header(default=None, alias="If-Match"),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> VaultMetaOut:
    """Optimistic concurrency: the write is accepted only if the client's base
    version still matches the stored one. Otherwise 409 with the server version,
    and the client re-downloads, merges locally, and retries.

    Last-writer-wins would be the easy alternative and would silently destroy an
    entry added on another device -- unacceptable for this data.
    """
    settings = get_settings()
    raw = base64.b64decode(body.blob, validate=True)
    if len(raw) > settings.max_blob_bytes:
        raise HTTPException(status_code=413, detail="vault too large")
    if len(raw) == 0:
        raise HTTPException(status_code=400, detail="empty blob")

    expected = body.base_version
    if if_match is not None:
        stripped = if_match.strip().strip('"')
        if not stripped.isdigit():
            raise HTTPException(status_code=400, detail="malformed If-Match")
        if int(stripped) != expected:
            raise HTTPException(status_code=400, detail="If-Match disagrees with base_version")

    blob = db.get(VaultBlob, user.id)
    current_version = blob.version if blob else 0
    if expected != current_version:
        audit.record(
            db, request, "vault.conflict", user_id=user.id,
            detail=f"base={expected} server={current_version}",
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"detail": "version conflict", "server_version": current_version},
            headers={"ETag": f'"{current_version}"'},
        )

    if blob is None:
        blob = VaultBlob(user_id=user.id, blob=raw, version=1, size_bytes=len(raw))
        db.add(blob)
    else:
        blob.blob = raw
        blob.version = current_version + 1
        blob.size_bytes = len(raw)
    db.commit()
    db.refresh(blob)
    audit.record(db, request, "vault.uploaded", user_id=user.id, detail=f"version={blob.version}")
    response.headers["ETag"] = f'"{blob.version}"'
    return VaultMetaOut(**_meta(blob))


@router.delete("", status_code=200)
def delete_vault(
    request: Request,
    confirm: str = "",
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict[str, bool]:
    """Irreversible: there is no server-side copy of the key, so nothing here can
    be recovered afterwards. Requires ?confirm=DELETE."""
    if confirm != "DELETE":
        raise HTTPException(status_code=400, detail="pass ?confirm=DELETE")
    blob = db.get(VaultBlob, user.id)
    if blob:
        db.delete(blob)
        db.commit()
    audit.record(db, request, "vault.deleted", user_id=user.id)
    return {"deleted": True}


@router.get("/audit", response_model=list[AuditEventOut])
def my_audit_log(
    limit: int = 50, user: User = Depends(current_user), db: Session = Depends(get_db)
) -> list[AuditEventOut]:
    """A user's own security events -- logins, conflicts, MFA changes.

    Visible to the account holder because unexplained logins are exactly what a
    victim needs to see early.
    """
    limit = max(1, min(limit, 200))
    rows = (
        db.query(AuditEvent)
        .filter(AuditEvent.user_id == user.id)
        .order_by(AuditEvent.created_at.desc())
        .limit(limit)
        .all()
    )
    return [
        AuditEventOut(
            event=r.event, ip=r.ip, user_agent=r.user_agent,
            detail=r.detail, created_at=r.created_at.isoformat(),
        )
        for r in rows
    ]
