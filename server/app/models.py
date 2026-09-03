"""Persistence. Note what is *absent*: no password, no plaintext, no vault schema.

The `vault_blobs.blob` column is the only user data of substance, and the server
treats it as an opaque array of bytes with a size limit.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def _uuid() -> str:
    return uuid.uuid4().hex


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True, nullable=False)

    # Argon2id hash of the client-derived auth secret. NOT of a password: the
    # server has never seen the master passphrase and cannot derive this itself.
    auth_hash: Mapped[str] = mapped_column(Text, nullable=False)

    # Public KDF parameters, returned so a new device can derive the same keys.
    # Not secret; withholding them would only break multi-device setup.
    kdf_salt: Mapped[str] = mapped_column(String(64), nullable=False)
    kdf_ops_limit: Mapped[int] = mapped_column(Integer, nullable=False)
    kdf_mem_limit_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    kdf_parallelism: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    totp_secret: Mapped[str | None] = mapped_column(Text, nullable=True)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    vault: Mapped["VaultBlob | None"] = relationship(back_populates="user", uselist=False)


class VaultBlob(Base):
    """One encrypted blob per user. Deliberately the simplest thing that works.

    Per-record sync comes later (see docs/NEXT_STEPS.md); doing it first would
    have meant designing conflict resolution before the crypto was settled.
    """

    __tablename__ = "vault_blobs"

    user_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    blob: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    # Server-authoritative counter, bumped on every accepted write. Clients pass
    # the value they based their edit on in If-Match; a mismatch is a conflict.
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    user: Mapped[User] = relationship(back_populates="vault")


class RefreshToken(Base):
    """Hashed refresh tokens with family tracking, for rotation + reuse detection."""

    __tablename__ = "refresh_tokens"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    family_id: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditEvent(Base):
    """Append-only security log. Metadata only -- never request bodies."""

    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    user_id: Mapped[str | None] = mapped_column(String(32), index=True, nullable=True)
    event: Mapped[str] = mapped_column(String(64), nullable=False)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(256), nullable=True)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


Index("ix_audit_user_time", AuditEvent.user_id, AuditEvent.created_at)
