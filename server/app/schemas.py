"""Request/response models. The vault blob is base64 and is never introspected."""

from __future__ import annotations

import base64

from pydantic import BaseModel, EmailStr, Field, field_validator

B64_MAX = 24 * 1024 * 1024  # base64 expansion of the 16 MiB blob cap


class KdfParamsIn(BaseModel):
    salt: str = Field(min_length=16, max_length=64)
    ops_limit: int = Field(ge=2, le=64)
    mem_limit_bytes: int = Field(ge=19 * 1024 * 1024, le=4 * 1024**3)
    parallelism: int = Field(default=1, ge=1, le=16)
    key_length: int = Field(default=32, ge=16, le=64)

    @field_validator("salt")
    @classmethod
    def _b64(cls, v: str) -> str:
        try:
            raw = base64.b64decode(v, validate=True)
        except Exception as exc:
            raise ValueError("salt must be base64") from exc
        if not 16 <= len(raw) <= 32:
            raise ValueError("salt must decode to 16-32 bytes")
        return v


class KdfParamsOut(KdfParamsIn):
    pass


class RegisterIn(BaseModel):
    email: EmailStr
    # A base64 32-byte value derived client-side. Never the master passphrase --
    # the server rejects anything that is not exactly 32 bytes, which makes
    # "someone accidentally POSTed the real passphrase" a validation error.
    auth_secret: str = Field(min_length=40, max_length=64)
    kdf: KdfParamsIn

    @field_validator("auth_secret")
    @classmethod
    def _is_32_bytes(cls, v: str) -> str:
        try:
            raw = base64.b64decode(v, validate=True)
        except Exception as exc:
            raise ValueError("auth_secret must be base64") from exc
        if len(raw) != 32:
            raise ValueError("auth_secret must decode to exactly 32 bytes")
        return v


class LoginIn(BaseModel):
    email: EmailStr
    auth_secret: str = Field(min_length=40, max_length=64)
    totp_code: str | None = Field(default=None, max_length=10)


class TokenOut(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class MfaRequiredOut(BaseModel):
    mfa_required: bool = True
    mfa_token: str


class MfaVerifyIn(BaseModel):
    mfa_token: str
    code: str = Field(min_length=6, max_length=10)


class MfaEnrollOut(BaseModel):
    secret: str
    otpauth_uri: str


class MfaActivateIn(BaseModel):
    code: str = Field(min_length=6, max_length=10)


class RefreshIn(BaseModel):
    refresh_token: str = Field(min_length=20, max_length=256)


class VaultMetaOut(BaseModel):
    version: int
    size_bytes: int
    updated_at: str | None = None


class VaultOut(VaultMetaOut):
    blob: str  # base64 ciphertext, opaque to this server


class VaultPutIn(BaseModel):
    blob: str = Field(max_length=B64_MAX)
    # The version the client based this edit on. 0 means "I believe none exists".
    base_version: int = Field(ge=0)

    @field_validator("blob")
    @classmethod
    def _b64(cls, v: str) -> str:
        try:
            base64.b64decode(v, validate=True)
        except Exception as exc:
            raise ValueError("blob must be base64") from exc
        return v


class ConflictOut(BaseModel):
    detail: str = "version conflict"
    server_version: int


class AuditEventOut(BaseModel):
    event: str
    ip: str | None
    user_agent: str | None
    detail: str | None
    created_at: str
