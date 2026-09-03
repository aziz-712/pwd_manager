"""Request/response models. The vault blob is base64 and is never introspected.

Field descriptions and examples here are what Swagger UI renders, so they are
written for someone driving the API by hand from /docs -- in particular the
distinction between the master passphrase (never sent) and the derived
`auth_secret` (sent, and validated to be exactly 32 bytes).
"""

from __future__ import annotations

import base64

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

B64_MAX = 24 * 1024 * 1024  # base64 expansion of the 16 MiB blob cap

# Deterministic, obviously-fake values for the docs. Real ones are random.
_EXAMPLE_SALT = "AAECAwQFBgcICQoLDA0ODw=="
_EXAMPLE_AUTH = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
_EXAMPLE_BLOB = "WktWMQABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhs="
_EXAMPLE_KDF = {
    "salt": _EXAMPLE_SALT,
    "ops_limit": 3,
    "mem_limit_bytes": 268435456,
    "parallelism": 1,
    "key_length": 32,
}


class KdfParamsIn(BaseModel):
    """Public Argon2id parameters. Public on purpose: a new device needs them to
    derive the same keys, and they reveal nothing about the passphrase."""

    model_config = ConfigDict(json_schema_extra={"example": _EXAMPLE_KDF})

    salt: str = Field(
        min_length=16,
        max_length=64,
        description="Base64 of 16-32 random bytes. Not a secret.",
    )
    ops_limit: int = Field(description="Argon2id time cost (iterations).", ge=2, le=64)
    mem_limit_bytes: int = Field(
        description="Argon2id memory cost in bytes. 19 MiB is the OWASP floor; the client ships 256 MiB.",
        ge=19 * 1024 * 1024,
        le=4 * 1024**3,
    )
    parallelism: int = Field(default=1, ge=1, le=16, description="Argon2id lanes.")
    key_length: int = Field(default=32, ge=16, le=64, description="Derived key length in bytes.")

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
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "email": "you@example.com",
                "auth_secret": _EXAMPLE_AUTH,
                "kdf": _EXAMPLE_KDF,
            }
        }
    )

    email: EmailStr
    # A base64 32-byte value derived client-side. Never the master passphrase --
    # the server rejects anything that is not exactly 32 bytes, which makes
    # "someone accidentally POSTed the real passphrase" a validation error.
    auth_secret: str = Field(
        min_length=40,
        max_length=64,
        description=(
            "Base64 of exactly 32 bytes: BLAKE2b(Argon2id(passphrase, salt), "
            '"zkvault/v1/server-auth"). Never the passphrase itself.'
        ),
    )
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


class RegisterOut(BaseModel):
    user_id: str = Field(description="Opaque account id. Not needed to authenticate.")


class LoginIn(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={"example": {"email": "you@example.com", "auth_secret": _EXAMPLE_AUTH}}
    )

    email: EmailStr
    auth_secret: str = Field(
        min_length=40, max_length=64, description="Same derived value used at registration."
    )
    totp_code: str | None = Field(
        default=None,
        max_length=10,
        description="Optional. Supply it to complete MFA in one step instead of via /auth/mfa/verify.",
    )


class TokenOut(BaseModel):
    access_token: str = Field(description="Bearer token for the Authorization header.")
    refresh_token: str = Field(description="Single use; rotates on every refresh.")
    token_type: str = "bearer"
    expires_in: int = Field(description="Access token lifetime in seconds.")


class MfaRequiredOut(BaseModel):
    """Returned by /auth/login instead of tokens when TOTP is enabled and no
    code was supplied. Exchange `mfa_token` at /auth/mfa/verify."""

    mfa_required: bool = True
    mfa_token: str = Field(description="Short-lived challenge token. Not an access token.")


class MfaVerifyIn(BaseModel):
    mfa_token: str
    code: str = Field(min_length=6, max_length=10, description="Current TOTP code.")


class MfaEnrollOut(BaseModel):
    secret: str = Field(description="Base32 TOTP secret. Inert until /auth/mfa/activate succeeds.")
    otpauth_uri: str = Field(description="otpauth:// URI for an authenticator app.")


class MfaActivateIn(BaseModel):
    code: str = Field(
        min_length=6, max_length=10, description="A code from the enrolled secret, proving the clock."
    )


class MfaActivateOut(BaseModel):
    totp_enabled: bool = True


class RefreshIn(BaseModel):
    refresh_token: str = Field(
        min_length=20,
        max_length=256,
        description="The token from the last login or refresh. Replaying a spent one revokes the family.",
    )


class LogoutOut(BaseModel):
    logged_out: bool = True


class VaultMetaOut(BaseModel):
    version: int = Field(description="Monotonic; 0 means nothing is stored yet.")
    size_bytes: int = Field(description="Ciphertext length. Padmé-padded, so it does not track entry count.")
    updated_at: str | None = Field(default=None, description="ISO-8601 UTC, or null if never written.")


class VaultOut(VaultMetaOut):
    blob: str = Field(description="Base64 ciphertext, opaque to this server.")


class VaultPutIn(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={"example": {"blob": _EXAMPLE_BLOB, "base_version": 0}}
    )

    blob: str = Field(max_length=B64_MAX, description="Base64 ciphertext, at most 16 MiB decoded.")
    # The version the client based this edit on. 0 means "I believe none exists".
    base_version: int = Field(
        ge=0,
        description="The version this edit was based on. 0 asserts that no vault is stored yet.",
    )

    @field_validator("blob")
    @classmethod
    def _b64(cls, v: str) -> str:
        try:
            base64.b64decode(v, validate=True)
        except Exception as exc:
            raise ValueError("blob must be base64") from exc
        return v


class VaultDeleteOut(BaseModel):
    deleted: bool = True


class ConflictDetail(BaseModel):
    detail: str = "version conflict"
    server_version: int = Field(description="The version the client must merge against.")


class ConflictOut(BaseModel):
    """The 409 body from PUT /vault. `detail` is an object here, not a string,
    so the client can re-sync without a second request."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {"detail": {"detail": "version conflict", "server_version": 4}}
        }
    )

    detail: ConflictDetail


class ErrorOut(BaseModel):
    """The shape of every non-409 error response."""

    model_config = ConfigDict(json_schema_extra={"example": {"detail": "invalid credentials"}})

    detail: str


class AuditEventOut(BaseModel):
    event: str = Field(description="e.g. login.ok, login.failed, vault.uploaded, vault.conflict.")
    ip: str | None
    user_agent: str | None
    detail: str | None = Field(description="Metadata only; never derived from a request body.")
    created_at: str


class HealthOut(BaseModel):
    status: str = "ok"
    environment: str = Field(description="Value of ZKVAULT_ENVIRONMENT.")
