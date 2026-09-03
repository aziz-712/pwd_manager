"""Server-side crypto: hashing the auth secret, JWTs, TOTP, decoy KDF params.

None of this touches vault contents. The server's job is to decide *who* is
asking, never *what* they are storing.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from jose import JWTError, jwt

from .config import get_settings


def _hasher() -> PasswordHasher:
    s = get_settings()
    return PasswordHasher(
        time_cost=s.server_argon2_time_cost,
        memory_cost=s.server_argon2_memory_kib,
        parallelism=s.server_argon2_parallelism,
        hash_len=32,
        salt_len=16,
    )


def hash_auth_secret(auth_secret_b64: str) -> str:
    return _hasher().hash(auth_secret_b64)


def verify_auth_secret(auth_hash: str, auth_secret_b64: str) -> bool:
    try:
        return _hasher().verify(auth_hash, auth_secret_b64)
    except (VerifyMismatchError, InvalidHashError, Exception):
        return False


# A precomputed hash of a random value. Verified against on unknown-email logins
# so that "user does not exist" and "wrong secret" take the same wall-clock time.
_DUMMY_HASH = _hasher().hash(secrets.token_urlsafe(32))


def burn_time() -> None:
    verify_auth_secret(_DUMMY_HASH, "not-the-secret")


# --- tokens ----------------------------------------------------------------


def _now() -> datetime:
    return datetime.now(timezone.utc)


def create_access_token(user_id: str, extra: dict[str, Any] | None = None) -> tuple[str, int]:
    s = get_settings()
    ttl = s.access_token_ttl_seconds
    claims = {
        "sub": user_id,
        "typ": "access",
        "iat": int(_now().timestamp()),
        "exp": int((_now() + timedelta(seconds=ttl)).timestamp()),
        "jti": secrets.token_urlsafe(12),
        **(extra or {}),
    }
    return jwt.encode(claims, s.resolved_jwt_secret(), algorithm=s.jwt_algorithm), ttl


def create_mfa_challenge_token(user_id: str) -> str:
    """Short-lived, single-purpose token proving step 1 of login succeeded."""
    s = get_settings()
    claims = {
        "sub": user_id,
        "typ": "mfa",
        "exp": int((_now() + timedelta(seconds=s.mfa_challenge_ttl_seconds)).timestamp()),
        "jti": secrets.token_urlsafe(12),
    }
    return jwt.encode(claims, s.resolved_jwt_secret(), algorithm=s.jwt_algorithm)


def decode_token(token: str, expected_type: str) -> dict[str, Any] | None:
    s = get_settings()
    try:
        claims = jwt.decode(token, s.resolved_jwt_secret(), algorithms=[s.jwt_algorithm])
    except JWTError:
        return None
    if claims.get("typ") != expected_type:  # stops an MFA token being used as access
        return None
    return claims


def new_refresh_token() -> tuple[str, str]:
    """(opaque token, sha256 hex). Only the hash is stored.

    Refresh tokens are random 256-bit strings rather than JWTs so that revocation
    is a database fact, not a claim we have to hope the client honours.
    """
    token = secrets.token_urlsafe(32)
    return token, hashlib.sha256(token.encode()).hexdigest()


def hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


# --- TOTP ------------------------------------------------------------------


def new_totp_secret() -> str:
    return pyotp.random_base32()


def totp_uri(secret: str, email: str, issuer: str = "zkvault") -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name=issuer)


def verify_totp(secret: str, code: str) -> bool:
    """One step of clock skew either way; anything wider widens the brute window."""
    if not code or not code.strip().isdigit():
        return False
    return pyotp.TOTP(secret).verify(code.strip(), valid_window=1)


# --- user-enumeration resistance -------------------------------------------


def decoy_kdf_params(email: str) -> dict[str, Any]:
    """Deterministic, plausible KDF parameters for an unknown account.

    /auth/kdf-params has to answer before login, so it would otherwise be a
    perfect account-existence oracle. Deriving a stable fake salt via HMAC means
    an attacker polling the endpoint sees an ordinary answer, identical across
    retries, and cannot tell registered addresses from unregistered ones.
    """
    key = get_settings().resolved_enumeration_secret().encode()
    digest = hmac.new(key, email.strip().lower().encode(), hashlib.sha256).digest()
    return {
        "salt": base64.b64encode(digest[:16]).decode(),
        "ops_limit": 3,
        "mem_limit_bytes": 256 * 1024 * 1024,
        "parallelism": 1,
        "key_length": 32,
    }
