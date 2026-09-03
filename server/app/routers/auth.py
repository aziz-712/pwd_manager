"""Authentication.

The server authenticates a *derived* secret, not a password. The client computes

    master   = Argon2id(passphrase, salt)
    auth     = BLAKE2b(master, "zkvault/v1/server-auth")

and sends `auth`. The server stores Argon2id(auth). Compromising the database
therefore yields neither the passphrase nor the key that decrypts the vault, and
the server has no way to compute one from the other.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Union

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from .. import audit, security
from ..config import get_settings
from ..db import get_db
from ..deps import auth_rate_limit, current_user
from ..models import RefreshToken, User, _uuid
from ..openapi import errors
from ..schemas import (
    KdfParamsOut,
    LoginIn,
    LogoutOut,
    MfaActivateIn,
    MfaActivateOut,
    MfaEnrollOut,
    MfaRequiredOut,
    MfaVerifyIn,
    RefreshIn,
    RegisterIn,
    RegisterOut,
    TokenOut,
)

router = APIRouter(prefix="/auth", tags=["auth"])

INVALID_CREDENTIALS = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid credentials"
)


def _issue_tokens(db: Session, user: User, family_id: str | None = None) -> TokenOut:
    access, ttl = security.create_access_token(user.id)
    raw, token_hash = security.new_refresh_token()
    db.add(
        RefreshToken(
            user_id=user.id,
            family_id=family_id or _uuid(),
            token_hash=token_hash,
            expires_at=datetime.now(timezone.utc)
            + timedelta(seconds=get_settings().refresh_token_ttl_seconds),
        )
    )
    db.commit()
    return TokenOut(access_token=access, refresh_token=raw, expires_in=ttl)


@router.post(
    "/register",
    status_code=201,
    response_model=RegisterOut,
    summary="Create an account",
    description=(
        "Takes the derived `auth_secret` and the public KDF parameters, and stores "
        "`Argon2id(auth_secret)`. Nothing sent here can decrypt a vault."
    ),
    # 422 is left to FastAPI: its auto-generated body is a list of field errors,
    # not the flat {"detail": "..."} every other failure here uses.
    responses=errors(409, 429, describe={409: "An account with this email already exists."}),
    dependencies=[Depends(auth_rate_limit)],
)
def register(body: RegisterIn, request: Request, db: Session = Depends(get_db)) -> dict[str, str]:
    email = body.email.lower()
    if db.query(User).filter(User.email == email).first():
        # Registration cannot hide account existence the way login can, so the
        # rate limiter is what keeps this from becoming a bulk enumeration tool.
        audit.record(db, request, "register.duplicate", detail=None)
        raise HTTPException(status_code=409, detail="account already exists")

    user = User(
        email=email,
        auth_hash=security.hash_auth_secret(body.auth_secret),
        kdf_salt=body.kdf.salt,
        kdf_ops_limit=body.kdf.ops_limit,
        kdf_mem_limit_bytes=body.kdf.mem_limit_bytes,
        kdf_parallelism=body.kdf.parallelism,
    )
    db.add(user)
    db.commit()
    audit.record(db, request, "register.ok", user_id=user.id)
    return {"user_id": user.id}


@router.get(
    "/kdf-params",
    response_model=KdfParamsOut,
    summary="Public KDF parameters for an account",
    responses=errors(429),
    dependencies=[Depends(auth_rate_limit)],
)
def kdf_params(
    email: str = Query(description="Account email. Unknown addresses get decoy parameters, not a 404."),
    db: Session = Depends(get_db),
) -> KdfParamsOut:
    """Public KDF parameters for an account, so a new device can derive its keys.

    Unknown accounts get deterministic decoy parameters instead of a 404: the
    endpoint must answer before authentication, so a truthful 404 would be a free
    account-existence oracle.
    """
    user = db.query(User).filter(User.email == email.lower()).first()
    if user is None:
        return KdfParamsOut(**security.decoy_kdf_params(email))
    return KdfParamsOut(
        salt=user.kdf_salt,
        ops_limit=user.kdf_ops_limit,
        mem_limit_bytes=user.kdf_mem_limit_bytes,
        parallelism=user.kdf_parallelism,
    )


# A genuine union rather than a bare 200: the two shapes are what a client has
# to branch on, and declaring it puts both in the schema instead of leaving the
# MFA case undocumented.
@router.post(
    "/login",
    response_model=Union[TokenOut, MfaRequiredOut],
    summary="Exchange the derived secret for tokens",
    description=(
        "Returns a token pair, or -- when TOTP is enabled and no `totp_code` was "
        "supplied -- an MFA challenge to redeem at `/auth/mfa/verify`. Unknown "
        "accounts and wrong secrets are deliberately indistinguishable, in body "
        "and in timing."
    ),
    responses=errors(401, 429, describe={401: "Unknown account, wrong secret, or wrong TOTP code."}),
    dependencies=[Depends(auth_rate_limit)],
)
def login(body: LoginIn, request: Request, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == body.email.lower()).first()
    if user is None or not user.is_active:
        security.burn_time()  # equalise timing with the real verify path
        audit.record(db, request, "login.failed", detail="unknown or inactive account")
        raise INVALID_CREDENTIALS
    if not security.verify_auth_secret(user.auth_hash, body.auth_secret):
        audit.record(db, request, "login.failed", user_id=user.id)
        raise INVALID_CREDENTIALS

    if user.totp_enabled and user.totp_secret:
        if body.totp_code:
            if not security.verify_totp(user.totp_secret, body.totp_code):
                audit.record(db, request, "login.mfa_failed", user_id=user.id)
                raise INVALID_CREDENTIALS
        else:
            # Two-step flow for clients that prompt for the code separately.
            audit.record(db, request, "login.mfa_challenge", user_id=user.id)
            return MfaRequiredOut(mfa_token=security.create_mfa_challenge_token(user.id))

    user.last_login_at = datetime.now(timezone.utc)
    db.commit()
    audit.record(db, request, "login.ok", user_id=user.id)
    return _issue_tokens(db, user)


@router.post(
    "/mfa/verify",
    response_model=TokenOut,
    summary="Redeem an MFA challenge for tokens",
    responses=errors(401, 429, describe={401: "Expired challenge token, or wrong code."}),
    dependencies=[Depends(auth_rate_limit)],
)
def mfa_verify(body: MfaVerifyIn, request: Request, db: Session = Depends(get_db)) -> TokenOut:
    claims = security.decode_token(body.mfa_token, expected_type="mfa")
    if not claims:
        raise INVALID_CREDENTIALS
    user = db.get(User, claims.get("sub"))
    if user is None or not user.totp_enabled or not user.totp_secret:
        raise INVALID_CREDENTIALS
    if not security.verify_totp(user.totp_secret, body.code):
        audit.record(db, request, "login.mfa_failed", user_id=user.id)
        raise INVALID_CREDENTIALS
    audit.record(db, request, "login.ok", user_id=user.id, detail="mfa")
    return _issue_tokens(db, user)


@router.post(
    "/mfa/enroll",
    response_model=MfaEnrollOut,
    summary="Start TOTP enrolment",
    responses=errors(401, 409, describe={409: "MFA is already enabled for this account."}),
)
def mfa_enroll(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Hands out a TOTP secret; it is inert until /mfa/activate proves the clock.

    MFA guards *sync access only*. It cannot gate decryption -- the vault opens
    offline from the passphrase alone, and pretending otherwise would be theatre.
    """
    if user.totp_enabled:
        raise HTTPException(status_code=409, detail="MFA already enabled")
    secret = security.new_totp_secret()
    user.totp_secret = secret
    db.commit()
    audit.record(db, request, "mfa.enroll_started", user_id=user.id)
    return MfaEnrollOut(secret=secret, otpauth_uri=security.totp_uri(secret, user.email))


@router.post(
    "/mfa/activate",
    response_model=MfaActivateOut,
    summary="Finish TOTP enrolment",
    responses=errors(400, 401, describe={400: "No enrolment in progress, or the code did not verify."}),
)
def mfa_activate(
    body: MfaActivateIn,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict[str, bool]:
    if not user.totp_secret:
        raise HTTPException(status_code=400, detail="no enrolment in progress")
    if not security.verify_totp(user.totp_secret, body.code):
        audit.record(db, request, "mfa.activate_failed", user_id=user.id)
        raise HTTPException(status_code=400, detail="invalid code")
    user.totp_enabled = True
    db.commit()
    audit.record(db, request, "mfa.enabled", user_id=user.id)
    return {"totp_enabled": True}


@router.post(
    "/refresh",
    response_model=TokenOut,
    summary="Rotate a refresh token",
    responses=errors(
        401,
        429,
        describe={401: "Unknown, expired, or already-spent token. Reuse revokes the whole family."},
    ),
    dependencies=[Depends(auth_rate_limit)],
)
def refresh(body: RefreshIn, request: Request, db: Session = Depends(get_db)) -> TokenOut:
    """Rotating refresh with reuse detection.

    Presenting a token that was already spent means either a replay or a stolen
    token, and we cannot tell which -- so the whole family is revoked and both
    the attacker and the legitimate client are forced back through login.
    """
    token_hash = security.hash_refresh_token(body.refresh_token)
    stored = db.query(RefreshToken).filter(RefreshToken.token_hash == token_hash).first()
    if stored is None:
        audit.record(db, request, "refresh.unknown_token")
        raise INVALID_CREDENTIALS

    if stored.revoked:
        db.query(RefreshToken).filter(RefreshToken.family_id == stored.family_id).update(
            {"revoked": True}
        )
        db.commit()
        audit.record(db, request, "refresh.reuse_detected", user_id=stored.user_id)
        raise INVALID_CREDENTIALS

    if stored.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        audit.record(db, request, "refresh.expired", user_id=stored.user_id)
        raise INVALID_CREDENTIALS

    user = db.get(User, stored.user_id)
    if user is None or not user.is_active:
        raise INVALID_CREDENTIALS

    stored.revoked = True
    db.commit()
    audit.record(db, request, "refresh.ok", user_id=user.id)
    return _issue_tokens(db, user, family_id=stored.family_id)


@router.post(
    "/logout",
    response_model=LogoutOut,
    summary="Revoke every refresh token for the account",
    responses=errors(401),
)
def logout(
    request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)
) -> dict[str, bool]:
    """Revokes every refresh token for the user.

    Access tokens stay valid until they expire; keeping a revocation list for
    them would mean a database read per request. The 15-minute TTL is the
    trade-off, and it is the reason that TTL is short.
    """
    db.query(RefreshToken).filter(RefreshToken.user_id == user.id).update({"revoked": True})
    db.commit()
    audit.record(db, request, "logout", user_id=user.id)
    return {"logged_out": True}
