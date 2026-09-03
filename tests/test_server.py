"""Backend behaviour: auth, token rotation, blind storage, conflicts, limits."""

import base64
import os
import re
import tempfile

import pytest

# Settings are read at import time, so the environment must be set first.
_DB = os.path.join(tempfile.mkdtemp(), "test.db")
os.environ.update(
    ZKVAULT_DATABASE_URL=f"sqlite:///{_DB}",
    ZKVAULT_ENVIRONMENT="test",
    ZKVAULT_JWT_SECRET="test-jwt-secret-not-for-production",
    ZKVAULT_ENUMERATION_SECRET="test-enumeration-secret",
    ZKVAULT_SERVER_ARGON2_MEMORY_KIB="8192",  # keep the suite quick
    ZKVAULT_SERVER_ARGON2_TIME_COST="1",
)

from fastapi.testclient import TestClient  # noqa: E402

from app.db import Base, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.models import User  # noqa: E402
from app.ratelimit import limiter  # noqa: E402
from app.security import new_totp_secret, verify_totp  # noqa: E402

API = "/api/v1"
AUTH_SECRET = base64.b64encode(b"\x11" * 32).decode()
OTHER_SECRET = base64.b64encode(b"\x22" * 32).decode()
KDF = {"salt": base64.b64encode(b"\x33" * 16).decode(), "ops_limit": 3,
       "mem_limit_bytes": 256 * 1024 * 1024, "parallelism": 1, "key_length": 32}


@pytest.fixture
def client():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    limiter.reset()
    with TestClient(app) as c:
        yield c


def register(client, email="user@example.com", secret=AUTH_SECRET):
    return client.post(f"{API}/auth/register", json={"email": email, "auth_secret": secret, "kdf": KDF})


def login(client, email="user@example.com", secret=AUTH_SECRET, **extra):
    return client.post(f"{API}/auth/login", json={"email": email, "auth_secret": secret, **extra})


def auth_header(client, **kw):
    return {"Authorization": f"Bearer {login(client, **kw).json()['access_token']}"}


# --- registration and login ------------------------------------------------


def test_register_then_login(client):
    assert register(client).status_code == 201
    body = login(client).json()
    assert body["token_type"] == "bearer" and body["access_token"] and body["refresh_token"]


def test_the_master_passphrase_shape_is_rejected(client):
    """A client bug that POSTed the real passphrase must fail validation, not be
    quietly accepted and hashed as if it were a derived secret."""
    resp = client.post(f"{API}/auth/register", json={
        "email": "a@example.com", "auth_secret": "correct horse battery staple", "kdf": KDF})
    assert resp.status_code == 422


def test_duplicate_registration_is_refused(client):
    register(client)
    assert register(client).status_code == 409


def test_wrong_secret_and_unknown_account_are_indistinguishable(client):
    register(client)
    wrong = login(client, secret=OTHER_SECRET)
    unknown = login(client, email="nobody@example.com")
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json()["detail"] == unknown.json()["detail"]


def test_kdf_params_do_not_reveal_whether_an_account_exists(client):
    register(client)
    known = client.get(f"{API}/auth/kdf-params", params={"email": "user@example.com"})
    unknown = client.get(f"{API}/auth/kdf-params", params={"email": "nobody@example.com"})
    assert known.status_code == unknown.status_code == 200
    assert known.json().keys() == unknown.json().keys()
    assert known.json()["salt"] == KDF["salt"]
    # Decoys must be stable, or repeated polling would expose them as fakes.
    again = client.get(f"{API}/auth/kdf-params", params={"email": "nobody@example.com"})
    assert again.json() == unknown.json()


def test_password_is_never_stored_anywhere(client):
    register(client)
    from app.db import SessionLocal
    with SessionLocal() as db:
        user = db.query(User).first()
        assert AUTH_SECRET not in user.auth_hash
        assert user.auth_hash.startswith("$argon2id$")


# --- tokens ----------------------------------------------------------------


def test_access_token_is_required(client):
    register(client)
    assert client.get(f"{API}/vault/meta").status_code == 401
    assert client.get(f"{API}/vault/meta", headers={"Authorization": "Bearer nonsense"}).status_code == 401


def test_refresh_rotates_and_detects_reuse(client):
    register(client)
    first = login(client).json()["refresh_token"]
    rotated = client.post(f"{API}/auth/refresh", json={"refresh_token": first})
    assert rotated.status_code == 200
    second = rotated.json()["refresh_token"]
    assert second != first

    # Replaying the spent token revokes the whole family.
    assert client.post(f"{API}/auth/refresh", json={"refresh_token": first}).status_code == 401
    assert client.post(f"{API}/auth/refresh", json={"refresh_token": second}).status_code == 401


def test_logout_revokes_refresh_tokens(client):
    register(client)
    tokens = login(client).json()
    client.post(f"{API}/auth/logout", headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert client.post(f"{API}/auth/refresh", json={"refresh_token": tokens["refresh_token"]}).status_code == 401


def test_an_mfa_token_cannot_be_used_as_an_access_token(client):
    register(client)
    headers = auth_header(client)
    secret = client.post(f"{API}/auth/mfa/enroll", headers=headers).json()["secret"]
    import pyotp
    client.post(f"{API}/auth/mfa/activate", json={"code": pyotp.TOTP(secret).now()}, headers=headers)
    mfa_token = login(client).json()["mfa_token"]
    assert client.get(f"{API}/vault/meta", headers={"Authorization": f"Bearer {mfa_token}"}).status_code == 401


# --- MFA -------------------------------------------------------------------


def test_mfa_challenge_then_verify(client):
    import pyotp
    register(client)
    headers = auth_header(client)
    secret = client.post(f"{API}/auth/mfa/enroll", headers=headers).json()["secret"]
    assert client.post(f"{API}/auth/mfa/activate", json={"code": "000000"}, headers=headers).status_code == 400
    assert client.post(f"{API}/auth/mfa/activate", json={"code": pyotp.TOTP(secret).now()},
                       headers=headers).status_code == 200

    challenge = login(client).json()
    assert challenge["mfa_required"] is True
    bad = client.post(f"{API}/auth/mfa/verify", json={"mfa_token": challenge["mfa_token"], "code": "000000"})
    assert bad.status_code == 401
    good = client.post(f"{API}/auth/mfa/verify",
                       json={"mfa_token": challenge["mfa_token"], "code": pyotp.TOTP(secret).now()})
    assert good.status_code == 200 and good.json()["access_token"]


def test_totp_rejects_junk():
    secret = new_totp_secret()
    assert not verify_totp(secret, "")
    assert not verify_totp(secret, "abcdef")
    assert not verify_totp(secret, "000000 or 1=1")


# --- blind vault storage ---------------------------------------------------


def test_upload_download_roundtrip(client):
    register(client)
    headers = auth_header(client)
    blob = os.urandom(2048)
    put = client.put(f"{API}/vault", json={"blob": base64.b64encode(blob).decode(), "base_version": 0},
                     headers=headers)
    assert put.status_code == 200 and put.json()["version"] == 1
    got = client.get(f"{API}/vault", headers=headers)
    assert base64.b64decode(got.json()["blob"]) == blob
    assert got.headers["ETag"] == '"1"'


def test_the_server_stores_bytes_it_cannot_interpret(client):
    """Not a vault, not JSON, not even valid UTF-8 -- and the server does not care."""
    register(client)
    headers = auth_header(client)
    junk = bytes(range(256)) * 4
    client.put(f"{API}/vault", json={"blob": base64.b64encode(junk).decode(), "base_version": 0},
               headers=headers)
    assert base64.b64decode(client.get(f"{API}/vault", headers=headers).json()["blob"]) == junk


def test_conflicting_write_is_refused(client):
    register(client)
    headers = auth_header(client)
    body = {"blob": base64.b64encode(b"v1" * 100).decode(), "base_version": 0}
    client.put(f"{API}/vault", json=body, headers=headers)
    conflict = client.put(f"{API}/vault", json=body, headers=headers)  # stale base
    assert conflict.status_code == 409
    assert conflict.json()["detail"]["server_version"] == 1


def test_if_match_must_agree_with_the_body(client):
    register(client)
    headers = {**auth_header(client), "If-Match": '"7"'}
    resp = client.put(f"{API}/vault", json={"blob": base64.b64encode(b"x" * 64).decode(),
                                            "base_version": 0}, headers=headers)
    assert resp.status_code == 400


def test_users_cannot_read_each_others_vaults(client):
    register(client, "alice@example.com")
    register(client, "bob@example.com", OTHER_SECRET)
    alice = auth_header(client, email="alice@example.com")
    bob = auth_header(client, email="bob@example.com", secret=OTHER_SECRET)
    client.put(f"{API}/vault", json={"blob": base64.b64encode(b"alice-data" * 20).decode(),
                                     "base_version": 0}, headers=alice)
    assert client.get(f"{API}/vault", headers=bob).status_code == 404


def test_oversized_blob_is_rejected(client):
    register(client)
    huge = base64.b64encode(b"x" * (17 * 1024 * 1024)).decode()
    resp = client.put(f"{API}/vault", json={"blob": huge, "base_version": 0}, headers=auth_header(client))
    assert resp.status_code in (413, 422)


def test_delete_requires_explicit_confirmation(client):
    register(client)
    headers = auth_header(client)
    client.put(f"{API}/vault", json={"blob": base64.b64encode(b"data" * 50).decode(),
                                     "base_version": 0}, headers=headers)
    assert client.request("DELETE", f"{API}/vault", headers=headers).status_code == 400
    assert client.request("DELETE", f"{API}/vault?confirm=DELETE", headers=headers).status_code == 200
    assert client.get(f"{API}/vault", headers=headers).status_code == 404


# --- rate limiting, logging, headers ---------------------------------------


def test_login_attempts_are_rate_limited(client):
    register(client)
    codes = [login(client, secret=OTHER_SECRET).status_code for _ in range(15)]
    assert 429 in codes
    assert codes.count(401) <= 10


def test_security_headers_are_present(client):
    resp = client.get("/healthz")
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert "no-store" in resp.headers["Cache-Control"]
    assert resp.headers["Content-Security-Policy"].startswith("default-src 'none'")


def test_audit_log_records_events_without_vault_material(client):
    register(client)
    headers = auth_header(client)
    secret_blob = b"SUPER-SECRET-CIPHERTEXT-MARKER"
    client.put(f"{API}/vault", json={"blob": base64.b64encode(secret_blob * 40).decode(),
                                     "base_version": 0}, headers=headers)
    rows = client.get(f"{API}/vault/audit", headers=headers).json()
    events = {r["event"] for r in rows}
    assert {"register.ok", "login.ok", "vault.uploaded"} <= events
    dump = str(rows)
    assert "SUPER-SECRET" not in dump and AUTH_SECRET not in dump


# --- developer documentation -----------------------------------------------


def test_docs_are_served_with_a_csp_that_does_not_break_them(client):
    """The API's own `default-src 'none'` blocks Swagger UI's CDN bundle, which
    fails silently -- a 200 that renders a blank page. Pin the exemption."""
    resp = client.get("/docs")
    assert resp.status_code == 200
    csp = resp.headers["Content-Security-Policy"]
    assert "https://cdn.jsdelivr.net" in csp
    assert "'unsafe-inline'" in csp  # FastAPI boots the bundle from an inline script
    for asset in re.findall(r'https://[^"\']+', resp.text):
        host = asset.split("/")[2]
        assert host in csp, f"{asset} is loaded by /docs but not allowed by the CSP"
    # The exemption must not leak to the API itself.
    assert client.get("/healthz").headers["Content-Security-Policy"] == (
        "default-src 'none'; frame-ancestors 'none'"
    )


def test_openapi_documents_every_route(client):
    spec = client.get("/openapi.json").json()
    operations = [op for ops in spec["paths"].values() for op in ops.values()]
    assert operations
    for op in operations:
        assert op.get("summary"), op
        assert op.get("tags"), op

    refs, defined = set(), {f"#/components/schemas/{k}" for k in spec["components"]["schemas"]}

    def walk(node):
        if isinstance(node, dict):
            if "$ref" in node:
                refs.add(node["$ref"])
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(spec)
    assert not refs - defined, "dangling $ref in the schema"


@pytest.mark.parametrize("env", ["production", "prod", "staging"])
def test_docs_are_not_published_outside_development(env):
    """A route map is free reconnaissance; a deployed instance publishes none."""
    from app.config import Settings
    from app.openapi import app_metadata

    meta = app_metadata(Settings(environment=env))
    assert meta["docs_url"] is None
    assert meta["redoc_url"] is None
    assert meta["openapi_url"] is None


def test_login_documents_both_of_its_response_shapes(client):
    """A client has to branch on tokens vs. an MFA challenge, so both must be
    in the schema -- not just whichever one the happy path returns."""
    schema = client.get("/openapi.json").json()["paths"]["/api/v1/auth/login"]["post"]
    body = str(schema["responses"]["200"])
    assert "TokenOut" in body and "MfaRequiredOut" in body
