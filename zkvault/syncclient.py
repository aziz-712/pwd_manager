"""Client half of the blind sync protocol.

Invariant for this module: the only things it may send are (a) the derived auth
secret, (b) public KDF parameters, (c) vault ciphertext. Anything else is a bug.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any

import httpx

from .crypto import KdfParams
from .vault import b64d, b64e, derive_auth_secret

API_PREFIX = "/api/v1"
DEFAULT_TIMEOUT = 30.0


class SyncError(Exception):
    pass


class AuthRequired(SyncError):
    pass


class MfaRequired(SyncError):
    def __init__(self, mfa_token: str):
        super().__init__("multi-factor authentication required")
        self.mfa_token = mfa_token


@dataclass
class Conflict(SyncError):
    """The server has a newer version than the one we based our edit on."""

    server_version: int

    def __str__(self) -> str:
        return f"version conflict: server is at version {self.server_version}"


class SyncClient:
    def __init__(self, base_url: str, verify_tls: bool | str = True):
        base = base_url.rstrip("/")
        if not base.startswith("https://") and "localhost" not in base and "127.0.0.1" not in base:
            # The auth secret and blob are useless to a passive attacker, but
            # plaintext HTTP still leaks who syncs with whom and when, and allows
            # an active attacker to serve stale vaults.
            raise SyncError("refusing to sync over plaintext HTTP to a remote host")
        self.base_url = base
        self._http = httpx.Client(
            base_url=base + API_PREFIX, timeout=DEFAULT_TIMEOUT, verify=verify_tls
        )
        self._access_token: str | None = None
        self._refresh_token: str | None = None

    # --- plumbing ----------------------------------------------------------

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> "SyncClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        h = dict(extra or {})
        if self._access_token:
            h["Authorization"] = f"Bearer {self._access_token}"
        return h

    def _request(self, method: str, path: str, *, retry_on_401: bool = True, **kw) -> httpx.Response:
        kw["headers"] = self._headers(kw.pop("headers", None))
        resp = self._http.request(method, path, **kw)
        if resp.status_code == 401 and retry_on_401 and self._refresh_token:
            if self._try_refresh():
                return self._request(method, path, retry_on_401=False, **kw)
        return resp

    def _try_refresh(self) -> bool:
        resp = self._http.post("/auth/refresh", json={"refresh_token": self._refresh_token})
        if resp.status_code != 200:
            self._access_token = self._refresh_token = None
            return False
        self._store_tokens(resp.json())
        return True

    def _store_tokens(self, data: dict[str, Any]) -> None:
        self._access_token = data["access_token"]
        self._refresh_token = data["refresh_token"]

    @staticmethod
    def _error(resp: httpx.Response) -> str:
        try:
            detail = resp.json().get("detail")
        except Exception:
            detail = None
        return f"{resp.status_code}: {detail or resp.text[:200]}"

    # --- account -----------------------------------------------------------

    def fetch_kdf_params(self, email: str) -> KdfParams:
        """Fetch the salt/parameters for an account so a second device can derive
        the same keys. Unknown accounts get plausible decoys, so a wrong email
        fails at login rather than here."""
        resp = self._http.get("/auth/kdf-params", params={"email": email})
        if resp.status_code != 200:
            raise SyncError(f"could not fetch KDF parameters ({self._error(resp)})")
        d = resp.json()
        return KdfParams(
            salt=b64d(d["salt"], field="kdf.salt"),
            ops_limit=d["ops_limit"],
            mem_limit_bytes=d["mem_limit_bytes"],
            parallelism=d.get("parallelism", 1),
            key_length=d.get("key_length", 32),
        )

    def register(self, email: str, passphrase: str, kdf: KdfParams) -> str:
        auth_secret = derive_auth_secret(passphrase, kdf)
        resp = self._http.post(
            "/auth/register",
            json={
                "email": email,
                "auth_secret": auth_secret,
                "kdf": {
                    "salt": b64e(kdf.salt),
                    "ops_limit": kdf.ops_limit,
                    "mem_limit_bytes": kdf.mem_limit_bytes,
                    "parallelism": kdf.parallelism,
                    "key_length": kdf.key_length,
                },
            },
        )
        if resp.status_code != 201:
            raise SyncError(f"registration failed ({self._error(resp)})")
        return resp.json()["user_id"]

    def login(self, email: str, passphrase: str, kdf: KdfParams, totp_code: str | None = None) -> None:
        """Derives the auth secret locally and sends only that."""
        payload = {"email": email, "auth_secret": derive_auth_secret(passphrase, kdf)}
        if totp_code:
            payload["totp_code"] = totp_code
        resp = self._http.post("/auth/login", json=payload)
        if resp.status_code != 200:
            raise AuthRequired(f"login failed ({self._error(resp)})")
        data = resp.json()
        if data.get("mfa_required"):
            raise MfaRequired(data["mfa_token"])
        self._store_tokens(data)

    def complete_mfa(self, mfa_token: str, code: str) -> None:
        resp = self._http.post("/auth/mfa/verify", json={"mfa_token": mfa_token, "code": code})
        if resp.status_code != 200:
            raise AuthRequired(f"MFA verification failed ({self._error(resp)})")
        self._store_tokens(resp.json())

    def logout(self) -> None:
        if self._access_token:
            self._request("POST", "/auth/logout")
        self._access_token = self._refresh_token = None

    # --- sync --------------------------------------------------------------

    def meta(self) -> dict[str, Any]:
        resp = self._request("GET", "/vault/meta")
        if resp.status_code != 200:
            raise SyncError(f"could not read vault metadata ({self._error(resp)})")
        return resp.json()

    def download(self) -> tuple[bytes, int] | None:
        """(vault bytes, server version), or None if the server has nothing."""
        resp = self._request("GET", "/vault")
        if resp.status_code == 404:
            return None
        if resp.status_code != 200:
            raise SyncError(f"download failed ({self._error(resp)})")
        data = resp.json()
        return base64.b64decode(data["blob"]), int(data["version"])

    def upload(self, blob: bytes, base_version: int) -> int:
        resp = self._request(
            "PUT",
            "/vault",
            json={"blob": base64.b64encode(blob).decode(), "base_version": base_version},
            headers={"If-Match": f'"{base_version}"'},
        )
        if resp.status_code == 409:
            body = resp.json().get("detail", {})
            server_version = body.get("server_version") if isinstance(body, dict) else None
            raise Conflict(server_version=int(server_version or 0))
        if resp.status_code != 200:
            raise SyncError(f"upload failed ({self._error(resp)})")
        return int(resp.json()["version"])

    def audit_log(self, limit: int = 20) -> list[dict[str, Any]]:
        resp = self._request("GET", "/vault/audit", params={"limit": limit})
        if resp.status_code != 200:
            raise SyncError(f"could not read audit log ({self._error(resp)})")
        return resp.json()
