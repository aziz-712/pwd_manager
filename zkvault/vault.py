"""The vault file format, and the key hierarchy that protects it.

Key hierarchy
-------------

    master passphrase
        | Argon2id(salt, ops, mem)          <- parameters public, in the header
        v
    master key (32B, never stored, never sent)
        |-- BLAKE2b("zkvault/v1/kek")        --> KEK  (key-encryption key)
        '-- BLAKE2b("zkvault/v1/server-auth")--> auth secret (the ONLY derived
                                                  value that ever leaves the box)
    KEK  --XChaCha20-Poly1305--> wraps VEK (random 32B vault encryption key)
    VEK  --XChaCha20-Poly1305--> encrypts the whole entry payload

Why the extra hop: changing the master passphrase re-wraps 32 bytes instead of
re-encrypting the vault, the VEK can be rotated without the user touching their
passphrase, and a device (Android Keystore, Apple Keychain) can hold its own
wrapping of the VEK for biometric unlock without ever holding the passphrase.

File layout: UTF-8 JSON. Every field outside `payload` is cleartext, and the
fields that matter are authenticated as associated data, so a tampered header --
a downgraded KDF, a spliced-in older payload -- fails the Poly1305 check instead
of being silently accepted.

Two counters, on purpose:

    vault_version  bumped on ANY change to the file, including a re-wrap of the
                   VEK. This is what the sync server compares. Not in any AAD.
    payload_seq    bumped only when the payload is resealed, and bound into the
                   payload's AAD. An attacker cannot raise it without the VEK.

Keeping them apart is what makes `change_passphrase` genuinely cheap: it rewraps
32 bytes and bumps vault_version, without ever decrypting the payload. Keeping
payload_seq inside the AAD is what stops the complementary attack -- splicing an
old payload under a fresh-looking header to defeat the client's rollback check.
"""

from __future__ import annotations

import base64
import json
import os
import stat
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import FORMAT_NAME, FORMAT_VERSION
from .crypto import (
    AEAD_XCHACHA,
    CTX_AUTH,
    CTX_KEK,
    KEY_BYTES,
    NONCE_BYTES,
    TAG_BYTES,
    CryptoFailure,
    KdfParams,
    Secret,
    aead_decrypt,
    aead_encrypt,
    derive_master_key,
    derive_subkey,
    new_key,
    random_bytes,
)
from .model import VaultContents, new_id

# Defence-in-depth limits against malformed/hostile files (fuzzing target).
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_PAYLOAD_BYTES = 32 * 1024 * 1024
MIN_PADDED_BYTES = 1024
LENGTH_PREFIX_BYTES = 4


class VaultFormatError(Exception):
    """The bytes are not a vault we can parse. Never includes file content."""


class RollbackDetected(Exception):
    """A vault older than one we have already seen. Possibly a hostile server."""


# --- helpers ---------------------------------------------------------------


def b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64d(text: Any, *, field: str, expect: int | None = None) -> bytes:
    if not isinstance(text, str):
        raise VaultFormatError(f"{field}: expected a base64 string")
    try:
        raw = base64.b64decode(text, validate=True)
    except Exception as exc:
        raise VaultFormatError(f"{field}: invalid base64") from exc
    if expect is not None and len(raw) != expect:
        raise VaultFormatError(f"{field}: expected {expect} bytes, got {len(raw)}")
    return raw


def canonical(obj: Any) -> bytes:
    """Deterministic JSON. Used for AAD, so it must never vary across clients."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def padme(length: int) -> int:
    """Padme padding (Nikitin et al., PETS 2019): <=12% overhead, bounded leak.

    Bucketing the ciphertext length stops the sync server from reading precise
    vault growth -- "they added one entry today" -- off the blob size alone.
    """
    if length <= MIN_PADDED_BYTES:
        return MIN_PADDED_BYTES
    e = length.bit_length() - 1          # floor(log2 length)
    s = e.bit_length()                   # bits needed to represent e
    mask = (1 << (e - s)) - 1
    return (length + mask) & ~mask


def pad_payload(plaintext: bytes) -> bytes:
    body = len(plaintext).to_bytes(LENGTH_PREFIX_BYTES, "big") + plaintext
    return body + b"\x00" * (padme(len(body)) - len(body))


def unpad_payload(padded: bytes) -> bytes:
    if len(padded) < LENGTH_PREFIX_BYTES:
        raise VaultFormatError("payload truncated")
    n = int.from_bytes(padded[:LENGTH_PREFIX_BYTES], "big")
    if n > len(padded) - LENGTH_PREFIX_BYTES or n > MAX_PAYLOAD_BYTES:
        raise VaultFormatError("payload length prefix out of range")
    return padded[LENGTH_PREFIX_BYTES : LENGTH_PREFIX_BYTES + n]


def today_utc() -> str:
    """Day-granularity mtime: enough to order syncs, too coarse to track habits."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


@dataclass
class DerivedKeys:
    """Everything the passphrase unlocks. Wipe when done."""

    kek: Secret
    auth_secret: Secret

    def wipe(self) -> None:
        self.kek.wipe()
        self.auth_secret.wipe()

    def __enter__(self) -> "DerivedKeys":
        return self

    def __exit__(self, *exc) -> None:
        self.wipe()


def derive_keys(passphrase: str, params: KdfParams) -> DerivedKeys:
    """Run the expensive KDF once, then split into role-specific subkeys."""
    with derive_master_key(passphrase, params) as master:
        return DerivedKeys(
            kek=derive_subkey(master, CTX_KEK),
            auth_secret=derive_subkey(master, CTX_AUTH),
        )


def derive_auth_secret(passphrase: str, params: KdfParams) -> str:
    """The value sent to the sync server in place of a password (base64).

    The server stores only Argon2id(this), so a full server breach yields neither
    the passphrase nor anything that decrypts the vault.
    """
    with derive_keys(passphrase, params) as keys:
        return b64e(keys.auth_secret.bytes)


# --- the file --------------------------------------------------------------


class VaultFile:
    """A locked vault: header in the clear, entries under AEAD."""

    def __init__(
        self,
        *,
        vault_id: str,
        kdf: KdfParams,
        wrapped_vek_nonce: bytes,
        wrapped_vek_ct: bytes,
        payload_nonce: bytes,
        payload_ct: bytes,
        vault_version: int = 1,
        payload_seq: int = 1,
        modified_day: str | None = None,
        cipher: str = AEAD_XCHACHA,
        format_version: int = FORMAT_VERSION,
    ):
        self.vault_id = vault_id
        self.kdf = kdf
        self.wrapped_vek_nonce = wrapped_vek_nonce
        self.wrapped_vek_ct = wrapped_vek_ct
        self.payload_nonce = payload_nonce
        self.payload_ct = payload_ct
        self.vault_version = vault_version
        self.payload_seq = payload_seq
        self.modified_day = modified_day or today_utc()
        self.cipher = cipher
        self.format_version = format_version

    # --- AAD ---------------------------------------------------------------

    def _key_binding(self) -> bytes:
        """AAD for the wrapped VEK: identity + KDF parameters + cipher.

        Excludes the version counter so that saving the vault does not require
        re-wrapping the VEK, but still pins the KDF parameters to the wrap.
        """
        return canonical(
            {
                "format": FORMAT_NAME,
                "format_version": self.format_version,
                "vault_id": self.vault_id,
                "cipher": self.cipher,
                "kdf": self._kdf_dict(),
            }
        )

    def _payload_binding(self) -> bytes:
        """AAD for the payload: vault identity plus the payload sequence number.

        Deliberately excludes `kdf` and `wrapped_vek` so that changing the
        passphrase does not force a re-encryption of the payload -- those two
        fields are authenticated separately, under the KEK, by `_key_binding`.

        Note what this does and does not buy: it stops an attacker from splicing
        an old payload under a newer header. It cannot stop a hostile server from
        serving a complete, genuinely-old file. That is caught by the client's
        own high-water mark -- see `state.py`.
        """
        return canonical(
            {
                "format": FORMAT_NAME,
                "format_version": self.format_version,
                "vault_id": self.vault_id,
                "cipher": self.cipher,
                "payload_seq": self.payload_seq,
            }
        )

    def _kdf_dict(self) -> dict[str, Any]:
        return {
            "algorithm": self.kdf.algorithm,
            "salt": b64e(self.kdf.salt),
            "ops_limit": self.kdf.ops_limit,
            "mem_limit_bytes": self.kdf.mem_limit_bytes,
            "parallelism": self.kdf.parallelism,
            "key_length": self.kdf.key_length,
        }

    # --- construction ------------------------------------------------------

    @staticmethod
    def create(
        passphrase: str,
        contents: VaultContents | None = None,
        kdf: KdfParams | None = None,
    ) -> "VaultFile":
        params = kdf or KdfParams.generate()
        params.validate()
        vek = new_key()
        try:
            with derive_keys(passphrase, params) as keys:
                wn, wc = aead_encrypt(keys.kek, vek.bytes, b"")  # AAD set below
                vf = VaultFile(
                    vault_id=new_id(),
                    kdf=params,
                    wrapped_vek_nonce=wn,
                    wrapped_vek_ct=wc,
                    payload_nonce=b"\x00" * NONCE_BYTES,
                    payload_ct=b"",
                    vault_version=0,
                    payload_seq=0,
                )
                # Re-wrap now that vault_id exists and the binding is computable.
                vf.wrapped_vek_nonce, vf.wrapped_vek_ct = aead_encrypt(
                    keys.kek, vek.bytes, vf._key_binding()
                )
            vf._seal(vek, contents or VaultContents())
            return vf
        finally:
            vek.wipe()

    def _seal(self, vek: Secret, contents: VaultContents) -> None:
        """Encrypt `contents` under the VEK, bumping both counters."""
        self.vault_version += 1
        self.payload_seq += 1
        self.modified_day = today_utc()
        plaintext = pad_payload(canonical(contents.to_dict()))
        self.payload_nonce, self.payload_ct = aead_encrypt(vek, plaintext, self._payload_binding())

    # --- serialisation -----------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": FORMAT_NAME,
            "format_version": self.format_version,
            "vault_id": self.vault_id,
            "cipher": self.cipher,
            "kdf": self._kdf_dict(),
            "wrapped_vek": {
                "nonce": b64e(self.wrapped_vek_nonce),
                "ciphertext": b64e(self.wrapped_vek_ct),
            },
            "vault_version": self.vault_version,
            "payload_seq": self.payload_seq,
            "modified_day": self.modified_day,
            "payload": {
                "nonce": b64e(self.payload_nonce),
                "ciphertext": b64e(self.payload_ct),
            },
        }

    def to_bytes(self) -> bytes:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True).encode("utf-8") + b"\n"

    @staticmethod
    def from_bytes(raw: bytes) -> "VaultFile":
        """Strict parser. Every failure path raises VaultFormatError, never a
        bare KeyError/TypeError -- malformed input is expected, not exceptional."""
        if len(raw) > MAX_FILE_BYTES:
            raise VaultFormatError("vault file implausibly large")
        try:
            doc = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            raise VaultFormatError("not valid UTF-8 JSON") from exc
        if not isinstance(doc, dict):
            raise VaultFormatError("top level must be an object")
        if doc.get("format") != FORMAT_NAME:
            raise VaultFormatError("not a zkvault file")

        fv = doc.get("format_version")
        if not isinstance(fv, int) or isinstance(fv, bool):
            raise VaultFormatError("format_version must be an integer")
        if fv > FORMAT_VERSION:
            raise VaultFormatError(
                f"vault format v{fv} is newer than this client (v{FORMAT_VERSION}); upgrade"
            )
        if doc.get("cipher") != AEAD_XCHACHA:
            raise VaultFormatError(f"unsupported cipher: {doc.get('cipher')!r}")

        vault_id = doc.get("vault_id")
        if not isinstance(vault_id, str) or not (1 <= len(vault_id) <= 64):
            raise VaultFormatError("vault_id missing or malformed")

        kdf_raw = doc.get("kdf")
        if not isinstance(kdf_raw, dict):
            raise VaultFormatError("kdf section missing")
        try:
            kdf = KdfParams(
                salt=b64d(kdf_raw.get("salt"), field="kdf.salt"),
                ops_limit=_as_int(kdf_raw.get("ops_limit"), "kdf.ops_limit"),
                mem_limit_bytes=_as_int(kdf_raw.get("mem_limit_bytes"), "kdf.mem_limit_bytes"),
                parallelism=_as_int(kdf_raw.get("parallelism"), "kdf.parallelism"),
                key_length=_as_int(kdf_raw.get("key_length"), "kdf.key_length"),
                algorithm=str(kdf_raw.get("algorithm", "")),
            )
            kdf.validate()  # downgrade guard, before we allocate anything
        except CryptoFailure as exc:
            raise VaultFormatError(f"unusable KDF parameters: {exc}") from exc

        wrapped = doc.get("wrapped_vek")
        payload = doc.get("payload")
        if not isinstance(wrapped, dict) or not isinstance(payload, dict):
            raise VaultFormatError("wrapped_vek or payload section missing")

        payload_ct = b64d(payload.get("ciphertext"), field="payload.ciphertext")
        if len(payload_ct) > MAX_PAYLOAD_BYTES + TAG_BYTES:
            raise VaultFormatError("payload implausibly large")

        return VaultFile(
            vault_id=vault_id,
            kdf=kdf,
            wrapped_vek_nonce=b64d(wrapped.get("nonce"), field="wrapped_vek.nonce", expect=NONCE_BYTES),
            wrapped_vek_ct=b64d(
                wrapped.get("ciphertext"), field="wrapped_vek.ciphertext", expect=KEY_BYTES + TAG_BYTES
            ),
            payload_nonce=b64d(payload.get("nonce"), field="payload.nonce", expect=NONCE_BYTES),
            payload_ct=payload_ct,
            vault_version=_as_int(doc.get("vault_version"), "vault_version"),
            payload_seq=_as_int(doc.get("payload_seq"), "payload_seq"),
            modified_day=str(doc.get("modified_day", "")) or today_utc(),
            format_version=fv,
        )

    # --- file I/O ----------------------------------------------------------

    @staticmethod
    def load(path: Path) -> "VaultFile":
        return VaultFile.from_bytes(Path(path).read_bytes())

    def save(self, path: Path) -> None:
        """Atomic, 0600, fsync'd. A crash mid-write must not truncate a vault."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".zkvault-", suffix=".tmp")
        try:
            os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
            with os.fdopen(fd, "wb") as fh:
                fh.write(self.to_bytes())
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, path)
            dir_fd = os.open(str(path.parent), os.O_RDONLY)
            try:
                os.fsync(dir_fd)  # durability of the rename itself
            finally:
                os.close(dir_fd)
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise

    # --- unlock / rekey ----------------------------------------------------

    def unwrap_vek(self, passphrase: str) -> Secret:
        with derive_keys(passphrase, self.kdf) as keys:
            raw = aead_decrypt(
                keys.kek, self.wrapped_vek_nonce, self.wrapped_vek_ct, self._key_binding()
            )
        if len(raw) != KEY_BYTES:
            raise CryptoFailure("unwrapped key has the wrong length")
        return Secret(raw)

    def unlock(self, passphrase: str) -> "UnlockedVault":
        vek = self.unwrap_vek(passphrase)
        try:
            padded = aead_decrypt(vek, self.payload_nonce, self.payload_ct, self._payload_binding())
            contents = VaultContents.from_dict(json.loads(unpad_payload(padded).decode("utf-8")))
        except CryptoFailure:
            vek.wipe()
            raise
        except Exception as exc:
            vek.wipe()
            raise VaultFormatError(f"decrypted payload is malformed: {exc}") from exc
        return UnlockedVault(self, vek, contents)

    def change_passphrase(self, old: str, new: str, kdf: KdfParams | None = None) -> None:
        """Re-wrap the VEK only. The payload is untouched, so this is O(32 bytes).

        A new salt is drawn by default: reusing a salt across passphrases would
        let an attacker with both old and new files amortise a cracking attempt.
        """
        vek = self.unwrap_vek(old)
        try:
            self.kdf = kdf or KdfParams.generate(
                ops_limit=self.kdf.ops_limit, mem_limit_bytes=self.kdf.mem_limit_bytes
            )
            self.kdf.validate()
            with derive_keys(new, self.kdf) as keys:
                self.wrapped_vek_nonce, self.wrapped_vek_ct = aead_encrypt(
                    keys.kek, vek.bytes, self._key_binding()
                )
            # The payload is not touched: its AAD covers neither the KDF nor the
            # wrapped key. Only the sync counter moves.
            self.vault_version += 1
            self.modified_day = today_utc()
        finally:
            vek.wipe()

    def unlock_with_vek(self, vek: Secret) -> VaultContents:
        padded = aead_decrypt(vek, self.payload_nonce, self.payload_ct, self._payload_binding())
        return VaultContents.from_dict(json.loads(unpad_payload(padded).decode("utf-8")))

    def rotate_vek(self, passphrase: str) -> None:
        """Draw a fresh VEK and re-encrypt the payload under it.

        Use after a suspected key compromise, or on a schedule. The passphrase is
        unchanged, so the user does not need to relearn anything.
        """
        old_vek = self.unwrap_vek(passphrase)
        new_vek = new_key()
        try:
            contents = self.unlock_with_vek(old_vek)
            with derive_keys(passphrase, self.kdf) as keys:
                self.wrapped_vek_nonce, self.wrapped_vek_ct = aead_encrypt(
                    keys.kek, new_vek.bytes, self._key_binding()
                )
            self._seal(new_vek, contents)
        finally:
            old_vek.wipe()
            new_vek.wipe()


def _as_int(value: Any, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise VaultFormatError(f"{field}: expected an integer")
    if not (0 <= value <= 2**40):
        raise VaultFormatError(f"{field}: out of range")
    return value


class UnlockedVault:
    """An open vault. Holds the VEK in memory; wipe it by calling lock()."""

    def __init__(self, file: VaultFile, vek: Secret, contents: VaultContents):
        self.file = file
        self._vek = vek
        self.contents = contents

    @property
    def locked(self) -> bool:
        return self._vek.wiped

    def save(self, path: Path) -> None:
        if self.locked:
            raise CryptoFailure("vault is locked")
        self.file._seal(self._vek, self.contents)
        self.file.save(path)

    def lock(self) -> None:
        self._vek.wipe()

    def __enter__(self) -> "UnlockedVault":
        return self

    def __exit__(self, *exc) -> None:
        self.lock()
