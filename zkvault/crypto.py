"""Cryptographic primitives.

Everything here is a thin, boring wrapper over libsodium (via PyNaCl). We add no
cryptographic construction of our own beyond domain-separated subkey derivation
with keyed BLAKE2b, which is libsodium's own KDF construction.

Choices, and why:

* Argon2id for password -> key. Memory-hard, side-channel resistant hybrid mode.
  Parameters live in the vault header so they can be raised later per device.
* XChaCha20-Poly1305-IETF for all encryption. 24-byte nonces mean random nonces
  are safe (collision probability is negligible), which removes the single most
  common catastrophic bug class in this kind of software: nonce reuse from a
  counter that gets rolled back by a restore/sync.
* Keyed BLAKE2b for subkey derivation, with a distinct ASCII context per subkey.
"""

from __future__ import annotations

import hmac
import time
from dataclasses import dataclass, replace
from typing import Final

import nacl.bindings as sodium
import nacl.hash
import nacl.pwhash
import nacl.utils
from nacl.encoding import RawEncoder
from nacl.exceptions import CryptoError

# --- algorithm identifiers, written into the vault header -------------------

KDF_ARGON2ID: Final = "argon2id"
AEAD_XCHACHA: Final = "xchacha20poly1305-ietf"

KEY_BYTES: Final = sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES      # 32
NONCE_BYTES: Final = sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES   # 24
TAG_BYTES: Final = sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES        # 16
SALT_BYTES: Final = nacl.pwhash.argon2id.SALTBYTES                         # 16

# Subkey contexts. Changing any of these string constants is a format break.
CTX_KEK: Final = b"zkvault/v1/kek"          # wraps the vault encryption key
CTX_AUTH: Final = b"zkvault/v1/server-auth"  # what the sync server may learn

# OWASP ASVS floor for Argon2id is 19 MiB / t=2 / p=1. We default well above it
# because a password vault is a high-value, offline-attackable target; `zkvault
# benchmark` lets a user tune this for the weakest device that must open it.
OWASP_MIN_MEM_BYTES: Final = 19 * 1024 * 1024
OWASP_MIN_OPS: Final = 2
DEFAULT_MEM_BYTES: Final = 256 * 1024 * 1024
DEFAULT_OPS: Final = 3


class CryptoFailure(Exception):
    """Decryption or authentication failed. Deliberately says nothing more."""


@dataclass(frozen=True)
class KdfParams:
    """Argon2id parameters. Public: they travel in the clear in the header."""

    salt: bytes
    ops_limit: int = DEFAULT_OPS
    mem_limit_bytes: int = DEFAULT_MEM_BYTES
    parallelism: int = 1  # libsodium's high-level Argon2id API fixes p=1
    key_length: int = KEY_BYTES
    algorithm: str = KDF_ARGON2ID

    @staticmethod
    def generate(**kw) -> "KdfParams":
        return KdfParams(salt=nacl.utils.random(SALT_BYTES), **kw)

    def validate(self) -> None:
        """Reject anything we cannot safely run.

        This is a downgrade guard: the header is attacker-reachable (it is stored
        on the sync server), so a tampered header must never talk us into a cheap
        KDF. The header is also AAD-bound to the ciphertext, so tampering breaks
        decryption anyway -- this check just fails earlier and louder.
        """
        if self.algorithm != KDF_ARGON2ID:
            raise CryptoFailure(f"unsupported KDF: {self.algorithm!r}")
        if len(self.salt) < 16 or len(self.salt) > 32:
            raise CryptoFailure("KDF salt must be 16-32 bytes")
        if len(self.salt) != SALT_BYTES:
            raise CryptoFailure(f"this libsodium build requires a {SALT_BYTES}-byte salt")
        if self.ops_limit < OWASP_MIN_OPS:
            raise CryptoFailure("KDF ops_limit below the OWASP floor (2)")
        if self.mem_limit_bytes < OWASP_MIN_MEM_BYTES:
            raise CryptoFailure("KDF mem_limit below the OWASP floor (19 MiB)")
        if self.mem_limit_bytes > 4 * 1024 * 1024 * 1024:
            raise CryptoFailure("KDF mem_limit implausibly large; refusing to allocate")
        if self.parallelism != 1:
            raise CryptoFailure("only parallelism=1 is supported by the libsodium API")
        if self.key_length != KEY_BYTES:
            raise CryptoFailure("key_length must be 32")


class Secret:
    """A key held in a mutable buffer so it can be overwritten on lock.

    CPython gives no guarantee that this is the only copy (the GC moves nothing,
    but `bytes(...)` conversions, swap, and core dumps are all outside our
    control). Wiping is a real reduction in exposure window, not a guarantee --
    see docs/ARCHITECTURE.md, "Limits of in-process memory hygiene".
    """

    __slots__ = ("_buf", "_wiped")

    def __init__(self, data: bytes | bytearray):
        self._buf = bytearray(data)
        self._wiped = False

    def __len__(self) -> int:
        return len(self._buf)

    @property
    def bytes(self) -> bytes:
        if self._wiped:
            raise CryptoFailure("use of a wiped secret")
        return bytes(self._buf)

    def wipe(self) -> None:
        for i in range(len(self._buf)):
            self._buf[i] = 0
        self._wiped = True

    @property
    def wiped(self) -> bool:
        return self._wiped

    def __enter__(self) -> "Secret":
        return self

    def __exit__(self, *exc) -> None:
        self.wipe()

    def __repr__(self) -> str:  # never leak key material into logs or tracebacks
        return f"<Secret {len(self._buf)}B {'wiped' if self._wiped else 'live'}>"

    __str__ = __repr__


def random_bytes(n: int) -> bytes:
    """CSPRNG bytes (libsodium's randombytes_buf -> the OS CSPRNG)."""
    return nacl.utils.random(n)


def new_key() -> Secret:
    return Secret(random_bytes(KEY_BYTES))


def new_nonce() -> bytes:
    """A fresh random 192-bit nonce.

    Random-per-message is the whole point of XChaCha20: with 24 bytes there is no
    counter to persist, so a vault restored from backup cannot reuse a nonce.
    """
    return random_bytes(NONCE_BYTES)


def derive_master_key(passphrase: str, params: KdfParams) -> Secret:
    """Argon2id: master passphrase -> 32-byte master key. Never leaves the device."""
    params.validate()
    raw = nacl.pwhash.argon2id.kdf(
        params.key_length,
        passphrase.encode("utf-8"),
        params.salt,
        opslimit=params.ops_limit,
        memlimit=params.mem_limit_bytes,
    )
    return Secret(raw)


def derive_subkey(master: Secret, context: bytes, length: int = KEY_BYTES) -> Secret:
    """Domain-separated subkey via keyed BLAKE2b.

    Distinct contexts guarantee that the value we hand the server (the auth
    secret) is computationally unrelated to the key that wraps the vault. Learning
    one tells an attacker nothing about the other.
    """
    return Secret(
        nacl.hash.blake2b(context, key=master.bytes, digest_size=length, encoder=RawEncoder)
    )


def aead_encrypt(key: Secret, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    """Returns (nonce, ciphertext||tag). A fresh random nonce every call."""
    nonce = new_nonce()
    ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, nonce, key.bytes)
    return nonce, ct


def aead_decrypt(key: Secret, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    """Authenticated decrypt. Any tampering (of ct *or* aad) raises CryptoFailure."""
    if len(nonce) != NONCE_BYTES:
        raise CryptoFailure("bad nonce length")
    if len(ciphertext) < TAG_BYTES:
        raise CryptoFailure("ciphertext shorter than the authentication tag")
    try:
        return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
            ciphertext, aad, nonce, key.bytes
        )
    except CryptoError as exc:  # wrong key, tampered data, or tampered header
        raise CryptoFailure("decryption failed: wrong passphrase or corrupted vault") from exc


def constant_time_eq(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)


def benchmark_kdf(params: KdfParams, passphrase: str = "benchmark-passphrase") -> float:
    """Wall-clock seconds for one derivation with these parameters."""
    started = time.perf_counter()
    derive_master_key(passphrase, params).wipe()
    return time.perf_counter() - started


def tune_kdf(target_seconds: float = 1.0, ceiling_mem_bytes: int = DEFAULT_MEM_BYTES) -> KdfParams:
    """Pick the largest parameters that stay under `target_seconds` on this box.

    Memory first (memory-hardness is what actually costs an attacker with GPUs),
    then iterations. Never returns anything below the OWASP floor.
    """
    best = KdfParams.generate(ops_limit=OWASP_MIN_OPS, mem_limit_bytes=OWASP_MIN_MEM_BYTES)
    mem = OWASP_MIN_MEM_BYTES
    while mem <= ceiling_mem_bytes:
        candidate = replace(best, mem_limit_bytes=mem)
        if benchmark_kdf(candidate) > target_seconds:
            break
        best, mem = candidate, mem * 2
    for ops in range(OWASP_MIN_OPS + 1, 8):
        candidate = replace(best, ops_limit=ops)
        if benchmark_kdf(candidate) > target_seconds:
            break
        best = candidate
    return best
