"""Primitive-level properties. If any of these break, nothing above matters."""

import pytest

from zkvault.crypto import (
    CTX_AUTH,
    CTX_KEK,
    CryptoFailure,
    KdfParams,
    Secret,
    aead_decrypt,
    aead_encrypt,
    derive_master_key,
    derive_subkey,
    new_key,
    new_nonce,
    random_bytes,
)


def test_kdf_is_deterministic_for_the_same_salt(kdf, passphrase):
    a = derive_master_key(passphrase, kdf).bytes
    b = derive_master_key(passphrase, kdf).bytes
    assert a == b


def test_kdf_output_changes_with_the_salt(passphrase):
    p1 = KdfParams.generate(ops_limit=2, mem_limit_bytes=19 * 1024 * 1024)
    p2 = KdfParams.generate(ops_limit=2, mem_limit_bytes=19 * 1024 * 1024)
    assert p1.salt != p2.salt
    assert derive_master_key(passphrase, p1).bytes != derive_master_key(passphrase, p2).bytes


def test_subkeys_are_independent(kdf, passphrase):
    """The value handed to the server must reveal nothing about the vault key."""
    master = derive_master_key(passphrase, kdf)
    kek = derive_subkey(master, CTX_KEK).bytes
    auth = derive_subkey(master, CTX_AUTH).bytes
    assert kek != auth
    assert len(set(kek) & set(auth)) < 32  # sanity: not a trivial transform


@pytest.mark.parametrize(
    "bad",
    [
        {"ops_limit": 1},
        {"mem_limit_bytes": 8 * 1024 * 1024},
        {"algorithm": "sha256"},
        {"parallelism": 4},
        {"key_length": 16},
    ],
)
def test_weak_kdf_parameters_are_rejected(bad):
    params = KdfParams.generate(**{**{"ops_limit": 2, "mem_limit_bytes": 19 * 1024 * 1024}, **bad})
    with pytest.raises(CryptoFailure):
        params.validate()


def test_nonces_do_not_repeat():
    nonces = {new_nonce() for _ in range(2000)}
    assert len(nonces) == 2000


def test_aead_roundtrip_and_tamper_detection():
    key = new_key()
    nonce, ct = aead_encrypt(key, b"plaintext", b"header")
    assert aead_decrypt(key, nonce, ct, b"header") == b"plaintext"

    with pytest.raises(CryptoFailure):  # tampered associated data
        aead_decrypt(key, nonce, ct, b"header!")
    with pytest.raises(CryptoFailure):  # tampered ciphertext
        flipped = bytearray(ct)
        flipped[0] ^= 0x01
        aead_decrypt(key, nonce, bytes(flipped), b"header")
    with pytest.raises(CryptoFailure):  # wrong key
        aead_decrypt(new_key(), nonce, ct, b"header")
    with pytest.raises(CryptoFailure):  # truncated below the tag
        aead_decrypt(key, nonce, ct[:8], b"header")
    with pytest.raises(CryptoFailure):  # wrong nonce length
        aead_decrypt(key, nonce[:12], ct, b"header")


def test_same_plaintext_encrypts_differently_each_time():
    key = new_key()
    n1, c1 = aead_encrypt(key, b"same", b"")
    n2, c2 = aead_encrypt(key, b"same", b"")
    assert n1 != n2 and c1 != c2


def test_secret_wipe_blocks_reuse():
    s = Secret(random_bytes(32))
    s.wipe()
    assert s.wiped
    with pytest.raises(CryptoFailure):
        _ = s.bytes


def test_secret_never_prints_key_material():
    raw = random_bytes(32)
    s = Secret(raw)
    assert raw.hex() not in repr(s) and raw.hex() not in str(s)
