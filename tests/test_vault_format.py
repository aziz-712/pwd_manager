"""Vault file format: roundtrip, tamper resistance, and malformed-input handling."""

import base64
import json
import os
import random

import pytest

from zkvault.crypto import CryptoFailure, KdfParams
from zkvault.model import Entry, VaultContents
from zkvault.state import DeviceState
from zkvault.vault import (
    MIN_PADDED_BYTES,
    VaultFile,
    VaultFormatError,
    derive_auth_secret,
    pad_payload,
    padme,
    unpad_payload,
)


def make_vault(passphrase, kdf, titles=("GitHub",)):
    contents = VaultContents()
    for t in titles:
        contents.add(Entry(title=t, username="u@example.com", password=f"pw-for-{t}"))
    return VaultFile.create(passphrase, contents, kdf=kdf)


def test_roundtrip_through_disk(vault_path, passphrase, kdf):
    make_vault(passphrase, kdf).save(vault_path)
    unlocked = VaultFile.load(vault_path).unlock(passphrase)
    assert [e.title for e in unlocked.contents.entries] == ["GitHub"]
    assert unlocked.contents.entries[0].password == "pw-for-GitHub"


def test_vault_file_is_owner_only(vault_path, passphrase, kdf):
    make_vault(passphrase, kdf).save(vault_path)
    assert oct(os.stat(vault_path).st_mode & 0o777) == "0o600"


def test_no_plaintext_leaks_into_the_file(vault_path, passphrase, kdf):
    contents = VaultContents()
    contents.add(Entry(title="MyBank", username="alice@example.com", password="hunter2",
                       url="https://bank.example", notes="account 12345"))
    VaultFile.create(passphrase, contents, kdf=kdf).save(vault_path)
    raw = vault_path.read_bytes()
    for secret in (b"MyBank", b"alice@example.com", b"hunter2", b"bank.example", b"12345",
                   passphrase.encode()):
        assert secret not in raw


def test_wrong_passphrase_is_rejected(vault_path, passphrase, kdf):
    make_vault(passphrase, kdf).save(vault_path)
    with pytest.raises(CryptoFailure):
        VaultFile.load(vault_path).unlock(passphrase + "x")


@pytest.mark.parametrize("field", ["payload.ciphertext", "payload.nonce", "wrapped_vek.ciphertext",
                                   "wrapped_vek.nonce", "kdf.salt"])
def test_bit_flips_are_detected(vault_path, passphrase, kdf, field):
    make_vault(passphrase, kdf).save(vault_path)
    doc = json.loads(vault_path.read_text())
    section, key = field.split(".")
    raw = bytearray(base64.b64decode(doc[section][key]))
    raw[0] ^= 0x01
    doc[section][key] = base64.b64encode(bytes(raw)).decode()
    with pytest.raises((CryptoFailure, VaultFormatError)):
        VaultFile.from_bytes(json.dumps(doc).encode()).unlock(passphrase)


def test_payload_sequence_cannot_be_forged(vault_path, passphrase, kdf):
    """Splicing an old payload under a bumped counter must fail.

    This is what stops a hostile server defeating the client's rollback check by
    relabelling an old vault as new.
    """
    make_vault(passphrase, kdf).save(vault_path)
    doc = json.loads(vault_path.read_text())
    doc["payload_seq"] += 5
    with pytest.raises(CryptoFailure):
        VaultFile.from_bytes(json.dumps(doc).encode()).unlock(passphrase)


def test_kdf_downgrade_is_refused_at_parse_time(vault_path, passphrase, kdf):
    make_vault(passphrase, kdf).save(vault_path)
    doc = json.loads(vault_path.read_text())
    doc["kdf"]["mem_limit_bytes"] = 1024
    doc["kdf"]["ops_limit"] = 1
    with pytest.raises(VaultFormatError):
        VaultFile.from_bytes(json.dumps(doc).encode())


def test_future_format_version_is_refused(vault_path, passphrase, kdf):
    make_vault(passphrase, kdf).save(vault_path)
    doc = json.loads(vault_path.read_text())
    doc["format_version"] = 99
    with pytest.raises(VaultFormatError, match="newer"):
        VaultFile.from_bytes(json.dumps(doc).encode())


def test_wrapped_key_from_another_vault_is_rejected(vault_path, passphrase, kdf):
    """Substituting an attacker's wrapped VEK yields a key that cannot open the
    payload, so the attack degrades to denial of service, not disclosure."""
    a = make_vault(passphrase, kdf)
    b = make_vault("a-different-master-passphrase-entirely", kdf)
    doc = json.loads(a.to_bytes())
    doc["wrapped_vek"] = json.loads(b.to_bytes())["wrapped_vek"]
    with pytest.raises(CryptoFailure):
        VaultFile.from_bytes(json.dumps(doc).encode()).unlock(passphrase)


def test_change_passphrase_does_not_touch_the_payload(vault_path, passphrase, kdf):
    vf = make_vault(passphrase, kdf)
    before_ct, before_seq = vf.payload_ct, vf.payload_seq
    vf.change_passphrase(passphrase, "an-entirely-new-master-passphrase", kdf=KdfParams.generate(
        ops_limit=2, mem_limit_bytes=19 * 1024 * 1024))
    assert vf.payload_ct == before_ct and vf.payload_seq == before_seq
    assert vf.vault_version > 1  # sync still sees a change
    with pytest.raises(CryptoFailure):
        vf.unlock(passphrase)
    assert vf.unlock("an-entirely-new-master-passphrase").contents.entries[0].title == "GitHub"


def test_rotate_vek_reencrypts_but_keeps_the_passphrase(vault_path, passphrase, kdf):
    vf = make_vault(passphrase, kdf)
    before = vf.payload_ct
    vf.rotate_vek(passphrase)
    assert vf.payload_ct != before
    assert vf.unlock(passphrase).contents.entries[0].password == "pw-for-GitHub"


def test_auth_secret_is_stable_and_not_the_passphrase(passphrase, kdf):
    secret = derive_auth_secret(passphrase, kdf)
    assert secret == derive_auth_secret(passphrase, kdf)
    assert len(base64.b64decode(secret)) == 32
    assert passphrase not in secret


# --- padding ---------------------------------------------------------------


def test_padding_hides_small_differences():
    assert padme(10) == MIN_PADDED_BYTES
    assert padme(MIN_PADDED_BYTES + 1) > MIN_PADDED_BYTES
    for n in (2000, 5000, 100_000):
        assert padme(n) >= n
        assert padme(n) <= n * 1.12 + MIN_PADDED_BYTES


def test_padding_roundtrips_exactly():
    for n in (0, 1, 100, 1023, 1024, 5000):
        data = os.urandom(n)
        assert unpad_payload(pad_payload(data)) == data


def test_vault_size_does_not_track_entry_count_closely(vault_path, passphrase, kdf):
    """One extra entry should usually not change the on-disk size at all."""
    sizes = []
    for count in (1, 2, 3):
        make_vault(passphrase, kdf, titles=[f"site{i}" for i in range(count)]).save(vault_path)
        sizes.append(vault_path.stat().st_size)
    assert len(set(sizes)) < 3


# --- malformed input (fuzz) ------------------------------------------------


def test_random_bytes_never_crash_the_parser():
    rng = random.Random(1337)
    for _ in range(500):
        blob = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 400)))
        with pytest.raises(VaultFormatError):
            VaultFile.from_bytes(blob)


def test_mutated_vaults_never_raise_unexpected_exceptions(vault_path, passphrase, kdf):
    """Every corruption must surface as VaultFormatError or CryptoFailure.

    A KeyError or a UnicodeDecodeError escaping here would mean the parser is
    reachable in an unintended state -- the shape of bug that turns "opens a file
    someone sent me" into a real problem.
    """
    make_vault(passphrase, kdf).save(vault_path)
    original = vault_path.read_bytes()
    rng = random.Random(42)
    for _ in range(400):
        data = bytearray(original)
        for _ in range(rng.randrange(1, 6)):
            data[rng.randrange(len(data))] = rng.randrange(256)
        try:
            VaultFile.from_bytes(bytes(data)).unlock(passphrase)
        except (VaultFormatError, CryptoFailure):
            pass


def test_truncation_at_every_offset_is_handled(vault_path, passphrase, kdf):
    make_vault(passphrase, kdf).save(vault_path)
    original = vault_path.read_bytes()
    for cut in range(0, len(original), 37):
        try:
            VaultFile.from_bytes(original[:cut]).unlock(passphrase)
        except (VaultFormatError, CryptoFailure):
            pass


@pytest.mark.parametrize("doc", [
    b"{}", b"[]", b'{"format":"zkvault"}', b'{"format":"other","format_version":1}',
    b'{"format":"zkvault","format_version":"1"}',
    b'{"format":"zkvault","format_version":1,"cipher":"aes-ecb"}',
    b'\x00\x01\x02', b'', b'{"format":"zkvault","format_version":1,"vault_id":123}',
])
def test_structurally_invalid_documents_are_rejected(doc):
    with pytest.raises(VaultFormatError):
        VaultFile.from_bytes(doc)


def test_oversized_input_is_refused_without_allocating():
    with pytest.raises(VaultFormatError, match="implausibly large"):
        VaultFile.from_bytes(b"x" * (64 * 1024 * 1024 + 1))


# --- rollback --------------------------------------------------------------


def test_device_state_detects_rollback(zk_home):
    state = DeviceState.load()
    state.record("vault-1", vault_version=7, payload_seq=5)
    assert state.check_not_rolled_back("vault-1", 7, 5) is None
    assert state.check_not_rolled_back("vault-1", 8, 6) is None
    assert "payload sequence" in state.check_not_rolled_back("vault-1", 8, 4)
    assert "vault version" in state.check_not_rolled_back("vault-1", 6, 5)
    assert state.check_not_rolled_back("unknown-vault", 1, 1) is None
