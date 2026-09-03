"""Client and server together: what actually crosses the wire, and conflicts."""

import base64
import json
import os
import tempfile

import pytest

_DB = os.path.join(tempfile.mkdtemp(), "sync.db")
os.environ.update(
    ZKVAULT_DATABASE_URL=f"sqlite:///{_DB}",
    ZKVAULT_ENVIRONMENT="test",
    ZKVAULT_JWT_SECRET="test-jwt-secret-not-for-production",
    ZKVAULT_ENUMERATION_SECRET="test-enumeration-secret",
    ZKVAULT_SERVER_ARGON2_MEMORY_KIB="8192",
    ZKVAULT_SERVER_ARGON2_TIME_COST="1",
)

import threading  # noqa: E402
import time  # noqa: E402

import uvicorn  # noqa: E402

from app.db import Base, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.ratelimit import limiter  # noqa: E402
from zkvault.model import Entry, VaultContents  # noqa: E402
from zkvault.syncclient import Conflict, SyncClient, SyncError  # noqa: E402
from zkvault.vault import VaultFile  # noqa: E402

EMAIL = "sync-user@example.com"


@pytest.fixture(scope="session")
def live_server():
    """A real uvicorn process-in-a-thread.

    The client speaks HTTP for real here rather than through an in-process test
    shim, so header handling, status codes and the 409 body are exercised the way
    a deployed client would meet them.
    """
    config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 15
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.05)
    assert server.started, "test server did not start"
    port = server.servers[0].sockets[0].getsockname()[1]
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(timeout=10)


@pytest.fixture
def sync_client(live_server):
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    limiter.reset()
    with SyncClient(live_server) as c:
        yield c


@pytest.fixture
def second_client(live_server):
    """A second device: same account, independent client state."""
    with SyncClient(live_server) as c:
        yield c


def build_vault(passphrase, kdf, titles=("GitHub",)):
    contents = VaultContents()
    for t in titles:
        contents.add(Entry(title=t, password=f"pw-{t}"))
    return VaultFile.create(passphrase, contents, kdf=kdf)


def test_register_login_push_pull(sync_client, passphrase, kdf, tmp_path):
    vf = build_vault(passphrase, kdf)
    sync_client.register(EMAIL, passphrase, kdf)
    sync_client.login(EMAIL, passphrase, kdf)
    assert sync_client.download() is None
    version = sync_client.upload(vf.to_bytes(), base_version=0)
    assert version == 1

    blob, server_version = sync_client.download()
    assert server_version == 1
    restored = VaultFile.from_bytes(blob).unlock(passphrase)
    assert [e.title for e in restored.contents.entries] == ["GitHub"]


def test_a_second_device_can_derive_its_keys_from_public_params(sync_client, second_client, passphrase, kdf):
    """The whole multi-device story: salt from the server, keys from the head."""
    sync_client.register(EMAIL, passphrase, kdf)
    sync_client.login(EMAIL, passphrase, kdf)
    sync_client.upload(build_vault(passphrase, kdf).to_bytes(), base_version=0)

    fetched = second_client.fetch_kdf_params(EMAIL)
    assert fetched.salt == kdf.salt and fetched.ops_limit == kdf.ops_limit
    second_client.login(EMAIL, passphrase, fetched)
    blob, _ = second_client.download()
    assert VaultFile.from_bytes(blob).unlock(passphrase).contents.entries[0].password == "pw-GitHub"


def test_wrong_passphrase_cannot_log_in(sync_client, passphrase, kdf):
    sync_client.register(EMAIL, passphrase, kdf)
    with pytest.raises(SyncError):
        sync_client.login(EMAIL, passphrase + "typo", kdf)


def test_concurrent_edits_conflict_rather_than_overwrite(sync_client, second_client, passphrase, kdf):
    """Two devices, both editing from version 1. The second push must be refused
    -- last-writer-wins here means one device's new password disappears."""
    vf = build_vault(passphrase, kdf)
    sync_client.register(EMAIL, passphrase, kdf)
    sync_client.login(EMAIL, passphrase, kdf)
    sync_client.upload(vf.to_bytes(), base_version=0)
    second_client.login(EMAIL, passphrase, kdf)

    device_a = VaultFile.from_bytes(sync_client.download()[0])
    device_b = VaultFile.from_bytes(second_client.download()[0])

    a = device_a.unlock(passphrase)
    a.contents.add(Entry(title="Added on A", password="a"))
    a.file._seal(a._vek, a.contents)
    assert sync_client.upload(a.file.to_bytes(), base_version=1) == 2

    b = device_b.unlock(passphrase)
    b.contents.add(Entry(title="Added on B", password="b"))
    b.file._seal(b._vek, b.contents)
    with pytest.raises(Conflict) as raised:
        second_client.upload(b.file.to_bytes(), base_version=1)
    assert raised.value.server_version == 2

    # After pulling, B can rebase its change and push cleanly.
    merged = VaultFile.from_bytes(second_client.download()[0]).unlock(passphrase)
    merged.contents.add(Entry(title="Added on B", password="b"))
    merged.file._seal(merged._vek, merged.contents)
    assert second_client.upload(merged.file.to_bytes(), base_version=2) == 3
    final = VaultFile.from_bytes(sync_client.download()[0]).unlock(passphrase)
    assert {e.title for e in final.contents.entries} == {"GitHub", "Added on A", "Added on B"}


def test_what_reaches_the_server_is_only_ciphertext(sync_client, passphrase, kdf):
    """Read the stored row directly and confirm no plaintext is recoverable."""
    contents = VaultContents()
    contents.add(Entry(title="MyBank", username="alice@example.com", password="hunter2",
                       url="https://bank.example", notes="sort code 00-00-00"))
    vf = VaultFile.create(passphrase, contents, kdf=kdf)
    sync_client.register(EMAIL, passphrase, kdf)
    sync_client.login(EMAIL, passphrase, kdf)
    sync_client.upload(vf.to_bytes(), base_version=0)

    from app.db import SessionLocal
    from app.models import VaultBlob
    with SessionLocal() as db:
        stored = db.query(VaultBlob).first().blob

    for secret in (b"MyBank", b"alice@example.com", b"hunter2", b"bank.example",
                   b"00-00-00", passphrase.encode()):
        assert secret not in stored

    # What IS visible: the format header. This is the metadata we accept leaking.
    header = json.loads(stored)
    assert set(header) == {"format", "format_version", "vault_id", "cipher", "kdf",
                           "wrapped_vek", "vault_version", "payload_seq", "modified_day", "payload"}
    assert header["modified_day"].count("-") == 2  # day precision, not a timestamp


def test_the_server_cannot_open_a_vault_it_stores(sync_client, passphrase, kdf):
    sync_client.register(EMAIL, passphrase, kdf)
    sync_client.login(EMAIL, passphrase, kdf)
    sync_client.upload(build_vault(passphrase, kdf).to_bytes(), base_version=0)
    blob, _ = sync_client.download()

    # Everything the server holds about this user, tried as a key.
    from app.db import SessionLocal
    from app.models import User
    with SessionLocal() as db:
        user = db.query(User).first()
        server_knowledge = [user.auth_hash, user.kdf_salt, user.email, user.id]

    from zkvault.crypto import CryptoFailure
    for candidate in server_knowledge:
        with pytest.raises(CryptoFailure):
            VaultFile.from_bytes(blob).unlock(candidate)


def test_plaintext_http_to_a_remote_host_is_refused():
    with pytest.raises(SyncError, match="plaintext"):
        SyncClient("http://vault.example.com")
    SyncClient("http://localhost:8000").close()  # local development is allowed
