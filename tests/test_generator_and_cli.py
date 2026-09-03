"""Generation quality, and the CLI paths a user actually walks."""

import json
import string
import subprocess
import sys
from pathlib import Path

import pytest

from zkvault import generator

ROOT = Path(__file__).resolve().parents[1]


def test_passphrase_words_are_drawn_independently():
    """A generator that repeats across calls, or within one, is a broken CSPRNG."""
    seen = {generator.passphrase(6) for _ in range(200)}
    assert len(seen) == 200


def test_passphrase_entropy_matches_the_wordlist():
    assert len(generator.load_wordlist()) == 7776
    assert generator.passphrase_entropy_bits(6) == pytest.approx(77.5, abs=0.1)


def test_short_passphrases_are_refused():
    with pytest.raises(ValueError):
        generator.passphrase(3)


def test_generated_passwords_cover_every_requested_class():
    for _ in range(50):
        pw = generator.password(length=20)
        assert len(pw) == 20
        assert any(c in string.ascii_lowercase for c in pw)
        assert any(c in string.ascii_uppercase for c in pw)
        assert any(c in string.digits for c in pw)
        assert any(c in generator.DEFAULT_SYMBOLS for c in pw)


def test_password_distribution_is_not_obviously_biased():
    """Not a statistical test of the CSPRNG -- a smoke test that we are not, say,
    fixing character classes to positions, which would halve real entropy."""
    firsts = {generator.password(length=12)[0] for _ in range(300)}
    assert len(firsts) > 30


def test_ambiguous_characters_can_be_excluded():
    pw = generator.password(length=40, avoid_ambiguous=True)
    assert not (set(pw) & set(generator.AMBIGUOUS))


def test_empty_alphabet_is_an_error():
    with pytest.raises(ValueError):
        generator.password(lowercase=False, uppercase=False, digits=False, symbols=False)


# --- CLI -------------------------------------------------------------------


@pytest.fixture
def cli(tmp_path, monkeypatch):
    home = tmp_path / "home"
    vault = home / "vault.zkv"
    env = {
        "ZKVAULT_HOME": str(home),
        "ZKVAULT_PASSPHRASE": "correct-horse-battery-staple-anvil-rope",
        "PATH": "/usr/bin:/bin",
    }

    def run(*args, expect_success=True, passphrase=None):
        proc = subprocess.run(
            [sys.executable, "-m", "zkvault", "--vault", str(vault), *args],
            cwd=ROOT, capture_output=True, text=True, timeout=120,
            env={**env, **({"ZKVAULT_PASSPHRASE": passphrase} if passphrase else {})},
            stdin=subprocess.DEVNULL,
        )
        if expect_success:
            assert proc.returncode == 0, f"{args} failed: {proc.stderr}"
        return proc

    run.vault = vault  # type: ignore[attr-defined]
    return run


def test_full_lifecycle(cli, tmp_path):
    cli("init", "--kdf-ops", "2", "--kdf-mem-mib", "19")
    assert cli.vault.exists() if hasattr(cli, "vault") else True

    cli("add", "GitHub", "--username", "me@example.com", "--url", "https://github.com", "--generate")
    cli("add", "Bank", "--username", "acct", "--generate", "--length", "32")

    listing = cli("list").stdout
    assert "GitHub" in listing and "Bank" in listing

    shown = json.loads(cli("get", "GitHub", "--show").stdout)
    assert shown["username"] == "me@example.com" and len(shown["password"]) == 20

    cli("edit", "GitHub", "--username", "new@example.com")
    assert "new@example.com" in cli("list").stdout

    out = tmp_path / "export.json"
    cli("export", str(out), "--yes")
    exported = json.loads(out.read_text())
    assert {e["title"] for e in exported["entries"]} == {"GitHub", "Bank"}
    assert oct(out.stat().st_mode & 0o777) == "0o600"

    cli("rm", "Bank", "--yes")
    assert "Bank" not in cli("list").stdout


def test_wrong_passphrase_exits_nonzero(cli):
    cli("init", "--kdf-ops", "2", "--kdf-mem-mib", "19")
    proc = cli("list", expect_success=False, passphrase="not-the-right-passphrase")
    assert proc.returncode == 4
    assert "wrong passphrase" in proc.stderr


def test_init_refuses_to_clobber_an_existing_vault(cli):
    cli("init", "--kdf-ops", "2", "--kdf-mem-mib", "19")
    proc = cli("init", "--kdf-ops", "2", "--kdf-mem-mib", "19", expect_success=False)
    assert proc.returncode == 1 and "already exists" in proc.stderr


def test_missing_vault_is_a_clear_error(cli):
    proc = cli("list", expect_success=False)
    assert "run 'zkvault init'" in (proc.stderr + proc.stdout)


def test_passphrase_change_keeps_entries_readable(cli):
    cli("init", "--kdf-ops", "2", "--kdf-mem-mib", "19")
    cli("add", "Example", "--username", "u", "--url", "", "--generate")
    # `passwd` needs two different passphrases, so drive it through the library.
    from zkvault.vault import VaultFile
    vf = VaultFile.load(cli.vault)
    vf.change_passphrase("correct-horse-battery-staple-anvil-rope", "a-brand-new-master-passphrase-x")
    vf.save(cli.vault)
    proc = cli("list", passphrase="a-brand-new-master-passphrase-x")
    assert "Example" in proc.stdout
