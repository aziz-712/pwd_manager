"""Command line interface. Contains no cryptography -- it only calls into it.

Session model, stated plainly because it is a security decision:

  * One-shot commands (`add`, `list`, `get`, ...) derive the key, do one thing,
    and wipe it. Argon2id runs each time, which is deliberate friction.
  * `unlock` opens an interactive session that holds the VEK in one process's
    memory, with an idle timer. Closing it wipes the key.
  * There is no background agent holding keys between commands. An agent would
    be more convenient and would put a long-lived key in a process any other
    program running as the same user could attach to. See docs/NEXT_STEPS.md.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import threading
import time
from pathlib import Path

from . import __version__
from .crypto import (
    DEFAULT_MEM_BYTES,
    DEFAULT_OPS,
    CryptoFailure,
    KdfParams,
    benchmark_kdf,
    tune_kdf,
)
from .model import Entry, VaultContents
from .session import ClipboardUnavailable, IdleLock, clear as clipboard_clear, copy_with_timeout
from .state import Config, DeviceState, default_vault_path
from .syncclient import AuthRequired, Conflict, MfaRequired, SyncClient, SyncError
from .vault import RollbackDetected, UnlockedVault, VaultFile, VaultFormatError

MIN_PASSPHRASE_WORDS = 4


# --- terminal helpers ------------------------------------------------------


def err(msg: str) -> None:
    print(f"error: {msg}", file=sys.stderr)


def warn(msg: str) -> None:
    print(f"warning: {msg}", file=sys.stderr)


def interactive() -> bool:
    return sys.stdin.isatty()


def ask(label: str, provided: str | None, default: str = "") -> str:
    """A flag wins; otherwise prompt, but only when a human is actually there.

    Without the isatty check, running any of these commands from a script or a
    cron job hangs forever on a prompt nobody can see.
    """
    if provided is not None:
        return provided
    if not interactive():
        return default
    return input(f"{label}: ").strip()


def confirm(prompt: str, expect: str = "yes") -> bool:
    if not interactive():
        return False
    return input(f"{prompt} (type '{expect}' to continue): ").strip() == expect


def read_passphrase(prompt: str = "Master passphrase: ", confirm_prompt: str | None = None) -> str:
    """Reads from the terminal, never from argv (argv is world-readable in ps).

    ZKVAULT_PASSPHRASE exists so tests and CI can drive the CLI. It is not a
    supported way to use this tool: environment variables leak into child
    processes, crash dumps, and `ps e` on some systems.
    """
    env = os.environ.get("ZKVAULT_PASSPHRASE")
    if env:
        warn("using ZKVAULT_PASSPHRASE from the environment (test use only)")
        return env
    pw = getpass.getpass(prompt)
    if confirm_prompt:
        if pw != getpass.getpass(confirm_prompt):
            raise SystemExit("passphrases did not match")
    return pw


def vault_path(args: argparse.Namespace, cfg: Config) -> Path:
    return Path(args.vault).expanduser() if args.vault else Path(cfg.vault_path).expanduser()


def load_locked(path: Path) -> VaultFile:
    if not path.exists():
        raise SystemExit(f"no vault at {path} -- run 'zkvault init' first")
    return VaultFile.load(path)


def open_vault(args: argparse.Namespace, cfg: Config) -> tuple[UnlockedVault, Path]:
    """Load, check for rollback, unlock. The single entry point for every command."""
    path = vault_path(args, cfg)
    vf = load_locked(path)
    state = DeviceState.load()
    reason = state.check_not_rolled_back(vf.vault_id, vf.vault_version, vf.payload_seq)
    if reason:
        msg = (
            f"this vault is older than one this device has already seen ({reason}).\n"
            "That can mean a restored backup -- or a sync server serving you a stale\n"
            "vault to resurrect a password you deleted. Re-run with --allow-rollback\n"
            "only if you know why."
        )
        if not getattr(args, "allow_rollback", False):
            raise RollbackDetected(msg)
        warn("proceeding past a rollback warning at your request")
    unlocked = vf.unlock(read_passphrase())
    state.record(vf.vault_id, vf.vault_version, vf.payload_seq)
    return unlocked, path


def print_entries(entries: list[Entry], show_ids: bool = True) -> None:
    if not entries:
        print("(no entries)")
        return
    width = max(len(e.title) for e in entries)
    for e in sorted(entries, key=lambda x: x.title.lower()):
        prefix = f"{e.id[:8]}  " if show_ids else ""
        user = f"  {e.username}" if e.username else ""
        url = f"  {e.url}" if e.url else ""
        print(f"{prefix}{e.title.ljust(width)}{user}{url}")


def copy_secret(value: str, seconds: int) -> None:
    try:
        thread = copy_with_timeout(value, seconds)
    except ClipboardUnavailable as exc:
        err(f"clipboard unavailable ({exc}); not printing the secret")
        return
    print(f"copied to clipboard; clearing in {seconds}s (Ctrl-C to clear now)")
    try:
        thread.join()
        print("clipboard cleared")
    except KeyboardInterrupt:
        clipboard_clear(only_if_equals=value)
        print("\nclipboard cleared")


# --- commands --------------------------------------------------------------


def cmd_init(args: argparse.Namespace, cfg: Config) -> int:
    from .generator import passphrase as gen_passphrase, passphrase_entropy_bits

    path = vault_path(args, cfg)
    if path.exists() and not args.force:
        err(f"{path} already exists (use --force to overwrite, which destroys it)")
        return 1

    if args.tune:
        print("benchmarking Argon2id on this machine...")
        kdf = tune_kdf(target_seconds=args.tune)
    else:
        kdf = KdfParams.generate(ops_limit=args.kdf_ops, mem_limit_bytes=args.kdf_mem_mib * 1024 * 1024)
    print(
        f"KDF: Argon2id, {kdf.mem_limit_bytes // (1024*1024)} MiB, "
        f"{kdf.ops_limit} iterations (~{benchmark_kdf(kdf):.2f}s per unlock on this machine)"
    )

    suggestion = gen_passphrase(6)
    print(
        "\nYour master passphrase is the only thing protecting this vault.\n"
        "There is no reset, no recovery email, and no support line. If you forget\n"
        "it, the data is gone -- that is what makes the server unable to read it.\n"
        f"\nSuggested ({passphrase_entropy_bits(6):.0f} bits of entropy): {suggestion}\n"
    )
    pw = read_passphrase("Choose a master passphrase: ", "Confirm master passphrase: ")
    if len(pw.split()) < MIN_PASSPHRASE_WORDS and len(pw) < 20 and not args.force:
        err("that passphrase is too short; use at least 4 random words (--force to override)")
        return 1

    vf = VaultFile.create(pw, VaultContents(), kdf=kdf)
    vf.save(path)
    DeviceState.load().record(vf.vault_id, vf.vault_version, vf.payload_seq)
    cfg.vault_path = str(path)
    cfg.save()
    print(f"\ncreated {path} (vault id {vf.vault_id[:8]})")
    print("Back this file up. An encrypted vault you have lost is as gone as a forgotten passphrase.")
    return 0


def cmd_list(args: argparse.Namespace, cfg: Config) -> int:
    with open_vault(args, cfg)[0] as v:
        entries = v.contents.search(args.query) if args.query else v.contents.entries
        print_entries(entries)
    return 0


def cmd_get(args: argparse.Namespace, cfg: Config) -> int:
    with open_vault(args, cfg)[0] as v:
        entry = v.contents.get(args.entry)
        if entry is None:
            matches = v.contents.search(args.entry)
            if len(matches) != 1:
                err(f"no unique match for {args.entry!r}" + (f" ({len(matches)} candidates)" if matches else ""))
                return 1
            entry = matches[0]
        if args.show:
            print(json.dumps(entry.to_dict(), indent=2))
        else:
            print(json.dumps(entry.redacted(), indent=2))
            copy_secret(entry.password, cfg.clipboard_clear_seconds)
    return 0


def cmd_add(args: argparse.Namespace, cfg: Config) -> int:
    from .generator import password as gen_password, password_entropy_bits, strength_label

    unlocked, path = open_vault(args, cfg)
    with unlocked as v:
        title = args.title or ask("Title", None)
        if not title:
            err("a title is required")
            return 1
        username = ask("Username", args.username)
        url = ask("URL", args.url)

        if args.generate:
            secret = gen_password(length=args.length)
            bits = password_entropy_bits(args.length, 26 + 26 + 10 + 17)
            print(f"generated a {args.length}-character password ({bits:.0f} bits, {strength_label(bits)})")
        else:
            secret = read_passphrase("Password (blank to generate): ")
            if not secret:
                secret = gen_password(length=args.length)
                print(f"generated a {args.length}-character password")

        entry = Entry(title=title, username=username, url=url, password=secret, notes=args.notes or "")
        v.contents.add(entry)
        v.save(path)
        DeviceState.load().record(v.file.vault_id, v.file.vault_version, v.file.payload_seq)
        print(f"added {entry.title} ({entry.id[:8]})")
    return 0


def cmd_edit(args: argparse.Namespace, cfg: Config) -> int:
    from .generator import password as gen_password

    unlocked, path = open_vault(args, cfg)
    with unlocked as v:
        entry = v.contents.get(args.entry)
        if entry is None:
            err(f"no entry matching {args.entry!r}")
            return 1
        changed = False
        for field in ("title", "username", "url", "notes"):
            value = getattr(args, field)
            if value is not None:
                setattr(entry, field, value)
                changed = True
        if args.generate:
            entry.password = gen_password(length=args.length)
            changed = True
            print(f"regenerated a {args.length}-character password")
        elif args.password:
            new = read_passphrase("New password: ", "Confirm new password: ")
            entry.password = new
            changed = True
        if not changed:
            err("nothing to change; pass --title/--username/--url/--notes/--password/--generate")
            return 1
        entry.touch()
        v.save(path)
        DeviceState.load().record(v.file.vault_id, v.file.vault_version, v.file.payload_seq)
        print(f"updated {entry.title}")
    return 0


def cmd_rm(args: argparse.Namespace, cfg: Config) -> int:
    unlocked, path = open_vault(args, cfg)
    with unlocked as v:
        entry = v.contents.get(args.entry)
        if entry is None:
            err(f"no entry matching {args.entry!r}")
            return 1
        if not args.yes and not confirm(f"delete {entry.title!r}?"):
            print("cancelled")
            return 1
        v.contents.remove(entry.id)
        v.save(path)
        DeviceState.load().record(v.file.vault_id, v.file.vault_version, v.file.payload_seq)
        print(f"deleted {entry.title}")
    return 0


def cmd_gen(args: argparse.Namespace, cfg: Config) -> int:
    from .generator import (
        passphrase as gen_passphrase,
        passphrase_entropy_bits,
        password as gen_password,
        password_entropy_bits,
        strength_label,
    )

    if args.words:
        value = gen_passphrase(args.words)
        bits = passphrase_entropy_bits(args.words)
    else:
        value = gen_password(length=args.length, symbols=not args.no_symbols)
        bits = password_entropy_bits(args.length, 26 + 26 + 10 + (0 if args.no_symbols else 17))
    print(value)
    print(f"({bits:.0f} bits, {strength_label(bits)})", file=sys.stderr)
    if args.copy:
        copy_secret(value, cfg.clipboard_clear_seconds)
    return 0


def cmd_export(args: argparse.Namespace, cfg: Config) -> int:
    """Plaintext export exists because a password manager you cannot leave is a
    trap. It is guarded, loud, and writes 0600 -- but it does export in clear."""
    if args.format == "encrypted":
        src = vault_path(args, cfg)
        dest = Path(args.out).expanduser()
        dest.write_bytes(src.read_bytes())
        os.chmod(dest, 0o600)
        print(f"copied the encrypted vault to {dest} (still needs the passphrase to open)")
        return 0

    print(
        "This writes every password to disk in the clear.\n"
        "Anything that can read the file -- backup agents, cloud sync, another\n"
        "user on this machine -- gets all of them. Delete it when you are done."
    )
    if not args.yes and not confirm("continue?"):
        print("cancelled")
        return 1

    with open_vault(args, cfg)[0] as v:
        payload = {"exported_at": v.contents.updated_at, "entries": [e.to_dict() for e in v.contents.entries]}
        dest = Path(args.out).expanduser()
        fd = os.open(str(dest), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        print(f"exported {len(v.contents.entries)} entries to {dest} (mode 0600) -- IN THE CLEAR")
    return 0


def cmd_import(args: argparse.Namespace, cfg: Config) -> int:
    raw = json.loads(Path(args.file).expanduser().read_text(encoding="utf-8"))
    rows = raw.get("entries", raw) if isinstance(raw, dict) else raw
    if not isinstance(rows, list):
        err("expected a JSON list of entries, or an object with an 'entries' list")
        return 1
    unlocked, path = open_vault(args, cfg)
    with unlocked as v:
        for row in rows:
            if isinstance(row, dict) and row.get("title"):
                v.contents.add(Entry.from_dict(row))
        v.save(path)
        DeviceState.load().record(v.file.vault_id, v.file.vault_version, v.file.payload_seq)
        print(f"imported {len(rows)} entries; vault now holds {len(v.contents.entries)}")
    return 0


def cmd_passwd(args: argparse.Namespace, cfg: Config) -> int:
    path = vault_path(args, cfg)
    vf = load_locked(path)
    old = read_passphrase("Current master passphrase: ")
    new = read_passphrase("New master passphrase: ", "Confirm new master passphrase: ")
    if len(new.split()) < MIN_PASSPHRASE_WORDS and len(new) < 20 and not args.force:
        err("that passphrase is too short; use at least 4 random words (--force to override)")
        return 1
    vf.change_passphrase(old, new)
    vf.save(path)
    DeviceState.load().record(vf.vault_id, vf.vault_version, vf.payload_seq)
    print("passphrase changed (only the wrapped key was rewritten; entries were not re-encrypted)")
    if cfg.server_url:
        warn("run 'zkvault sync register' again or re-derive server credentials: the auth secret changed")
    return 0


def cmd_rotate_key(args: argparse.Namespace, cfg: Config) -> int:
    path = vault_path(args, cfg)
    vf = load_locked(path)
    vf.rotate_vek(read_passphrase())
    vf.save(path)
    DeviceState.load().record(vf.vault_id, vf.vault_version, vf.payload_seq)
    print("vault encryption key rotated and the payload re-encrypted under it")
    return 0


def cmd_benchmark(args: argparse.Namespace, cfg: Config) -> int:
    print(f"{'memory':>10} {'ops':>4} {'seconds':>8}")
    for mem_mib in (19, 64, 128, 256, 512):
        for ops in (2, 3, 4):
            params = KdfParams.generate(ops_limit=ops, mem_limit_bytes=mem_mib * 1024 * 1024)
            print(f"{mem_mib:>7} MiB {ops:>4} {benchmark_kdf(params):>8.2f}")
    print("\nPick the slowest setting you will tolerate on your *weakest* device;")
    print("the vault must open there too. 'zkvault init --tune 1.0' does this for you.")
    return 0


def cmd_lock(args: argparse.Namespace, cfg: Config) -> int:
    cleared = clipboard_clear()
    print("clipboard cleared" if cleared else "clipboard could not be cleared")
    print(
        "No key material persists between one-shot commands, so there is nothing\n"
        "else to lock. An interactive 'zkvault unlock' session locks on its own\n"
        "idle timer, or with 'lock' at its prompt."
    )
    return 0


# --- interactive session ---------------------------------------------------

SESSION_HELP = """\
  ls [query]        list entries (optionally filtered)
  get <entry>       show an entry and copy its password
  show <entry>      print an entry including the password
  add               add an entry
  edit <entry>      edit an entry
  rm <entry>        delete an entry
  gen [len]         generate a password
  save              write changes to disk
  sync              push/pull with the configured server
  lock / quit       wipe the key and exit
  help              this list\
"""


def cmd_unlock(args: argparse.Namespace, cfg: Config) -> int:
    from .generator import password as gen_password

    unlocked, path = open_vault(args, cfg)
    idle = IdleLock(cfg.auto_lock_seconds)
    dirty = False

    def watchdog() -> None:
        """Wipes the key and kills the process on idle.

        Hard exit is intentional: the main thread is usually blocked in input(),
        and there is no portable way to interrupt it. Unsaved changes are lost --
        which is the right trade when the alternative is a live key on an
        unattended screen.
        """
        while True:
            time.sleep(1)
            if unlocked.locked:
                return
            if idle.expired:
                unlocked.lock()
                print(f"\n\nauto-locked after {cfg.auto_lock_seconds}s idle", file=sys.stderr)
                clipboard_clear()
                os._exit(0)

    threading.Thread(target=watchdog, daemon=True, name="idle-lock").start()

    print(f"vault {path} unlocked; {len(unlocked.contents.entries)} entries. 'help' for commands.")
    print(f"auto-locks after {cfg.auto_lock_seconds}s of inactivity.")
    try:
        while True:
            try:
                line = input("zkvault> ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            idle.touch()
            if not line:
                continue
            cmd, _, rest = line.partition(" ")
            rest = rest.strip()
            try:
                if cmd in ("quit", "exit", "lock"):
                    break
                elif cmd == "help":
                    print(SESSION_HELP)
                elif cmd == "ls":
                    print_entries(unlocked.contents.search(rest) if rest else unlocked.contents.entries)
                elif cmd in ("get", "show"):
                    entry = unlocked.contents.get(rest)
                    if entry is None:
                        matches = unlocked.contents.search(rest)
                        entry = matches[0] if len(matches) == 1 else None
                    if entry is None:
                        err(f"no unique match for {rest!r}")
                        continue
                    print(json.dumps(entry.to_dict() if cmd == "show" else entry.redacted(), indent=2))
                    if cmd == "get":
                        copy_secret(entry.password, cfg.clipboard_clear_seconds)
                        idle.touch()
                elif cmd == "add":
                    title = input("Title: ").strip()
                    if not title:
                        err("a title is required")
                        continue
                    username = input("Username: ").strip()
                    url = input("URL: ").strip()
                    secret = getpass.getpass("Password (blank to generate): ") or gen_password()
                    unlocked.contents.add(Entry(title=title, username=username, url=url, password=secret))
                    dirty = True
                    print(f"added {title} (unsaved -- 'save' to write)")
                elif cmd == "edit":
                    entry = unlocked.contents.get(rest)
                    if entry is None:
                        err(f"no entry matching {rest!r}")
                        continue
                    new_title = input(f"Title [{entry.title}]: ").strip()
                    new_user = input(f"Username [{entry.username}]: ").strip()
                    new_pw = getpass.getpass("Password (blank to keep): ")
                    entry.title = new_title or entry.title
                    entry.username = new_user or entry.username
                    entry.password = new_pw or entry.password
                    entry.touch()
                    dirty = True
                    print("updated (unsaved)")
                elif cmd == "rm":
                    entry = unlocked.contents.get(rest)
                    if entry is None:
                        err(f"no entry matching {rest!r}")
                        continue
                    if confirm(f"delete {entry.title!r}?"):
                        unlocked.contents.remove(entry.id)
                        dirty = True
                        print("deleted (unsaved)")
                elif cmd == "gen":
                    length = int(rest) if rest.isdigit() else 20
                    print(gen_password(length=length))
                elif cmd == "save":
                    unlocked.save(path)
                    DeviceState.load().record(
                        unlocked.file.vault_id, unlocked.file.vault_version, unlocked.file.payload_seq
                    )
                    dirty = False
                    print(f"saved (version {unlocked.file.vault_version})")
                elif cmd == "sync":
                    if dirty:
                        err("save before syncing")
                        continue
                    _sync_push_pull(args, cfg, path)
                else:
                    err(f"unknown command {cmd!r}; try 'help'")
            except (CryptoFailure, VaultFormatError, SyncError, ValueError) as exc:
                err(str(exc))
            idle.touch()
    finally:
        if dirty and confirm("save changes before locking?"):
            unlocked.save(path)
            print("saved")
        unlocked.lock()
        clipboard_clear()
        print("locked")
    return 0


# --- sync ------------------------------------------------------------------


def _server_client(cfg: Config, args: argparse.Namespace) -> SyncClient:
    url = args.server or cfg.server_url
    if not url:
        raise SystemExit("no server configured; use 'zkvault sync setup --server URL --email YOU'")
    return SyncClient(url, verify_tls=not getattr(args, "insecure_skip_tls_verify", False))


def _login(client: SyncClient, cfg: Config, args: argparse.Namespace, passphrase: str, kdf) -> None:
    email = args.email or cfg.email
    if not email:
        raise SystemExit("no email configured; use 'zkvault sync setup'")
    try:
        client.login(email, passphrase, kdf)
    except MfaRequired as challenge:
        client.complete_mfa(challenge.mfa_token, input("Authenticator code: ").strip())


def _sync_push_pull(args: argparse.Namespace, cfg: Config, path: Path) -> None:
    """Push if we are ahead, pull if the server is. Never merges silently."""
    vf = VaultFile.load(path)
    passphrase = read_passphrase("Master passphrase (for server login): ")
    state = DeviceState.load()
    known_version = state.seen.get(vf.vault_id, {}).get("server_version", 0)
    with _server_client(cfg, args) as client:
        _login(client, cfg, args, passphrase, vf.kdf)
        meta = client.meta()
        server_version = int(meta["version"])
        if server_version > known_version:
            print(f"server has version {server_version} (this device last saw {known_version}); pulling")
            _pull_into(client, path, vf, passphrase, state)
            return
        new_version = client.upload(vf.to_bytes(), base_version=server_version)
        entry = state.seen.setdefault(vf.vault_id, {})
        entry["server_version"] = new_version
        state.save()
        print(f"pushed; server is now at version {new_version}")


def _pull_into(client: SyncClient, path: Path, local: VaultFile, passphrase: str, state: DeviceState) -> None:
    downloaded = client.download()
    if downloaded is None:
        print("server has no vault yet")
        return
    blob, server_version = downloaded
    remote = VaultFile.from_bytes(blob)  # strict parse before we trust anything
    if remote.vault_id != local.vault_id:
        raise SyncError(
            f"server vault id {remote.vault_id[:8]} does not match local {local.vault_id[:8]}; "
            "refusing to overwrite"
        )
    reason = state.check_not_rolled_back(remote.vault_id, remote.vault_version, remote.payload_seq)
    if reason:
        raise RollbackDetected(f"server served an older vault than we have seen ({reason})")
    remote.unlock(passphrase).lock()  # prove it decrypts before replacing local
    remote.save(path)
    state.record(remote.vault_id, remote.vault_version, remote.payload_seq)
    entry = state.seen.setdefault(remote.vault_id, {})
    entry["server_version"] = server_version
    state.save()
    print(f"pulled server version {server_version} into {path}")


def cmd_sync(args: argparse.Namespace, cfg: Config) -> int:
    path = vault_path(args, cfg)

    if args.action == "setup":
        if args.server:
            cfg.server_url = args.server
        if args.email:
            cfg.email = args.email
        cfg.save()
        print(f"sync configured: {cfg.email or '(no email)'} @ {cfg.server_url or '(no server)'}")
        return 0

    vf = load_locked(path)

    if args.action == "register":
        passphrase = read_passphrase()
        vf.unwrap_vek(passphrase).wipe()  # fail fast on a typo, before the network
        with _server_client(cfg, args) as client:
            user_id = client.register(args.email or cfg.email, passphrase, vf.kdf)
        print(f"registered (user {user_id[:8]}). The server received a derived auth secret,")
        print("your KDF salt, and nothing else. It cannot open your vault.")
        return 0

    if args.action == "status":
        passphrase = read_passphrase("Master passphrase (for server login): ")
        with _server_client(cfg, args) as client:
            _login(client, cfg, args, passphrase, vf.kdf)
            meta = client.meta()
        print(f"local:  vault_version={vf.vault_version} payload_seq={vf.payload_seq}")
        print(f"server: version={meta['version']} size={meta['size_bytes']}B updated={meta['updated_at']}")
        return 0

    if args.action == "audit":
        passphrase = read_passphrase("Master passphrase (for server login): ")
        with _server_client(cfg, args) as client:
            _login(client, cfg, args, passphrase, vf.kdf)
            for row in client.audit_log(args.limit):
                print(f"{row['created_at']}  {row['event']:<24} {row['ip'] or '-'}  {row['detail'] or ''}")
        return 0

    if args.action == "push":
        passphrase = read_passphrase("Master passphrase (for server login): ")
        state = DeviceState.load()
        with _server_client(cfg, args) as client:
            _login(client, cfg, args, passphrase, vf.kdf)
            base = int(client.meta()["version"]) if args.force else state.seen.get(vf.vault_id, {}).get("server_version", 0)
            try:
                version = client.upload(vf.to_bytes(), base_version=base)
            except Conflict as conflict:
                err(
                    f"{conflict}. Another device wrote first. Run 'zkvault sync pull',\n"
                    "reconcile, then push again. --force overwrites the server copy."
                )
                return 2
            entry = state.seen.setdefault(vf.vault_id, {})
            entry["server_version"] = version
            state.save()
            print(f"pushed; server is now at version {version}")
        return 0

    if args.action == "pull":
        passphrase = read_passphrase("Master passphrase (for server login): ")
        state = DeviceState.load()
        with _server_client(cfg, args) as client:
            _login(client, cfg, args, passphrase, vf.kdf)
            _pull_into(client, path, vf, passphrase, state)
        return 0

    err(f"unknown sync action {args.action!r}")
    return 1


# --- argument parsing ------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="zkvault", description="local-first, zero-knowledge password manager")
    p.add_argument("--version", action="version", version=f"zkvault {__version__}")
    p.add_argument("--vault", help="path to the vault file (default: from config)")
    p.add_argument("--allow-rollback", action="store_true", help="open a vault older than the last one seen")
    sub = p.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="create a new vault")
    init.add_argument("--force", action="store_true", help="overwrite an existing vault / weak passphrase")
    init.add_argument("--tune", type=float, metavar="SECONDS", help="benchmark KDF parameters to this cost")
    init.add_argument("--kdf-ops", type=int, default=DEFAULT_OPS)
    init.add_argument("--kdf-mem-mib", type=int, default=DEFAULT_MEM_BYTES // (1024 * 1024))
    init.set_defaults(func=cmd_init)

    unlock = sub.add_parser("unlock", help="open an interactive session")
    unlock.set_defaults(func=cmd_unlock)

    lock = sub.add_parser("lock", help="clear the clipboard and report session state")
    lock.set_defaults(func=cmd_lock)

    ls = sub.add_parser("list", help="list entries")
    ls.add_argument("query", nargs="?", default="")
    ls.set_defaults(func=cmd_list)

    get = sub.add_parser("get", help="show one entry and copy its password")
    get.add_argument("entry")
    get.add_argument("--show", action="store_true", help="print the password instead of copying it")
    get.set_defaults(func=cmd_get)

    add = sub.add_parser("add", help="add an entry")
    add.add_argument("title", nargs="?")
    add.add_argument("--username")
    add.add_argument("--url")
    add.add_argument("--notes")
    add.add_argument("--generate", action="store_true", help="generate the password")
    add.add_argument("--length", type=int, default=20)
    add.set_defaults(func=cmd_add)

    edit = sub.add_parser("edit", help="edit an entry")
    edit.add_argument("entry")
    edit.add_argument("--title")
    edit.add_argument("--username")
    edit.add_argument("--url")
    edit.add_argument("--notes")
    edit.add_argument("--password", action="store_true", help="prompt for a new password")
    edit.add_argument("--generate", action="store_true", help="generate a new password")
    edit.add_argument("--length", type=int, default=20)
    edit.set_defaults(func=cmd_edit)

    rm = sub.add_parser("rm", help="delete an entry")
    rm.add_argument("entry")
    rm.add_argument("--yes", action="store_true")
    rm.set_defaults(func=cmd_rm)

    gen = sub.add_parser("gen", help="generate a password or passphrase")
    gen.add_argument("--length", type=int, default=20)
    gen.add_argument("--words", type=int, help="generate a diceware passphrase instead")
    gen.add_argument("--no-symbols", action="store_true")
    gen.add_argument("--copy", action="store_true")
    gen.set_defaults(func=cmd_gen)

    export = sub.add_parser("export", help="export the vault")
    export.add_argument("out")
    export.add_argument("--format", choices=("json", "encrypted"), default="json")
    export.add_argument("--yes", action="store_true", help="skip the plaintext confirmation")
    export.set_defaults(func=cmd_export)

    imp = sub.add_parser("import", help="import entries from a JSON file")
    imp.add_argument("file")
    imp.set_defaults(func=cmd_import)

    passwd = sub.add_parser("passwd", help="change the master passphrase")
    passwd.add_argument("--force", action="store_true")
    passwd.set_defaults(func=cmd_passwd)

    rotate = sub.add_parser("rotate-key", help="rotate the vault encryption key")
    rotate.set_defaults(func=cmd_rotate_key)

    bench = sub.add_parser("benchmark", help="time Argon2id parameters on this machine")
    bench.set_defaults(func=cmd_benchmark)

    sync = sub.add_parser("sync", help="talk to a blind sync server")
    sync.add_argument("action", choices=("setup", "register", "push", "pull", "status", "audit"))
    sync.add_argument("--server")
    sync.add_argument("--email")
    sync.add_argument("--limit", type=int, default=20)
    sync.add_argument("--force", action="store_true", help="push over the server's version")
    sync.add_argument("--insecure-skip-tls-verify", action="store_true", help="testing only")
    sync.set_defaults(func=cmd_sync)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    cfg = Config.load()
    if not cfg.vault_path:
        cfg.vault_path = str(default_vault_path())
    try:
        return args.func(args, cfg)
    except RollbackDetected as exc:
        err(str(exc))
        return 3
    except (CryptoFailure, VaultFormatError) as exc:
        err(str(exc))
        return 4
    except (SyncError, AuthRequired) as exc:
        err(str(exc))
        return 5
    except KeyboardInterrupt:
        print()
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
