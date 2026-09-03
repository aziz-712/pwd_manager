"""Client configuration and the local anti-rollback high-water mark.

Nothing secret is stored here -- no keys, no tokens, no passphrase. The one
security-relevant field is the highest vault version this device has seen, which
is what lets us notice a sync server (or a restored backup) handing back an older
vault than the one we last wrote.
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


def home() -> Path:
    """ZKVAULT_HOME, else XDG config dir. Created 0700 on first use."""
    env = os.environ.get("ZKVAULT_HOME")
    if env:
        base = Path(env).expanduser()
    else:
        xdg = os.environ.get("XDG_CONFIG_HOME")
        base = (Path(xdg) if xdg else Path.home() / ".config") / "zkvault"
    base.mkdir(parents=True, exist_ok=True)
    os.chmod(base, stat.S_IRWXU)
    return base


def default_vault_path() -> Path:
    return home() / "vault.zkv"


def _write_private_json(path: Path, data: dict[str, Any]) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


@dataclass
class Config:
    vault_path: str = ""
    server_url: str = ""
    email: str = ""
    auto_lock_seconds: int = 300
    clipboard_clear_seconds: int = 15

    @staticmethod
    def path() -> Path:
        return home() / "config.json"

    @staticmethod
    def load() -> "Config":
        p = Config.path()
        if not p.exists():
            return Config(vault_path=str(default_vault_path()))
        try:
            raw = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return Config(vault_path=str(default_vault_path()))
        known = {f for f in Config.__dataclass_fields__}
        cfg = Config(**{k: v for k, v in raw.items() if k in known})
        if not cfg.vault_path:
            cfg.vault_path = str(default_vault_path())
        return cfg

    def save(self) -> None:
        _write_private_json(Config.path(), asdict(self))


@dataclass
class DeviceState:
    """Per-vault high-water marks, keyed by vault_id."""

    seen: dict[str, dict[str, int]] = field(default_factory=dict)

    @staticmethod
    def path() -> Path:
        return home() / "state.json"

    @staticmethod
    def load() -> "DeviceState":
        p = DeviceState.path()
        if not p.exists():
            return DeviceState()
        try:
            raw = json.loads(p.read_text(encoding="utf-8"))
            return DeviceState(seen=raw.get("seen", {}) if isinstance(raw, dict) else {})
        except Exception:
            return DeviceState()

    def save(self) -> None:
        _write_private_json(DeviceState.path(), {"seen": self.seen})

    def check_not_rolled_back(self, vault_id: str, vault_version: int, payload_seq: int) -> str | None:
        """Returns a human-readable reason if this vault looks older than what we
        have already accepted for this vault_id, else None.

        Both counters are checked: `vault_version` alone can be forged by anyone
        who can edit the file, but `payload_seq` is authenticated under the VEK,
        so an attacker who cannot decrypt cannot raise it.
        """
        prev = self.seen.get(vault_id)
        if not prev:
            return None
        if payload_seq < prev.get("payload_seq", 0):
            return (
                f"payload sequence went backwards: saw {prev['payload_seq']}, "
                f"this vault says {payload_seq}"
            )
        if vault_version < prev.get("vault_version", 0):
            return (
                f"vault version went backwards: saw {prev['vault_version']}, "
                f"this vault says {vault_version}"
            )
        return None

    def record(self, vault_id: str, vault_version: int, payload_seq: int) -> None:
        prev = self.seen.get(vault_id, {})
        self.seen[vault_id] = {
            "vault_version": max(vault_version, prev.get("vault_version", 0)),
            "payload_seq": max(payload_seq, prev.get("payload_seq", 0)),
        }
        self.save()
