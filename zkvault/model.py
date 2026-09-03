"""Plaintext data model. Contains no crypto and no I/O.

Everything in this module lives *inside* the encrypted payload. The server never
sees any of it -- not titles, not URLs, not timestamps. That is deliberate: URLs
and per-entry timestamps are the metadata that would otherwise let a hostile
server profile a user without ever breaking the encryption.
"""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


def utcnow() -> str:
    """RFC 3339 timestamp, second precision (sub-second adds nothing but entropy)."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def new_id() -> str:
    return uuid.uuid4().hex


@dataclass
class Entry:
    title: str
    username: str = ""
    password: str = ""
    url: str = ""
    notes: str = ""
    totp_secret: str = ""
    custom_fields: dict[str, str] = field(default_factory=dict)
    id: str = field(default_factory=new_id)
    created_at: str = field(default_factory=utcnow)
    updated_at: str = field(default_factory=utcnow)

    def touch(self) -> None:
        self.updated_at = utcnow()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "Entry":
        known = {f for f in Entry.__dataclass_fields__}
        # Drop unknown keys rather than crashing: a newer client may have added
        # fields. We do *not* silently round-trip them -- see VaultContents.
        return Entry(**{k: v for k, v in d.items() if k in known})

    def redacted(self) -> dict[str, Any]:
        """Safe-to-display projection. Never includes password or TOTP seed."""
        d = self.to_dict()
        d["password"] = "********" if self.password else ""
        d["totp_secret"] = "set" if self.totp_secret else ""
        return d

    def matches(self, needle: str) -> bool:
        n = needle.lower()
        return any(n in (v or "").lower() for v in (self.title, self.username, self.url, self.notes))


@dataclass
class VaultContents:
    """The decrypted vault: entries plus the state needed for sync bookkeeping."""

    entries: list[Entry] = field(default_factory=list)
    schema_version: int = 1
    updated_at: str = field(default_factory=utcnow)

    # Fields written by a future, newer client. We keep them verbatim so that an
    # older client editing a vault does not destroy data it does not understand.
    _unknown: dict[str, Any] = field(default_factory=dict, repr=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._unknown,
            "schema_version": self.schema_version,
            "updated_at": self.updated_at,
            "entries": [e.to_dict() for e in self.entries],
        }

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "VaultContents":
        if not isinstance(d, dict):
            raise ValueError("vault payload is not an object")
        entries_raw = d.get("entries", [])
        if not isinstance(entries_raw, list):
            raise ValueError("vault payload 'entries' is not a list")
        known = {"entries", "schema_version", "updated_at"}
        return VaultContents(
            entries=[Entry.from_dict(e) for e in entries_raw],
            schema_version=int(d.get("schema_version", 1)),
            updated_at=str(d.get("updated_at", utcnow())),
            _unknown={k: v for k, v in d.items() if k not in known},
        )

    # --- entry operations ---------------------------------------------------

    def add(self, entry: Entry) -> Entry:
        self.entries.append(entry)
        self.updated_at = utcnow()
        return entry

    def get(self, entry_id_or_title: str) -> Entry | None:
        for e in self.entries:
            if e.id == entry_id_or_title:
                return e
        matches = [e for e in self.entries if e.title.lower() == entry_id_or_title.lower()]
        return matches[0] if len(matches) == 1 else None

    def search(self, needle: str) -> list[Entry]:
        return [e for e in self.entries if e.matches(needle)]

    def remove(self, entry_id: str) -> bool:
        before = len(self.entries)
        self.entries = [e for e in self.entries if e.id != entry_id]
        if len(self.entries) != before:
            self.updated_at = utcnow()
            return True
        return False
