"""Lifetime of an unlocked vault: idle auto-lock and clipboard hygiene.

The threat here is mundane and real: an unattended terminal, and a clipboard that
still holds a banking password an hour later because some other app read it.
"""

from __future__ import annotations

import platform
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass


class ClipboardUnavailable(Exception):
    pass


def _clipboard_tools() -> tuple[list[str], list[str] | None]:
    """(copy_cmd, paste_cmd). paste is optional; without it we clear blindly."""
    system = platform.system()
    if system == "Darwin":
        return ["pbcopy"], ["pbpaste"]
    if system == "Windows":
        return ["clip"], None
    if shutil.which("wl-copy"):
        return ["wl-copy"], (["wl-paste", "-n"] if shutil.which("wl-paste") else None)
    if shutil.which("xclip"):
        return ["xclip", "-selection", "clipboard"], ["xclip", "-selection", "clipboard", "-o"]
    if shutil.which("xsel"):
        return ["xsel", "--clipboard", "--input"], ["xsel", "--clipboard", "--output"]
    raise ClipboardUnavailable("no clipboard tool found (install xclip, xsel or wl-clipboard)")


def copy(text: str) -> None:
    cmd, _ = _clipboard_tools()
    proc = subprocess.run(cmd, input=text.encode("utf-8"), check=False)
    if proc.returncode != 0:
        raise ClipboardUnavailable(f"{cmd[0]} exited {proc.returncode}")


def read() -> str | None:
    _, paste = _clipboard_tools()
    if paste is None:
        return None
    try:
        out = subprocess.run(paste, capture_output=True, check=False, timeout=5)
        return out.stdout.decode("utf-8", "replace")
    except Exception:
        return None


def clear(only_if_equals: str | None = None) -> bool:
    """Overwrite the clipboard, optionally only when it still holds our value.

    Clobbering whatever the user copied in the meantime is both rude and a way to
    lose their data, so we check first when the platform lets us read back.
    """
    if only_if_equals is not None:
        current = read()
        if current is not None and current.strip() != only_if_equals.strip():
            return False
    try:
        copy("")
        return True
    except ClipboardUnavailable:
        return False


def copy_with_timeout(text: str, seconds: int) -> threading.Thread:
    """Copy, then clear after `seconds` in a daemon thread.

    The caller must stay alive that long for the clear to happen -- the CLI's
    one-shot commands block on the returned thread and say so.
    """
    copy(text)

    def _clear_later() -> None:
        time.sleep(seconds)
        clear(only_if_equals=text)

    t = threading.Thread(target=_clear_later, daemon=True, name="clipboard-clear")
    t.start()
    return t


@dataclass
class IdleLock:
    """Wall-clock idle timer. `touch()` on every user action."""

    timeout_seconds: int
    last_activity: float = 0.0

    def __post_init__(self) -> None:
        self.touch()

    def touch(self) -> None:
        self.last_activity = time.monotonic()

    @property
    def expired(self) -> bool:
        if self.timeout_seconds <= 0:
            return False
        return (time.monotonic() - self.last_activity) >= self.timeout_seconds

    @property
    def remaining(self) -> float:
        return max(0.0, self.timeout_seconds - (time.monotonic() - self.last_activity))
