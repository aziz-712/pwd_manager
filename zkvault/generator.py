"""Password and passphrase generation. CSPRNG only -- never `random`.

`secrets` and libsodium's randombytes both draw from the OS CSPRNG. The module
`random` is a Mersenne Twister and is trivially predictable from its output; the
v1 prototype used it, which is one of the reasons v2 exists.
"""

from __future__ import annotations

import math
import secrets
import string
from pathlib import Path

WORDLIST_PATH = Path(__file__).parent / "data" / "eff_large_wordlist.txt"

AMBIGUOUS = "Il1O0|`'\"{}[]()/\\"
DEFAULT_SYMBOLS = "!@#$%^&*_-+=?.,:;"

_wordlist_cache: list[str] | None = None


def load_wordlist() -> list[str]:
    """EFF long wordlist (7776 words = 12.925 bits per word)."""
    global _wordlist_cache
    if _wordlist_cache is None:
        lines = WORDLIST_PATH.read_text(encoding="utf-8").splitlines()
        # Format is "11111\tabacus"; tolerate a plain one-word-per-line file too.
        words = [ln.split("\t")[-1].strip() for ln in lines if ln.strip()]
        if len(words) < 1024:
            raise RuntimeError(f"wordlist too small ({len(words)} words) to be safe")
        _wordlist_cache = words
    return _wordlist_cache


def passphrase(words: int = 6, separator: str = "-", capitalize: bool = False) -> str:
    """A diceware passphrase. Each word is an independent CSPRNG draw."""
    if words < 4:
        raise ValueError("a master passphrase needs at least 4 random words")
    wl = load_wordlist()
    chosen = [secrets.choice(wl) for _ in range(words)]
    if capitalize:
        chosen = [w.capitalize() for w in chosen]
    return separator.join(chosen)


def passphrase_entropy_bits(words: int, wordlist_size: int | None = None) -> float:
    size = wordlist_size if wordlist_size is not None else len(load_wordlist())
    return words * math.log2(size)


def password(
    length: int = 20,
    lowercase: bool = True,
    uppercase: bool = True,
    digits: bool = True,
    symbols: bool = True,
    avoid_ambiguous: bool = False,
) -> str:
    """A uniformly random password over the selected alphabet.

    Guaranteeing "one of each class" technically shrinks the space, but by a
    negligible amount at these lengths, and many sites still enforce it. We do it
    by rejection sampling rather than by placing characters at fixed positions,
    which would bias the output.
    """
    pools: list[str] = []
    if lowercase:
        pools.append(string.ascii_lowercase)
    if uppercase:
        pools.append(string.ascii_uppercase)
    if digits:
        pools.append(string.digits)
    if symbols:
        pools.append(DEFAULT_SYMBOLS)
    if not pools:
        raise ValueError("at least one character class must be enabled")
    if avoid_ambiguous:
        pools = ["".join(c for c in p if c not in AMBIGUOUS) for p in pools]
        pools = [p for p in pools if p]
    alphabet = "".join(pools)
    if length < len(pools):
        raise ValueError(f"length must be at least {len(pools)} to include every class")

    while True:
        candidate = "".join(secrets.choice(alphabet) for _ in range(length))
        if all(any(c in pool for c in candidate) for pool in pools):
            return candidate


def password_entropy_bits(length: int, alphabet_size: int) -> float:
    return length * math.log2(alphabet_size)


def strength_label(bits: float) -> str:
    if bits < 40:
        return "weak"
    if bits < 60:
        return "fair"
    if bits < 80:
        return "strong"
    return "very strong"
