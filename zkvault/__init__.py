"""zkvault - a local-first, zero-knowledge password manager client.

Layering (keep these boundaries; they are what makes the design auditable):

    crypto.py     primitives only (libsodium via PyNaCl). No file or CLI concerns.
    model.py      plaintext data model. No crypto.
    vault.py      vault file format: binds model <-> crypto, owns the key hierarchy.
    generator.py  CSPRNG password/passphrase generation.
    session.py    unlocked-state lifetime: idle lock, clipboard hygiene.
    syncclient.py talks to the blind sync server. Only ever sends ciphertext.
    cli.py        user interface. No crypto.
"""

__version__ = "2.0.0-dev"
FORMAT_NAME = "zkvault"
FORMAT_VERSION = 1
