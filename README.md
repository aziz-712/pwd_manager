# zkvault

A local-first, zero-knowledge password manager. Your vault is encrypted on your
device with a key derived from a passphrase that never leaves it; the server
stores an opaque blob it cannot read, search, or recover.

**Status:** the CLI and the sync server are implemented and tested. The Kotlin
Multiplatform client is a reviewed skeleton, not yet compiled. Nothing here has
had an external security review — see [docs/NEXT_STEPS.md](docs/NEXT_STEPS.md)
before trusting it with real credentials.

```
zkvault/     Python client: crypto, vault format, CLI
server/      FastAPI blind sync service
kmp/         Kotlin Multiplatform client (skeleton)
docs/        architecture, format spec, security checklist, roadmap
tests/       93 tests, including tamper, fuzz, rollback and conflict cases
legacy/      the v1 prototype, kept for reference and explicitly superseded
```

## The guarantee, and its price

The server never receives the master passphrase or anything that decrypts the
vault. It gets a derived authentication secret (which it Argon2id-hashes again),
your public KDF salt, and ciphertext.

**Which means: if you forget your passphrase, the vault is gone.** No reset link,
no support override, no escrow. A recovery path the server can execute is a
decryption path the server can execute.

## Quick start

```bash
make install                    # venv + dependencies
make test                       # the full suite

.venv/bin/python -m zkvault init            # create a vault (suggests a passphrase)
.venv/bin/python -m zkvault add GitHub --generate --username you@example.com
.venv/bin/python -m zkvault list
.venv/bin/python -m zkvault get GitHub      # copies the password, clears in 15s
.venv/bin/python -m zkvault unlock          # interactive session with idle auto-lock
```

Installed as a package, all of these are just `zkvault ...`.

### Sync

```bash
make serve                                  # dev server on 127.0.0.1:8000

zkvault sync setup --server https://vault.example.com --email you@example.com
zkvault sync register
zkvault sync push
zkvault sync pull
zkvault sync status
zkvault sync audit                          # your own login history
```

### Other commands

| Command | Does |
|---|---|
| `passwd` | Change the master passphrase (rewraps 48 bytes; the payload is untouched) |
| `rotate-key` | Draw a new vault key and re-encrypt, passphrase unchanged |
| `gen --words 6` | Diceware passphrase from the EFF long list (77.5 bits) |
| `benchmark` | Time Argon2id parameters on this machine |
| `export` / `import` | Leave, or arrive. Plaintext export is guarded and loud |
| `lock` | Clear the clipboard and report session state |

## How it works

```
master passphrase --Argon2id(256 MiB, t=3)--> master key
                                                |-- BLAKE2b --> KEK --wraps--> VEK --encrypts--> vault
                                                '-- BLAKE2b --> auth secret --> server
```

Encryption is XChaCha20-Poly1305 throughout, with random 192-bit nonces — chosen
over AES-GCM specifically because a 24-byte random nonce removes the nonce-reuse
failure mode that a backup restore or a sync conflict can otherwise cause.

The whole vault is encrypted, not just password fields: titles, usernames and
URLs are exactly the metadata that profiles a person. Ciphertext is Padmé-padded,
so blob size does not track entry count.

Full detail: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) ·
[docs/VAULT_FORMAT.md](docs/VAULT_FORMAT.md) ·
[docs/SECURITY_CHECKLIST.md](docs/SECURITY_CHECKLIST.md)

## What the server can see

Email address, KDF salt and parameters, bucketed blob size, sync times, IP and
user agent, and a day-precision modification date. **Not** entry count, titles,
usernames, URLs, passwords, notes, TOTP seeds, or per-entry timestamps.

## API docs

The sync server publishes an OpenAPI schema **in development only**:

```bash
make serve                 # then open the browser
```

| URL | What |
|---|---|
| `http://127.0.0.1:8000/docs` | Swagger UI. Register, log in, click **Authorize**, paste the access token, and drive the API by hand |
| `http://127.0.0.1:8000/redoc` | The same schema, laid out for reading |
| `http://127.0.0.1:8000/openapi.json` | The raw schema, for client generators |

`make openapi` writes the same schema to
[docs/openapi.json](docs/openapi.json) without a server running — useful for
diffing an API change in review.

All three URLs are switched off when `ZKVAULT_ENVIRONMENT` is `production`,
`prod` or `staging`: a published route map is free reconnaissance against a
service that is otherwise supposed to give an attacker nothing.

## Deploying the server

```bash
cp server/.env.example server/.env    # then fill in the two secrets it names
cd server && uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Behind TLS, always. The app refuses plaintext requests in production, and refuses
to boot without its signing secrets. Before real use, work through the blocking
items at the end of [docs/SECURITY_CHECKLIST.md](docs/SECURITY_CHECKLIST.md) —
in particular, replace the in-process rate limiter with a shared one and move off
SQLite.

## Security

No external review or penetration test yet. Do not use this for credentials you
cannot afford to lose until that has happened. Issues: please report privately
rather than opening a public issue.

The v1 prototype in `legacy/` bcrypt-*hashed* passwords (so they could never be
read back), stored them with `pickle` (loading a file was code execution), and
generated them with `random.choice` (predictable from a few hundred characters of
output). It is kept for reference and is not wired into anything.

## Licence

MIT — see `LISENCE.txt`.
