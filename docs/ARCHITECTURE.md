# zkvault — architecture and threat model

**Status:** v2 design, CLI + blind sync server implemented. Not yet independently
reviewed or penetration tested. See [NEXT_STEPS.md](NEXT_STEPS.md).

---

## 1. The claim, stated precisely

> The server stores an authenticated ciphertext blob and a hash of a derived
> authentication secret. It cannot decrypt the blob, cannot search it, cannot
> recover it, and cannot reset the passphrase that opens it.

Everything below exists to make that sentence true, and to be honest about where
it stops being true.

The corollary is not negotiable and is the price of the property: **a forgotten
master passphrase means the vault is gone.** There is no recovery email, no
support override, no escrow. A recovery path the server can execute is, by
definition, a decryption path the server can execute.

---

## 2. Components

| Component | Language | Role | Holds keys? |
|---|---|---|---|
| `zkvault/` | Python 3.11+ | Client core: crypto, vault format, CLI | Yes, in RAM while unlocked |
| `server/` | Python (FastAPI) | Blind sync: auth + opaque blob storage | Never |
| `kmp/` | Kotlin Multiplatform | Android/iOS/desktop client (skeleton) | Yes, via platform keystore |

The client core is layered so each boundary can be reviewed on its own:

```
cli.py          user interaction            (no crypto)
  |
vault.py        file format + key hierarchy  <-- the security-critical seam
  |          \
crypto.py     model.py                       (libsodium wrappers | plain data)
syncclient.py   network                      (ciphertext only)
```

`grep -rn "aead_\|derive_" zkvault/ --include=*.py | grep -v crypto.py` should
only ever match `vault.py`. That is the invariant a reviewer can check in one
command.

---

## 3. Key hierarchy

```
                      master passphrase  (>=4 random words; never stored, never sent)
                              |
                              |  Argon2id(salt, m=256 MiB, t=3, p=1)      <- tunable, in header
                              v
                        master key (32 B)                                 <- exists only in RAM
                         /            \
      BLAKE2b(key=mk,   /              \   BLAKE2b(key=mk,
        "zkvault/v1/   /                \   "zkvault/v1/server-auth")
             kek")    v                  v
                    KEK (32 B)        auth secret (32 B)  ──────────────► server
                       |                                    (server stores Argon2id(auth secret))
       XChaCha20-Poly1305 wrap
                       |
                       v
                    VEK (32 B, random)   <- wrapped into the vault header
                       |
       XChaCha20-Poly1305 encrypt
                       |
                       v
                 vault payload (all entries, padded)
```

### Why each hop exists

**Argon2id, not PBKDF2/bcrypt/scrypt-only.** The attacker's advantage in offline
cracking is hardware parallelism. Argon2id is memory-hard, which prices GPU and
ASIC attacks in RAM rather than in cheap cores, and its hybrid mode resists the
side-channel attacks that pure Argon2i and Argon2d each trade away. Defaults are
256 MiB / t=3 / p=1, well above the OWASP floor of 19 MiB / t=2 / p=1;
`zkvault init --tune 1.0` benchmarks the actual device instead of guessing.
Parameters travel in the header, so they can be raised later without a format
change — and `KdfParams.validate()` refuses anything below the floor, so a
tampered header cannot talk a client into a cheap KDF.

**A separate auth secret.** If the server were sent the passphrase (or anything
that decrypts the vault), a malicious or breached server would hold everything.
Instead it receives a BLAKE2b subkey under a distinct context string. Learning
the auth secret gives no information about the KEK: they are independent outputs
of a PRF keyed by the master key. The server then Argon2id-hashes even that, so a
database dump does not yield a usable login credential either.

**KEK wrapping a VEK, rather than encrypting entries directly with the KEK.**
Three concrete wins:
- *Passphrase change is O(32 bytes).* Re-wrap the VEK; the payload is untouched.
  Deriving the KEK for a 100 MB vault would otherwise mean re-encrypting all of
  it, on a phone, over a metered connection.
- *Key rotation is independent of the passphrase.* `rotate-key` draws a new VEK
  and re-encrypts, without asking the user to memorise anything new.
- *Device unlock without the passphrase.* Android Keystore can hold its own
  wrapping of the VEK behind a biometric prompt. The Keystore never sees the
  passphrase, and revoking a device is just discarding that wrapping.

**XChaCha20-Poly1305, not AES-GCM.** Both are fine AEADs; the deciding factor is
nonce management. AES-GCM's 96-bit nonce demands a counter, and a counter that a
backup restore or a sync conflict can rewind produces nonce reuse — which in GCM
leaks plaintext *and* the authentication key. XChaCha20's 192-bit nonce is safe
to draw at random every single time, so there is no counter to get wrong, no
state to persist, and no rollback to fear. It is also fast in constant time on
phones without AES hardware.

---

## 4. Data flows

### Local unlock

```
user types passphrase
   -> Argon2id (~1 s, 256 MiB)          [deliberate cost; the only rate limit
   -> master key                          an offline attacker ever faces]
   -> KEK, auth secret
   -> unwrap VEK from the header        [AEAD; fails on any header tampering]
   -> decrypt payload                   [AEAD; fails on any ciphertext tampering]
   -> entries in memory
   -> idle timer starts
```

On lock: the VEK buffer is zeroed and the clipboard is cleared.

### Sync (push)

```
client                                        server
  |-- POST /auth/login {email, auth secret} -->|  Argon2id verify, TOTP if enabled
  |<-- access (15 min) + refresh (rotating) ---|
  |-- GET /vault/meta ------------------------>|
  |<-- {version: N} ---------------------------|
  |-- PUT /vault {blob, base_version: N} ----->|  if stored.version != N -> 409
  |<-- {version: N+1} ------------------------|
```

Only three things ever leave the device: the derived auth secret, the public KDF
parameters, and the ciphertext blob. `syncclient.py` has no other outbound
payload, and `test_what_reaches_the_server_is_only_ciphertext` reads the stored
row back out of the database to prove it.

### Conflict handling

The first iteration stores one blob per user, and writes are optimistically
concurrent: the client sends the version it based its edit on, and a mismatch is
a `409` carrying the server's version. The client must pull, reconcile, and push
again.

Last-writer-wins was rejected. For this data type a silent overwrite means a
password added on a phone vanishes when a laptop syncs — and the user finds out
when they are locked out of something. A visible conflict is worse UX and better
engineering. Per-entry merge is designed in [NEXT_STEPS.md](NEXT_STEPS.md); doing
it first would have meant settling conflict semantics before the crypto.

---

## 5. Trust boundaries

```
+-------------------------------------------------------------+
|  TRUSTED: the unlocked client process                        |
|  passphrase, master key, KEK, VEK, plaintext entries         |
|  Compromise here = total compromise. No defence below helps. |
+-------------------------------------------------------------+
                   | ciphertext + auth secret
                   v
+-------------------------------------------------------------+
|  SEMI-TRUSTED: the local filesystem                          |
|  vault.zkv (0600), config, high-water state                  |
|  Assumed: readable by an attacker with disk access.          |
|  Assumed NOT: silently modifiable without detection (AEAD).  |
+-------------------------------------------------------------+
                   | TLS
                   v
+-------------------------------------------------------------+
|  UNTRUSTED: the sync server and everything between           |
|  Assumed: reads everything it stores, logs metadata, may be  |
|  hostile, breached, subpoenaed, or replaced.                 |
|  Must not be able to: decrypt, forge, or silently roll back. |
+-------------------------------------------------------------+
```

---

## 6. Threat model

### T1 — Server operator is malicious or breached *(primary threat)*

**Gets:** email addresses, KDF salts and parameters, ciphertext blobs, blob sizes
(bucketed), sync timestamps, IP addresses and user agents from the audit log,
day-granularity vault modification dates.

**Does not get:** any entry field, any URL, entry count, per-entry timestamps, or
anything that decrypts them. Cracking one vault means a full Argon2id search
against a ≥77-bit passphrase — per user, since salts are unique.

**Residual:** traffic analysis. Sync frequency and rough vault size are visible
and we do not hide them. A user in a threat model where "this person uses a
password manager, and edited it on Tuesday" is dangerous needs Tor or a
self-hosted server.

### T2 — Server serves a stale vault (rollback / resurrection)

A hostile server can replay an old, perfectly authentic vault to resurrect a
credential the user revoked, or to hide a newly added one. Cryptography alone
cannot detect this: the old file is genuine.

**Mitigation:** the client keeps a high-water mark per `vault_id` in
`state.json`, tracking both counters, and refuses to open anything lower without
`--allow-rollback`. `payload_seq` is bound into the payload's AAD, so a server
cannot relabel an old payload as new — it would have to forge Poly1305.

**Residual:** a fresh device has no history and will accept whatever it is given
first. Cross-device verification (comparing a short vault fingerprint over an
out-of-band channel) is future work.

### T3 — Network attacker

TLS is required; the client refuses plaintext HTTP to any non-loopback host. Even
without TLS, the blob is authenticated ciphertext and the auth secret is not the
passphrase — but the metadata leak and active stale-serving are reason enough to
refuse.

### T4 — Attacker with the vault file (stolen laptop, backup, cloud drive)

Reduces to offline cracking of Argon2id over the passphrase. At 256 MiB / t=3, a
six-word EFF passphrase (77.5 bits) is not attackable with any budget that
currently exists. A four-word passphrase (51.7 bits) is the documented floor and
is meaningfully weaker; the tool suggests six and warns below four.

### T5 — Malware on an unlocked device

**Out of scope, and stated as such rather than hand-waved.** Code running as the
user can read process memory, log keystrokes, and take the plaintext directly.
What we do is shrink the window: idle auto-lock, clipboard clearing with
read-back verification, zeroed key buffers, no background key-holding agent, and
no plaintext ever written to disk unless the user explicitly exports.

### T6 — Malicious vault file

Opening a vault from an untrusted source is an attack surface. The parser is
strict, size-capped, and typed at every field; every failure raises
`VaultFormatError` or `CryptoFailure` and never a bare `KeyError`. Tests mutate
and truncate real vaults thousands of times and assert nothing else escapes.
Notably, the v1 prototype used `pickle`, where opening a file *was* code
execution; v2 is JSON with no reflection anywhere.

### T7 — Supply chain

The client depends on PyNaCl (libsodium) and httpx; the server adds FastAPI,
SQLAlchemy, argon2-cffi, python-jose and pyotp. A backdoored dependency in the
*client* defeats everything, since it runs in the trusted zone. Mitigations:
pinned hashes in CI, a small dependency surface, reproducible builds, and no
runtime code loading. This is the strongest argument against a web client — see
[NEXT_STEPS.md](NEXT_STEPS.md) §4.

### T8 — Compromised client updates

Same trust zone as T7. Signed releases and, ideally, transparency-logged builds.
Unimplemented; tracked in NEXT_STEPS.

---

## 7. What the server can see, exactly

Everything in this list is a deliberate acceptance, not an oversight:

| Visible | Why it is not hidden |
|---|---|
| Email address | It is the account identifier and the MFA channel |
| KDF salt and parameters | A new device must derive the same keys; not secret |
| Blob size, bucketed by Padmé | Storage has to allocate something; padding caps the leak at ~12% |
| `vault_id` | Prevents cross-account blob confusion during sync |
| `vault_version`, `payload_seq` | Conflict detection and rollback defence |
| `modified_day` (day precision) | Enough to order syncs; too coarse to profile habits |
| IP, user agent, sync times | Needed for abuse defence and the user's own audit log |

**Not visible:** entry count, titles, usernames, URLs, passwords, notes, TOTP
seeds, custom fields, per-entry timestamps, folder structure.

---

## 8. Limits of in-process memory hygiene

`Secret` holds keys in a `bytearray` and zeroes it on lock. This is a real
reduction in exposure window and it is not a guarantee:

- CPython may have copied the value during `bytes()` conversions or interning.
- Pages can be swapped to disk before wiping (`mlock` is not used; PyNaCl exposes
  no portable binding for it here).
- A core dump, a hibernation image, or a debugger takes the whole heap.
- Python strings — the passphrase as typed — are immutable and cannot be wiped.

The mobile clients are the answer for anyone whose threat model includes this:
the VEK lives in hardware-backed storage and never enters app memory in the clear
on Android with StrongBox. Documented rather than papered over.

---

## 9. Why FastAPI, not Django

The service has four tables and no server-rendered UI. Django's admin, template
engine, sessions and CSRF machinery are precisely the parts you would disable
first — and an admin panel that can browse user rows is a liability for a service
whose entire value proposition is that operators cannot see anything useful.
FastAPI keeps the attack surface to the endpoints actually written here, and
Pydantic enforces strict validation at the boundary, which is worth more than any
battery Django includes. Flask would also have worked; FastAPI adds typed schemas
and generated OpenAPI for free, and the client is generated against it.

There is no CSRF protection because there are no cookies: authentication is a
`Authorization: Bearer` header, so a cross-site request cannot carry credentials.
A future browser client that switches to cookies must add CSRF tokens in the same
change — noted in the checklist.

---

## 10. Cryptographic decision log

| Decision | Chosen | Rejected | Reason |
|---|---|---|---|
| KDF | Argon2id, 256 MiB / t=3 | PBKDF2, bcrypt, scrypt | Memory-hard; hybrid side-channel resistance; OWASP-aligned |
| AEAD | XChaCha20-Poly1305 | AES-256-GCM | 192-bit random nonces remove the reuse class entirely |
| Nonces | Random, per message | Counter | Nothing to persist, nothing a restore can rewind |
| Subkeys | Keyed BLAKE2b, per-context | HKDF-SHA256 | Same guarantee; already in libsodium; no extra primitive |
| Encryption scope | Whole vault | Password fields only | Titles and URLs are the metadata that profiles a person |
| Padding | Padmé | None; fixed blocks | Bounded ~12% overhead, hides fine-grained growth |
| Server auth | Derived secret, Argon2id at rest | Passphrase over TLS | Server must never hold anything that decrypts |
| Sync unit | One blob | Per-record | Get the crypto right before the merge semantics |
| Conflicts | Optimistic, 409 | Last-writer-wins | Silent data loss is unacceptable for credentials |
| Recovery | None | Escrow, questions | Any server-side recovery is a server-side decryption path |
