# Security checklist

Aligned to **OWASP ASVS 4.0.3** (server and client), **OWASP MASVS 2.x /
MASTG** (mobile), and this design's own invariants.

Status is honest, not aspirational:
**[x] implemented and tested** · **[~] partial, gap noted** · **[ ] not built yet**

---

## 1. Cryptographic design (ASVS V6, V2.4–2.9)

- [x] **V6.2.1** No custom primitives. libsodium (PyNaCl) only; no hand-rolled modes.
- [x] **V6.2.2** All secrets from a CSPRNG (`randombytes`, `secrets`). No `random` anywhere in the client.
- [x] **V2.4.1** Argon2id for password-based derivation, 256 MiB / t=3 / p=1 by default — above the OWASP floor of 19 MiB / t=2 / p=1.
- [x] **V2.4.5** Unique 16-byte CSPRNG salt per vault; a new salt on every passphrase change.
- [x] **V6.2.3** Authenticated encryption everywhere (XChaCha20-Poly1305). No unauthenticated ciphertext exists in the format.
- [x] **V6.2.4** Nonces are 192-bit random, fresh per message. No counters, so no rollback-induced reuse. Tested for collisions.
- [x] **V6.2.5** Algorithm, KDF parameters, salt, nonce and version are recorded in every record and authenticated as AAD.
- [x] Domain-separated subkeys (keyed BLAKE2b with distinct contexts) for the KEK and the server auth secret.
- [x] KEK/VEK hierarchy: passphrase change re-wraps 48 bytes; the VEK rotates independently.
- [x] KDF downgrade is refused at parse time, before memory is allocated.
- [x] Whole-vault encryption, not field-level. Titles, URLs and timestamps are inside the ciphertext.
- [x] Padmé padding, 1024-byte floor, so blob size does not track entry count.
- [ ] Whole-file signature (would close the header-substitution DoS in VAULT_FORMAT §3).
- [ ] Formal cryptographic review by an external party.

## 2. Key and memory handling (ASVS V6.4, V2.9)

- [x] Keys held in mutable buffers and zeroed on lock (`Secret.wipe`).
- [x] `Secret.__repr__` never renders key bytes, so tracebacks and logs stay clean.
- [x] No key material is written to disk, ever. No key cache, no session file.
- [x] No background agent holds keys between one-shot commands — a deliberate convenience/exposure trade, documented.
- [~] Python cannot guarantee single-copy memory: strings are immutable, pages may swap, core dumps take everything. Bounded, not solved — see ARCHITECTURE §8. The mobile clients address it with hardware keystores.
- [ ] `mlock`/`madvise(MADV_DONTDUMP)` for key pages (needs a libsodium binding not exposed by PyNaCl).

## 3. Vault file handling (ASVS V5, V12)

- [x] Strict typed parsing; every failure is `VaultFormatError` or `CryptoFailure`, never a bare exception.
- [x] Size caps on the file (64 MiB) and payload (32 MiB) before allocation.
- [x] Fuzzed: ~900 mutated and truncated real vaults per run, plus random bytes; no unexpected exception escapes.
- [x] Atomic writes: temp file → `fsync` → `rename` → directory `fsync`.
- [x] Vault, config, state and exports all created `0600`; config directory `0700`.
- [x] No `pickle`, `eval`, or any reflective deserialisation (the v1 prototype's worst flaw).
- [x] Anti-rollback high-water mark per vault, checking both counters.
- [ ] Coverage-guided fuzzing in CI (Atheris/libFuzzer) rather than the current property tests.

## 4. Authentication (ASVS V2)

- [x] **V2.1.7** The master passphrase never reaches the server; only a BLAKE2b-derived secret does.
- [x] Server stores Argon2id(auth secret) — a database dump yields no usable credential.
- [x] **V2.2.1** Rate limiting on all auth endpoints (10/min/IP by default).
- [x] **V2.2.3** Identical response and timing for "unknown account" and "wrong secret" (`burn_time`).
- [x] User-enumeration resistance on `/auth/kdf-params` via deterministic HMAC decoys.
- [x] TOTP MFA for sync access, with a separate typed challenge token that cannot be used as an access token (tested).
- [x] **V2.10** No password recovery, no security questions, no escrow. By design.
- [x] Request validation rejects an `auth_secret` that is not exactly 32 bytes — a client bug that POSTed the real passphrase fails closed.
- [~] Rate limiting is in-process; behind multiple workers it under-counts. **Replace with Redis before production.**
- [ ] WebAuthn / passkeys as a second factor.
- [ ] Device-level revocation list.

## 5. Session and token management (ASVS V3)

- [x] **V3.2** Short-lived access tokens (15 min) and rotating refresh tokens.
- [x] **V3.3.1** Refresh reuse detection revokes the whole token family (tested).
- [x] Refresh tokens are random 256-bit values stored hashed — revocation is a database fact, not a claim.
- [x] Token type (`access` / `mfa`) is checked on every decode.
- [x] Logout revokes every refresh token for the user.
- [x] `Cache-Control: no-store` on all responses.
- [~] Access tokens are not individually revocable; the 15-minute TTL is the mitigation, and is why it is short.
- [ ] Key rotation for the JWT signing secret (needs `kid` and a key ring).

## 6. Transport and headers (ASVS V9, V14.4)

- [x] Client refuses plaintext HTTP to any non-loopback host.
- [x] Server refuses plaintext requests in production rather than redirecting (a redirect still leaks the first request).
- [x] HSTS with `includeSubDomains; preload` in production.
- [x] `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Content-Security-Policy: default-src 'none'`, `Cross-Origin-Resource-Policy`.
- [x] CORS defaults to disabled; explicit origins only, never a wildcard with credentials.
- [x] No cookies, so no CSRF surface. **A future browser client that adopts cookies must add CSRF tokens in the same change.**
- [ ] TLS certificate pinning in the mobile clients.

## 7. Server-side data handling (ASVS V4, V8)

- [x] The server never parses vault contents; no import of the client format exists in `server/`.
- [x] Per-user authorisation on every vault route; cross-user reads tested and refused.
- [x] Optimistic concurrency (`base_version` + `If-Match`); conflicts are `409`, never a silent overwrite.
- [x] Blob size cap (16 MiB) enforced after decode.
- [x] Vault deletion requires explicit confirmation and is irreversible.
- [x] Parameterised queries throughout (SQLAlchemy ORM); no string-built SQL.
- [ ] Per-user storage quotas and abuse throttling.
- [ ] Encryption at rest for the database (defence in depth; the blob is already ciphertext).

## 8. Logging and monitoring (ASVS V7)

- [x] **V7.1.1** Request bodies are never logged. Query strings are not logged.
- [x] Audit events record metadata only (event, user id, IP, user agent, short detail); tested that ciphertext markers never appear.
- [x] Correlation IDs (`X-Request-ID`) on every request and response.
- [x] Security-relevant events logged at WARNING: failed logins, MFA failures, refresh reuse, conflicts, deletions.
- [x] Users can read their own audit log — unexplained logins are what a victim needs to see early.
- [ ] Alerting on the security events (currently logged, not routed anywhere).
- [ ] Log retention and deletion policy.

## 9. Client application security

- [x] Passphrases read via `getpass`, never from `argv` (which is world-readable in `ps`).
- [x] Clipboard cleared after 15 s, and only if it still holds our value — clobbering a user's later copy is both rude and data loss.
- [x] Idle auto-lock (5 min default) that wipes the key and exits.
- [x] Plaintext export is guarded by an explicit confirmation, writes `0600`, and says plainly what it is doing.
- [x] Interactive prompts are skipped when stdin is not a TTY, so scripted use fails fast instead of hanging.
- [x] `ZKVAULT_PASSPHRASE` (test-only) warns loudly on every use.
- [ ] Screen-lock detection on desktop.
- [ ] Signed release binaries.

## 10. Mobile — MASVS (planned, `kmp/`)

- [ ] **MASVS-STORAGE-1** Only ciphertext in app storage; no plaintext caches.
- [ ] **MASVS-CRYPTO-2** VEK wrapped by an Android Keystore key with `setUserAuthenticationRequired(true)`; StrongBox where available.
- [ ] **MASVS-AUTH-2** Biometric or device-credential prompt before unwrapping, with a short authentication validity window.
- [ ] `FLAG_SECURE` on entry-detail and unlock screens; no content in the recents thumbnail.
- [ ] Clipboard cleared after timeout; `EXTRA_IS_SENSITIVE` set on Android 13+.
- [ ] `android:allowBackup="false"`; the vault excluded from auto-backup and D2D transfer.
- [ ] No secrets in logs, crash reports, analytics, or notifications.
- [ ] Root/jailbreak signal surfaced to the user (informational, never a security control).
- [ ] iOS: Keychain with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, Secure Enclave wrapping.
- [ ] MASTG test suite run against a release build.

## 11. Build, dependencies, release

- [x] Small dependency surface; the client needs only PyNaCl and httpx.
- [x] No runtime code loading or dynamic imports of user-controlled paths.
- [ ] Hash-pinned lockfiles and `pip install --require-hashes` in CI.
- [ ] Automated dependency scanning (Dependabot + `pip-audit`).
- [ ] Reproducible builds and signed releases.
- [ ] SBOM per release.

## 12. Process

- [x] Threat model written, with residual risks stated rather than elided.
- [x] Crypto format and design published for review.
- [x] Regression tests for each attack the design claims to stop: tamper, splice, downgrade, rollback, cross-user access, conflict, reuse.
- [ ] Independent cryptographic review.
- [ ] Independent penetration test of the server and mobile clients.
- [ ] Documented incident response and disclosure process (`SECURITY.md`).
- [ ] Bug bounty or at minimum a published security contact.

---

## Blocking items before any production use

1. Replace in-process rate limiting with a shared store (Redis).
2. Set `ZKVAULT_JWT_SECRET` and `ZKVAULT_ENUMERATION_SECRET`; the app refuses to
   boot in production without them, but verify it in staging.
3. Move off SQLite to PostgreSQL, with backups and encryption at rest.
4. Hash-pinned dependencies in CI.
5. Independent cryptographic review of the vault format.
6. Penetration test of the sync API.
7. Publish `SECURITY.md` with a disclosure contact.
