# Next steps

Ordered by what unblocks the most, and honest about what is not built.

---

## 0. Before anything else: verify the foundation

The vault format is the one thing that cannot change cheaply later — every
existing vault has to be migrated. Get it reviewed **before** building clients on
top of it.

- [ ] External cryptographic review of `docs/VAULT_FORMAT.md` and `zkvault/vault.py`.
      Specific questions for a reviewer: is the AAD split between key binding and
      payload binding sound? Is the two-counter rollback defence complete? Does
      the header-substitution DoS in VAULT_FORMAT §3 warrant a whole-file
      signature in v1?
- [ ] Publish the format and threat model for public comment.
- [ ] Coverage-guided fuzzing (Atheris) against `VaultFile.from_bytes`, in CI,
      not just the property tests that exist now.
- [ ] Cross-implementation test vectors green in Kotlin (`tools/gen_test_vectors.py`).

## 1. Android client (Kotlin Multiplatform) — the main effort

`kmp/` has the shared core: crypto contract, vault format, canonical JSON,
padding, Keystore wrapping. None of it is compiled. Order of work:

1. **Gradle wrapper and CI.** Nothing else is verifiable until the module builds.
2. **JVM actual + vector tests.** The JVM target is the fastest way to prove the
   Kotlin format implementation matches Python. Do this before any UI.
3. **JSON envelope codec.** Strict, typed, size-capped, mirroring
   `VaultFile.from_bytes` — including the KDF floor check before allocating
   memory, which on a phone is also a denial-of-service defence.
4. **Argon2id on real devices.** 256 MiB is fine on a flagship and may be refused
   on a budget phone. Benchmark across a device matrix and set the default from
   the *weakest* device that must open the vault, not the fastest.
5. **Biometric unlock** via `AndroidVaultKeyStore` + `BiometricPrompt`:
   passphrase unlock once, wrap the VEK under a Keystore key, then fingerprint
   thereafter. Re-prompt for the passphrase on reboot, after biometric
   enrolment changes, and on a periodic schedule.
6. **Storage.** SQLite or a flat file holding only the encrypted vault, plus the
   `WrappedVek` and the rollback high-water mark. Nothing decrypted persists.
7. **Sync** via Ktor, mirroring `zkvault/syncclient.py` exactly.
8. **Hardening**: `FLAG_SECURE`, `allowBackup=false`, clipboard timeout with
   `EXTRA_IS_SENSITIVE`, no secrets in logs or crash reports, ProGuard rules
   verified on a release build.
9. **Autofill service.** The feature that decides whether people actually use it,
   and a security surface of its own: match by verified package signature and
   Digital Asset Links, never by a URL string a hostile app can supply.
10. **MASTG test pass** against a release build.

## 2. iOS

- libsodium via cinterop; the `commonMain` code is unchanged.
- Keychain with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` — `ThisDeviceOnly`
  matters, or the wrapped key rides an iCloud backup off the device.
- Secure Enclave wrapping with `LAContext` biometric gating.
- AutoFill Credential Provider extension.

## 3. Desktop

The JVM target plus Compose Desktop gets Windows, macOS and Linux from the same
core. Per-platform key storage: DPAPI, Keychain, `libsecret`.

## 4. Web client — read this before agreeing to build one

A browser client cannot offer the same guarantee, and saying so plainly is more
useful than shipping one that implies otherwise.

**The problem:** the server that stores your ciphertext also serves the
JavaScript that decrypts it. Every page load re-downloads the crypto code. A
malicious or compromised server sends one modified bundle to one targeted user
and receives their master passphrase — and there is no artifact left behind to
audit. The native clients avoid this because the binary is installed once and
updates are signed.

**If a web client is required anyway,** the mitigations are real but partial:

- Strict CSP: `default-src 'none'`, no `unsafe-inline`, no `unsafe-eval`, and
  Subresource Integrity on everything.
- WebAssembly libsodium, pinned by hash.
- A browser *extension* rather than a page: extension code is installed and
  versioned, not re-fetched per load, which is a genuinely different trust model.
- Code-signing plus a transparency log for the bundle, and third-party
  verification that the served bundle matches the published source.
- Tell the user, in the product, that the web client is weaker than the native
  one, and why.

**Recommendation:** ship the extension, not the page, and only after the native
clients are done.

## 5. Sync layer v2 — per-record

The current model is one blob per user: simple, correct, and it means every edit
re-uploads the whole vault and every concurrent edit is a conflict the user must
resolve by hand.

Design sketch, deferred deliberately until the crypto is settled:

- Each entry becomes its own AEAD record under a per-entry key derived from the
  VEK: `entry_key = BLAKE2b(VEK, "zkvault/v1/entry" || entry_id)`.
- The server stores an append-only log of `(record_id, ciphertext, version)`,
  still opaque, still unparsed.
- Conflicts resolve per entry, not per vault, so two devices adding two different
  passwords simply merge.
- The record set itself needs authentication — otherwise the server can drop or
  reorder records undetectably. A Merkle root over record ids, signed under a
  VEK-derived key, and checked on every pull.
- Deletion tombstones, and a compaction story for them.

**Do not start this before the format review.** The per-record design changes
what the server can see (record count, per-record update timing), and that trade
belongs in the threat model first.

## 6. Server production readiness

Blocking, from `docs/SECURITY_CHECKLIST.md`:

- [ ] Redis-backed rate limiting (the current limiter is per-process).
- [ ] PostgreSQL, backups, encryption at rest.
- [ ] `ZKVAULT_JWT_SECRET` and `ZKVAULT_ENUMERATION_SECRET` set and rotated.
- [ ] Alerting on the security events that are already logged.
- [ ] Hash-pinned dependencies, `pip-audit` in CI, SBOM per release.
- [ ] Per-user storage quotas.
- [ ] `SECURITY.md` with a disclosure contact and response commitment.

Worth building next: account deletion (GDPR and plain decency), device list and
revocation, and an emergency-access scheme — which must be client-side secret
sharing (Shamir, shares held by trustees), never a server-side escrow, or the
zero-knowledge property dies for everyone.

## 7. External review and testing

| What | When | Why |
|---|---|---|
| Cryptographic review of the format | **Before mobile work** | The format is the expensive thing to change |
| Penetration test of the sync API | Before public beta | Auth, tenant isolation, rate limits |
| Mobile pen test (MASTG) | Before store release | Keystore usage, storage, autofill |
| Supply-chain audit | Before 1.0 | The client runs in the trusted zone |
| Public bug bounty | At 1.0 | Continuous review beats a point-in-time test |

## 8. Deliberately not planned

- **Server-side password recovery.** Any mechanism the server can execute to
  recover a vault is a mechanism it can execute to read one.
- **Browser-based password *checking* against breach corpora**, unless done with
  k-anonymity (send a hash prefix, never a password or a full hash).
- **Cloud backup of the plaintext vault.** Encrypted vault, yes. Plaintext,
  never, including "temporarily" during an import.
- **Telemetry that includes entry counts or titles.** If it is not needed to keep
  the service running, it is not collected.
