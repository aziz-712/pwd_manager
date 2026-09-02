# zkvault — Kotlin Multiplatform client

**Status: skeleton.** The security-critical pieces are written — the crypto
contract, the shared vault format, canonical JSON, Padmé padding, and the Android
Keystore integration. It has **not been compiled or run**; there is no Gradle
wrapper checked in, and no UI. Treat every file here as a reviewed design under
implementation, not as working code.

## Why KMP for the client

The vault format and key hierarchy are the parts that must not diverge between
platforms. Writing them once in `commonMain` and sharing them across Android,
iOS, and desktop means one implementation to review and one to keep in step with
the Python reference — rather than three that drift, each with its own subtle
canonical-JSON bug. Only two things are genuinely per-platform: the libsodium
binding, and the OS keystore.

```
shared/src/
  commonMain/     format, key hierarchy, canonical JSON, padding   <- review this once
    Crypto.kt         expect declarations + Secret + deriveKeys
    CanonicalJson.kt  byte-compatible with Python's json.dumps
    VaultFile.kt      AAD construction, unwrap/seal/rewrap, Padmé
  androidMain/    libsodium (lazysodium) + Android Keystore
  iosMain/        libsodium via cinterop + Keychain/Secure Enclave   (TODO)
  jvmMain/        libsodium (lazysodium-java), for desktop + tests   (TODO)
```

## The one rule

`commonMain` must produce byte-identical output to the Python client. Canonical
JSON is the AAD, so a one-byte disagreement means vaults written on a phone will
not open on a laptop — and it presents as data corruption, not as a serialisation
bug, which is a miserable thing to debug at 2 a.m.

Test vectors are generated from the Python reference:

```bash
python3 tools/gen_test_vectors.py > kmp/shared/src/commonTest/resources/vectors.json
```

They cover Argon2id output, both subkeys, canonical JSON (including Unicode and
escapes), Padmé bucket sizes, both AAD strings, and a complete vault that must
decrypt to a known entry. **Write the `commonTest` suite against these before
writing any UI.** A green cross-implementation test is the definition of done for
this module.

## What is left

| Piece | Status |
|---|---|
| `Crypto` expect declarations | done |
| Canonical JSON | done, needs the vector test |
| `VaultFile` AAD + seal/unwrap/rewrap | done, needs the vector test |
| Padmé padding | done, needs the vector test |
| Android libsodium actual | written, uncompiled |
| Android Keystore VEK wrapping | written, uncompiled |
| JSON envelope parse/serialise | **TODO** — strict, typed, size-capped, mirroring `VaultFile.from_bytes` |
| Entry model + payload codec | **TODO** — must preserve unknown fields |
| iOS / JVM actuals | **TODO** |
| Ktor sync client | **TODO** — mirror `zkvault/syncclient.py` |
| Rollback high-water store | **TODO** — per `vault_id`, both counters |
| Compose UI, biometric flow | **TODO** |
| Gradle wrapper, CI | **TODO** |

## Android security requirements (MASVS)

Non-negotiable for a release build; see `docs/SECURITY_CHECKLIST.md` §10:

- Only ciphertext in app storage. No plaintext cache, no `SharedPreferences`
  copy of a decrypted field, ever.
- The VEK is wrapped by a Keystore key with `setUserAuthenticationRequired(true)`
  and StrongBox where available (`AndroidVaultKeyStore` does this).
- `setInvalidatedByBiometricEnrollment(true)`, so adding a fingerprint to a
  seized phone does not inherit vault access.
- `FLAG_SECURE` on unlock and entry-detail screens; nothing sensitive in the
  recents thumbnail.
- `android:allowBackup="false"`; exclude the vault from auto-backup and D2D
  transfer. A vault in a cloud backup is a vault outside your threat model.
- Clipboard cleared on a timer, with `ClipDescription.EXTRA_IS_SENSITIVE` set on
  Android 13+.
- No secrets in logs, crash reports, analytics, or notification content. Strip
  them in ProGuard rules and verify on a release build, not a debug one.

## Building (once the wrapper exists)

```bash
cd kmp
./gradlew :shared:jvmTest          # cross-implementation vectors
./gradlew :shared:assembleRelease  # Android AAR
```
