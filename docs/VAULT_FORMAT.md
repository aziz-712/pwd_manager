# zkvault vault file format — v1

**Media type:** `application/vnd.zkvault+json`
**Extension:** `.zkv`
**Encoding:** UTF-8 JSON, all binary fields standard base64 (RFC 4648, padded)

This is the interoperability contract. Any client — the Python CLI, the Kotlin
Multiplatform app, or a third party's — must produce and consume exactly this.
Every field outside `payload` is cleartext and is visible to the sync server.

---

## 1. Example

```json
{
  "format": "zkvault",
  "format_version": 1,
  "vault_id": "d497a6e3f1b04c2f8e9a7c5d3b1e0f42",
  "cipher": "xchacha20poly1305-ietf",
  "kdf": {
    "algorithm": "argon2id",
    "salt": "3q2+796tvu/erb7v3q2+7w==",
    "ops_limit": 3,
    "mem_limit_bytes": 268435456,
    "parallelism": 1,
    "key_length": 32
  },
  "wrapped_vek": {
    "nonce": "8J+SgeKAjfCfkYHwn5GB4oCN8J+RgQ==",
    "ciphertext": "…48 bytes: 32-byte VEK + 16-byte Poly1305 tag…"
  },
  "vault_version": 7,
  "payload_seq": 5,
  "modified_day": "2026-09-02",
  "payload": {
    "nonce": "…24 bytes…",
    "ciphertext": "…padded plaintext + 16-byte tag…"
  }
}
```

---

## 2. Field reference

| Field | Type | Required | Meaning |
|---|---|---|---|
| `format` | string | yes | Always `"zkvault"`. Reject otherwise. |
| `format_version` | int | yes | `1`. A **higher** value must be refused, not guessed at. |
| `vault_id` | string, 1–64 chars | yes | Random hex identity. Stable for the life of the vault, across passphrase changes and key rotations. |
| `cipher` | string | yes | Always `"xchacha20poly1305-ietf"` in v1. |
| `kdf.algorithm` | string | yes | `"argon2id"`. |
| `kdf.salt` | base64, 16 B | yes | Unique per vault, CSPRNG. Redrawn on passphrase change. |
| `kdf.ops_limit` | int ≥ 2 | yes | Argon2id iterations. |
| `kdf.mem_limit_bytes` | int ≥ 19 MiB | yes | Argon2id memory. |
| `kdf.parallelism` | int | yes | `1` (fixed by libsodium's high-level API). |
| `kdf.key_length` | int | yes | `32`. |
| `wrapped_vek.nonce` | base64, 24 B | yes | Random. |
| `wrapped_vek.ciphertext` | base64, 48 B | yes | VEK (32 B) + tag (16 B), under the KEK. |
| `vault_version` | int ≥ 0 | yes | Bumped on **any** change, including a re-wrap. Sync ordering. |
| `payload_seq` | int ≥ 0 | yes | Bumped only when the payload is resealed. **Authenticated.** |
| `modified_day` | `YYYY-MM-DD` | yes | Day precision only, deliberately. |
| `payload.nonce` | base64, 24 B | yes | Random, fresh on every seal. |
| `payload.ciphertext` | base64 | yes | Padded plaintext + tag, under the VEK. |

Unknown top-level fields must be ignored on read. They are not preserved on
write: forward compatibility lives inside the encrypted payload, where an old
client can round-trip fields it does not understand (`VaultContents._unknown`).

### Two counters, and why

`vault_version` moves on every write so the sync layer always sees a change.
`payload_seq` moves only when the payload is re-encrypted, and is bound into the
payload's AAD.

This split is what makes a passphrase change cheap: rewrapping the VEK does not
touch the payload, so `change_passphrase` on a 100 MB vault rewrites 48 bytes.
Binding `payload_seq` into the AAD is what closes the matching hole — an attacker
cannot take an old payload, relabel it with a high counter, and slip it past the
client's rollback check, because raising `payload_seq` requires the VEK.

---

## 3. Associated data (AAD)

Both AEAD operations are bound to canonical JSON: keys sorted, no whitespace
(`separators=(",", ":")`), UTF-8, non-ASCII left unescaped. Byte-exact agreement
across implementations is mandatory — a Kotlin client that serialises differently
will produce vaults the Python client cannot open.

**Wrapped VEK AAD** — identity and KDF parameters:

```json
{"cipher":"xchacha20poly1305-ietf","format":"zkvault","format_version":1,"kdf":{"algorithm":"argon2id","key_length":32,"mem_limit_bytes":268435456,"ops_limit":3,"parallelism":1,"salt":"…"},"vault_id":"…"}
```

Downgrading the KDF or swapping the salt therefore breaks the unwrap.

**Payload AAD** — identity and the payload counter:

```json
{"cipher":"xchacha20poly1305-ietf","format":"zkvault","format_version":1,"payload_seq":5,"vault_id":"…"}
```

It deliberately excludes `kdf` and `wrapped_vek`, which is what decouples a
passphrase change from the payload. Those two are authenticated independently,
under the KEK, by the wrapped-VEK AAD.

**Known limitation:** an attacker who controls storage can replace the entire
header *and* payload with a vault of their own. The victim's passphrase then
fails to open it, so this is denial of service or substitution, never disclosure.
Detecting it requires a signature over the whole file with a key the attacker
lacks; deferred, and recorded in the threat model rather than left implicit.

---

## 4. Payload plaintext

Before encryption the payload is length-prefixed and padded:

```
+-------------------+------------------------+----------------------+
| length (4 B, BE)  | canonical JSON         | zero padding         |
+-------------------+------------------------+----------------------+
|<------------------ Padmé(4 + len(JSON)), minimum 1024 ----------->|
```

Padding uses **Padmé** (Nikitin et al., PETS 2019), which caps overhead at ~12%
while collapsing nearby sizes into shared buckets, with a 1024-byte floor. The
point is that adding one entry usually does not change the file size at all, so
blob size tells the server much less than it otherwise would.

Decoding: read the 4-byte length, take that many bytes, ignore the rest. A length
exceeding the remaining buffer is a format error, not a truncation to fix up.

### Decrypted structure

```json
{
  "schema_version": 1,
  "updated_at": "2026-09-02T19:22:24+00:00",
  "entries": [
    {
      "id": "5d0659d4a1b24c3e8f7a6b5c4d3e2f10",
      "title": "GitHub",
      "username": "user@example.com",
      "password": "6Tb;D&%c4gq2tFsx+7m^",
      "url": "https://github.com",
      "notes": "recovery codes in the safe",
      "totp_secret": "JBSWY3DPEHPK3PXP",
      "custom_fields": {"security question": "…"},
      "created_at": "2026-09-02T19:20:01+00:00",
      "updated_at": "2026-09-02T19:22:24+00:00"
    }
  ]
}
```

All of it is encrypted — not just the `password` field. Titles and URLs are the
metadata that profiles a person ("banks with X, uses dating site Y"), and per-
entry timestamps reveal behaviour. Encrypting only passwords would leak exactly
the parts an analyst wants.

---

## 5. JSON Schema (Draft 2020-12)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://zkvault.example/schemas/vault-v1.json",
  "title": "zkvault vault file, version 1",
  "type": "object",
  "required": ["format", "format_version", "vault_id", "cipher", "kdf",
               "wrapped_vek", "vault_version", "payload_seq", "modified_day", "payload"],
  "properties": {
    "format": {"const": "zkvault"},
    "format_version": {"const": 1},
    "vault_id": {"type": "string", "minLength": 1, "maxLength": 64,
                 "pattern": "^[A-Za-z0-9_-]+$"},
    "cipher": {"const": "xchacha20poly1305-ietf"},
    "kdf": {
      "type": "object",
      "required": ["algorithm", "salt", "ops_limit", "mem_limit_bytes", "parallelism", "key_length"],
      "properties": {
        "algorithm": {"const": "argon2id"},
        "salt": {"type": "string", "contentEncoding": "base64", "minLength": 24, "maxLength": 44},
        "ops_limit": {"type": "integer", "minimum": 2, "maximum": 64},
        "mem_limit_bytes": {"type": "integer", "minimum": 19922944, "maximum": 4294967296},
        "parallelism": {"const": 1},
        "key_length": {"const": 32}
      },
      "additionalProperties": false
    },
    "wrapped_vek": {"$ref": "#/$defs/aeadBlock"},
    "payload": {"$ref": "#/$defs/aeadBlock"},
    "vault_version": {"type": "integer", "minimum": 0},
    "payload_seq": {"type": "integer", "minimum": 0},
    "modified_day": {"type": "string", "pattern": "^\\d{4}-\\d{2}-\\d{2}$"}
  },
  "$defs": {
    "aeadBlock": {
      "type": "object",
      "required": ["nonce", "ciphertext"],
      "properties": {
        "nonce": {"type": "string", "contentEncoding": "base64", "minLength": 32, "maxLength": 32},
        "ciphertext": {"type": "string", "contentEncoding": "base64", "minLength": 24}
      },
      "additionalProperties": false
    }
  }
}
```

Schema validation is necessary but not sufficient: a conforming document can
still carry a forged header. Implementations must also enforce the KDF floor
before allocating memory, and must treat AEAD failure as the real gate.

---

## 6. Operations

### Create
1. Draw a 16-byte salt and a 32-byte VEK from the CSPRNG.
2. Derive the master key (Argon2id), then the KEK.
3. Wrap the VEK under the KEK with the wrapped-VEK AAD.
4. Seal an empty payload (`vault_version = payload_seq = 1`).
5. Write atomically, mode `0600`.

### Unlock
1. Parse strictly; refuse a higher `format_version` and any KDF below the floor.
2. Check the local high-water mark for this `vault_id`; refuse a regression
   unless the user explicitly overrides.
3. Derive the master key → KEK; unwrap the VEK (fails on header tampering).
4. Decrypt the payload (fails on ciphertext or `payload_seq` tampering).
5. Unpad, parse JSON, record the new high-water mark.

### Save
Bump both counters, set `modified_day`, draw a **fresh nonce**, re-encrypt,
write atomically (temp file → `fsync` → `rename` → `fsync` directory).

### Change passphrase
Unwrap the VEK with the old passphrase, draw a **new salt**, derive the new KEK,
re-wrap, bump `vault_version` only. The payload is not read or written. Reusing
the old salt would let an attacker holding both files amortise one cracking run
across two passphrases.

### Rotate VEK
Decrypt the payload with the old VEK, draw a new one, wrap it, re-seal. The
passphrase is unchanged.

---

## 7. Implementation requirements

1. **Never reuse a (key, nonce) pair.** Draw the nonce from the CSPRNG on every
   encryption. Never derive a nonce from a counter, a timestamp, or the content.
2. **Treat AEAD failure as fatal and uninformative.** One error message for wrong
   passphrase and for corruption — distinguishing them is an oracle.
3. **Validate before allocating.** Check the KDF ceiling before asking Argon2id
   for memory, or a hostile header is a denial-of-service primitive.
4. **Canonical JSON must match byte for byte** across implementations, or vaults
   will not be portable.
5. **Write atomically at `0600`.** A partial write during a sync must never
   truncate the only copy.
6. **Never log any part of `payload`,** including its length, in a form that
   reaches a server or a crash reporter.
7. **Wipe key material** as soon as the vault locks, as far as the platform
   allows (see ARCHITECTURE §8 for what that is worth in Python).

---

## 8. Versioning policy

`format_version` increments only on a breaking change to the envelope. A client
must refuse a version it does not know rather than guessing. Additive changes
belong inside the encrypted payload, guarded by `schema_version`, where old
clients preserve unknown fields instead of destroying them.
