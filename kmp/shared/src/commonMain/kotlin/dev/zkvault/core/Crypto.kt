package dev.zkvault.core

/**
 * Platform crypto contract. Implementations MUST call libsodium and MUST NOT
 * substitute anything else -- the format is defined by libsodium's exact
 * constructions, and a "compatible" reimplementation will produce vaults the
 * Python client cannot open.
 */
expect object Crypto {
    /** Argon2id. `memLimitBytes` and `opsLimit` come from the vault header. */
    fun argon2id(passphrase: String, salt: ByteArray, opsLimit: Int, memLimitBytes: Long, outLen: Int = 32): ByteArray

    /** Keyed BLAKE2b, used for domain-separated subkeys. */
    fun blake2b(context: ByteArray, key: ByteArray, outLen: Int = 32): ByteArray

    /** XChaCha20-Poly1305-IETF. Returns ciphertext||tag. */
    fun aeadEncrypt(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, aad: ByteArray): ByteArray

    /** Returns null on ANY authentication failure. Never throw a distinguishing error. */
    fun aeadDecrypt(key: ByteArray, nonce: ByteArray, ciphertext: ByteArray, aad: ByteArray): ByteArray?

    /** CSPRNG bytes. Must be libsodium's randombytes, never java.util.Random. */
    fun randomBytes(n: Int): ByteArray

    /** Best-effort zeroing of a key buffer. */
    fun wipe(buffer: ByteArray)
}

object CryptoConstants {
    const val KEY_BYTES = 32
    const val NONCE_BYTES = 24
    const val TAG_BYTES = 16
    const val SALT_BYTES = 16

    // Byte-for-byte identical to zkvault/crypto.py. Changing either side breaks
    // cross-platform vault compatibility.
    val CTX_KEK = "zkvault/v1/kek".encodeToByteArray()
    val CTX_AUTH = "zkvault/v1/server-auth".encodeToByteArray()

    const val OWASP_MIN_MEM_BYTES = 19L * 1024 * 1024
    const val OWASP_MIN_OPS = 2
}

/** A key buffer with an explicit lifetime. Always use inside `use { }`. */
class Secret(private val buffer: ByteArray) : AutoCloseable {
    var wiped: Boolean = false
        private set

    val bytes: ByteArray
        get() {
            check(!wiped) { "use of a wiped secret" }
            return buffer
        }

    override fun close() {
        Crypto.wipe(buffer)
        wiped = true
    }

    // Never render key material, so it cannot reach a log or a crash report.
    override fun toString(): String = "<Secret ${buffer.size}B ${if (wiped) "wiped" else "live"}>"
}

/** Derives the two role-specific subkeys. The master key is wiped immediately. */
fun deriveKeys(passphrase: String, kdf: KdfParams): DerivedKeys {
    kdf.validate()
    val master = Crypto.argon2id(passphrase, kdf.salt, kdf.opsLimit, kdf.memLimitBytes)
    try {
        return DerivedKeys(
            kek = Secret(Crypto.blake2b(CryptoConstants.CTX_KEK, master)),
            authSecret = Secret(Crypto.blake2b(CryptoConstants.CTX_AUTH, master)),
        )
    } finally {
        Crypto.wipe(master)
    }
}

class DerivedKeys(val kek: Secret, val authSecret: Secret) : AutoCloseable {
    override fun close() {
        kek.close()
        authSecret.close()
    }
}
