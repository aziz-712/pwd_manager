package dev.zkvault.core

import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

/**
 * The vault file format, shared by every platform. A direct port of
 * `zkvault/vault.py`, with docs/VAULT_FORMAT.md as the contract both implement.
 * The two must stay in lockstep; the cross-implementation test vectors described
 * in kmp/README.md are what keep them honest.
 */

class VaultFormatException(message: String) : Exception(message)
class CryptoFailure(message: String = "decryption failed: wrong passphrase or corrupted vault") : Exception(message)
class RollbackDetected(message: String) : Exception(message)

data class KdfParams(
    val salt: ByteArray,
    val opsLimit: Int,
    val memLimitBytes: Long,
    val parallelism: Int = 1,
    val keyLength: Int = 32,
    val algorithm: String = "argon2id",
) {
    /** Downgrade guard. The header is attacker-reachable, so never trust it blindly. */
    fun validate() {
        if (algorithm != "argon2id") throw VaultFormatException("unsupported KDF: $algorithm")
        if (salt.size != CryptoConstants.SALT_BYTES) throw VaultFormatException("salt must be 16 bytes")
        if (opsLimit < CryptoConstants.OWASP_MIN_OPS) throw VaultFormatException("ops_limit below the OWASP floor")
        if (memLimitBytes < CryptoConstants.OWASP_MIN_MEM_BYTES) throw VaultFormatException("mem_limit below the OWASP floor")
        if (memLimitBytes > 4L * 1024 * 1024 * 1024) throw VaultFormatException("mem_limit implausibly large")
        if (parallelism != 1) throw VaultFormatException("only parallelism=1 is supported")
        if (keyLength != CryptoConstants.KEY_BYTES) throw VaultFormatException("key_length must be 32")
    }
}

@OptIn(ExperimentalEncodingApi::class)
class VaultFile(
    val vaultId: String,
    val kdf: KdfParams,
    var wrappedVekNonce: ByteArray,
    var wrappedVekCt: ByteArray,
    var payloadNonce: ByteArray,
    var payloadCt: ByteArray,
    var vaultVersion: Long,
    var payloadSeq: Long,
    var modifiedDay: String,
    val cipher: String = "xchacha20poly1305-ietf",
    val formatVersion: Int = 1,
) {
    /** AAD for the wrapped VEK: identity plus KDF parameters. */
    internal fun keyBinding(): ByteArray = CanonicalJson.encode(
        CanonicalJson.O(mapOf(
            "format" to CanonicalJson.S("zkvault"),
            "format_version" to CanonicalJson.I(formatVersion.toLong()),
            "vault_id" to CanonicalJson.S(vaultId),
            "cipher" to CanonicalJson.S(cipher),
            "kdf" to CanonicalJson.O(mapOf(
                "algorithm" to CanonicalJson.S(kdf.algorithm),
                "salt" to CanonicalJson.S(Base64.encode(kdf.salt)),
                "ops_limit" to CanonicalJson.I(kdf.opsLimit.toLong()),
                "mem_limit_bytes" to CanonicalJson.I(kdf.memLimitBytes),
                "parallelism" to CanonicalJson.I(kdf.parallelism.toLong()),
                "key_length" to CanonicalJson.I(kdf.keyLength.toLong()),
            )),
        ))
    )

    /**
     * AAD for the payload: identity plus the payload counter. Excludes the KDF
     * and the wrapped key on purpose, which is what lets a passphrase change
     * avoid re-encrypting the payload.
     */
    private fun payloadBinding(): ByteArray = CanonicalJson.encode(
        CanonicalJson.O(mapOf(
            "format" to CanonicalJson.S("zkvault"),
            "format_version" to CanonicalJson.I(formatVersion.toLong()),
            "vault_id" to CanonicalJson.S(vaultId),
            "cipher" to CanonicalJson.S(cipher),
            "payload_seq" to CanonicalJson.I(payloadSeq),
        ))
    )

    fun unwrapVek(passphrase: String): Secret {
        deriveKeys(passphrase, kdf).use { keys ->
            val raw = Crypto.aeadDecrypt(keys.kek.bytes, wrappedVekNonce, wrappedVekCt, keyBinding())
                ?: throw CryptoFailure()
            if (raw.size != CryptoConstants.KEY_BYTES) throw CryptoFailure("unwrapped key has the wrong length")
            return Secret(raw)
        }
    }

    fun decryptPayload(vek: Secret): ByteArray {
        val padded = Crypto.aeadDecrypt(vek.bytes, payloadNonce, payloadCt, payloadBinding())
            ?: throw CryptoFailure()
        return Padding.unpad(padded)
    }

    /** Encrypt under the VEK, bumping both counters. A fresh random nonce every time. */
    fun seal(vek: Secret, plaintext: ByteArray, today: String) {
        vaultVersion += 1
        payloadSeq += 1
        modifiedDay = today
        payloadNonce = Crypto.randomBytes(CryptoConstants.NONCE_BYTES)
        payloadCt = Crypto.aeadEncrypt(vek.bytes, payloadNonce, Padding.pad(plaintext), payloadBinding())
    }

    /** Re-wrap the VEK under a new passphrase. The payload is neither read nor written. */
    fun rewrap(vek: Secret, newPassphrase: String, newKdf: KdfParams): VaultFile {
        newKdf.validate()
        deriveKeys(newPassphrase, newKdf).use { keys ->
            val nonce = Crypto.randomBytes(CryptoConstants.NONCE_BYTES)
            val rewrapped = VaultFile(
                vaultId, newKdf, nonce, ByteArray(0), payloadNonce, payloadCt,
                vaultVersion + 1, payloadSeq, modifiedDay, cipher, formatVersion,
            )
            rewrapped.wrappedVekCt = Crypto.aeadEncrypt(keys.kek.bytes, nonce, vek.bytes, rewrapped.keyBinding())
            return rewrapped
        }
    }
}

/** Padme padding (PETS 2019): bounded overhead, hides fine-grained vault growth. */
object Padding {
    const val MIN_PADDED_BYTES = 1024
    private const val LENGTH_PREFIX = 4

    fun padme(length: Int): Int {
        if (length <= MIN_PADDED_BYTES) return MIN_PADDED_BYTES
        val e = 31 - length.countLeadingZeroBits()   // floor(log2 length)
        val s = 32 - e.countLeadingZeroBits()        // bits needed to represent e
        val mask = (1 shl (e - s)) - 1
        return (length + mask) and mask.inv()
    }

    fun pad(plaintext: ByteArray): ByteArray {
        val n = plaintext.size
        val body = ByteArray(LENGTH_PREFIX + n)
        body[0] = (n ushr 24).toByte(); body[1] = (n ushr 16).toByte()
        body[2] = (n ushr 8).toByte(); body[3] = n.toByte()
        plaintext.copyInto(body, LENGTH_PREFIX)
        return body.copyOf(padme(body.size))
    }

    fun unpad(padded: ByteArray): ByteArray {
        if (padded.size < LENGTH_PREFIX) throw VaultFormatException("payload truncated")
        val n = ((padded[0].toInt() and 0xFF) shl 24) or ((padded[1].toInt() and 0xFF) shl 16) or
                ((padded[2].toInt() and 0xFF) shl 8) or (padded[3].toInt() and 0xFF)
        if (n < 0 || n > padded.size - LENGTH_PREFIX) throw VaultFormatException("payload length prefix out of range")
        return padded.copyOfRange(LENGTH_PREFIX, LENGTH_PREFIX + n)
    }
}
