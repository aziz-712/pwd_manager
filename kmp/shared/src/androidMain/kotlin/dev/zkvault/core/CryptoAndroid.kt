package dev.zkvault.core

import com.goterl.lazysodium.LazySodiumAndroid
import com.goterl.lazysodium.SodiumAndroid
import com.goterl.lazysodium.interfaces.PwHash

/**
 * libsodium on Android via lazysodium. Deliberately thin: every function maps to
 * exactly one libsodium call, with no logic of our own in between.
 */
actual object Crypto {
    private val sodium = LazySodiumAndroid(SodiumAndroid())

    actual fun argon2id(
        passphrase: String, salt: ByteArray, opsLimit: Int, memLimitBytes: Long, outLen: Int,
    ): ByteArray {
        val out = ByteArray(outLen)
        val pw = passphrase.encodeToByteArray()
        val ok = sodium.cryptoPwHash(
            out, out.size, pw, pw.size, salt,
            opsLimit.toLong(), memLimitBytes.toInt(), PwHash.Alg.PWHASH_ALG_ARGON2ID13,
        )
        // Failure here is almost always the device refusing the memory request.
        // Surface it: silently falling back to weaker parameters would be worse.
        check(ok) { "Argon2id failed; the device may not have ${memLimitBytes / (1024 * 1024)} MiB available" }
        return out
    }

    actual fun blake2b(context: ByteArray, key: ByteArray, outLen: Int): ByteArray {
        val out = ByteArray(outLen)
        sodium.cryptoGenericHash(out, outLen, context, context.size.toLong(), key, key.size)
        return out
    }

    actual fun aeadEncrypt(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, aad: ByteArray): ByteArray {
        val out = ByteArray(plaintext.size + CryptoConstants.TAG_BYTES)
        sodium.cryptoAeadXChaCha20Poly1305IetfEncrypt(
            out, longArrayOf(out.size.toLong()), plaintext, plaintext.size.toLong(),
            aad, aad.size.toLong(), null, nonce, key,
        )
        return out
    }

    actual fun aeadDecrypt(key: ByteArray, nonce: ByteArray, ciphertext: ByteArray, aad: ByteArray): ByteArray? {
        if (nonce.size != CryptoConstants.NONCE_BYTES) return null
        if (ciphertext.size < CryptoConstants.TAG_BYTES) return null
        val out = ByteArray(ciphertext.size - CryptoConstants.TAG_BYTES)
        val ok = sodium.cryptoAeadXChaCha20Poly1305IetfDecrypt(
            out, longArrayOf(out.size.toLong()), null, ciphertext, ciphertext.size.toLong(),
            aad, aad.size.toLong(), nonce, key,
        )
        // One undifferentiated failure. Telling "bad tag" from "wrong key" apart
        // would hand an attacker an oracle.
        if (!ok) { out.fill(0); return null }
        return out
    }

    actual fun randomBytes(n: Int): ByteArray = sodium.randomBytesBuf(n)

    actual fun wipe(buffer: ByteArray) = buffer.fill(0)
}
