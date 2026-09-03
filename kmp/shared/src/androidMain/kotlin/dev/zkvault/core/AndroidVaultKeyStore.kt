package dev.zkvault.core

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Device-local wrapping of the VEK, so routine unlock is a fingerprint instead of
 * a six-word passphrase.
 *
 * What this changes, and what it does not:
 *  - The VEK is wrapped by an AES key held in the Android Keystore (StrongBox
 *    where the device has it). The app can use that key but can never read it,
 *    even with root.
 *  - Using it requires a fresh biometric or device-credential authentication.
 *  - The master passphrase is NEVER stored here and cannot be recovered from
 *    this wrapping. Biometrics gate a *device* convenience path; the vault's
 *    security still rests on the passphrase.
 *  - Enrolling a new fingerprint invalidates the key
 *    (`setInvalidatedByBiometricEnrollment`), forcing a passphrase unlock. That
 *    is deliberate: someone who adds their own fingerprint to a seized phone
 *    must not inherit vault access.
 *
 * MASVS-STORAGE-1, MASVS-CRYPTO-2, MASVS-AUTH-2.
 */
class AndroidVaultKeyStore(private val alias: String = "zkvault.vek.wrapping.v1") {

    private val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    fun hasWrappingKey(): Boolean = keyStore.containsAlias(alias)

    /**
     * @param validitySeconds how long one authentication stays good for. Shorter
     *   is safer; 0 would demand a prompt for every single operation.
     */
    fun createWrappingKey(validitySeconds: Int = 30, requireStrongBox: Boolean = true) {
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        val spec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationParameters(
                validitySeconds,
                KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
            )
            .setInvalidatedByBiometricEnrollment(true)
            .setRandomizedEncryptionRequired(true) // Keystore chooses the GCM IV
            .apply { if (requireStrongBox) setIsStrongBoxBacked(true) }
            .build()
        try {
            generator.init(spec)
            generator.generateKey()
        } catch (e: StrongBoxUnavailableException) {
            // Fall back to the TEE, and tell the user: whether their key sits in
            // dedicated hardware is exactly the kind of thing to surface, not hide.
            if (requireStrongBox) createWrappingKey(validitySeconds, requireStrongBox = false) else throw e
        }
    }

    /** Hand this Cipher to BiometricPrompt; wrap only after the user authenticates. */
    fun wrapCipher(): Cipher =
        Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, secretKey()) }

    fun unwrapCipher(iv: ByteArray): Cipher =
        Cipher.getInstance(TRANSFORMATION).apply {
            init(Cipher.DECRYPT_MODE, secretKey(), GCMParameterSpec(128, iv))
        }

    /** Call with the Cipher returned inside BiometricPrompt's CryptoObject. */
    fun wrapVek(authenticatedCipher: Cipher, vek: ByteArray): WrappedVek =
        WrappedVek(iv = authenticatedCipher.iv, ciphertext = authenticatedCipher.doFinal(vek))

    fun unwrapVek(authenticatedCipher: Cipher, wrapped: WrappedVek): ByteArray =
        authenticatedCipher.doFinal(wrapped.ciphertext)

    /** Discards the wrapping key: biometric unlock is revoked, the passphrase still works. */
    fun forget() {
        if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias)
    }

    private fun secretKey(): SecretKey =
        (keyStore.getEntry(alias, null) as KeyStore.SecretKeyEntry).secretKey

    /** Store alongside the vault; useless without the Keystore key. */
    data class WrappedVek(val iv: ByteArray, val ciphertext: ByteArray)

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
    }
}
