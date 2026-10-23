package com.tanuki276.keybooks.security

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.security.keystore.KeyPermanentlyInvalidatedException
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

data class EncryptedPayload(
    val encryptedValue: ByteArray,
    val iv: ByteArray,
    val passwordSalt: ByteArray? = null
)

class CryptoManager {
    private val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    private val secureRandom = SecureRandom()

    fun encryptWithoutAuthentication(value: String): EncryptedPayload {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateStandardKey())
        return EncryptedPayload(Envelope.encrypt(cipher, value), cipher.iv)
    }

    fun decryptWithoutAuthentication(encryptedValue: ByteArray, iv: ByteArray): String {
        requireValidIv(iv)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, getOrCreateStandardKey(), GCMParameterSpec(GCM_TAG_BITS, iv))
        return Envelope.decrypt(cipher, encryptedValue)
    }

    /**
     * Encrypts metadata with a key that is deliberately separate from secret-value keys.
     * associatedData is authenticated (not encrypted) and domain-separates metadata fields.
     */
    fun encryptMetadata(value: String, associatedData: String): EncryptedPayload {
        require(associatedData.startsWith(METADATA_AAD_PREFIX)) { "Invalid metadata AAD" }
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateMetadataKey())
        cipher.updateAAD(associatedData.toByteArray(Charsets.UTF_8))
        return EncryptedPayload(cipher.doFinal(value.toByteArray(Charsets.UTF_8)), cipher.iv)
    }

    fun decryptMetadata(
        encryptedValue: ByteArray,
        iv: ByteArray,
        associatedData: String
    ): String {
        requireValidIv(iv)
        require(associatedData.startsWith(METADATA_AAD_PREFIX)) { "Invalid metadata AAD" }
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, getOrCreateMetadataKey(), GCMParameterSpec(GCM_TAG_BITS, iv))
        cipher.updateAAD(associatedData.toByteArray(Charsets.UTF_8))
        return cipher.doFinal(encryptedValue).toString(Charsets.UTF_8)
    }

    fun newBiometricEncryptCipher(): Cipher {
        fun create() = Cipher.getInstance(TRANSFORMATION).apply {
            init(Cipher.ENCRYPT_MODE, getOrCreateBiometricKey(NEW_BIOMETRIC_KEY_ALIAS))
        }
        return try { create() } catch (_: KeyPermanentlyInvalidatedException) {
            // All entries under this alias already require their recovery password.
            keyStore.deleteEntry(NEW_BIOMETRIC_KEY_ALIAS)
            create()
        }
    }

    fun newBiometricDecryptCipher(iv: ByteArray, envelope: Boolean = false): Cipher = Cipher.getInstance(TRANSFORMATION).apply {
        requireValidIv(iv)
        init(Cipher.DECRYPT_MODE, getOrCreateBiometricKey(if (envelope) NEW_BIOMETRIC_KEY_ALIAS else BIOMETRIC_KEY_ALIAS), GCMParameterSpec(GCM_TAG_BITS, iv))
    }

    fun encryptWithAuthenticatedCipher(cipher: Cipher, value: String): EncryptedPayload =
        EncryptedPayload(Envelope.encrypt(cipher, value), cipher.iv)

    fun decryptWithAuthenticatedCipher(cipher: Cipher, encryptedValue: ByteArray): String =
        Envelope.decrypt(cipher, encryptedValue)

    fun encryptWithPassword(value: String, password: String): EncryptedPayload {
        require(password.isNotBlank()) { "Password must not be blank" }
        val salt = ByteArray(PASSWORD_SALT_BYTES).also(secureRandom::nextBytes)
        val key = derivePasswordKey(password, salt)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key)
        return EncryptedPayload(Envelope.encrypt(cipher, value), cipher.iv, salt)
    }

    fun decryptWithPassword(
        encryptedValue: ByteArray,
        iv: ByteArray,
        salt: ByteArray,
        password: String
    ): String {
        requireValidIv(iv)
        require(salt.size == PASSWORD_SALT_BYTES) { "Invalid salt" }
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(
            Cipher.DECRYPT_MODE,
            derivePasswordKey(password, salt),
            GCMParameterSpec(GCM_TAG_BITS, iv)
        )
        return Envelope.decrypt(cipher, encryptedValue)
    }

    private fun getOrCreateStandardKey(): SecretKey =
        getOrCreateUnauthenticatedKey(STANDARD_KEY_ALIAS)

    private fun getOrCreateMetadataKey(): SecretKey =
        getOrCreateUnauthenticatedKey(METADATA_KEY_ALIAS)

    private fun getOrCreateUnauthenticatedKey(alias: String): SecretKey {
        val existing = keyStore.getEntry(alias, null) as? KeyStore.SecretKeyEntry
        if (existing != null) return existing.secretKey

        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(AES_KEY_BITS)
            .setRandomizedEncryptionRequired(true)
        return generateKey(generator, builder)
    }

    private fun getOrCreateBiometricKey(alias: String): SecretKey {
        val existing = keyStore.getEntry(alias, null) as? KeyStore.SecretKeyEntry
        if (existing != null) return existing.secretKey

        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        val builder = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(AES_KEY_BITS)
            .setRandomizedEncryptionRequired(true)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
        } else {
            @Suppress("DEPRECATION")
            builder.setUserAuthenticationValidityDurationSeconds(-1)
        }

        return generateKey(generator, builder)
    }

    private fun generateKey(generator: KeyGenerator, builder: KeyGenParameterSpec.Builder): SecretKey {
        try {
            generator.init(builder.setIsStrongBoxBacked(true).build())
            return generator.generateKey()
        } catch (_: StrongBoxUnavailableException) {
            generator.init(builder.setIsStrongBoxBacked(false).build())
            return generator.generateKey()
        }
    }

    private fun derivePasswordKey(password: String, salt: ByteArray): SecretKey {
        val spec = PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, AES_KEY_BITS)
        return try {
            val bytes = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM).generateSecret(spec).encoded
            try {
                SecretKeySpec(bytes, "AES")
            } finally {
                bytes.fill(0)
            }
        } finally {
            spec.clearPassword()
        }
    }

    private fun requireValidIv(iv: ByteArray) {
        require(iv.size == GCM_IV_BYTES) { "Invalid IV" }
    }

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val STANDARD_KEY_ALIAS = "keybooks_standard_v2"
        private const val NEW_BIOMETRIC_KEY_ALIAS = "keybooks_biometric_envelope_v1"
        private const val BIOMETRIC_KEY_ALIAS = "keybooks_biometric_v2"
        private const val METADATA_KEY_ALIAS = "keybooks_metadata_v1"
        private const val METADATA_AAD_PREFIX = "keybooks:metadata:"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val GCM_TAG_BITS = 128
        private const val GCM_IV_BYTES = 12
        private const val AES_KEY_BITS = 256
        private const val PASSWORD_SALT_BYTES = 32
        private const val PBKDF2_ITERATIONS = 600_000
        private const val PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256"
    }
}
