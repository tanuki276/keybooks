package com.tanuki276.keybooks.security

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
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
        return EncryptedPayload(cipher.doFinal(value.toByteArray()), cipher.iv)
    }

    fun decryptWithoutAuthentication(encryptedValue: ByteArray, iv: ByteArray): String {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, getOrCreateStandardKey(), GCMParameterSpec(GCM_TAG_BITS, iv))
        return cipher.doFinal(encryptedValue).toString(Charsets.UTF_8)
    }

    fun newBiometricEncryptCipher(): Cipher = Cipher.getInstance(TRANSFORMATION).apply {
        init(Cipher.ENCRYPT_MODE, getOrCreateBiometricKey())
    }

    fun newBiometricDecryptCipher(iv: ByteArray): Cipher = Cipher.getInstance(TRANSFORMATION).apply {
        init(Cipher.DECRYPT_MODE, getOrCreateBiometricKey(), GCMParameterSpec(GCM_TAG_BITS, iv))
    }

    fun encryptWithAuthenticatedCipher(cipher: Cipher, value: String): EncryptedPayload =
        EncryptedPayload(cipher.doFinal(value.toByteArray()), cipher.iv)

    fun decryptWithAuthenticatedCipher(cipher: Cipher, encryptedValue: ByteArray): String =
        cipher.doFinal(encryptedValue).toString(Charsets.UTF_8)

    fun encryptWithPassword(value: String, password: String): EncryptedPayload {
        val salt = ByteArray(PASSWORD_SALT_BYTES).also(secureRandom::nextBytes)
        val key = derivePasswordKey(password, salt)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key)
        return EncryptedPayload(cipher.doFinal(value.toByteArray()), cipher.iv, salt)
    }

    fun decryptWithPassword(encryptedValue: ByteArray, iv: ByteArray, salt: ByteArray, password: String): String {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, derivePasswordKey(password, salt), GCMParameterSpec(GCM_TAG_BITS, iv))
        return cipher.doFinal(encryptedValue).toString(Charsets.UTF_8)
    }

    private fun getOrCreateStandardKey(): SecretKey {
        val existing = keyStore.getEntry(STANDARD_KEY_ALIAS, null) as? KeyStore.SecretKeyEntry
        if (existing != null) return existing.secretKey
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(STANDARD_KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
        )
        return generator.generateKey()
    }

    private fun getOrCreateBiometricKey(): SecretKey {
        val existing = keyStore.getEntry(BIOMETRIC_KEY_ALIAS, null) as? KeyStore.SecretKeyEntry
        if (existing != null) return existing.secretKey

        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        val builder = KeyGenParameterSpec.Builder(BIOMETRIC_KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
        } else {
            @Suppress("DEPRECATION")
            builder.setUserAuthenticationValidityDurationSeconds(-1)
        }

        generator.init(builder.build())
        return generator.generateKey()
    }

    private fun derivePasswordKey(password: String, salt: ByteArray): SecretKey {
        val spec = PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, AES_KEY_BITS)
        return try {
            val bytes = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM).generateSecret(spec).encoded
            SecretKeySpec(bytes, "AES")
        } finally {
            spec.clearPassword()
        }
    }

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val STANDARD_KEY_ALIAS = "keybooks_standard_v1"
        private const val BIOMETRIC_KEY_ALIAS = "keybooks_biometric_v1"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val GCM_TAG_BITS = 128
        private const val AES_KEY_BITS = 256
        private const val PASSWORD_SALT_BYTES = 16
        private const val PBKDF2_ITERATIONS = 210_000
        private const val PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256"
    }
}
