package com.tanuki276.keybooks.security

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/** Versioned, authenticated portable backup. No Android Keystore dependency. */
object PortableCrypto {
    const val MAX_BYTES = 16 * 1024 * 1024
    private val magic = byteArrayOf(75, 66, 66, 49)
    private const val ITERATIONS = 600_000

    fun seal(plaintext: ByteArray, password: String): ByteArray {
        require(plaintext.size <= MAX_BYTES - 80) { "バックアップが大きすぎます" }
        require(password.length >= 12) { "12文字以上のパスワードを設定してください" }
        val salt = ByteArray(32).also(SecureRandom()::nextBytes)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key(password, salt))
        val header = magic + salt + cipher.iv
        cipher.updateAAD(header)
        return header + cipher.doFinal(plaintext)
    }

    fun open(bytes: ByteArray, password: String): ByteArray {
        require(bytes.size in 64..MAX_BYTES && bytes.copyOfRange(0, 4).contentEquals(magic)) {
            "未対応または破損したバックアップです"
        }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key(password, bytes.copyOfRange(4, 36)),
            GCMParameterSpec(128, bytes.copyOfRange(36, 48)))
        cipher.updateAAD(bytes.copyOfRange(0, 48))
        return cipher.doFinal(bytes.copyOfRange(48, bytes.size))
    }

    private fun key(password: String, salt: ByteArray): SecretKeySpec {
        val chars = password.toCharArray()
        val spec = PBEKeySpec(chars, salt, ITERATIONS, 256)
        chars.fill('\u0000')
        return try {
            val bytes = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
            try { SecretKeySpec(bytes, "AES") } finally { bytes.fill(0) }
        } finally { spec.clearPassword() }
    }
}

/** A random data key is wrapped by the selected authentication key. Legacy values remain readable. */
object Envelope {
    private val magic = byteArrayOf(75, 66, 69, 49)
    fun isEnvelope(bytes: ByteArray): Boolean = bytes.take(4).toByteArray().contentEquals(magic)
    fun encrypt(wrapper: Cipher, value: String): ByteArray {
        val raw = ByteArray(32).also(SecureRandom()::nextBytes)
        return try {
            val content = Cipher.getInstance("AES/GCM/NoPadding")
            content.init(Cipher.ENCRYPT_MODE, SecretKeySpec(raw, "AES"))
            content.updateAAD(magic)
            magic + wrapper.doFinal(raw) + content.iv + content.doFinal(value.toByteArray(Charsets.UTF_8))
        } finally { raw.fill(0) }
    }
    fun decrypt(wrapper: Cipher, bytes: ByteArray): String {
        if (!bytes.take(4).toByteArray().contentEquals(magic)) {
            return wrapper.doFinal(bytes).toString(Charsets.UTF_8)
        }
        require(bytes.size >= 80) { "Invalid envelope" }
        val raw = wrapper.doFinal(bytes.copyOfRange(4, 52))
        return try {
            val content = Cipher.getInstance("AES/GCM/NoPadding")
            content.init(Cipher.DECRYPT_MODE, SecretKeySpec(raw, "AES"),
                GCMParameterSpec(128, bytes.copyOfRange(52, 64)))
            content.updateAAD(magic)
            content.doFinal(bytes.copyOfRange(64, bytes.size)).toString(Charsets.UTF_8)
        } finally { raw.fill(0) }
    }
}

object PasswordStrength {
    fun warning(password: String): String? = when {
        password.length < 12 -> "弱いパスワードです。12文字以上の長いパスフレーズを推奨します"
        password.toSet().size < 5 -> "同じ文字の繰り返しは避けてください"
        else -> null
    }
}
