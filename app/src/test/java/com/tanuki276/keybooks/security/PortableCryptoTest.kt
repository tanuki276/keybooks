package com.tanuki276.keybooks.security

import org.junit.Assert.*
import org.junit.Test
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class PortableCryptoTest {
    private val password = "a long recovery phrase 123!"
    private fun rejects(block: () -> Unit) {
        try { block(); fail("Tampering must fail closed") } catch (_: java.security.GeneralSecurityException) {
        } catch (_: IllegalArgumentException) { }
    }
    @Test fun backupRoundTripAndRandomization() {
        val value = "秘密とプロジェクト".toByteArray()
        val first = PortableCrypto.seal(value, password)
        val second = PortableCrypto.seal(value, password)
        assertFalse(first.contentEquals(second))
        assertArrayEquals(value, PortableCrypto.open(first, password))
    }
    @Test fun backupRejectsWrongPasswordAndTampering() {
        val bytes = PortableCrypto.seal("secret".toByteArray(), password)
        rejects { PortableCrypto.open(bytes, "wrong password") }
        for (position in listOf(0, 4, 35, 36, 47, 48, bytes.lastIndex)) {
            val tampered = bytes.copyOf()
            tampered[position] = (tampered[position].toInt() xor 1).toByte()
            rejects { PortableCrypto.open(tampered, password) }
        }
        rejects { PortableCrypto.open(bytes.copyOf(50), password) }
        rejects { PortableCrypto.open(ByteArray(PortableCrypto.MAX_BYTES + 1), password) }
    }
    @Test fun envelopeRejectsWrappedKeyIvAndCiphertextTampering() {
        val key = SecretKeySpec(ByteArray(32) { it.toByte() }, "AES")
        val encrypt = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key) }
        val bytes = Envelope.encrypt(encrypt, "secret")
        fun decrypt(data: ByteArray): String = Envelope.decrypt(Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, encrypt.iv))
        }, data)
        assertEquals("secret", decrypt(bytes))
        for (position in listOf(0, 4, 51, 52, 63, 64, bytes.lastIndex)) {
            val tampered = bytes.copyOf()
            tampered[position] = (tampered[position].toInt() xor 1).toByte()
            rejects { decrypt(tampered) }
        }
    }
    @Test fun legacyCiphertextStillReadable() {
        val key = SecretKeySpec(ByteArray(32), "AES")
        val encrypt = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key) }
        val bytes = encrypt.doFinal("legacy".toByteArray())
        val decrypt = Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, encrypt.iv))
        }
        assertEquals("legacy", Envelope.decrypt(decrypt, bytes))
    }
    @Test fun passwordWarning() {
        assertNotNull(PasswordStrength.warning("short"))
        assertNotNull(PasswordStrength.warning("aaaaaaaaaaaa"))
        assertNull(PasswordStrength.warning(password))
    }
}
