package com.tanuki276.keybooks.security

import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import javax.crypto.Cipher

class BiometricGate(private val activity: FragmentActivity) {
    fun authenticate(
        cipher: Cipher,
        title: String,
        onSuccess: (Cipher) -> Unit,
        onError: (String) -> Unit
    ) {
        val allowed = BiometricManager.Authenticators.BIOMETRIC_STRONG
        val status = BiometricManager.from(activity).canAuthenticate(allowed)
        if (status != BiometricManager.BIOMETRIC_SUCCESS) {
            onError("生体認証を利用できません。端末設定を確認してください。")
            return
        }

        val prompt = BiometricPrompt(
            activity,
            ContextCompat.getMainExecutor(activity),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    val authenticatedCipher = result.cryptoObject?.cipher
                    if (authenticatedCipher == null) {
                        onError("生体認証用の暗号処理を開始できませんでした。")
                    } else {
                        onSuccess(authenticatedCipher)
                    }
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    onError(errString.toString())
                }

                override fun onAuthenticationFailed() {
                    onError("生体認証に失敗しました。")
                }
            }
        )

        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle("Keybooks の機密情報を保護しています")
            .setAllowedAuthenticators(allowed)
            .setNegativeButtonText("キャンセル")
            .build()

        prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
    }
}
