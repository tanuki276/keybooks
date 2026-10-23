package com.tanuki276.keybooks

import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.compose.material3.MaterialTheme
import androidx.fragment.app.FragmentActivity
import com.tanuki276.keybooks.data.KeybooksDatabase
import com.tanuki276.keybooks.security.BiometricGate
import com.tanuki276.keybooks.security.CryptoManager
import com.tanuki276.keybooks.security.SecurityPolicy
import com.tanuki276.keybooks.settings.AppPreferences
import com.tanuki276.keybooks.ui.KeybooksApp

class MainActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        SecurityPolicy.hardenWindow(window)

        val database = KeybooksDatabase(this)
        val cryptoManager = CryptoManager()
        val biometricGate = BiometricGate(this)
        val appPreferences = AppPreferences(this)

        setContent {
            MaterialTheme {
                KeybooksApp(database, cryptoManager, biometricGate, appPreferences)
            }
        }
    }
}
