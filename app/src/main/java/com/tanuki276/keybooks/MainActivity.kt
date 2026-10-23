package com.tanuki276.keybooks

import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.mutableIntStateOf
import androidx.fragment.app.FragmentActivity
import com.tanuki276.keybooks.data.KeybooksDatabase
import com.tanuki276.keybooks.security.BiometricGate
import com.tanuki276.keybooks.security.CryptoManager
import com.tanuki276.keybooks.security.SecurityPolicy
import com.tanuki276.keybooks.settings.AppPreferences
import com.tanuki276.keybooks.ui.KeybooksApp

class MainActivity : FragmentActivity() {
    private val maskEpoch = mutableIntStateOf(0)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        SecurityPolicy.hardenWindow(window)

        val cryptoManager = CryptoManager()
        val database = KeybooksDatabase(this, cryptoManager)
        val biometricGate = BiometricGate(this)
        val appPreferences = AppPreferences(this)

        setContent {
            MaterialTheme {
                KeybooksApp(
                    database = database,
                    cryptoManager = cryptoManager,
                    biometricGate = biometricGate,
                    appPreferences = appPreferences,
                    maskEpoch = maskEpoch.intValue
                )
            }
        }
    }

    override fun onStop() {
        maskEpoch.intValue++
        super.onStop()
    }
}
