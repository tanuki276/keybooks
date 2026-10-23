package com.tanuki276.keybooks

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.compose.material3.MaterialTheme
import androidx.fragment.app.FragmentActivity
import com.tanuki276.keybooks.data.KeybooksDatabase
import com.tanuki276.keybooks.security.BiometricGate
import com.tanuki276.keybooks.security.CryptoManager
import com.tanuki276.keybooks.ui.KeybooksApp

class MainActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)

        val database = KeybooksDatabase(this)
        val cryptoManager = CryptoManager()
        val biometricGate = BiometricGate(this)

        setContent {
            MaterialTheme {
                KeybooksApp(database, cryptoManager, biometricGate)
            }
        }
    }
}
