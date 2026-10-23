package com.tanuki276.keybooks.security

import android.os.Build
import android.view.View
import android.view.Window
import android.view.WindowManager

object SecurityPolicy {
    fun hardenWindow(window: Window) {
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)

        val decor = window.decorView
        decor.importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            decor.importantForContentCapture = View.IMPORTANT_FOR_CONTENT_CAPTURE_NO_EXCLUDE_DESCENDANTS
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            window.setHideOverlayWindows(true)
        }
    }
}
