package com.tanuki276.keybooks.settings

import android.content.Context

class AppPreferences(context: Context) {
    private val preferences = context.applicationContext.getSharedPreferences(
        PREFERENCES_NAME,
        Context.MODE_PRIVATE
    )

    var clipboardClearSeconds: Long?
        get() {
            val stored = preferences.getLong(KEY_CLIPBOARD_CLEAR_SECONDS, DEFAULT_CLIPBOARD_SECONDS)
            return stored.takeIf { it > 0L }
        }
        set(value) {
            val safeValue = value?.takeIf { it > 0L } ?: NEVER_CLEAR
            preferences.edit().putLong(KEY_CLIPBOARD_CLEAR_SECONDS, safeValue).apply()
        }

    companion object {
        private const val PREFERENCES_NAME = "keybooks_preferences"
        private const val KEY_CLIPBOARD_CLEAR_SECONDS = "clipboard_clear_seconds"
        private const val DEFAULT_CLIPBOARD_SECONDS = 30L
        private const val NEVER_CLEAR = -1L
    }
}
