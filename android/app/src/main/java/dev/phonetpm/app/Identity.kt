package dev.phonetpm.app

import android.content.Context
import android.util.Base64
import uniffi.phonetpm_mobile.endpointIdFor
import uniffi.phonetpm_mobile.generateSecretKey

/** The phone's stable iroh identity plus the "service enabled" flag. */
class Identity(ctx: Context) {
    private val prefs = ctx.getSharedPreferences("identity", Context.MODE_PRIVATE)

    val secretKey: ByteArray = prefs.getString(KEY_SECRET, null)
        ?.let { Base64.decode(it, Base64.NO_WRAP) }
        ?: generateSecretKey().also {
            prefs.edit().putString(KEY_SECRET, Base64.encodeToString(it, Base64.NO_WRAP)).apply()
        }

    val endpointId: String = endpointIdFor(secretKey)

    var serviceEnabled: Boolean
        get() = prefs.getBoolean(KEY_ENABLED, false)
        set(value) = prefs.edit().putBoolean(KEY_ENABLED, value).apply()

    private companion object {
        const val KEY_SECRET = "secret_key"
        const val KEY_ENABLED = "service_enabled"
    }
}
