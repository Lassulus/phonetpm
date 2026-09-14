package dev.phonetpm.app

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import org.json.JSONArray
import org.json.JSONObject
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.spec.ECGenParameterSpec
import uniffi.phonetpm_mobile.KeyInfo
import uniffi.phonetpm_mobile.KeyKind

data class KeyMeta(
    val id: String,
    val label: String,
    val kind: KeyKind,
    val createdAt: Long,
    val strongBox: Boolean,
)

/**
 * Biometric-bound EC P-256 keys in Android Keystore. The Keystore alias is
 * the key id; label/kind/createdAt/strongBox live in SharedPreferences.
 */
class KeyStoreRepo(ctx: Context) {
    private val prefs = ctx.getSharedPreferences("keys", Context.MODE_PRIVATE)
    private val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    private val state = MutableStateFlow(load())
    val all: StateFlow<List<KeyMeta>> = state

    fun find(id: String): KeyMeta? = state.value.firstOrNull { it.id == id }

    /** SPKI DER of the key's public half, or null if the Keystore entry is gone. */
    fun publicKey(id: String): ByteArray? = keyStore.getCertificate(id)?.publicKey?.encoded

    fun privateKey(id: String): PrivateKey? = keyStore.getKey(id, null) as? PrivateKey

    fun keyInfos(): List<KeyInfo> = state.value.mapNotNull { m ->
        publicKey(m.id)?.let { KeyInfo(m.id, m.label, m.kind, it) }
    }

    /** Blocking; StrongBox key generation can take a while. */
    @Synchronized
    fun create(label: String, kind: KeyKind): KeyMeta {
        val id = newId()
        val strongBox = generate(id, kind)
        val meta = KeyMeta(id, label, kind, System.currentTimeMillis(), strongBox)
        save(state.value + meta)
        return meta
    }

    @Synchronized
    fun delete(id: String) {
        if (keyStore.containsAlias(id)) keyStore.deleteEntry(id)
        save(state.value.filterNot { it.id == id })
    }

    /** Returns whether the key ended up in StrongBox. */
    private fun generate(alias: String, kind: KeyKind): Boolean {
        try {
            generate(alias, kind, strongBox = true)
            return true
        } catch (_: StrongBoxUnavailableException) {
            generate(alias, kind, strongBox = false)
            return false
        }
    }

    private fun generate(alias: String, kind: KeyKind, strongBox: Boolean) {
        val purposes = when (kind) {
            KeyKind.SSH -> KeyProperties.PURPOSE_SIGN
            KeyKind.AGE -> KeyProperties.PURPOSE_AGREE_KEY
        }
        val spec = KeyGenParameterSpec.Builder(alias, purposes)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
            .apply {
                when (kind) {
                    KeyKind.SSH -> {
                        setDigests(KeyProperties.DIGEST_SHA256)
                        // Per-operation auth via BiometricPrompt CryptoObject.
                        setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                    }
                    KeyKind.AGE -> {
                        // KeyAgreement cannot be wrapped in a CryptoObject, so a
                        // short post-auth window is the tightest option.
                        setUserAuthenticationParameters(AGE_AUTH_WINDOW_SECONDS, KeyProperties.AUTH_BIOMETRIC_STRONG)
                    }
                }
                if (strongBox) setIsStrongBoxBacked(true)
            }
            .build()
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE).run {
            initialize(spec)
            generateKeyPair()
        }
    }

    private fun save(keys: List<KeyMeta>) {
        val arr = JSONArray()
        for (k in keys) {
            arr.put(
                JSONObject()
                    .put("id", k.id)
                    .put("label", k.label)
                    .put("kind", k.kind.name)
                    .put("createdAt", k.createdAt)
                    .put("strongBox", k.strongBox)
            )
        }
        prefs.edit().putString(KEY, arr.toString()).apply()
        state.value = keys
    }

    private fun load(): List<KeyMeta> {
        val raw = prefs.getString(KEY, null) ?: return emptyList()
        val arr = JSONArray(raw)
        return List(arr.length()) { i ->
            val o = arr.getJSONObject(i)
            KeyMeta(
                id = o.getString("id"),
                label = o.getString("label"),
                kind = KeyKind.valueOf(o.getString("kind")),
                createdAt = o.getLong("createdAt"),
                strongBox = o.optBoolean("strongBox", false),
            )
        }
    }

    companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val AGE_AUTH_WINDOW_SECONDS = 10
        private const val KEY = "keys"
        private const val HEX = "0123456789abcdef"

        private fun newId(): String {
            val rnd = ByteArray(8).also { SecureRandom().nextBytes(it) }
            return buildString(16) {
                for (b in rnd) {
                    append(HEX[(b.toInt() shr 4) and 0xf])
                    append(HEX[b.toInt() and 0xf])
                }
            }
        }

        /** OpenSSH-style `SHA256:<base64 without padding>` fingerprint of SPKI DER. */
        fun fingerprint(spki: ByteArray): String {
            val digest = MessageDigest.getInstance("SHA-256").digest(spki)
            return "SHA256:" + android.util.Base64.encodeToString(digest, android.util.Base64.NO_WRAP or android.util.Base64.NO_PADDING)
        }
    }
}
