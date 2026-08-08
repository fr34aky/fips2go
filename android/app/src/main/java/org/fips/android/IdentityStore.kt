package org.fips.android

import android.content.Context
import android.util.Log
import org.json.JSONObject

/**
 * Stores the node's nsec, encrypted at rest via [SecureStore] (Android
 * Keystore). Shared by the UI and the VPN service so the nsec is decrypted
 * only in-process, on demand — never written in plaintext and never passed
 * through an Intent.
 */
object IdentityStore {
    private const val PREFS = "fips"
    private const val KEY_NSEC_ENC = "nsec_enc"
    private const val KEY_NSEC_LEGACY = "nsec" // pre-Keystore plaintext
    private const val TAG = "IdentityStore"

    private fun prefs(context: Context) =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    /**
     * The stored nsec (decrypted), creating and persisting a fresh identity if
     * none exists. Migrates a legacy plaintext nsec into the Keystore, and
     * regenerates if the ciphertext can't be decrypted (e.g. the Keystore key
     * was invalidated).
     */
    fun getOrCreate(context: Context): String {
        val prefs = prefs(context)

        prefs.getString(KEY_NSEC_LEGACY, null)?.let { legacy ->
            Log.i(TAG, "migrating legacy plaintext nsec into the Keystore")
            store(context, legacy)
            return legacy
        }

        prefs.getString(KEY_NSEC_ENC, null)?.let { enc ->
            return try {
                SecureStore.decrypt(enc)
            } catch (e: Exception) {
                Log.w(TAG, "nsec decrypt failed; regenerating identity", e)
                regenerate(context)
            }
        }

        return regenerate(context)
    }

    /** Encrypt and persist `nsec`, dropping any legacy plaintext copy. */
    fun store(context: Context, nsec: String) {
        prefs(context).edit()
            .putString(KEY_NSEC_ENC, SecureStore.encrypt(nsec))
            .remove(KEY_NSEC_LEGACY)
            .apply()
    }

    /** Generate a brand-new identity, persist it, and return the new nsec. */
    fun regenerate(context: Context): String {
        val info = JSONObject(FipsNative.deriveIdentity(""))
        val nsec = info.getString("nsec")
        store(context, nsec)
        return nsec
    }
}
