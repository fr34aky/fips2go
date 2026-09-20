package org.fips.android

import android.content.Context
import java.io.File
import org.json.JSONObject

/**
 * The user's mesh names: readable name → npub, so a mesh app can use
 * `home.fips` instead of `npub1….fips`.
 *
 * The file IS the store — there is no copy in the prefs. It is a fips hosts
 * file (`name npub` per line, `#` comments; the format of `/etc/fips/hosts`)
 * in the app's private files dir, and the shim's DNS proxy reads the very same
 * file ([ConfigStore.buildConfigJson] passes its path as `hosts_path`),
 * re-reading it whenever the mtime changes. So an edit applies on the next
 * lookup: no rebind, no node restart, unlike relays or mesh apps.
 *
 * Writes go through a temp file + rename because the shim may read at any
 * moment, and a half-written file would parse as a shorter list.
 */
object HostsStore {

    data class Host(val name: String, val npub: String)

    /** A hosts file is typed by hand; keep it phone-sized. */
    const val MAX_HOSTS = 64

    private const val FILE = "hosts"

    fun file(context: Context) = File(context.filesDir, FILE)

    /** Entries in file order; lines fips would skip are skipped here too. */
    fun load(context: Context): List<Host> {
        val text = runCatching { file(context).readText() }.getOrNull() ?: return emptyList()
        val hosts = LinkedHashMap<String, Host>()
        for (line in text.lines()) {
            val trimmed = line.trim()
            if (trimmed.isEmpty() || trimmed.startsWith("#")) continue
            val fields = trimmed.split(Regex("\\s+"))
            if (fields.size != 2 || nameError(fields[0]) != null) continue
            // A repeated name: the later line wins, as in fips's HostMap.
            hosts[fields[0].lowercase()] = Host(fields[0].lowercase(), fields[1])
        }
        return hosts.values.toList()
    }

    fun save(context: Context, hosts: List<Host>) {
        val target = file(context)
        val tmp = File(target.parentFile, "$FILE.tmp")
        tmp.writeText(hosts.joinToString("") { "${it.name} ${it.npub}\n" })
        if (!tmp.renameTo(target)) {
            tmp.delete()
            throw java.io.IOException("could not replace ${target.name}")
        }
    }

    /** What the user typed, minus a pasted `.fips` and any capitals. */
    fun normalizeName(typed: String) = typed.trim().lowercase().removeSuffix(".fips")

    /**
     * Why [name] cannot be a mesh name, or null when it can. Mirrors fips's
     * `validate_hostname` (`src/upper/hosts.rs`) — the shim drops a line that
     * fails it, so anything accepted here that fips rejects would be listed
     * in the app and never resolve.
     */
    fun nameError(name: String): String? = when {
        name.isEmpty() -> "Enter a name"
        name.length > 63 -> "At most 63 characters"
        name.lowercase().startsWith("npub1") -> "A name cannot start with npub1"
        name.startsWith("-") || name.endsWith("-") -> "Cannot start or end with a hyphen"
        name.any { !(it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' || it == '-') } ->
            "Letters, digits and hyphens only — no dots or spaces"
        else -> null
    }

    /**
     * Canonical npub for what the user typed (with or without a pasted
     * `.fips`), or null if it is not one. Validated by the same code that
     * will resolve it.
     */
    fun normalizeNpub(typed: String): String? {
        val raw = typed.trim().lowercase().removeSuffix(".fips")
        if (raw.isEmpty()) return null
        val info = runCatching { JSONObject(FipsNative.resolveNpub(raw)) }.getOrNull()
        return info?.optString("npub")?.takeIf { it.startsWith("npub1") }
    }
}
