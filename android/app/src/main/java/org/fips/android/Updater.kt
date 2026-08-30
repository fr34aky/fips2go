package org.fips.android

import android.content.Context
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

/**
 * In-app updater against GitHub Releases. Blocking network calls throughout —
 * run off the main thread.
 *
 * The APK is only handed to the system package installer, which enforces the
 * release signing key on an in-place update; on top of that the download is
 * checked against the release's published .sha256 asset before install.
 */
object Updater {
    private const val LATEST_URL =
        "https://api.github.com/repos/fr34aky/fips2go/releases/latest"

    data class Update(
        val version: String,
        val apkUrl: String,
        val sha256Url: String?,
        val notes: String,
    )

    /** Latest release if strictly newer than [currentVersion], else null. */
    fun check(currentVersion: String, abi: String): Update? {
        val json = JSONObject(get(LATEST_URL))
        val version = json.getString("tag_name").removePrefix("v")
        if (!isNewer(version, currentVersion)) return null

        var apkUrl: String? = null
        var shaUrl: String? = null
        val assets = json.optJSONArray("assets") ?: return null
        for (i in 0 until assets.length()) {
            val a = assets.getJSONObject(i)
            val name = a.getString("name")
            when {
                name.endsWith("-$abi.apk") -> apkUrl = a.getString("browser_download_url")
                name.endsWith("-$abi.apk.sha256") -> shaUrl = a.getString("browser_download_url")
            }
        }
        return apkUrl?.let { Update(version, it, shaUrl, json.optString("body")) }
    }

    /**
     * Download the update APK (reusing a previous verified download if
     * present) and verify it against the release's sha256 asset. Returns the
     * ready-to-install file.
     */
    fun fetch(context: Context, update: Update): File {
        val dir = File(context.cacheDir, "updates").apply { mkdirs() }
        // One file per version; stale versions are cleaned out.
        val apk = File(dir, "fips-android-v${update.version}.apk")
        dir.listFiles()?.filter { it != apk }?.forEach { it.delete() }

        // No checksum means no verification, so refuse rather than hand an
        // unchecked APK to the installer. The installer still enforces the
        // signing key, but that is the last line of defence, not the only one.
        val shaUrl = update.sha256Url
            ?: throw IllegalStateException(
                "release v${update.version} has no .sha256 for this device — " +
                    "refusing to install an unverified APK"
            )
        val expected = get(shaUrl).trim().split(Regex("\\s+")).first().lowercase()
        if (expected.length != 64 || !expected.all { it.isDigit() || it in 'a'..'f' }) {
            throw IllegalStateException("release v${update.version} has a malformed .sha256")
        }
        if (!(apk.exists() && sha256(apk) == expected)) {
            download(update.apkUrl, apk)
            if (sha256(apk) != expected) {
                apk.delete()
                throw IllegalStateException("checksum mismatch — refusing to install")
            }
        }
        return apk
    }

    /** Numeric dotted-version comparison; non-numeric parts compare as 0. */
    fun isNewer(latest: String, current: String): Boolean {
        fun parts(v: String) =
            v.substringBefore('-').split('.').map { it.toIntOrNull() ?: 0 }
        val l = parts(latest)
        val c = parts(current)
        for (i in 0 until maxOf(l.size, c.size)) {
            val a = l.getOrElse(i) { 0 }
            val b = c.getOrElse(i) { 0 }
            if (a != b) return a > b
        }
        return false
    }

    private fun connect(url: String): HttpURLConnection =
        (URL(url).openConnection() as HttpURLConnection).apply {
            setRequestProperty("User-Agent", "fips-android-updater")
            setRequestProperty("Accept", "application/vnd.github+json")
            connectTimeout = 15_000
            readTimeout = 30_000
        }

    private fun get(url: String): String = connect(url).run {
        try {
            if (responseCode !in 200..299) throw IllegalStateException("HTTP $responseCode from $url")
            inputStream.bufferedReader().readText()
        } finally {
            disconnect()
        }
    }

    private fun download(url: String, dest: File) = connect(url).run {
        try {
            if (responseCode !in 200..299) throw IllegalStateException("HTTP $responseCode from $url")
            dest.outputStream().use { out -> inputStream.copyTo(out) }
        } finally {
            disconnect()
        }
    }

    private fun sha256(file: File): String {
        val md = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buf = ByteArray(64 * 1024)
            while (true) {
                val n = input.read(buf)
                if (n < 0) break
                md.update(buf, 0, n)
            }
        }
        return md.digest().joinToString("") { "%02x".format(it) }
    }
}
