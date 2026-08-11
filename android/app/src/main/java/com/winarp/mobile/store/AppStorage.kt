package com.winarp.mobile.store

import android.content.Context
import java.io.File

/** The persisted, sticky subset of the UI — toggles/fields that should survive app restarts. */
data class Settings(
    val workers: String = "64",
    val intervalMs: String = "1000",
    val resolveName: Boolean = true,
    val oneWay: Boolean = false,
    val forwardMitm: Boolean = false,
    val cidr: String = "",
    val gateway: String = "",
    val targetSpec: String = "",
    val fromIp: String = "",
    val toIp: String = "",
    val spoofModeName: String = "SINGLE_PAGE",
    val redirectUrl: String = "",
    val targetHosts: String = "",
    val spaFallback: Boolean = true,
    val assistCaptivePortal: Boolean = true,
    val spoofHtml: String = ""
)

/** SharedPreferences-backed settings store. Cheap async writes (apply); safe to call often. */
class Prefs(context: Context) {
    private val sp = context.applicationContext.getSharedPreferences("winarp_settings", Context.MODE_PRIVATE)

    fun load(): Settings = Settings(
        workers = sp.getString("workers", "64") ?: "64",
        intervalMs = sp.getString("intervalMs", "1000") ?: "1000",
        resolveName = sp.getBoolean("resolveName", true),
        oneWay = sp.getBoolean("oneWay", false),
        forwardMitm = sp.getBoolean("forwardMitm", false),
        cidr = sp.getString("cidr", "") ?: "",
        gateway = sp.getString("gateway", "") ?: "",
        targetSpec = sp.getString("targetSpec", "") ?: "",
        fromIp = sp.getString("fromIp", "") ?: "",
        toIp = sp.getString("toIp", "") ?: "",
        spoofModeName = sp.getString("spoofMode", "SINGLE_PAGE") ?: "SINGLE_PAGE",
        redirectUrl = sp.getString("redirectUrl", "") ?: "",
        targetHosts = sp.getString("targetHosts", "") ?: "",
        spaFallback = sp.getBoolean("spaFallback", true),
        assistCaptivePortal = sp.getBoolean("assistCaptivePortal", true),
        spoofHtml = sp.getString("spoofHtml", "") ?: ""
    )

    fun save(s: Settings) {
        sp.edit()
            .putString("workers", s.workers)
            .putString("intervalMs", s.intervalMs)
            .putBoolean("resolveName", s.resolveName)
            .putBoolean("oneWay", s.oneWay)
            .putBoolean("forwardMitm", s.forwardMitm)
            .putString("cidr", s.cidr)
            .putString("gateway", s.gateway)
            .putString("targetSpec", s.targetSpec)
            .putString("fromIp", s.fromIp)
            .putString("toIp", s.toIp)
            .putString("spoofMode", s.spoofModeName)
            .putString("redirectUrl", s.redirectUrl)
            .putString("targetHosts", s.targetHosts)
            .putBoolean("spaFallback", s.spaFallback)
            .putBoolean("assistCaptivePortal", s.assistCaptivePortal)
            .putString("spoofHtml", s.spoofHtml)
            .apply()
    }
}

/**
 * Append-only log persisted to the app's external files dir (scoped-storage safe on Android 11+,
 * no permission needed, and user-visible under Android/data/<pkg>/files/logs). Every line is
 * flushed to disk so nothing is lost across restarts; rotates at ~5 MB.
 */
class FileLogger(context: Context) {
    private val dir: File =
        (context.getExternalFilesDir("logs") ?: File(context.filesDir, "logs")).apply { mkdirs() }
    private val file = File(dir, "winarp.log")
    private val lock = Any()
    private val maxBytes = 5L * 1024 * 1024

    fun append(line: String) {
        synchronized(lock) {
            try {
                if (file.exists() && file.length() > maxBytes) {
                    val old = File(dir, "winarp.old.log")
                    if (old.exists()) old.delete()
                    file.renameTo(old)
                }
                file.appendText(line + "\n")
            } catch (_: Throwable) {
                // best effort; never crash on logging
            }
        }
    }

    fun path(): String = file.absolutePath
}
