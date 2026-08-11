package com.winarp.mobile.net

import android.content.Context

/**
 * MAC OUI → manufacturer lookup, loaded once from a bundled IEEE table (assets/oui.txt,
 * "PREFIX<TAB>Vendor" per line). This names devices instantly and offline from the MAC we
 * already learn via ARP — unlike reverse-DNS/NetBIOS which is slow and rarely resolves phones.
 */
object OuiDb {
    @Volatile private var map: Map<String, String>? = null

    fun ensureLoaded(context: Context) {
        if (map != null) return
        synchronized(this) {
            if (map != null) return
            val m = HashMap<String, String>(45000)
            try {
                context.applicationContext.assets.open("oui.txt").bufferedReader().useLines { lines ->
                    for (l in lines) {
                        val t = l.indexOf('\t')
                        if (t <= 0) continue
                        m[l.substring(0, t)] = l.substring(t + 1)
                    }
                }
            } catch (_: Throwable) {
                // asset missing → vendor() just returns null
            }
            map = m
        }
    }

    /** Vendor for a MAC (any separator), or null if unknown / not loaded yet. */
    fun vendor(mac: String): String? {
        val m = map ?: return null
        val hex = mac.filter { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' }.uppercase()
        if (hex.length < 6) return null
        return m[hex.substring(0, 6)]
    }
}
