package com.winarp.mobile.data

/**
 * Per-host traffic control applied while that host is MITM'd through this device:
 *  - [kbps] caps bandwidth both ways (0 = unlimited),
 *  - [delayMs] / [lossPct] add artificial lag / packet loss (netem),
 *  - [blocked] drops the host's forwarded traffic (cut internet, keep others online),
 *  - [proxied] redirects the host's HTTP (:80) into the local server/proxy.
 */
data class HostControl(
    val kbps: Int = 0,
    val delayMs: Int = 0,
    val lossPct: Int = 0,
    val blocked: Boolean = false,
    val proxied: Boolean = false
) {
    val shaped: Boolean get() = kbps > 0 || delayMs > 0 || lossPct > 0
    val active: Boolean get() = shaped || blocked || proxied
}
