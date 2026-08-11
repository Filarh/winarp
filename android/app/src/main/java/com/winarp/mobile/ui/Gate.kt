package com.winarp.mobile.ui

import com.winarp.mobile.net.IpUtils

/**
 * Single source of truth for WHY an action is (un)available. Each function returns null when the
 * action is allowed, or a short human reason when it is blocked — so the UI can both disable a
 * control and show exactly why (nothing is ever greyed out without an explanation).
 */
object Gate {
    private fun gw(s: MainUiState) = s.gateway.ifBlank { s.selectedIface?.gateway ?: "" }

    fun scan(s: MainUiState): String? = when {
        s.selectedIface == null -> "connect Wi-Fi and pick a NIC above"
        s.scanning -> "a scan is already running"
        s.attacking -> "stop the attack first"
        else -> null
    }

    fun selectAll(s: MainUiState): String? =
        if (s.hosts.isEmpty()) "scan the LAN first" else null

    fun attackSelected(s: MainUiState): String? = when {
        s.selectedIface == null -> "pick a NIC on the Scan tab"
        s.scanning -> "a scan is running"
        s.attacking -> "an attack is already running"
        !IpUtils.isValidIpv4(gw(s)) -> "set a valid Gateway IP"
        s.selectedHostIps.isEmpty() -> "select devices on the Scan tab"
        else -> null
    }

    fun attackRange(s: MainUiState): String? = when {
        s.selectedIface == null -> "pick a NIC on the Scan tab"
        s.scanning -> "a scan is running"
        s.attacking -> "an attack is already running"
        !IpUtils.isValidIpv4(gw(s)) -> "set a valid Gateway IP"
        IpUtils.collectTargets(s.targetSpec, s.fromIp, s.toIp).isEmpty() -> "enter a target IP or range"
        else -> null
    }

    fun stop(s: MainUiState): String? =
        if (!s.attacking) "no attack is running" else null
}
