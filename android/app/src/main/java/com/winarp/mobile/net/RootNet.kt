package com.winarp.mobile.net

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Root-backed network plumbing for a transparent MITM and live traffic view.
 *
 * On Android the FORWARD chain ends in a tethering DROP and the default route lives in the
 * per-interface policy table (not `main`), so a poisoned victim just loses internet even with
 * `ip_forward=1`. [enableForwarding] fixes all of that so the victim keeps internet and its
 * traffic transits this device; [disableForwarding] reverts it. [spawnCapture] streams tcpdump.
 */
object RootNet {

    /** Turn this device into a working L3 forwarder for traffic entering on [ifName]. null = ok. */
    suspend fun enableForwarding(ifName: String): String? = withContext(Dispatchers.IO) {
        val script = buildString {
            append("sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || echo 1 > /proc/sys/net/ipv4/ip_forward; ")
            append("sysctl -w net.ipv4.conf.all.send_redirects=0 >/dev/null 2>&1; ")
            append("sysctl -w net.ipv4.conf.$ifName.send_redirects=0 >/dev/null 2>&1; ")
            append("sysctl -w net.ipv4.conf.$ifName.rp_filter=2 >/dev/null 2>&1; ")
            append("sysctl -w net.ipv4.conf.all.rp_filter=2 >/dev/null 2>&1; ")
            // accept intra-interface forwarding before Android's tetherctrl DROP
            append("iptables -C FORWARD -i $ifName -o $ifName -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -i $ifName -o $ifName -j ACCEPT; ")
            // forwarded packets must use the interface's routing table (it has the default route)
            append("ip rule list | grep -q \"iif $ifName lookup $ifName\" || ip rule add iif $ifName lookup $ifName priority 9000; ")
            append("echo DONE")
        }
        val (code, out) = RootHelper.execSu(script)
        if (out.contains("DONE") && code == 0) null
        else out.trim().ifBlank { "forwarding setup failed (code=$code)" }
    }

    /** Undo [enableForwarding]. Best-effort; ignores errors. */
    suspend fun disableForwarding(ifName: String) {
        val script = buildString {
            append("iptables -D FORWARD -i $ifName -o $ifName -j ACCEPT 2>/dev/null; ")
            append("ip rule del iif $ifName lookup $ifName priority 9000 2>/dev/null; ")
            append("echo 0 > /proc/sys/net/ipv4/ip_forward 2>/dev/null; ")
            append("echo DONE")
        }
        RootHelper.execSu(script)
    }

    /**
     * Start a live tcpdump on [ifName], optionally filtered to a single [host].
     * The caller reads the process stdout line by line and MUST destroy the process to stop.
     * Returns null if tcpdump could not be launched (missing binary / no root).
     */
    fun spawnCapture(ifName: String, host: String?): Process? {
        val filter = if (host.isNullOrBlank()) "not arp" else "host $host and not arp"
        return spawnCaptureRaw(ifName, filter)
    }

    /** Launch tcpdump with an arbitrary BPF [filter]. Caller reads stdout and destroys to stop. */
    fun spawnCaptureRaw(ifName: String, filter: String): Process? {
        val cmd = "/system/bin/tcpdump -i $ifName -n -l -q -s 0 $filter 2>&1"
        return try {
            ProcessBuilder("su", "-c", cmd)
                .redirectErrorStream(true)
                .start()
        } catch (_: Throwable) {
            null
        }
    }
}
