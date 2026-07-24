package com.winarp.mobile.net

import java.net.Inet4Address
import java.net.InetAddress
import java.nio.ByteBuffer

object IpUtils {
    fun isValidIpv4(text: String): Boolean {
        val parts = text.trim().split(".")
        if (parts.size != 4) return false
        return parts.all {
            val n = it.toIntOrNull() ?: return false
            n in 0..255
        }
    }

    fun ipv4ToLong(ip: String): Long {
        val parts = ip.trim().split(".").map { it.toInt() }
        require(parts.size == 4)
        var v = 0L
        for (p in parts) {
            v = (v shl 8) or (p.toLong() and 0xFF)
        }
        return v
    }

    fun longToIpv4(v: Long): String {
        return listOf(
            ((v ushr 24) and 0xFF).toInt(),
            ((v ushr 16) and 0xFF).toInt(),
            ((v ushr 8) and 0xFF).toInt(),
            (v and 0xFF).toInt()
        ).joinToString(".")
    }

    fun prefixToMask(prefix: Int): String {
        val p = prefix.coerceIn(0, 32)
        val mask = if (p == 0) 0 else (-1 shl (32 - p))
        return longToIpv4(mask.toLong() and 0xFFFFFFFFL)
    }

    fun cidrHosts(ip: String, prefix: Int, excludeNetworkAndBroadcast: Boolean = true): List<String> {
        val p = prefix.coerceIn(0, 32)
        if (p >= 31) {
            return listOf(ip).filter { isValidIpv4(it) }
        }
        val ipLong = ipv4ToLong(ip)
        val mask = if (p == 0) 0L else ((-1L shl (32 - p)) and 0xFFFFFFFFL)
        val network = ipLong and mask
        val broadcast = network or (mask.inv() and 0xFFFFFFFFL)
        val start = if (excludeNetworkAndBroadcast) network + 1 else network
        val end = if (excludeNetworkAndBroadcast) broadcast - 1 else broadcast
        if (start > end) return emptyList()
        // safety: avoid huge lists on tiny prefixes
        val maxHosts = 4096L
        val count = end - start + 1
        if (count > maxHosts) {
            val mid = (start + end) / 2
            val half = maxHosts / 2
            val s = (mid - half).coerceAtLeast(start)
            val e = (s + maxHosts - 1).coerceAtMost(end)
            return (s..e).map { longToIpv4(it) }
        }
        return (start..end).map { longToIpv4(it) }
    }

    fun parseCidr(cidr: String): Pair<String, Int>? {
        val t = cidr.trim()
        if (t.isEmpty()) return null
        val parts = t.split("/")
        if (parts.size != 2) return null
        val ip = parts[0].trim()
        val prefix = parts[1].trim().toIntOrNull() ?: return null
        if (!isValidIpv4(ip) || prefix !in 0..32) return null
        return ip to prefix
    }

    /**
     * Supports:
     *  - single IP
     *  - comma/space separated list
     *  - range: a.b.c.d-a.b.c.e  or a.b.c.d-e
     */
    fun parseIpList(spec: String): List<String> {
        val out = linkedSetOf<String>()
        val tokens = spec.split(',', ' ', '\n', '\t', ';')
            .map { it.trim() }
            .filter { it.isNotEmpty() }
        for (token in tokens) {
            if ("-" in token) {
                val segs = token.split("-", limit = 2)
                if (segs.size != 2) continue
                val left = segs[0].trim()
                val rightRaw = segs[1].trim()
                if (!isValidIpv4(left)) continue
                val right = when {
                    isValidIpv4(rightRaw) -> rightRaw
                    rightRaw.toIntOrNull() != null -> {
                        val base = left.substringBeforeLast(".")
                        "$base.${rightRaw.toInt()}"
                    }
                    else -> continue
                }
                if (!isValidIpv4(right)) continue
                var a = ipv4ToLong(left)
                var b = ipv4ToLong(right)
                if (a > b) {
                    val tmp = a; a = b; b = tmp
                }
                if (b - a > 1024) {
                    b = a + 1024
                }
                var cur = a
                while (cur <= b) {
                    out += longToIpv4(cur)
                    cur++
                }
            } else if (isValidIpv4(token)) {
                out += token
            }
        }
        return out.toList()
    }

    fun collectTargets(targetSpec: String, from: String, to: String): List<String> {
        val out = linkedSetOf<String>()
        if (targetSpec.isNotBlank()) {
            out += parseIpList(targetSpec)
        }
        if (from.isNotBlank() && to.isNotBlank() && isValidIpv4(from) && isValidIpv4(to)) {
            out += parseIpList("$from-$to")
        } else if (from.isNotBlank() && isValidIpv4(from)) {
            out += from
        }
        return out.toList()
    }

    fun normalizeMac(mac: String): String {
        val hex = mac.lowercase().replace('-', ':').filter { it.isDigit() || it in 'a'..'f' || it == ':' }
        val parts = hex.split(":").filter { it.isNotEmpty() }
        if (parts.size == 6) {
            return parts.joinToString(":") { it.padStart(2, '0').takeLast(2) }
        }
        val raw = hex.replace(":", "")
        if (raw.length == 12) {
            return raw.chunked(2).joinToString(":")
        }
        return mac.lowercase()
    }

    fun isZeroMac(mac: String): Boolean {
        val n = normalizeMac(mac)
        return n == "00:00:00:00:00:00" || n.isBlank()
    }

    fun isIpv4Address(addr: InetAddress): Boolean = addr is Inet4Address && !addr.isLoopbackAddress
}
