package com.winarp.mobile.net

import com.winarp.mobile.data.HostInfo
import com.winarp.mobile.data.IfaceInfo
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap

class LanScanner(
    private val networkRepository: NetworkRepository
) {
    suspend fun scan(
        iface: IfaceInfo,
        cidr: String,
        workers: Int,
        resolveName: Boolean,
        onProgress: (done: Int, total: Int) -> Unit = { _, _ -> }
    ): List<HostInfo> = withContext(Dispatchers.IO) {
        val parsed = if (cidr.isNotBlank()) {
            IpUtils.parseCidr(cidr)
        } else {
            iface.networkAddress to iface.prefixLength
        } ?: (iface.networkAddress to iface.prefixLength)

        val targets = IpUtils.cidrHosts(parsed.first, parsed.second)
            .filter { it != iface.ip }
        if (targets.isEmpty()) return@withContext emptyList()

        val limit = workers.coerceIn(1, 256)
        val sem = Semaphore(limit)
        val found = ConcurrentHashMap<String, HostInfo>()
        var done = 0

        // Seed from kernel ARP table first
        val arpTable = networkRepository.readProcArp()
        for ((ip, mac) in arpTable) {
            if (ip in targets || sameSubnet(ip, iface)) {
                found[ip] = HostInfo(ip = ip, mac = mac)
            }
        }

        coroutineScope {
            val jobs = targets.map { ip ->
                async {
                    sem.withPermit {
                        try {
                            val mac = resolveMac(iface, ip)
                            if (mac != null) {
                                found[ip] = HostInfo(ip = ip, mac = mac)
                            }
                        } finally {
                            val d = synchronized(this@LanScanner) {
                                done += 1
                                done
                            }
                            if (d % 8 == 0 || d == targets.size) {
                                onProgress(d, targets.size)
                            }
                        }
                    }
                }
            }
            jobs.awaitAll()
        }

        // refresh arp table after probes
        for ((ip, mac) in networkRepository.readProcArp()) {
            if (ip in targets || found.containsKey(ip) || sameSubnet(ip, iface)) {
                found.putIfAbsent(ip, HostInfo(ip = ip, mac = mac))
                found.computeIfPresent(ip) { _, old ->
                    if (IpUtils.isZeroMac(old.mac)) old.copy(mac = mac) else old
                }
            }
        }

        var hosts = found.values
            .filter { !IpUtils.isZeroMac(it.mac) && it.ip != iface.ip }
            .sortedBy { IpUtils.ipv4ToLong(it.ip) }

        if (resolveName && hosts.isNotEmpty()) {
            val nameSem = Semaphore(8)
            hosts = coroutineScope {
                hosts.map { h ->
                    async {
                        nameSem.withPermit {
                            val name = resolveDeviceName(h.ip)
                            h.copy(name = name)
                        }
                    }
                }.awaitAll()
            }.sortedBy { IpUtils.ipv4ToLong(it.ip) }
        }

        hosts
    }

    private fun sameSubnet(ip: String, iface: IfaceInfo): Boolean {
        return try {
            val a = IpUtils.ipv4ToLong(ip)
            val b = IpUtils.ipv4ToLong(iface.ip)
            val mask = IpUtils.ipv4ToLong(iface.mask)
            (a and mask) == (b and mask)
        } catch (_: Throwable) {
            false
        }
    }

    private suspend fun resolveMac(iface: IfaceInfo, ip: String): String? {
        // 1) native ARP request if raw socket available
        if (NativeArp.loaded) {
            val mac = NativeArp.probeArp(iface.name, iface.mac, iface.ip, ip, 350)
            if (!mac.isNullOrBlank() && !IpUtils.isZeroMac(mac)) {
                return IpUtils.normalizeMac(mac)
            }
        }

        // 2) traffic to populate neighbor cache, then read /proc/net/arp
        probeHost(ip)
        val fromTable = networkRepository.readProcArp()[ip]
        if (!fromTable.isNullOrBlank() && !IpUtils.isZeroMac(fromTable)) {
            return fromTable
        }
        return null
    }

    private fun probeHost(ip: String) {
        // UDP probe to common ports (no need for open ports)
        try {
            DatagramSocket().use { ds ->
                ds.soTimeout = 120
                val data = ByteArray(1)
                val addr = InetAddress.getByName(ip)
                for (port in intArrayOf(80, 53, 5353, 137)) {
                    try {
                        ds.send(DatagramPacket(data, data.size, addr, port))
                    } catch (_: Throwable) {
                    }
                }
            }
        } catch (_: Throwable) {
        }

        // short TCP connect attempt
        try {
            Socket().use { s ->
                s.soTimeout = 180
                s.connect(InetSocketAddress(ip, 80), 180)
            }
        } catch (_: Throwable) {
        }

        // ICMP-like reachability (may be blocked)
        try {
            InetAddress.getByName(ip).isReachable(220)
        } catch (_: Throwable) {
        }
    }

    private suspend fun resolveDeviceName(ip: String): String {
        val dns = withTimeoutOrNull(700) {
            try {
                val name = InetAddress.getByName(ip).canonicalHostName
                if (name.isNullOrBlank() || name == ip) null else name
            } catch (_: Throwable) {
                null
            }
        }
        if (!dns.isNullOrBlank()) return dns

        val nb = withTimeoutOrNull(700) { netbiosName(ip) }
        if (!nb.isNullOrBlank()) return nb
        return "-"
    }

    private fun netbiosName(ip: String): String? {
        return try {
            DatagramSocket().use { ds ->
                ds.soTimeout = 600
                val query = ByteArray(50)
                // transaction id
                query[0] = 0x10
                query[1] = 0x10
                // flags
                query[2] = 0x00
                query[3] = 0x00
                // questions
                query[4] = 0x00
                query[5] = 0x01
                // name: 32 bytes encoded '*' + nulls, type NBSTAT
                query[12] = 0x20
                // encoded name for '*'
                val star = encodeNetbiosName("*")
                System.arraycopy(star, 0, query, 13, 32)
                query[45] = 0x00
                query[46] = 0x00
                query[47] = 0x21 // NBSTAT
                query[48] = 0x00
                query[49] = 0x01

                val packet = DatagramPacket(query, query.size, InetAddress.getByName(ip), 137)
                ds.send(packet)
                val buf = ByteArray(512)
                val resp = DatagramPacket(buf, buf.size)
                ds.receive(resp)
                parseNetbiosResponse(buf, resp.length)
            }
        } catch (_: Throwable) {
            null
        }
    }

    private fun encodeNetbiosName(name: String): ByteArray {
        val padded = name.uppercase().padEnd(15, ' ').substring(0, 15) + "\u0000"
        val out = ByteArray(32)
        for (i in 0 until 16) {
            val c = padded[i].code
            out[i * 2] = ((c shr 4) + 'A'.code).toByte()
            out[i * 2 + 1] = ((c and 0x0F) + 'A'.code).toByte()
        }
        return out
    }

    private fun parseNetbiosResponse(buf: ByteArray, len: Int): String? {
        if (len < 57) return null
        // names start roughly after header; scan printable sequences
        var i = 57
        while (i + 18 <= len) {
            val nameBytes = buf.copyOfRange(i, i + 15)
            val name = nameBytes.toString(Charsets.US_ASCII).trim()
            val flags = buf[i + 15].toInt() and 0xFF
            // prefer unique workstation/file service names
            if (name.isNotBlank() && name.all { it.code in 32..126 } && (flags and 0x80) == 0) {
                return name
            }
            i += 18
        }
        return null
    }
}
