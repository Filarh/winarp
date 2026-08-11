package com.winarp.mobile.net

import android.os.SystemClock
import com.winarp.mobile.data.CaptureEndpoint
import com.winarp.mobile.data.CapturePeer
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.InetAddress

/**
 * Runs tcpdump on an interface and turns the packet firehose into a grouped, per-destination view.
 *
 * Generalized for the whole LAN: it captures ALL forwarded IPv4 traffic (every device you are
 * MITM-ing), classifies each packet as local (inside the interface subnet) vs remote, and groups
 * by the REMOTE peer — tracking which of your local devices talked to it, bytes up/down, and the
 * services used. A second DNS stream maps IP -> domain by correlating query/response txids, so
 * peers show real hostnames for any device using cleartext DNS (typical of Android TV boxes / IoT).
 * A bounded ring of raw lines keeps the "noise" available without a log storm.
 */
class CaptureEngine {

    private val _peers = MutableStateFlow<List<CapturePeer>>(emptyList())
    val peers: StateFlow<List<CapturePeer>> = _peers.asStateFlow()

    private val _raw = MutableStateFlow<List<String>>(emptyList())
    val raw: StateFlow<List<String>> = _raw.asStateFlow()

    private val _running = MutableStateFlow(false)
    val running: StateFlow<Boolean> = _running.asStateFlow()

    private val _label = MutableStateFlow<String?>(null)
    val target: StateFlow<String?> = _label.asStateFlow()

    private var proc: Process? = null
    private var job: Job? = null
    private var dnsProc: Process? = null
    private var dnsJob: Job? = null

    private val mutex = Mutex()
    private val agg = LinkedHashMap<String, MutPeer>()
    private val rawBuf = ArrayDeque<String>()
    private val resolving = HashSet<String>()
    private val ipToDomain = HashMap<String, String>()
    private val txidToName = LinkedHashMap<String, String>()
    @Volatile private var clearRequested = false

    private var localNet = 0L
    private var localMask = 0L
    private var selfIp = ""

    private class Ep(var packets: Int = 0, var bytes: Long = 0)
    private class MutPeer(val ip: String) {
        var packets = 0
        var bytes = 0L
        var up = 0L
        var down = 0L
        var first = 0L
        var last = 0L
        val eps = LinkedHashMap<String, Ep>()
        val sources = LinkedHashSet<String>()
    }

    private val line = Regex(
        """(\d+\.\d+\.\d+\.\d+)(?:\.(\d+))?\s*>\s*(\d+\.\d+\.\d+\.\d+)(?:\.(\d+))?:\s*([A-Za-z0-9]+)"""
    )
    private val trailingLen = Regex("""(\d+)\s*$""")
    private val dnsQuery = Regex(""":\s*(\d+)\+?\s.*?A+\?\s+([A-Za-z0-9._-]+)""")
    private val dnsAnswerId = Regex(""":\s*(\d+)\s""")
    private val dnsARecord = Regex("""\bA\s+(\d+\.\d+\.\d+\.\d+)""")

    fun start(scope: CoroutineScope, ifName: String, localIp: String, prefix: Int) {
        stop()
        selfIp = localIp
        localMask = if (prefix <= 0) 0L else ((-1L shl (32 - prefix.coerceIn(0, 32))) and 0xFFFFFFFFL)
        localNet = toLong(localIp) and localMask
        agg.clear(); rawBuf.clear(); resolving.clear(); ipToDomain.clear(); txidToName.clear()
        _peers.value = emptyList(); _raw.value = emptyList()
        _label.value = "forwarded traffic · $ifName"

        val p = RootNet.spawnCaptureRaw(ifName, "ip and not arp") ?: return
        proc = p
        _running.value = true
        job = scope.launch(Dispatchers.IO) {
            var lastEmit = 0L
            try {
                val reader = BufferedReader(InputStreamReader(p.inputStream))
                while (true) {
                    val l = reader.readLine() ?: break
                    if (l.isBlank()) continue
                    handle(l, scope)
                    val now = SystemClock.elapsedRealtime()
                    if (now - lastEmit > 400) {
                        lastEmit = now
                        emit()
                    }
                }
            } catch (_: Throwable) {
            } finally {
                emit()
                _running.value = false
            }
        }

        // DNS enrichment stream (cleartext DNS only)
        val dp = RootNet.spawnCaptureRaw(ifName, "udp port 53")
        if (dp != null) {
            dnsProc = dp
            dnsJob = scope.launch(Dispatchers.IO) {
                try {
                    val r = BufferedReader(InputStreamReader(dp.inputStream))
                    while (true) {
                        val l = r.readLine() ?: break
                        handleDns(l)
                    }
                } catch (_: Throwable) {
                }
            }
        }
    }

    fun stop() {
        try { proc?.destroyForcibly() } catch (_: Throwable) {}
        try { dnsProc?.destroyForcibly() } catch (_: Throwable) {}
        proc = null; dnsProc = null
        job?.cancel(); job = null
        dnsJob?.cancel(); dnsJob = null
        _running.value = false
    }

    fun clear() {
        clearRequested = true
        _peers.value = emptyList()
        _raw.value = emptyList()
    }

    private fun toLong(ip: String): Long {
        val p = ip.split(".")
        if (p.size != 4) return -1
        var v = 0L
        for (o in p) {
            val n = o.toIntOrNull() ?: return -1
            v = (v shl 8) or (n.toLong() and 0xFF)
        }
        return v
    }

    private fun isLocal(ip: String): Boolean {
        val v = toLong(ip)
        return v >= 0 && (v and localMask) == localNet
    }

    // remote = a routable global address we care about (not local subnet / multicast / link-local)
    private fun isRemote(ip: String): Boolean {
        if (isLocal(ip)) return false
        val first = ip.substringBefore('.').toIntOrNull() ?: return false
        if (first >= 224) return false                 // multicast / broadcast
        if (ip.startsWith("169.254.") || ip.startsWith("127.")) return false
        return true
    }

    private suspend fun handle(l: String, scope: CoroutineScope) {
        val m = line.find(l) ?: run { pushRaw(l); return }
        val sip = m.groupValues[1]
        val sport = m.groupValues[2].toIntOrNull()
        val dip = m.groupValues[3]
        val dport = m.groupValues[4].toIntOrNull()
        val proto = m.groupValues[5].uppercase()
        val len = trailingLen.find(l)?.groupValues?.get(1)?.toLongOrNull() ?: 0L

        // skip this device's own traffic; keep only the devices we forward
        if (sip == selfIp || dip == selfIp) { pushRaw(l); return }

        val outbound: Boolean
        val local: String
        val remote: String
        val remotePort: Int
        when {
            isRemote(dip) && !isRemote(sip) -> { outbound = true; local = sip; remote = dip; remotePort = dport ?: -1 }
            isRemote(sip) && !isRemote(dip) -> { outbound = false; local = dip; remote = sip; remotePort = sport ?: -1 }
            else -> { pushRaw(l); return }   // LAN-internal or uninteresting
        }
        val now = System.currentTimeMillis()

        mutex.withLock {
            if (clearRequested) { agg.clear(); rawBuf.clear(); clearRequested = false }
            val peer = agg.getOrPut(remote) { MutPeer(remote).also { it.first = now } }
            peer.packets++
            peer.bytes += len
            if (outbound) peer.up += len else peer.down += len
            peer.last = now
            if (peer.sources.size < 12) peer.sources.add(local)
            if (remotePort >= 0) {
                val key = "$proto/$remotePort"
                val ep = peer.eps.getOrPut(key) { Ep() }
                ep.packets++
                ep.bytes += len
            }
            rawBuf.addLast(l)
            while (rawBuf.size > 400) rawBuf.removeFirst()
        }
        maybeResolve(remote, scope)
    }

    private suspend fun handleDns(l: String) {
        try {
            dnsQuery.find(l)?.let { q ->
                val id = q.groupValues[1]
                val name = q.groupValues[2].trimEnd('.')
                if (name.isNotBlank()) {
                    synchronized(txidToName) {
                        txidToName[id] = name
                        while (txidToName.size > 512) txidToName.remove(txidToName.keys.first())
                    }
                }
                return
            }
            // response: map answer A-records to the query name via txid
            val id = dnsAnswerId.find(l)?.groupValues?.get(1) ?: return
            val name = synchronized(txidToName) { txidToName[id] } ?: return
            val ips = dnsARecord.findAll(l).map { it.groupValues[1] }.toList()
            if (ips.isEmpty()) return
            mutex.withLock { for (ip in ips) ipToDomain[ip] = name }
            emit()
        } catch (_: Throwable) {
        }
    }

    private fun maybeResolve(ip: String, scope: CoroutineScope) {
        synchronized(resolving) { if (!resolving.add(ip)) return }
        scope.launch(Dispatchers.IO) {
            val name = try {
                val n = InetAddress.getByName(ip).canonicalHostName
                if (n.isNullOrBlank() || n == ip) null else n
            } catch (_: Throwable) {
                null
            }
            if (name != null) {
                mutex.withLock { if (!ipToDomain.containsKey(ip)) ipToDomain[ip] = name }
                emit()
            }
        }
    }

    private suspend fun pushRaw(l: String) {
        mutex.withLock {
            if (clearRequested) { agg.clear(); rawBuf.clear(); clearRequested = false }
            rawBuf.addLast(l)
            while (rawBuf.size > 400) rawBuf.removeFirst()
        }
    }

    private suspend fun emit() = withContext(Dispatchers.Default) {
        val (peersSnap, rawSnap) = mutex.withLock {
            val ps = agg.values.map { p ->
                CapturePeer(
                    ip = p.ip,
                    host = ipToDomain[p.ip],
                    packets = p.packets,
                    bytes = p.bytes,
                    upBytes = p.up,
                    downBytes = p.down,
                    firstSeenMs = p.first,
                    lastSeenMs = p.last,
                    endpoints = p.eps.entries.map { (k, e) ->
                        val parts = k.split("/")
                        CaptureEndpoint(parts[0], parts.getOrNull(1)?.toIntOrNull() ?: -1, e.packets, e.bytes)
                    }.sortedByDescending { it.bytes },
                    sources = p.sources.toList()
                )
            }.sortedByDescending { it.bytes }
            ps to rawBuf.toList()
        }
        _peers.value = peersSnap
        _raw.value = rawSnap
    }
}
