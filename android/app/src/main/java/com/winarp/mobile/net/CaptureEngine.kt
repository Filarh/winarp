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
 * Runs tcpdump on an interface and turns the packet firehose into a grouped, per-peer view:
 * one [CapturePeer] per remote host (packets, bytes up/down, services), plus a bounded ring of
 * raw lines (the "noise"). This keeps the sniffer readable instead of a log storm.
 */
class CaptureEngine {

    private val _peers = MutableStateFlow<List<CapturePeer>>(emptyList())
    val peers: StateFlow<List<CapturePeer>> = _peers.asStateFlow()

    private val _raw = MutableStateFlow<List<String>>(emptyList())
    val raw: StateFlow<List<String>> = _raw.asStateFlow()

    private val _running = MutableStateFlow(false)
    val running: StateFlow<Boolean> = _running.asStateFlow()

    private val _target = MutableStateFlow<String?>(null)
    val target: StateFlow<String?> = _target.asStateFlow()

    private var proc: Process? = null
    private var job: Job? = null

    private val mutex = Mutex()
    private val agg = LinkedHashMap<String, MutPeer>()
    private val rawBuf = ArrayDeque<String>()
    private val resolving = HashSet<String>()
    private var host: String? = null
    @Volatile private var clearRequested = false

    private class Ep(var packets: Int = 0, var bytes: Long = 0)
    private class MutPeer(val ip: String) {
        var hostName: String? = null
        var packets = 0
        var bytes = 0L
        var up = 0L
        var down = 0L
        var first = 0L
        var last = 0L
        val eps = LinkedHashMap<String, Ep>()
    }

    // IP.port  >  IP.port :  proto ...  <len>
    private val line = Regex(
        """(\d+\.\d+\.\d+\.\d+)(?:\.(\d+))?\s*>\s*(\d+\.\d+\.\d+\.\d+)(?:\.(\d+))?:\s*([A-Za-z0-9]+)"""
    )
    private val trailingLen = Regex("""(\d+)\s*$""")

    fun start(scope: CoroutineScope, ifName: String, targetHost: String?) {
        stop()
        host = targetHost?.takeIf { it.isNotBlank() }
        _target.value = host
        agg.clear(); rawBuf.clear(); resolving.clear()
        _peers.value = emptyList(); _raw.value = emptyList()
        val filter = if (host == null) "ip and not arp" else "ip and host $host and not arp"
        val p = RootNet.spawnCaptureRaw(ifName, filter) ?: return
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
                // stream closed / process killed
            } finally {
                emit()
                _running.value = false
            }
        }
    }

    fun stop() {
        try {
            proc?.destroyForcibly()
        } catch (_: Throwable) {
        }
        proc = null
        job?.cancel()
        job = null
        _running.value = false
    }

    fun clear() {
        clearRequested = true
        _peers.value = emptyList()
        _raw.value = emptyList()
    }

    private suspend fun handle(l: String, scope: CoroutineScope) {
        val m = line.find(l) ?: run { pushRaw(l); return }
        val sip = m.groupValues[1]
        val sport = m.groupValues[2].toIntOrNull()
        val dip = m.groupValues[3]
        val dport = m.groupValues[4].toIntOrNull()
        val proto = m.groupValues[5].uppercase()
        val len = trailingLen.find(l)?.groupValues?.get(1)?.toLongOrNull() ?: 0L

        // remote = the side that is not the target (fallback: dst side)
        val outbound = when (host) {
            null -> true
            sip -> true
            else -> false
        }
        val remote = if (outbound) dip else sip
        val remotePort = (if (outbound) dport else sport) ?: -1
        val now = System.currentTimeMillis()

        mutex.withLock {
            if (clearRequested) {
                agg.clear(); rawBuf.clear(); clearRequested = false
            }
            val peer = agg.getOrPut(remote) { MutPeer(remote).also { it.first = now } }
            peer.packets++
            peer.bytes += len
            if (outbound) peer.up += len else peer.down += len
            peer.last = now
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

    private fun maybeResolve(ip: String, scope: CoroutineScope) {
        synchronized(resolving) {
            if (!resolving.add(ip)) return
        }
        scope.launch(Dispatchers.IO) {
            val name = try {
                val n = InetAddress.getByName(ip).canonicalHostName
                if (n.isNullOrBlank() || n == ip) null else n
            } catch (_: Throwable) {
                null
            }
            if (name != null) {
                mutex.withLock { agg[ip]?.hostName = name }
                emit()
            }
        }
    }

    private suspend fun pushRaw(l: String) {
        mutex.withLock {
            rawBuf.addLast(l)
            while (rawBuf.size > 400) rawBuf.removeFirst()
        }
    }

    private suspend fun emit() = withContext(Dispatchers.Default) {
        val (peersSnap, rawSnap) = mutex.withLock {
            val ps = agg.values.map { p ->
                CapturePeer(
                    ip = p.ip,
                    host = p.hostName,
                    packets = p.packets,
                    bytes = p.bytes,
                    upBytes = p.up,
                    downBytes = p.down,
                    firstSeenMs = p.first,
                    lastSeenMs = p.last,
                    endpoints = p.eps.entries
                        .map { (k, e) ->
                            val parts = k.split("/")
                            CaptureEndpoint(parts[0], parts.getOrNull(1)?.toIntOrNull() ?: -1, e.packets, e.bytes)
                        }
                        .sortedByDescending { it.bytes }
                )
            }.sortedByDescending { it.bytes }
            ps to rawBuf.toList()
        }
        _peers.value = peersSnap
        _raw.value = rawSnap
    }
}
