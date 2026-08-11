package com.winarp.mobile.net

import android.annotation.SuppressLint
import android.content.Context
import android.net.wifi.WifiManager
import android.os.SystemClock
import com.winarp.mobile.data.IfaceInfo
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.net.Inet4Address
import java.net.NetworkInterface
import java.util.Collections
import java.util.Locale

/**
 * Interface / ARP discovery.
 *
 * On Android 11+ (and hardened AOSP ROMs) the app process is denied the reads a LAN/ARP tool
 * needs: `NetworkInterface.getHardwareAddress()` returns null, sysfs net entries and
 * `/proc/net/arp` are unreadable, and AF_PACKET is blocked. This class therefore prefers the
 * already-present root channel (`su`) for enumeration, MAC, gateway and the neighbor table,
 * and only falls back to the sandboxed Java APIs when root is unavailable.
 */
class NetworkRepository(private val context: Context) {

    // tri-state root cache to avoid spawning `su` repeatedly once we know the answer
    @Volatile private var rootState: Boolean? = null

    // short-lived ARP/neighbor cache so a single scan does not spawn one `su` per host
    @Volatile private var arpCache: Map<String, String> = emptyMap()
    @Volatile private var arpCacheAt: Long = 0L
    private val arpCacheTtlMs = 800L
    private val arpMutex = Mutex()

    // ---------------------------------------------------------------------------------------
    // Interfaces
    // ---------------------------------------------------------------------------------------

    @SuppressLint("MissingPermission")
    suspend fun listIfaces(): List<IfaceInfo> = withContext(Dispatchers.IO) {
        val rootAddrs = readRootIpv4()          // authoritative when root is available
        val result = if (rootAddrs.isNotEmpty()) {
            buildFromRoot(rootAddrs)
        } else {
            buildFromJava()                     // no-root fallback (MAC may be blank)
        }
        result
            .distinctBy { it.name + "/" + it.ip }
            .sortedWith(compareByDescending<IfaceInfo> { it.isWifi }.thenBy { it.name })
    }

    private suspend fun buildFromRoot(rootAddrs: List<RootAddr>): List<IfaceInfo> {
        val macs = readRootMacs()               // name -> mac
        val gws = readRootGateways()            // name -> default gateway
        val wifiGateway = readWifiGateway()
        return rootAddrs.mapNotNull { a ->
            val ip = a.ip
            if (!IpUtils.isValidIpv4(ip) || ip.startsWith("127.")) return@mapNotNull null
            val isWifi = a.name.startsWith("wlan", true) || a.name.startsWith("ap", true)
            val gateway = gws[a.name]?.takeIf { it.isNotBlank() }
                ?: (if (isWifi && wifiGateway.isNotBlank()) wifiGateway else guessGateway(ip, a.prefix))
            IfaceInfo(
                name = a.name,
                displayName = a.name,
                ip = ip,
                prefixLength = a.prefix,
                mask = IpUtils.prefixToMask(a.prefix),
                mac = macs[a.name]?.let { IpUtils.normalizeMac(it) }.orEmpty(),
                gateway = gateway,
                isWifi = isWifi
            )
        }
    }

    @SuppressLint("MissingPermission")
    private fun buildFromJava(): List<IfaceInfo> {
        val result = mutableListOf<IfaceInfo>()
        val wifiGateway = readWifiGateway()
        val nifList = try {
            Collections.list(NetworkInterface.getNetworkInterfaces())
        } catch (_: Throwable) {
            emptyList()
        }
        for (nif in nifList) {
            val up = try {
                nif.isUp && !nif.isLoopback
            } catch (_: Throwable) {
                false
            }
            if (!up) continue

            // MAC via Java may be null on Android 11+ — keep the interface anyway (blank MAC).
            val javaMac = try {
                nif.hardwareAddress?.joinToString(":") { b -> "%02x".format(b) }
            } catch (_: Throwable) {
                null
            }
            val mac = javaMac?.takeIf { !IpUtils.isZeroMac(it) }?.let { IpUtils.normalizeMac(it) }.orEmpty()

            val addrs = try {
                Collections.list(nif.inetAddresses)
                    .filterIsInstance<Inet4Address>()
                    .filter { !it.isLoopbackAddress }
            } catch (_: Throwable) {
                emptyList()
            }
            for (addr in addrs) {
                val ip = addr.hostAddress ?: continue
                val prefix = try {
                    nif.interfaceAddresses.firstOrNull { it.address == addr }?.networkPrefixLength?.toInt()
                } catch (_: Throwable) {
                    null
                } ?: 24
                val isWifi = nif.name.startsWith("wlan", true) || nif.name.startsWith("ap", true)
                val gateway = if (isWifi && wifiGateway.isNotBlank()) wifiGateway else guessGateway(ip, prefix)
                result += IfaceInfo(
                    name = nif.name,
                    displayName = nif.displayName ?: nif.name,
                    ip = ip,
                    prefixLength = prefix,
                    mask = IpUtils.prefixToMask(prefix),
                    mac = mac,
                    gateway = gateway,
                    isWifi = isWifi
                )
            }
        }
        return result
    }

    // ---------------------------------------------------------------------------------------
    // ARP / neighbor table
    // ---------------------------------------------------------------------------------------

    /** IP -> MAC map. Prefers `ip neigh` via root; falls back to in-process /proc/net/arp. */
    suspend fun readProcArp(forceRefresh: Boolean = false): Map<String, String> = withContext(Dispatchers.IO) {
        fun fresh(): Boolean =
            arpCache.isNotEmpty() && SystemClock.elapsedRealtime() - arpCacheAt < arpCacheTtlMs
        if (!forceRefresh && fresh()) return@withContext arpCache
        arpMutex.withLock {
            // another coroutine may have refreshed while we waited for the lock
            if (!forceRefresh && fresh()) return@withLock arpCache
            val map = readRootNeigh().ifEmpty { readProcArpInProcess() }
            arpCache = map
            arpCacheAt = SystemClock.elapsedRealtime()
            map
        }
    }

    private fun readProcArpInProcess(): Map<String, String> {
        val map = linkedMapOf<String, String>()
        try {
            val lines = java.io.File("/proc/net/arp").readLines()
            for (line in lines.drop(1)) {
                val parts = line.trim().split(Regex("\\s+"))
                if (parts.size < 4) continue
                val ip = parts[0]
                val mac = parts[3]
                if (!IpUtils.isValidIpv4(ip)) continue
                if (IpUtils.isZeroMac(mac)) continue
                map[ip] = IpUtils.normalizeMac(mac)
            }
        } catch (_: Throwable) {
            // blocked on Android 10+ — expected
        }
        return map
    }

    private suspend fun readRootNeigh(): Map<String, String> {
        val out = su("ip neigh show") ?: return emptyMap()
        val map = linkedMapOf<String, String>()
        for (raw in out.lineSequence()) {
            val line = raw.trim()
            if (line.isEmpty()) continue
            // 192.168.1.1 dev wlan0 lladdr 50:d2:f5:0f:a9:cf REACHABLE
            val parts = line.split(Regex("\\s+"))
            val ip = parts.firstOrNull() ?: continue
            if (!IpUtils.isValidIpv4(ip)) continue          // skip IPv6 rows
            val li = parts.indexOf("lladdr")
            if (li < 0 || li + 1 >= parts.size) continue
            val mac = parts[li + 1]
            val state = parts.last().uppercase(Locale.US)
            if (state == "FAILED" || state == "INCOMPLETE") continue
            if (IpUtils.isZeroMac(mac)) continue
            map[ip] = IpUtils.normalizeMac(mac)
        }
        return map
    }

    // ---------------------------------------------------------------------------------------
    // Root-backed enumeration helpers
    // ---------------------------------------------------------------------------------------

    private data class RootAddr(val name: String, val ip: String, val prefix: Int)

    private suspend fun readRootIpv4(): List<RootAddr> {
        val out = su("ip -o -4 addr show") ?: return emptyList()
        val list = mutableListOf<RootAddr>()
        for (raw in out.lineSequence()) {
            val line = raw.trim()
            if (line.isEmpty()) continue
            // 36: wlan0    inet 192.168.1.109/24 brd 192.168.1.255 scope global wlan0
            val parts = line.split(Regex("\\s+"))
            val inetIdx = parts.indexOf("inet")
            if (inetIdx < 0 || inetIdx + 1 >= parts.size) continue
            val name = parts.getOrNull(1)?.trimEnd(':') ?: continue
            if (name == "lo") continue
            val cidr = parts[inetIdx + 1]
            val ip = cidr.substringBefore('/')
            val prefix = cidr.substringAfter('/', "24").toIntOrNull() ?: 24
            if (!IpUtils.isValidIpv4(ip)) continue
            list += RootAddr(name, ip, prefix)
        }
        return list
    }

    private suspend fun readRootMacs(): Map<String, String> {
        val out = su("ip -o link show") ?: return emptyMap()
        val map = linkedMapOf<String, String>()
        for (raw in out.lineSequence()) {
            val line = raw.trim()
            if (line.isEmpty()) continue
            // 36: wlan0: <...> mtu 1500 ... link/ether d6:be:ac:b8:09:7e brd ff:ff:ff:ff:ff:ff
            val parts = line.split(Regex("\\s+"))
            val name = parts.getOrNull(1)?.trimEnd(':') ?: continue
            val ei = parts.indexOf("link/ether")
            if (ei < 0 || ei + 1 >= parts.size) continue
            val mac = parts[ei + 1]
            if (!IpUtils.isZeroMac(mac)) map[name] = mac
        }
        return map
    }

    private suspend fun readRootGateways(): Map<String, String> {
        val out = su("ip route show table all") ?: return emptyMap()
        val map = linkedMapOf<String, String>()
        for (raw in out.lineSequence()) {
            val line = raw.trim()
            if (!line.startsWith("default")) continue
            // default via 192.168.1.1 dev wlan0 table wlan0 proto static
            val parts = line.split(Regex("\\s+"))
            val vi = parts.indexOf("via")
            val di = parts.indexOf("dev")
            if (vi < 0 || di < 0 || vi + 1 >= parts.size || di + 1 >= parts.size) continue
            val gw = parts[vi + 1]
            val dev = parts[di + 1]
            if (IpUtils.isValidIpv4(gw)) map.putIfAbsent(dev, gw)
        }
        return map
    }

    /** Run a command as root, caching root availability. Returns stdout on success, else null. */
    private suspend fun su(cmd: String): String? {
        if (rootState == false) return null
        val (code, out) = RootHelper.execSu(cmd)
        if (code != 0) {
            // non-zero here means su was denied/missing (these `ip` reads always exit 0 with root).
            // Disable the root path for the session so we don't spawn `su` on every host during a scan.
            rootState = false
            return null
        }
        rootState = true
        return out
    }

    // ---------------------------------------------------------------------------------------
    // Non-root gateway fallbacks
    // ---------------------------------------------------------------------------------------

    @SuppressLint("MissingPermission")
    private fun readWifiGateway(): String {
        return try {
            val wm = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
            @Suppress("DEPRECATION")
            val gw = wm.dhcpInfo?.gateway ?: return ""
            if (gw == 0) return ""
            String.format(
                Locale.US,
                "%d.%d.%d.%d",
                gw and 0xff,
                gw shr 8 and 0xff,
                gw shr 16 and 0xff,
                gw shr 24 and 0xff
            )
        } catch (_: Throwable) {
            ""
        }
    }

    private fun guessGateway(ip: String, prefix: Int): String {
        // common home gateway: x.x.x.1
        return try {
            val hosts = IpUtils.cidrHosts(ip, prefix, excludeNetworkAndBroadcast = true)
            hosts.firstOrNull { it.endsWith(".1") } ?: hosts.firstOrNull().orEmpty()
        } catch (_: Throwable) {
            ""
        }
    }
}
