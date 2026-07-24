package com.winarp.mobile.net

import android.annotation.SuppressLint
import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.wifi.WifiManager
import com.winarp.mobile.data.IfaceInfo
import java.net.Inet4Address
import java.net.NetworkInterface
import java.util.Collections
import java.util.Locale

class NetworkRepository(private val context: Context) {

    @SuppressLint("MissingPermission")
    fun listIfaces(): List<IfaceInfo> {
        val result = mutableListOf<IfaceInfo>()
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val wifiGateway = readWifiGateway()

        val activeLp: LinkProperties? = cm.activeNetwork?.let { cm.getLinkProperties(it) }
        val networks = cm.allNetworks
        val linkMap = networks.mapNotNull { n ->
            val lp = cm.getLinkProperties(n) ?: return@mapNotNull null
            val caps = cm.getNetworkCapabilities(n)
            val transportWifi = caps?.hasTransport(android.net.NetworkCapabilities.TRANSPORT_WIFI) == true
            lp to transportWifi
        }

        val nifList = Collections.list(NetworkInterface.getNetworkInterfaces())
        for (nif in nifList) {
            if (!nif.isUp || nif.isLoopback) continue
            val mac = try {
                nif.hardwareAddress?.joinToString(":") { b -> "%02x".format(b) } ?: continue
            } catch (_: Throwable) {
                continue
            }
            if (IpUtils.isZeroMac(mac)) continue

            val addrs = Collections.list(nif.inetAddresses)
                .filterIsInstance<Inet4Address>()
                .filter { !it.isLoopbackAddress }
            for (addr in addrs) {
                val ip = addr.hostAddress ?: continue
                val prefix = nif.interfaceAddresses
                    .firstOrNull { it.address == addr }
                    ?.networkPrefixLength
                    ?.toInt()
                    ?: 24
                val isWifi = nif.name.startsWith("wlan", true) ||
                    nif.name.startsWith("ap", true) ||
                    linkMap.any { (lp, wifi) ->
                        wifi && lp.linkAddresses.any { la ->
                            (la.address as? Inet4Address)?.hostAddress == ip
                        }
                    } ||
                    (activeLp?.interfaceName == nif.name && linkMap.any { it.second })

                val gateway = when {
                    isWifi && wifiGateway.isNotBlank() -> wifiGateway
                    else -> guessGateway(ip, prefix)
                }

                result += IfaceInfo(
                    name = nif.name,
                    displayName = nif.displayName ?: nif.name,
                    ip = ip,
                    prefixLength = prefix,
                    mask = IpUtils.prefixToMask(prefix),
                    mac = IpUtils.normalizeMac(mac),
                    gateway = gateway,
                    isWifi = isWifi
                )
            }
        }

        return result
            .distinctBy { it.name + "/" + it.ip }
            .sortedWith(compareByDescending<IfaceInfo> { it.isWifi }.thenBy { it.name })
    }

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

    fun readProcArp(): Map<String, String> {
        val map = linkedMapOf<String, String>()
        try {
            val lines = java.io.File("/proc/net/arp").readLines()
            for (line in lines.drop(1)) {
                val parts = line.trim().split(Regex("\\s+"))
                if (parts.size < 4) continue
                val ip = parts[0]
                val mac = parts[3]
                if (!IpUtils.isValidIpv4(ip)) continue
                if (mac == "00:00:00:00:00:00") continue
                map[ip] = IpUtils.normalizeMac(mac)
            }
        } catch (_: Throwable) {
            // ignore
        }
        return map
    }
}
