package com.winarp.mobile.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.winarp.mobile.data.AppScreen
import com.winarp.mobile.data.CapturePeer
import com.winarp.mobile.data.HostInfo
import com.winarp.mobile.data.IfaceInfo
import com.winarp.mobile.data.RootState
import com.winarp.mobile.data.SpoofConfig
import com.winarp.mobile.data.SpoofMode
import com.winarp.mobile.net.ArpPoisoner
import com.winarp.mobile.net.CaptureEngine
import com.winarp.mobile.net.IpUtils
import com.winarp.mobile.net.LanScanner
import com.winarp.mobile.net.NativeArp
import com.winarp.mobile.net.NetworkRepository
import com.winarp.mobile.net.RootHelper
import com.winarp.mobile.net.RootNet
import com.winarp.mobile.net.WebServer
import com.winarp.mobile.store.FileLogger
import com.winarp.mobile.store.Prefs
import com.winarp.mobile.store.Settings
import java.io.File
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

data class MainUiState(
    val ifaces: List<IfaceInfo> = emptyList(),
    val selectedIfaceIndex: Int = 0,
    val hosts: List<HostInfo> = emptyList(),
    val selectedHostIps: Set<String> = emptySet(),
    val cidr: String = "",
    val workers: String = "64",
    val intervalMs: String = "1000",
    val gateway: String = "",
    val targetSpec: String = "",
    val fromIp: String = "",
    val toIp: String = "",
    val resolveName: Boolean = true,
    val oneWay: Boolean = false,
    val forwardMitm: Boolean = false,
    val screen: AppScreen = AppScreen.Main,
    val showRaw: Boolean = false,
    val forcePlaintext: Boolean = false,
    val spoofConfig: SpoofConfig = SpoofConfig(),
    val spoofHtml: String = WebServer.DEFAULT_PAGE,
    val scanning: Boolean = false,
    val attacking: Boolean = false,
    val scanProgress: Pair<Int, Int>? = null,
    val status: String = "Ready",
    val rootState: RootState = RootState.Unknown,
    val logs: List<String> = emptyList(),
    val nativeLoaded: Boolean = NativeArp.loaded
) {
    val selectedIface: IfaceInfo?
        get() = ifaces.getOrNull(selectedIfaceIndex)
}

class MainViewModel(app: Application) : AndroidViewModel(app) {
    private val repo = NetworkRepository(app)
    private val scanner = LanScanner(repo)
    private val poisoner = ArpPoisoner(app, repo, viewModelScope)

    private val _state = MutableStateFlow(MainUiState())
    val state: StateFlow<MainUiState> = _state.asStateFlow()

    private val timeFmt = SimpleDateFormat("HH:mm:ss", Locale.getDefault())

    private val capture = CaptureEngine()
    val capturePeers: StateFlow<List<CapturePeer>> = capture.peers
    val captureRaw: StateFlow<List<String>> = capture.raw
    val captureRunning: StateFlow<Boolean> = capture.running
    val captureTarget: StateFlow<String?> = capture.target

    private val web = WebServer()
    val webRunning: StateFlow<Boolean> = web.running
    val webRequests: StateFlow<Int> = web.requests
    val webLog: StateFlow<List<String>> = web.log
    private val spoofDir = File(getApplication<Application>().filesDir, "spoofsite")
    private val singleFile = File(getApplication<Application>().filesDir, "spoof_single.html")

    private val prefs = Prefs(app)
    private val fileLog = FileLogger(app)

    init {
        // restore sticky settings from previous runs
        val s = prefs.load()
        _state.update {
            it.copy(
                workers = s.workers, intervalMs = s.intervalMs,
                resolveName = s.resolveName, oneWay = s.oneWay, forwardMitm = s.forwardMitm,
                cidr = s.cidr, gateway = s.gateway, targetSpec = s.targetSpec, fromIp = s.fromIp, toIp = s.toIp,
                spoofHtml = s.spoofHtml.ifBlank { WebServer.DEFAULT_PAGE },
                spoofConfig = it.spoofConfig.copy(
                    mode = runCatching { SpoofMode.valueOf(s.spoofModeName) }.getOrDefault(SpoofMode.SINGLE_PAGE),
                    redirectUrl = s.redirectUrl, targetHosts = s.targetHosts,
                    spaFallback = s.spaFallback, assistCaptivePortal = s.assistCaptivePortal
                )
            )
        }
        // auto-persist sticky settings on change (distinctUntilChanged ignores log/scan churn)
        state.map { it.toSettings() }.distinctUntilChanged().onEach { prefs.save(it) }.launchIn(viewModelScope)

        appendLog("WinARP Android - LAN scan / multi-thread ARP poison")
        appendLog("Tip: scanning works without root; disruption attack needs Root + AF_PACKET")
        appendLog("For CTF / authorized sandbox only")
        appendLog("[i] logs -> ${fileLog.path()}")
        if (!NativeArp.loaded) {
            appendLog("[!] native library failed to load: ${NativeArp.loadError}")
        } else {
            appendLog("[+] native engine loaded")
        }
        refreshIfaces()
        checkRoot()
    }

    fun refreshIfaces() {
        viewModelScope.launch {
            try {
                val list = repo.listIfaces()
                _state.update { st ->
                    val idx = st.selectedIfaceIndex.coerceIn(0, (list.size - 1).coerceAtLeast(0))
                    val selected = list.getOrNull(idx)
                    st.copy(
                        ifaces = list,
                        selectedIfaceIndex = if (list.isEmpty()) 0 else idx,
                        cidr = selected?.cidr ?: st.cidr,
                        gateway = selected?.gateway ?: st.gateway,
                        status = if (list.isEmpty()) "No usable NIC found, please connect Wi-Fi" else "Loaded ${list.size} NIC(s)"
                    )
                }
                if (list.isEmpty()) {
                    appendLog("[-] no usable IPv4 NIC")
                } else {
                    appendLog("[+] ${list.size} NIC(s)")
                    list.forEach {
                        appendLog("    ${it.name} ip=${it.ip} mac=${it.mac} gw=${it.gateway.ifBlank { "-" }}")
                    }
                }
            } catch (t: Throwable) {
                appendLog("[-] NIC load failed: ${t.message}")
                _state.update { it.copy(status = "NIC load failed") }
            }
        }
    }

    fun checkRoot() {
        viewModelScope.launch {
            val rs = RootHelper.checkRoot()
            _state.update { it.copy(rootState = rs) }
            when (rs) {
                RootState.Available -> appendLog("[+] Root available")
                RootState.Denied -> appendLog("[!] su detected but root not authorized")
                RootState.Missing -> appendLog("[!] no root environment detected (attack unavailable)")
                RootState.Unknown -> Unit
            }
        }
    }

    fun selectIface(index: Int) {
        _state.update { st ->
            val iface = st.ifaces.getOrNull(index)
            st.copy(
                selectedIfaceIndex = index,
                cidr = iface?.cidr ?: st.cidr,
                gateway = iface?.gateway ?: st.gateway
            )
        }
    }

    fun updateCidr(v: String) = _state.update { it.copy(cidr = v) }
    fun updateWorkers(v: String) = _state.update { it.copy(workers = v.filter { ch -> ch.isDigit() }.ifBlank { "" }) }
    fun updateInterval(v: String) = _state.update { it.copy(intervalMs = v.filter { ch -> ch.isDigit() }.ifBlank { "" }) }
    fun updateGateway(v: String) = _state.update { it.copy(gateway = v.trim()) }
    fun updateTargetSpec(v: String) = _state.update { it.copy(targetSpec = v.trim()) }
    fun updateFromIp(v: String) = _state.update { it.copy(fromIp = v.trim()) }
    fun updateToIp(v: String) = _state.update { it.copy(toIp = v.trim()) }
    fun updateResolveName(v: Boolean) = _state.update { it.copy(resolveName = v) }
    fun updateOneWay(v: Boolean) = _state.update { it.copy(oneWay = v) }
    fun updateForwardMitm(v: Boolean) = _state.update { it.copy(forwardMitm = v) }

    fun toggleHost(ip: String) {
        _state.update { st ->
            val set = st.selectedHostIps.toMutableSet()
            if (!set.add(ip)) set.remove(ip)
            st.copy(selectedHostIps = set)
        }
    }

    fun selectAllHosts(on: Boolean) {
        _state.update { st ->
            st.copy(selectedHostIps = if (on) st.hosts.map { it.ip }.toSet() else emptySet())
        }
    }

    fun clearLogs() {
        _state.update { it.copy(logs = emptyList()) }
    }

    fun scan() {
        val st = _state.value
        if (st.scanning || st.attacking) return
        val iface = st.selectedIface
        if (iface == null) {
            appendLog("[-] select a NIC first")
            return
        }
        val workers = st.workers.toIntOrNull() ?: 64
        val cidr = st.cidr.ifBlank { iface.cidr }

        _state.update {
            it.copy(
                scanning = true,
                status = "Scanning $cidr ...",
                scanProgress = 0 to 0,
                hosts = emptyList(),
                selectedHostIps = emptySet()
            )
        }
        appendLog("[*] start scan $cidr workers=$workers")

        viewModelScope.launch {
            try {
                val hosts = scanner.scan(
                    iface = iface,
                    cidr = cidr,
                    workers = workers,
                    resolveName = st.resolveName
                ) { done, total ->
                    _state.update { cur ->
                        cur.copy(
                            scanProgress = done to total,
                            status = "Scanning $done/$total"
                        )
                    }
                }
                _state.update {
                    it.copy(
                        hosts = hosts,
                        scanning = false,
                        scanProgress = null,
                        status = "Scan complete, ${hosts.size} device(s) found",
                        selectedHostIps = emptySet()
                    )
                }
                appendLog("[+] scan complete: ${hosts.size} hosts")
                hosts.take(30).forEach { h ->
                    appendLog("    ${h.ip}  ${h.mac}  ${h.name}")
                }
                if (hosts.size > 30) appendLog("    ... ${hosts.size - 30} more")
            } catch (t: Throwable) {
                _state.update {
                    it.copy(scanning = false, scanProgress = null, status = "Scan failed")
                }
                appendLog("[-] Scan failed: ${t.message}")
            }
        }
    }

    fun attackSelected() {
        val st = _state.value
        val ips = st.hosts.filter { it.ip in st.selectedHostIps }.map { it.ip }
        if (ips.isEmpty()) {
            appendLog("[-] select targets from the list first")
            _state.update { it.copy(status = "No targets selected") }
            return
        }
        startAttack(ips, "selected")
    }

    fun attackRange() {
        val st = _state.value
        val ips = IpUtils.collectTargets(st.targetSpec, st.fromIp, st.toIp)
        if (ips.isEmpty()) {
            appendLog("[-] target IP/range empty or invalid")
            _state.update { it.copy(status = "Invalid target") }
            return
        }
        startAttack(ips, "range")
    }

    private fun startAttack(targets: List<String>, tag: String) {
        val st = _state.value
        if (st.attacking || st.scanning) return
        val iface = st.selectedIface
        if (iface == null) {
            appendLog("[-] no NIC")
            return
        }
        val gateway = st.gateway.ifBlank { iface.gateway }
        if (!IpUtils.isValidIpv4(gateway)) {
            appendLog("[-] Invalid gateway")
            _state.update { it.copy(status = "Invalid gateway") }
            return
        }
        val workers = st.workers.toIntOrNull() ?: 32
        val interval = st.intervalMs.toIntOrNull() ?: 1000

        _state.update { it.copy(attacking = true, status = "Resolving targets...") }
        appendLog("[*] launch attack tag=$tag targets=${targets.size} workers=$workers")

        viewModelScope.launch {
            try {
                val poisonTargets = poisoner.resolveTargets(
                    iface = iface,
                    targets = targets,
                    gateway = gateway,
                    workers = workers,
                    resolveName = st.resolveName,
                    log = { appendLog(it) }
                )
                if (poisonTargets.isEmpty()) {
                    _state.update { it.copy(attacking = false, status = "No reachable targets") }
                    appendLog("[-] no reachable targets")
                    return@launch
                }

                val gwMac = resolveGatewayMac(iface, gateway)
                if (gwMac == null) {
                    _state.update { it.copy(attacking = false, status = "Gateway MAC resolution failed") }
                    appendLog("[-] gateway MAC $gateway not found")
                    return@launch
                }

                _state.update { it.copy(status = "Poisoning · ${poisonTargets.size} targets") }
                poisoner.start(
                    iface = iface,
                    targets = poisonTargets,
                    gatewayIp = gateway,
                    gatewayMac = gwMac,
                    intervalMs = interval,
                    oneWay = st.oneWay,
                    mitm = st.forwardMitm,
                    log = { appendLog(it) },
                    onStopped = {
                        _state.update { cur ->
                            cur.copy(attacking = false, status = "Stopped")
                        }
                    }
                )
            } catch (t: Throwable) {
                _state.update { it.copy(attacking = false, status = "Attack failed") }
                appendLog("[-] ${t.message}")
            }
        }
    }

    fun stopAttack() {
        viewModelScope.launch {
            _state.update { it.copy(status = "Stopping...") }
            poisoner.stop { appendLog(it) }
            _state.update { it.copy(attacking = false, status = "Stopped") }
        }
    }

    private suspend fun resolveGatewayMac(iface: IfaceInfo, gateway: String): String? {
        val table = repo.readProcArp()[gateway]
        if (!table.isNullOrBlank() && !IpUtils.isZeroMac(table)) return table
        if (NativeArp.loaded) {
            val mac = NativeArp.probeArp(iface.name, iface.mac, iface.ip, gateway, 800)
            if (!mac.isNullOrBlank() && !IpUtils.isZeroMac(mac)) return IpUtils.normalizeMac(mac)
        }
        try {
            java.net.InetAddress.getByName(gateway).isReachable(500)
        } catch (_: Throwable) {
        }
        return repo.readProcArp()[gateway]?.takeIf { !IpUtils.isZeroMac(it) }
    }

    /** Open the dedicated traffic screen and start capturing the current target. */
    fun openSniffer() {
        val iface = _state.value.selectedIface
        if (iface == null) {
            appendLog("[-] no NIC selected")
            return
        }
        _state.update { it.copy(screen = AppScreen.Sniffer) }
        if (!capture.running.value) {
            capture.start(viewModelScope, iface.name, iface.ip, iface.prefixLength)
        }
    }

    fun closeSniffer() {
        capture.setRawEnabled(false)
        if (_state.value.forcePlaintext) {
            _state.value.selectedIface?.let { iface ->
                viewModelScope.launch { RootNet.forcePlaintext(iface.name, false) }
            }
        }
        _state.update { it.copy(screen = AppScreen.Main, showRaw = false, forcePlaintext = false) }
    }

    /** Block DoT (853) + QUIC (UDP/443) so victims fall back to cleartext DNS/TLS (domains appear). */
    fun toggleForcePlaintext() {
        val iface = _state.value.selectedIface ?: return
        val on = !_state.value.forcePlaintext
        _state.update { it.copy(forcePlaintext = on) }
        viewModelScope.launch {
            val err = RootNet.forcePlaintext(iface.name, on)
            when {
                err != null -> appendLog("[!] force plaintext: $err")
                on -> appendLog("[+] force plaintext ON — blocked DoT(853) + QUIC(443)")
                else -> appendLog("[+] force plaintext OFF")
            }
        }
    }

    /** Start/stop the capture from the sniffer screen. */
    fun toggleCapture() {
        if (capture.running.value) {
            capture.stop()
            return
        }
        val iface = _state.value.selectedIface ?: return
        capture.start(viewModelScope, iface.name, iface.ip, iface.prefixLength)
    }

    fun clearCapture() = capture.clear()

    /** Raw packet feed is opt-in: not collected/rendered until the user asks for it. */
    fun toggleRaw() {
        val on = !_state.value.showRaw
        _state.update { it.copy(showRaw = on) }
        capture.setRawEnabled(on)
    }

    // ---- Page spoofing (configurable web server + :80 REDIRECT) ----

    fun openSpoof() = _state.update { it.copy(screen = AppScreen.Spoof) }

    fun closeSpoof() {
        if (web.running.value) stopSpoof()
        _state.update { it.copy(screen = AppScreen.Main) }
    }

    fun updateSpoofMode(m: SpoofMode) = _state.update { it.copy(spoofConfig = it.spoofConfig.copy(mode = m)) }
    fun updateRedirectUrl(v: String) = _state.update { it.copy(spoofConfig = it.spoofConfig.copy(redirectUrl = v.trim())) }
    fun updateTargetHosts(v: String) = _state.update { it.copy(spoofConfig = it.spoofConfig.copy(targetHosts = v)) }
    fun updateSpoofHtml(v: String) = _state.update { it.copy(spoofHtml = v) }
    fun toggleCaptive() = _state.update { it.copy(spoofConfig = it.spoofConfig.copy(assistCaptivePortal = !it.spoofConfig.assistCaptivePortal)) }
    fun toggleSpa() = _state.update { it.copy(spoofConfig = it.spoofConfig.copy(spaFallback = !it.spoofConfig.spaFallback)) }

    /** Absolute path of the document root, so users can push an imported site / Vite dist into it. */
    fun spoofDocRootPath(): String = spoofDir.absolutePath

    fun toggleSpoof() {
        if (web.running.value) stopSpoof() else startSpoof()
    }

    private fun startSpoof() {
        val iface = _state.value.selectedIface
        if (iface == null) {
            appendLog("[-] no NIC selected")
            return
        }
        val st = _state.value
        try {
            singleFile.writeText(st.spoofHtml.ifBlank { WebServer.DEFAULT_PAGE })
            if (!spoofDir.exists()) spoofDir.mkdirs()
            val idx = File(spoofDir, "index.html")
            if (!idx.exists()) idx.writeText(WebServer.DEFAULT_PAGE)
        } catch (t: Throwable) {
            appendLog("[!] spoof storage: ${t.message}")
        }
        val err = web.start(st.spoofConfig, spoofDir, singleFile)
        if (err != null) {
            appendLog("[!] spoof server: $err")
            return
        }
        viewModelScope.launch {
            val re = RootNet.enableHttpRedirect(iface.name, st.spoofConfig.port)
            if (re == null) {
                appendLog("[+] spoof ON — HTTP :80 -> :${st.spoofConfig.port} (poison targets with MITM to feed it)")
            } else {
                appendLog("[!] http redirect: $re")
            }
        }
    }

    private fun stopSpoof() {
        web.stop()
        val iface = _state.value.selectedIface
        val port = _state.value.spoofConfig.port
        if (iface != null) viewModelScope.launch { RootNet.disableHttpRedirect(iface.name, port) }
        appendLog("[*] spoof stopped")
    }

    /** Pick a single host to filter the sniff/attack: explicit From, else target spec, else a selected host. */
    private fun firstTargetIp(): String? {
        val st = _state.value
        val candidate = st.fromIp.ifBlank {
            st.targetSpec.split(',', ' ', '-', '\n', '\t', ';').firstOrNull { IpUtils.isValidIpv4(it.trim()) }?.trim()
                ?: st.selectedHostIps.firstOrNull().orEmpty()
        }
        return candidate.takeIf { IpUtils.isValidIpv4(it) }
    }

    override fun onCleared() {
        super.onCleared()
        capture.stop()
        web.stop()
    }

    private fun MainUiState.toSettings() = Settings(
        workers = workers,
        intervalMs = intervalMs,
        resolveName = resolveName,
        oneWay = oneWay,
        forwardMitm = forwardMitm,
        cidr = cidr,
        gateway = gateway,
        targetSpec = targetSpec,
        fromIp = fromIp,
        toIp = toIp,
        spoofModeName = spoofConfig.mode.name,
        redirectUrl = spoofConfig.redirectUrl,
        targetHosts = spoofConfig.targetHosts,
        spaFallback = spoofConfig.spaFallback,
        assistCaptivePortal = spoofConfig.assistCaptivePortal,
        spoofHtml = spoofHtml
    )

    private fun appendLog(line: String) {
        val ts = synchronized(timeFmt) { timeFmt.format(Date()) }
        val stamped = "$ts  $line"
        fileLog.append(stamped)
        _state.update { st ->
            val next = (st.logs + stamped).let { if (it.size > 500) it.takeLast(500) else it }
            st.copy(logs = next)
        }
    }
}
