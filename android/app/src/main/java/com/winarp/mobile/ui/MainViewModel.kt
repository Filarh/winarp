package com.winarp.mobile.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.winarp.mobile.data.HostInfo
import com.winarp.mobile.data.IfaceInfo
import com.winarp.mobile.data.RootState
import com.winarp.mobile.net.ArpPoisoner
import com.winarp.mobile.net.IpUtils
import com.winarp.mobile.net.LanScanner
import com.winarp.mobile.net.NativeArp
import com.winarp.mobile.net.NetworkRepository
import com.winarp.mobile.net.RootHelper
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
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
    val scanning: Boolean = false,
    val attacking: Boolean = false,
    val scanProgress: Pair<Int, Int>? = null,
    val status: String = "界面已就绪",
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

    init {
        appendLog("WinARP Android - 局域网扫描 / 多线程 ARP 污染")
        appendLog("提示: 扫描可无 Root；断网攻击需要 Root + AF_PACKET")
        appendLog("仅用于 CTF / 授权沙箱")
        if (!NativeArp.loaded) {
            appendLog("[!] native 库加载失败: ${NativeArp.loadError}")
        } else {
            appendLog("[+] native 引擎已加载")
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
                        status = if (list.isEmpty()) "未发现可用网卡，请连接 Wi-Fi" else "已加载 ${list.size} 个网卡"
                    )
                }
                if (list.isEmpty()) {
                    appendLog("[-] 没有可用 IPv4 网卡")
                } else {
                    appendLog("[+] 网卡 ${list.size} 个")
                    list.forEach {
                        appendLog("    ${it.name} ip=${it.ip} mac=${it.mac} gw=${it.gateway.ifBlank { "-" }}")
                    }
                }
            } catch (t: Throwable) {
                appendLog("[-] 网卡加载失败: ${t.message}")
                _state.update { it.copy(status = "网卡加载失败") }
            }
        }
    }

    fun checkRoot() {
        viewModelScope.launch {
            val rs = RootHelper.checkRoot()
            _state.update { it.copy(rootState = rs) }
            when (rs) {
                RootState.Available -> appendLog("[+] Root 可用")
                RootState.Denied -> appendLog("[!] 检测到 su 但未授权 Root")
                RootState.Missing -> appendLog("[!] 未检测到 Root 环境（攻击功能不可用）")
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
            appendLog("[-] 请先选择网卡")
            return
        }
        val workers = st.workers.toIntOrNull() ?: 64
        val cidr = st.cidr.ifBlank { iface.cidr }

        _state.update {
            it.copy(
                scanning = true,
                status = "正在扫描 $cidr ...",
                scanProgress = 0 to 0,
                hosts = emptyList(),
                selectedHostIps = emptySet()
            )
        }
        appendLog("[*] 开始扫描 $cidr workers=$workers")

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
                            status = "扫描中 $done/$total"
                        )
                    }
                }
                _state.update {
                    it.copy(
                        hosts = hosts,
                        scanning = false,
                        scanProgress = null,
                        status = "扫描完成，发现 ${hosts.size} 台设备",
                        selectedHostIps = emptySet()
                    )
                }
                appendLog("[+] 扫描完成: ${hosts.size} hosts")
                hosts.take(30).forEach { h ->
                    appendLog("    ${h.ip}  ${h.mac}  ${h.name}")
                }
                if (hosts.size > 30) appendLog("    ... ${hosts.size - 30} more")
            } catch (t: Throwable) {
                _state.update {
                    it.copy(scanning = false, scanProgress = null, status = "扫描失败")
                }
                appendLog("[-] 扫描失败: ${t.message}")
            }
        }
    }

    fun attackSelected() {
        val st = _state.value
        val ips = st.hosts.filter { it.ip in st.selectedHostIps }.map { it.ip }
        if (ips.isEmpty()) {
            appendLog("[-] 请先在列表中选择目标")
            _state.update { it.copy(status = "未选择目标") }
            return
        }
        startAttack(ips, "selected")
    }

    fun attackRange() {
        val st = _state.value
        val ips = IpUtils.collectTargets(st.targetSpec, st.fromIp, st.toIp)
        if (ips.isEmpty()) {
            appendLog("[-] 目标 IP/段 为空或无效")
            _state.update { it.copy(status = "目标无效") }
            return
        }
        startAttack(ips, "range")
    }

    private fun startAttack(targets: List<String>, tag: String) {
        val st = _state.value
        if (st.attacking || st.scanning) return
        val iface = st.selectedIface
        if (iface == null) {
            appendLog("[-] 无网卡")
            return
        }
        val gateway = st.gateway.ifBlank { iface.gateway }
        if (!IpUtils.isValidIpv4(gateway)) {
            appendLog("[-] 网关无效")
            _state.update { it.copy(status = "网关无效") }
            return
        }
        val workers = st.workers.toIntOrNull() ?: 32
        val interval = st.intervalMs.toIntOrNull() ?: 1000

        _state.update { it.copy(attacking = true, status = "正在解析目标...") }
        appendLog("[*] 启动攻击 tag=$tag targets=${targets.size} workers=$workers")

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
                    _state.update { it.copy(attacking = false, status = "没有可达目标") }
                    appendLog("[-] no reachable targets")
                    return@launch
                }

                val gwMac = resolveGatewayMac(iface, gateway)
                if (gwMac == null) {
                    _state.update { it.copy(attacking = false, status = "网关 MAC 解析失败") }
                    appendLog("[-] gateway MAC $gateway not found")
                    return@launch
                }

                _state.update { it.copy(status = "污染中 · ${poisonTargets.size} 目标") }
                poisoner.start(
                    iface = iface,
                    targets = poisonTargets,
                    gatewayIp = gateway,
                    gatewayMac = gwMac,
                    intervalMs = interval,
                    oneWay = st.oneWay,
                    log = { appendLog(it) },
                    onStopped = {
                        _state.update { cur ->
                            cur.copy(attacking = false, status = "已停止")
                        }
                    }
                )
            } catch (t: Throwable) {
                _state.update { it.copy(attacking = false, status = "攻击失败") }
                appendLog("[-] ${t.message}")
            }
        }
    }

    fun stopAttack() {
        viewModelScope.launch {
            _state.update { it.copy(status = "正在停止...") }
            poisoner.stop { appendLog(it) }
            _state.update { it.copy(attacking = false, status = "已停止") }
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

    private fun appendLog(line: String) {
        val stamped = "${timeFmt.format(Date())}  $line"
        _state.update { st ->
            val next = (st.logs + stamped).let { if (it.size > 500) it.takeLast(500) else it }
            st.copy(logs = next)
        }
    }
}
