package com.winarp.mobile.net

import android.content.Context
import android.os.Process as AndroidProcess
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Runs a privileged helper process via `su` + `app_process` so AF_PACKET works on Magisk/rooted devices.
 * Protocol (line based):
 *   SEND ifName dstMac srcMac op senderMac senderIp targetMac targetIp
 *   PING
 *   EXIT
 * replies: OK / ERR message
 */
class RootArpDaemon(private val context: Context) {
    private val mutex = Mutex()
    private var process: java.lang.Process? = null
    private var writer: OutputStreamWriter? = null
    private var reader: BufferedReader? = null
    private val started = AtomicBoolean(false)

    val isAlive: Boolean
        get() = process?.isAlive == true

    suspend fun ensureStarted(): String? = mutex.withLock {
        if (process?.isAlive == true) return null
        withContext(Dispatchers.IO) { startLocked() }
    }

    suspend fun send(
        ifName: String,
        dstMac: String,
        srcMac: String,
        op: Int,
        senderMac: String,
        senderIp: String,
        targetMac: String,
        targetIp: String
    ): String? = mutex.withLock {
        withContext(Dispatchers.IO) {
            val err = startLocked()
            if (err != null) return@withContext err
            val cmd = listOf(
                "SEND", ifName, dstMac, srcMac, op.toString(),
                senderMac, senderIp, targetMac, targetIp
            ).joinToString(" ")
            writeLine(cmd)
            val resp = readLine(timeoutMs = 3000) ?: return@withContext "no response from root daemon"
            when {
                resp == "OK" || resp.startsWith("OK ") -> null
                resp.startsWith("ERR") -> resp.removePrefix("ERR").trim().ifBlank { "root send failed" }
                else -> resp
            }
        }
    }

    suspend fun stop() = mutex.withLock {
        withContext(Dispatchers.IO) {
            try {
                writeLine("EXIT")
            } catch (_: Throwable) {
            }
            destroyLocked()
        }
    }

    private fun startLocked(): String? {
        if (process?.isAlive == true) return null
        destroyLocked()
        return try {
            val apkPath = context.applicationInfo.sourceDir
            val nativeDir = context.applicationInfo.nativeLibraryDir
            val niceName = context.packageName + ":rootarp"

            // app_process launches our Java entry with root uid
            val shell =
                "export CLASSPATH='$apkPath'; " +
                    "export LD_LIBRARY_PATH='$nativeDir'; " +
                    "exec app_process /system/bin com.winarp.mobile.net.RootArpEntry '$niceName'"
            val cmd = arrayOf("su", "-c", shell)
            val pb = ProcessBuilder(*cmd)
            pb.redirectErrorStream(true)
            pb.directory(context.filesDir)
            val p = pb.start()
            process = p
            writer = OutputStreamWriter(p.outputStream, Charsets.UTF_8)
            reader = BufferedReader(InputStreamReader(p.inputStream, Charsets.UTF_8))

            val hello = readLine(timeoutMs = 5000)
            if (hello == null) {
                destroyLocked()
                return "root daemon no hello (deny su?)"
            }
            if (!hello.startsWith("READY")) {
                destroyLocked()
                return "root daemon: $hello"
            }
            started.set(true)
            null
        } catch (t: Throwable) {
            destroyLocked()
            t.message ?: "failed to start root daemon"
        }
    }

    private fun writeLine(line: String) {
        val w = writer ?: throw IllegalStateException("daemon not running")
        w.write(line)
        w.write("\n")
        w.flush()
    }

    private fun readLine(timeoutMs: Long): String? {
        val p = process ?: return null
        val r = reader ?: return null
        val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMs)
        while (System.nanoTime() < deadline) {
            if (r.ready()) {
                return r.readLine()
            }
            if (!p.isAlive) {
                return try {
                    r.readLine()
                } catch (_: Throwable) {
                    null
                }
            }
            try {
                Thread.sleep(15)
            } catch (_: InterruptedException) {
                return null
            }
        }
        // last chance
        return try {
            if (r.ready()) r.readLine() else null
        } catch (_: Throwable) {
            null
        }
    }

    private fun destroyLocked() {
        try {
            writer?.close()
        } catch (_: Throwable) {
        }
        try {
            reader?.close()
        } catch (_: Throwable) {
        }
        try {
            process?.destroyForcibly()
        } catch (_: Throwable) {
        }
        writer = null
        reader = null
        process = null
        started.set(false)
    }
}

/**
 * Entry point executed as root through app_process.
 */
object RootArpEntry {
    @JvmStatic
    fun main(args: Array<String>) {
        try {
            // Ensure native lib can be found
            try {
                System.loadLibrary("winarp_native")
                NativeArp.forceMarkLoaded()
            } catch (_: Throwable) {
                // try absolute path candidates from LD_LIBRARY_PATH
                val paths = System.getenv("LD_LIBRARY_PATH")
                    ?.split(":")
                    ?.filter { it.isNotBlank() }
                    .orEmpty()
                var loaded = false
                for (dir in paths) {
                    val f = File(dir, "libwinarp_native.so")
                    if (f.exists()) {
                        System.load(f.absolutePath)
                        NativeArp.forceMarkLoaded()
                        loaded = true
                        break
                    }
                }
                if (!loaded) {
                    println("ERR native load failed uid=${AndroidProcess.myUid()}")
                    return
                }
            }

            println("READY uid=${AndroidProcess.myUid()}")
            System.out.flush()

            val reader = BufferedReader(InputStreamReader(System.`in`, Charsets.UTF_8))
            while (true) {
                val line = reader.readLine() ?: break
                val trimmed = line.trim()
                if (trimmed.isEmpty()) continue
                if (trimmed == "EXIT" || trimmed == "QUIT") {
                    println("OK bye")
                    System.out.flush()
                    break
                }
                if (trimmed == "PING") {
                    println("OK pong")
                    System.out.flush()
                    continue
                }
                if (trimmed.startsWith("SEND ")) {
                    val parts = trimmed.split(Regex("\\s+"))
                    if (parts.size < 9) {
                        println("ERR bad SEND args")
                        System.out.flush()
                        continue
                    }
                    // SEND if dst src op senderMac senderIp targetMac targetIp
                    val err = try {
                        NativeArp.sendArp(
                            ifName = parts[1],
                            dstMac = parts[2],
                            srcMac = parts[3],
                            op = parts[4].toInt(),
                            senderMac = parts[5],
                            senderIp = parts[6],
                            targetMac = parts[7],
                            targetIp = parts[8]
                        )
                    } catch (t: Throwable) {
                        t.message ?: "send exception"
                    }
                    if (err == null) {
                        println("OK")
                    } else {
                        println("ERR $err")
                    }
                    System.out.flush()
                    continue
                }
                println("ERR unknown command")
                System.out.flush()
            }
        } catch (t: Throwable) {
            println("ERR ${t.message}")
            System.out.flush()
        }
    }
}
