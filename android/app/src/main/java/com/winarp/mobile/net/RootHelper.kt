package com.winarp.mobile.net

import com.winarp.mobile.data.RootState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.BufferedReader
import java.io.InputStreamReader
import java.util.concurrent.TimeUnit

object RootHelper {
    suspend fun checkRoot(): RootState = withContext(Dispatchers.IO) {
        val candidates = listOf("su", "/system/xbin/su", "/system/bin/su", "/sbin/su")
        var sawBinary = false
        for (bin in candidates) {
            try {
                val pb = ProcessBuilder(bin, "-c", "id")
                pb.redirectErrorStream(true)
                val p = pb.start()
                sawBinary = true
                val out = BufferedReader(InputStreamReader(p.inputStream)).readText()
                val finished = p.waitFor(4, TimeUnit.SECONDS)
                if (!finished) {
                    p.destroyForcibly()
                    continue
                }
                if (p.exitValue() == 0 && out.contains("uid=0")) {
                    return@withContext RootState.Available
                }
            } catch (_: Throwable) {
                // try next
            }
        }
        if (sawBinary) RootState.Denied else RootState.Missing
    }

    suspend fun execSu(command: String, timeoutSec: Long = 8): Pair<Int, String> =
        withContext(Dispatchers.IO) {
            try {
                val pb = ProcessBuilder("su", "-c", command)
                pb.redirectErrorStream(true)
                val p = pb.start()
                val out = BufferedReader(InputStreamReader(p.inputStream)).readText()
                val finished = p.waitFor(timeoutSec, TimeUnit.SECONDS)
                if (!finished) {
                    p.destroyForcibly()
                    -1 to "timeout"
                } else {
                    p.exitValue() to out
                }
            } catch (t: Throwable) {
                -1 to (t.message ?: "su failed")
            }
        }
}
