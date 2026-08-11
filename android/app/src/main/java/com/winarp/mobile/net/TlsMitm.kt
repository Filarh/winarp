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
            vs.startHandshake()
            val host = matcher.host ?: run { vs.close(); return }

            val up = SSLContext.getInstance("TLS")
            up.init(null, trustAll, null)
            val us = up.socketFactory.createSocket(host, 443) as SSLSocket
            upstream = us
            val upp = us.getSSLParameters()
            upp.setServerNames(listOf(SNIHostName(host)))
            upp.setApplicationProtocols(arrayOf("http/1.1"))
            us.setSSLParameters(upp)
            us.startHandshake()

            val vIn = victim.inputStream; val vOut = victim.outputStream
            val uIn = upstream.inputStream; val uOut = upstream.outputStream
            val v = victim; val u = upstream
            // upstream -> victim
            thread(name = "tls-down") { pump(uIn, vOut); closeQuiet(v); closeQuiet(u) }
            // victim -> upstream (parse the first request for logging)
            val buf = ByteArray(16384)
            var sniffed = false
            while (true) {
                val n = vIn.read(buf)
                if (n < 0) break
                if (!sniffed) {
                    sniffed = true
                    logRequest(host, String(buf, 0, n.coerceAtMost(2048), Charsets.ISO_8859_1))
                }
                uOut.write(buf, 0, n); uOut.flush()
            }
        } catch (_: Throwable) {
            // handshake failed (pinned/validating client) or connection error
        } finally {
            closeQuiet(victim); closeQuiet(upstream); closeQuiet(raw)
        }
    }

    private fun logRequest(host: String, head: String) {
        val line = head.substringBefore("\r\n")
        val parts = line.split(" ")
        if (parts.size >= 2 && parts[0].length in 3..7) {
            onLine?.invoke("[TLS] ${parts[0]} https://$host${parts[1]}")
        } else {
            onLine?.invoke("[TLS] https://$host (${line.take(40)})")
        }
    }

    private fun pump(inp: java.io.InputStream, out: java.io.OutputStream) {
        val b = ByteArray(16384)
        try {
            while (true) {
                val n = inp.read(b)
                if (n < 0) break
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
