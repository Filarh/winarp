package com.winarp.mobile.net

import com.winarp.mobile.data.InterceptPlan
import com.winarp.mobile.data.InterceptStep
import com.winarp.mobile.data.InterceptTier
import com.winarp.mobile.data.Platform
import java.util.Locale

/**
 * Decides, per device, the best-first honest interception ladder. Pure logic, no Android/UI/root
 * coupling — it turns (vendor, name, open ports) into a [InterceptPlan]. The MITM core consumes the
 * plan; it never reaches back here. Adding a platform = one branch in [ladderFor] + optional
 * detection hints in [classify]. Nothing else changes.
 */
object InterceptPlanner {

    fun plan(vendor: String?, name: String?, openPorts: Set<Int> = emptySet()): InterceptPlan {
        val platform = classify(vendor.orEmpty(), name.orEmpty(), openPorts)
        val controllable = platform in CONTROLLABLE
        return InterceptPlan(
            platform = platform,
            controllable = controllable,
            summary = summaryFor(platform),
            ladder = ladderFor(platform)
        )
    }

    // ---- classification (vendor-first, ports refine) ----

    private fun classify(vendor: String, name: String, ports: Set<Int>): Platform {
        val v = (vendor + " " + name).lowercase(Locale.US)
        // TV / streaming first — their vendors overlap with phones, ports disambiguate
        if (v.contains("roku")) return Platform.Roku
        if (ports.contains(8008) || ports.contains(8009) || v.contains("chromecast") || v.contains("google") && ports.contains(8008))
            return Platform.Chromecast
        if (v.contains("tizen") || (v.contains("samsung") && (ports.contains(8001) || ports.contains(8002))))
            return Platform.Tizen
        if (v.contains("webos") || (v.contains("lg ") && (ports.contains(3000) || ports.contains(3001))))
            return Platform.WebOs
        if (v.contains("amazon") || v.contains("fire tv") || (ports.contains(5555) && v.contains("amazon")))
            return Platform.AndroidTv
        if (v.contains("android tv") || v.contains("bravia") || v.contains("shield") || v.contains("mibox"))
            return Platform.AndroidTv
        // Apple: Mac vs iOS by port fingerprint
        if (v.contains("apple")) {
            if (ports.contains(62078)) return Platform.IOS
            if (ports.any { it in setOf(22, 88, 445, 548, 5900) }) return Platform.MacOS
            return if (ports.contains(7000) || ports.contains(5000)) Platform.IOS else Platform.MacOS
        }
        // Windows / PC NICs
        if (ports.contains(3389) || ports.contains(135) || ports.contains(139) ||
            v.contains("microsoft") || v.contains("dell") || v.contains("hewlett") && ports.contains(445)
        ) {
            if (v.contains("hewlett") && (ports.contains(9100) || ports.contains(631))) return Platform.Printer
            return Platform.Windows
        }
        // Printers
        if (ports.contains(9100) || ports.contains(631) || v.contains("epson") || v.contains("canon") ||
            v.contains("brother") || (v.contains("hewlett") && ports.contains(9100))
        ) return Platform.Printer
        // Routers / gateways
        if (v.contains("tp-link") || v.contains("mercusys") || v.contains("huawei") && ports.contains(80) ||
            v.contains("mikrotik") || v.contains("ubiquiti") || v.contains("zte") || v.contains("routerboard")
        ) return Platform.Router
        // Android phones (common OEM Wi-Fi vendors)
        if (v.contains("xiaomi") || v.contains("oneplus") || v.contains("oppo") || v.contains("vivo") ||
            v.contains("realme") || v.contains("motorola") || v.contains("samsung") || v.contains("google") ||
            v.contains("huawei") || v.contains("honor")
        ) return Platform.AndroidPhone
        // Generic embedded / IoT chipset vendors
        if (v.contains("espressif") || v.contains("tuya") || v.contains("sonoff") || v.contains("shelly") ||
            v.contains("raspberry") || v.contains("texas instr") || v.contains("realtek") || v.contains("azurewave")
        ) return if (v.contains("raspberry")) Platform.Linux else Platform.IoT
        return Platform.Unknown
    }

    private val CONTROLLABLE = setOf(
        Platform.MacOS, Platform.Windows, Platform.Linux, Platform.AndroidPhone,
        Platform.AndroidTv, Platform.IOS
    )

    // ---- shared step factories (DRY) ----

    private fun keylog(browsersOnly: Boolean = false) = InterceptStep(
        tier = InterceptTier.IN_PROCESS,
        title = "Read the app's own TLS keys (SSLKEYLOGFILE)",
        why = "The endpoint voluntarily writes its session keys to a file; Wireshark then decrypts " +
            "everything — including pinned apps — with no MITM and no cert. Runs on the device itself." +
            if (browsersOnly) " Works for Chrome/Firefox/curl/Node; not Safari or most native apps." else "",
        automatable = false,
        tool = "SSLKEYLOGFILE + Wireshark",
        steps = listOf(
            "On the device: set the env var SSLKEYLOGFILE=~/tls.log before launching the browser/app",
            "Capture packets (Wireshark / tcpdump) at the same time",
            "Wireshark → Preferences → Protocols → TLS → (Pre)-Master-Secret log filename = that file",
            "Decrypted HTTP/2 and QUIC/HTTP-3 appear inline"
        )
    )

    private fun ecapture() = InterceptStep(
        tier = InterceptTier.IN_PROCESS,
        title = "In-process capture with eBPF/Frida (ecapture / friTap)",
        why = "Hooks SSL_read/SSL_write inside the process and reads plaintext before encryption, so " +
            "certificate pinning is irrelevant. Needs code execution on the device (root).",
        automatable = false,
        tool = "ecapture / friTap",
        steps = listOf(
            "On the (rooted) device: run ecapture tls  (or friTap -m <app>)",
            "It prints decrypted requests/responses live, even for pinned apps",
            "Only sees that device's own traffic — by design"
        )
    )

    private fun caInstall(platform: Platform) = InterceptStep(
        tier = InterceptTier.CA_INSTALL,
        title = "Install WinARP CA, then transparent MITM",
        why = "Our proxy terminates TLS; once THIS device trusts our CA, all non-pinned HTTPS decrypts " +
            "through it. Pinned apps still reject it — those need in-process capture.",
        automatable = true,
        tool = "WinARP TLS MITM",
        steps = when (platform) {
            Platform.MacOS -> listOf(
                "Settings → Export MITM CA (.pem); copy it to the Mac",
                "Keychain Access → System → File ▸ Import → the .pem",
                "Double-click it → Trust → Always Trust",
                "Attack this host with Keep online (MITM) + Decrypt HTTPS"
            )
            Platform.Windows -> listOf(
                "Export the CA; on Windows run certlm.msc",
                "Trusted Root Certification Authorities → Certificates → Import the .pem",
                "Attack this host with Decrypt HTTPS on"
            )
            Platform.Linux -> listOf(
                "Copy the CA to /usr/local/share/ca-certificates/winarp.crt",
                "sudo update-ca-certificates",
                "Attack this host with Decrypt HTTPS on"
            )
            Platform.IOS -> listOf(
                "Serve/AirDrop the CA to the device; open it → install the Profile",
                "Settings → General → About → Certificate Trust Settings → enable full trust for WinARP",
                "Attack this host with Decrypt HTTPS on"
            )
            Platform.AndroidPhone, Platform.AndroidTv -> listOf(
                "Android 7+ ignores user CAs by default — the device must be ROOTED",
                "Install a system-store CA module (e.g. AlwaysTrustUserCerts, Magisk/KernelSU) and add our CA",
                "Or, if it's your app under test: repackage with apk-mitm / unpin with Frida",
                "Attack this host with Decrypt HTTPS on"
            )
            else -> listOf(
                "Export the CA and add it to this device's trusted roots",
                "Attack this host with Decrypt HTTPS on"
            )
        }
    )

    private fun transparent() = InterceptStep(
        tier = InterceptTier.TRANSPARENT_MITM,
        title = "Transparent MITM (no cert install)",
        why = "Decrypts only clients that DON'T validate certificates — common in IoT, TV apps and " +
            "cheap embedded gear. Validating clients just error out (that's the honest limit).",
        automatable = true,
        tool = "WinARP TLS MITM"
    )

    private fun metadata(reason: String) = InterceptStep(
        tier = InterceptTier.METADATA_ONLY,
        title = "Metadata only (SNI / DNS / IPs)",
        why = reason,
        automatable = true,
        tool = "Sniffer"
    )

    // ---- the catalogue: one branch per platform, best-first ----

    private fun ladderFor(p: Platform): List<InterceptStep> = when (p) {
        Platform.MacOS -> listOf(keylog(browsersOnly = true), caInstall(p))
        Platform.Windows -> listOf(keylog(browsersOnly = true), caInstall(p))
        Platform.Linux -> listOf(keylog(browsersOnly = true), ecapture(), caInstall(p))
        Platform.AndroidPhone -> listOf(ecapture(), caInstall(p), transparent())
        Platform.AndroidTv -> listOf(caInstall(p), transparent(), metadata("Pinned apps (Netflix, Disney+, Prime) can't be decrypted; those are metadata only."))
        Platform.IOS -> listOf(caInstall(p), transparent())
        Platform.IoT -> listOf(transparent(), metadata("If it validates certs, only SNI/DNS/IP are visible."))
        Platform.Printer -> listOf(transparent(), metadata("Admin UI is often plain HTTP (:80) — check the Sniff/Spoof capture."))
        Platform.Roku -> listOf(metadata("Roku has no user CA store and no way to add one — HTTPS can't be decrypted. DNS/SNI only."))
        Platform.Tizen -> listOf(metadata("Stock Tizen has no CA-install path — HTTPS can't be decrypted without a modded TV. Metadata only."))
        Platform.WebOs -> listOf(metadata("Stock webOS uses a fixed trust list — needs a rooted TV to intercept. Metadata only."))
        Platform.Chromecast -> listOf(metadata("Google services are pinned to Google's own CA — no interception. Metadata only."))
        Platform.Router -> listOf(metadata("Log into its admin panel directly instead; on the wire it's metadata only."))
        Platform.Unknown -> listOf(transparent(), metadata("Unknown stack — try transparent MITM; if it validates, metadata only."))
    }

    private fun summaryFor(p: Platform): String = when (p) {
        Platform.MacOS, Platform.Windows, Platform.Linux ->
            "You control this machine — read its keys on-device (beats pinning) or trust our CA for the rest."
        Platform.AndroidPhone -> "Rooted → in-process capture beats pinning; otherwise CA-in-system-store for non-pinned."
        Platform.AndroidTv -> "Non-pinned apps decrypt with our CA (needs root); big streaming apps pin and stay dark."
        Platform.IOS -> "Install + fully trust our CA profile → non-pinned decrypts; pinned apps need a jailbreak."
        Platform.IoT, Platform.Printer -> "Often ignores cert validation → transparent MITM just works. This is WinARP's sweet spot."
        Platform.Roku, Platform.Tizen, Platform.WebOs, Platform.Chromecast ->
            "Closed platform with no CA path — realistically metadata only."
        Platform.Router -> "Manage it from its own admin panel; on the wire it's metadata."
        Platform.Unknown -> "Unclassified — we'll try transparent MITM and fall back to metadata."
    }
}
