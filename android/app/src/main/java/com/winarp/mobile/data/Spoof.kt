package com.winarp.mobile.data

/**
 * How the on-device web server answers intercepted HTTP:
 *  - SINGLE_PAGE: serve one HTML for every request (quick demo / captive page).
 *  - STATIC_SITE: serve files from a document root (drop an imported folder or a built
 *    Vite/React `dist/` there; SPA fallback to index.html). This is the extensible path.
 *  - REDIRECT: 302 every request to a configured URL.
 */
enum class SpoofMode { SINGLE_PAGE, STATIC_SITE, REDIRECT }

/**
 * Parametrized spoof configuration. Kept UI-editable; device-specific paths (docRoot,
 * single-page file) are resolved by the ViewModel from app storage, not stored here.
 */
data class SpoofConfig(
    val mode: SpoofMode = SpoofMode.SINGLE_PAGE,
    val port: Int = 8080,
    val redirectUrl: String = "",
    val targetHosts: String = "",          // comma/space separated; empty = all HTTP hosts
    val spaFallback: Boolean = true,        // STATIC_SITE: unknown paths -> index.html
    val assistCaptivePortal: Boolean = true // answer OS captive probes so the portal pops
)
