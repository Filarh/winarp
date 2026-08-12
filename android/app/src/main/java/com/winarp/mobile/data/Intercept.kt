package com.winarp.mobile.data

/**
 * Platform-agnostic model for "how much of THIS device's HTTPS can we actually see, and how".
 *
 * The interception core (transparent TLS MITM + capture) is shared and knows nothing about
 * platforms. Each platform contributes a [InterceptPlan] — an ordered, honest capability ladder
 * from best (in-process, beats pinning) to worst (metadata only) — as pure data. Adding a new
 * platform is one entry in the planner, never a change to the MITM core. That's the decoupling.
 */

enum class Platform(val label: String) {
    MacOS("macOS"),
    Windows("Windows"),
    Linux("Linux / PC"),
    AndroidPhone("Android phone"),
    AndroidTv("Android TV / Fire TV"),
    IOS("iPhone / iPad"),
    Roku("Roku"),
    Tizen("Samsung Tizen TV"),
    WebOs("LG webOS TV"),
    Chromecast("Chromecast / Google TV"),
    IoT("IoT / embedded"),
    Printer("Printer"),
    Router("Router / gateway"),
    Unknown("Unknown device")
}

/** How much we can do on a device, best first. Each tier states its own ceiling. */
enum class InterceptTier(val label: String) {
    IN_PROCESS("In-process capture — beats pinning"),
    CA_INSTALL("Install our CA — decrypts non-pinned"),
    TRANSPARENT_MITM("Transparent MITM — non-validating only"),
    METADATA_ONLY("Metadata only — no decryption")
}

/**
 * One rung of the ladder for a device.
 * [automatable] = WinARP can do it from here (network side). Otherwise [steps] is the manual
 * guide the user runs ON that device (it's their device — that's allowed and expected).
 */
data class InterceptStep(
    val tier: InterceptTier,
    val title: String,
    val why: String,
    val automatable: Boolean,
    val steps: List<String> = emptyList(),
    val tool: String? = null
)

/** A device's classification + its ordered, best-first plan. */
data class InterceptPlan(
    val platform: Platform,
    val controllable: Boolean,
    val summary: String,
    val ladder: List<InterceptStep>
) {
    /** The single best rung we can offer for this device. */
    val best: InterceptStep? get() = ladder.firstOrNull()
    /** True if anything WinARP can do from the network side applies. */
    val hasNetworkPath: Boolean get() = ladder.any { it.automatable }
}
