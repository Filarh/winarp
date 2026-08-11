package com.winarp.mobile.data

/** Which top-level screen is shown. */
enum class AppScreen { Main, Sniffer }

/** One remote service (proto + port) a peer was seen using. */
data class CaptureEndpoint(
    val proto: String,
    val port: Int,
    val packets: Int,
    val bytes: Long
)

/**
 * Aggregated view of one remote host the target talked to, as an immutable snapshot for the UI.
 * Grouping happens in CaptureEngine so the screen shows one row per peer instead of a log storm.
 */
data class CapturePeer(
    val ip: String,
    val host: String?,        // domain / reverse-DNS if known, else null
    val packets: Int,
    val bytes: Long,
    val upBytes: Long,        // target -> peer
    val downBytes: Long,      // peer -> target
    val firstSeenMs: Long,
    val lastSeenMs: Long,
    val endpoints: List<CaptureEndpoint>
) {
    val id: String get() = ip
}
