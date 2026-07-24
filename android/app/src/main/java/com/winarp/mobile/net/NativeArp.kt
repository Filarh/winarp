package com.winarp.mobile.net

object NativeArp {
    @Volatile
    var loaded: Boolean = false
        private set

    @Volatile
    var loadError: String? = null
        private set

    init {
        try {
            System.loadLibrary("winarp_native")
            loaded = true
        } catch (t: Throwable) {
            loaded = false
            loadError = t.message ?: t.javaClass.simpleName
        }
    }

    /** Used by root app_process helper after System.load(absolutePath). */
    fun forceMarkLoaded() {
        loaded = true
        loadError = null
    }

    fun canOpenRaw(ifName: String): Boolean {
        if (!loaded) return false
        return try {
            nativeCanOpenRaw(ifName)
        } catch (_: Throwable) {
            false
        }
    }

    fun sendArp(
        ifName: String,
        dstMac: String,
        srcMac: String,
        op: Int,
        senderMac: String,
        senderIp: String,
        targetMac: String,
        targetIp: String
    ): String? {
        if (!loaded) return loadError ?: "native not loaded"
        return try {
            val err = nativeSendArp(
                ifName, dstMac, srcMac, op,
                senderMac, senderIp, targetMac, targetIp
            )
            err?.ifBlank { null }
        } catch (t: Throwable) {
            t.message ?: "send failed"
        }
    }

    fun probeArp(
        ifName: String,
        localMac: String,
        localIp: String,
        targetIp: String,
        timeoutMs: Int
    ): String? {
        if (!loaded) return null
        return try {
            nativeProbeArp(ifName, localMac, localIp, targetIp, timeoutMs)
                ?.trim()
                ?.ifBlank { null }
        } catch (_: Throwable) {
            null
        }
    }

    private external fun nativeCanOpenRaw(ifName: String): Boolean

    private external fun nativeSendArp(
        ifName: String,
        dstMac: String,
        srcMac: String,
        op: Int,
        senderMac: String,
        senderIp: String,
        targetMac: String,
        targetIp: String
    ): String?

    private external fun nativeProbeArp(
        ifName: String,
        localMac: String,
        localIp: String,
        targetIp: String,
        timeoutMs: Int
    ): String?
}
