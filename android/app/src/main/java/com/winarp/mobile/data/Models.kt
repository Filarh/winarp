package com.winarp.mobile.data

data class IfaceInfo(
    val name: String,
    val displayName: String,
    val ip: String,
    val prefixLength: Int,
    val mask: String,
    val mac: String,
    val gateway: String,
    val isWifi: Boolean
) {
    val cidr: String
        get() = "$networkAddress/$prefixLength"

    val networkAddress: String
        get() {
            val ipParts = ip.split(".").mapNotNull { it.toIntOrNull() }
            val maskParts = mask.split(".").mapNotNull { it.toIntOrNull() }
            if (ipParts.size != 4 || maskParts.size != 4) return ip
            return ipParts.zip(maskParts).joinToString(".") { (a, b) -> (a and b).toString() }
        }

    override fun toString(): String {
        val kind = if (isWifi) "Wi-Fi" else "网卡"
        return "$kind · $displayName · $ip"
    }
}

data class HostInfo(
    val ip: String,
    val mac: String,
    val name: String = "-",
    val note: String = ""
) {
    val id: String get() = ip

    fun listLabel(): String {
        val n = if (name.isBlank() || name == "-") "" else "  ·  $name"
        return "$ip    $mac$n"
    }
}

data class PoisonTarget(
    val ip: String,
    val mac: String,
    val name: String = "-"
)

enum class RootState {
    Unknown,
    Available,
    Denied,
    Missing
}

data class UiSettings(
    val cidr: String = "",
    val workers: Int = 64,
    val intervalMs: Int = 1000,
    val gateway: String = "",
    val targetSpec: String = "",
    val resolveName: Boolean = true,
    val oneWay: Boolean = false
)
