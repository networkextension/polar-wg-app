package com.change.wg.data

import kotlinx.serialization.Serializable
import java.util.UUID

enum class NodeSource { MANUAL, PLATFORM }
enum class RouteMode { FULL, SPLIT }
enum class DNSMode {
    SYSTEM, PLAIN, DOH;

    val title: String get() = when (this) {
        SYSTEM -> "System DNS"
        PLAIN  -> "Config DNS"
        DOH    -> "DoH (1.1.1.1)"
    }

    val subtitle: String get() = when (this) {
        SYSTEM -> "Use device default"
        PLAIN  -> "Use DNS from wg-quick config"
        DOH    -> "Encrypted DNS via Cloudflare"
    }
}

data class VPNNode(
    val id: String = UUID.randomUUID().toString(),
    var name: String = "Default Node",
    var config: String = "",
    var source: NodeSource = NodeSource.MANUAL,
    var country: String = "",          // emoji flag "🇯🇵" or ""
    var routeMode: RouteMode = RouteMode.FULL,
    var dnsMode: DNSMode = DNSMode.PLAIN,
    var splitInjectedRoutes: String = "",
    // Platform metadata
    var platformProxyId: String? = null,
    var platformProfileId: String? = null,
    var proxyVersion: Int? = null,
)

/** Guess a flag emoji from a server name. */
fun flagEmoji(name: String): String {
    val low = name.lowercase()
    val map = listOf(
        "tokyo" to "🇯🇵", "japan" to "🇯🇵", "jp" to "🇯🇵",
        "us" to "🇺🇸", "united states" to "🇺🇸", "america" to "🇺🇸",
        "london" to "🇬🇧", "uk" to "🇬🇧",
        "frankfurt" to "🇩🇪", "germany" to "🇩🇪", "de" to "🇩🇪",
        "singapore" to "🇸🇬", "sg" to "🇸🇬",
        "sydney" to "🇦🇺", "australia" to "🇦🇺",
        "canada" to "🇨🇦", "toronto" to "🇨🇦",
        "korea" to "🇰🇷", "seoul" to "🇰🇷",
        "hong kong" to "🇭🇰", "hk" to "🇭🇰",
        "india" to "🇮🇳", "mumbai" to "🇮🇳",
        "france" to "🇫🇷", "paris" to "🇫🇷",
        "home" to "🏠", "local" to "🏠", "dev" to "🛠",
    )
    for ((keyword, emoji) in map) {
        if (low.contains(keyword)) return emoji
    }
    return "🌐"
}
