package com.change.wg.data

import android.content.Context
import android.content.SharedPreferences
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

/**
 * Simple SharedPreferences-based persistence for VPN nodes.
 * Matches iOS's Keychain-based profile storage.
 */
class NodeRepository(context: Context) {
    private val prefs: SharedPreferences =
        context.getSharedPreferences("wg_nodes", Context.MODE_PRIVATE)
    private val json = Json { ignoreUnknownKeys = true; prettyPrint = false }

    fun loadNodes(): List<VPNNode> {
        val raw = prefs.getString("nodes_json", null) ?: return emptyList()
        return try {
            json.decodeFromString<List<SerializableNode>>(raw).map { it.toVPNNode() }
        } catch (_: Exception) {
            emptyList()
        }
    }

    fun saveNodes(nodes: List<VPNNode>) {
        val raw = json.encodeToString(nodes.map { it.toSerializable() })
        prefs.edit().putString("nodes_json", raw).apply()
    }

    fun loadSelectedId(): String? = prefs.getString("selected_id", null)
    fun saveSelectedId(id: String?) {
        prefs.edit().putString("selected_id", id).apply()
    }

    var isSkippedLogin: Boolean
        get() = prefs.getBoolean("skipped_login", false)
        set(value) { prefs.edit().putBoolean("skipped_login", value).apply() }
}

/**
 * Kotlinx.serialization-friendly mirror of VPNNode.
 * (VPNNode uses enums which need explicit serializers.)
 */
@kotlinx.serialization.Serializable
data class SerializableNode(
    val id: String,
    val name: String,
    val config: String,
    val source: String,
    val country: String,
    val routeMode: String,
    val dnsMode: String,
    val splitInjectedRoutes: String,
    val platformProxyId: String? = null,
    val platformProfileId: String? = null,
    val proxyVersion: Int? = null,
)

fun VPNNode.toSerializable() = SerializableNode(
    id, name, config, source.name, country,
    routeMode.name, dnsMode.name, splitInjectedRoutes,
    platformProxyId, platformProfileId, proxyVersion
)

fun SerializableNode.toVPNNode() = VPNNode(
    id, name, config,
    NodeSource.valueOf(source),
    country,
    RouteMode.valueOf(routeMode),
    DNSMode.valueOf(dnsMode),
    splitInjectedRoutes,
    platformProxyId, platformProfileId, proxyVersion
)
