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

    // --- Polar mesh-join metadata per node -----------------------------------
    //
    // Stored as one JSON blob per node-id key. Lets a (future) heartbeat
    // agent recover device_id + token to call /v1/heartbeat without
    // re-running the join flow. Not part of SerializableNode because the
    // token is sensitive — keep it out of the main blob to keep the
    // "export this node as wg-quick conf" case from leaking it.

    fun saveMeshMeta(
        nodeId: String,
        deviceId: String,
        deviceIp: String,
        token: String,
        server: String,
        role: String,
        hubSlug: String,
        siteId: String,
    ) {
        val raw = json.encodeToString(
            MeshMetaEntry.serializer(),
            MeshMetaEntry(deviceId, deviceIp, token, server, role, hubSlug, siteId),
        )
        prefs.edit().putString("mesh_meta.$nodeId", raw).apply()
    }

    fun loadMeshMeta(nodeId: String): MeshMetaEntry? {
        val raw = prefs.getString("mesh_meta.$nodeId", null) ?: return null
        return try {
            json.decodeFromString(MeshMetaEntry.serializer(), raw)
        } catch (_: Exception) { null }
    }

    fun deleteMeshMeta(nodeId: String) {
        prefs.edit().remove("mesh_meta.$nodeId").apply()
    }
}

@kotlinx.serialization.Serializable
data class MeshMetaEntry(
    val deviceId: String,
    val deviceIp: String,
    val token: String,
    val server: String,
    val role: String,
    val hubSlug: String,
    val siteId: String,
)

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
