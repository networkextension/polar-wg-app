package com.change.wg.tunnel

import android.app.Application
import android.content.Intent
import android.net.VpnService
import com.change.wg.data.*
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.backend.Tunnel
import com.wireguard.config.Config
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.withContext
import java.io.StringReader

/**
 * Wraps the wireguard-android GoBackend and manages VPN state.
 * Equivalent to iOS TunnelManager.
 */
class WgTunnelManager(private val app: Application) {

    private val repo = NodeRepository(app)
    private val backend: GoBackend by lazy { GoBackend(app) }

    // Current tunnel handle (null = not connected)
    private var activeTunnel: WgTunnel? = null

    // Observable state
    val nodes = MutableStateFlow<List<VPNNode>>(emptyList())
    val selectedNodeId = MutableStateFlow<String?>(null)
    val tunnelState = MutableStateFlow(Tunnel.State.DOWN)
    val lastError = MutableStateFlow<String?>(null)
    val isSkippedLogin = MutableStateFlow(false)

    // Editor state (mirrors iOS configText / routeMode / dnsMode)
    val configText = MutableStateFlow("")
    val routeMode = MutableStateFlow(RouteMode.FULL)
    val dnsMode = MutableStateFlow(DNSMode.PLAIN)
    val splitInjectedRoutes = MutableStateFlow("")
    val nodeName = MutableStateFlow("")

    fun load() {
        val loaded = repo.loadNodes()
        if (loaded.isEmpty()) {
            val initial = VPNNode(name = "Default Node", config = DEFAULT_CONFIG)
            nodes.value = listOf(initial)
            repo.saveNodes(nodes.value)
            selectedNodeId.value = initial.id
        } else {
            nodes.value = loaded
            selectedNodeId.value = repo.loadSelectedId() ?: loaded.first().id
        }
        isSkippedLogin.value = repo.isSkippedLogin
        applySelectedToEditor()
    }

    val selectedNode: VPNNode?
        get() = nodes.value.find { it.id == selectedNodeId.value }

    fun selectNode(id: String) {
        syncEditorToNode()
        selectedNodeId.value = id
        repo.saveSelectedId(id)
        applySelectedToEditor()
    }

    fun addNode(name: String? = null) {
        syncEditorToNode()
        val base = selectedNode
        val node = VPNNode(
            name = name ?: "Node ${nodes.value.size + 1}",
            config = base?.config ?: DEFAULT_CONFIG,
            routeMode = base?.routeMode ?: RouteMode.FULL,
            dnsMode = base?.dnsMode ?: DNSMode.PLAIN,
            splitInjectedRoutes = base?.splitInjectedRoutes ?: "",
        )
        nodes.value = nodes.value + node
        selectedNodeId.value = node.id
        repo.saveNodes(nodes.value)
        repo.saveSelectedId(node.id)
        applySelectedToEditor()
    }

    fun deleteSelectedNode() {
        if (nodes.value.size <= 1) return
        val id = selectedNodeId.value ?: return
        nodes.value = nodes.value.filter { it.id != id }
        selectedNodeId.value = nodes.value.first().id
        repo.saveNodes(nodes.value)
        repo.saveSelectedId(selectedNodeId.value)
        applySelectedToEditor()
    }

    fun skipLogin() {
        isSkippedLogin.value = true
        repo.isSkippedLogin = true
    }

    fun logout() {
        disconnect()
        isSkippedLogin.value = false
        repo.isSkippedLogin = false
    }

    // ── Connect / Disconnect ───────────────────────────────────────────

    /**
     * Check if VPN permission has been granted.
     * Returns the intent to show if permission is needed, or null if OK.
     */
    fun prepareVpn(): Intent? {
        return VpnService.prepare(app)
    }

    suspend fun connect() {
        syncEditorToNode()
        val node = selectedNode ?: run {
            lastError.value = "No node selected"
            return
        }
        try {
            val config = Config.parse(StringReader(node.config))
            val tunnel = WgTunnel(node.name)
            activeTunnel = tunnel
            withContext(Dispatchers.IO) {
                backend.setState(tunnel, Tunnel.State.UP, config)
            }
            tunnelState.value = Tunnel.State.UP
            lastError.value = null
        } catch (e: Exception) {
            lastError.value = "Connect failed: ${e.localizedMessage}"
            tunnelState.value = Tunnel.State.DOWN
        }
    }

    fun disconnect() {
        try {
            activeTunnel?.let { tunnel ->
                backend.setState(tunnel, Tunnel.State.DOWN, null)
            }
        } catch (_: Exception) {}
        activeTunnel = null
        tunnelState.value = Tunnel.State.DOWN
    }

    fun getStatistics(): String? {
        val tunnel = activeTunnel ?: return null
        return try {
            val stats = backend.getStatistics(tunnel)
            buildString {
                appendLine("tx_bytes=${stats.totalTx()}")
                appendLine("rx_bytes=${stats.totalRx()}")
            }
        } catch (_: Exception) {
            null
        }
    }

    // ── Persistence ────────────────────────────────────────────────────

    fun saveCurrentNode() {
        syncEditorToNode()
        repo.saveNodes(nodes.value)
    }

    private fun applySelectedToEditor() {
        val node = selectedNode ?: return
        configText.value = node.config
        routeMode.value = node.routeMode
        dnsMode.value = node.dnsMode
        splitInjectedRoutes.value = node.splitInjectedRoutes
        nodeName.value = node.name
    }

    private fun syncEditorToNode() {
        val id = selectedNodeId.value ?: return
        nodes.value = nodes.value.map {
            if (it.id == id) it.copy(
                config = configText.value,
                name = nodeName.value,
                routeMode = routeMode.value,
                dnsMode = dnsMode.value,
                splitInjectedRoutes = splitInjectedRoutes.value,
            ) else it
        }
        repo.saveNodes(nodes.value)
    }

    // ── Platform / Manual helpers ──────────────────────────────────────

    val platformNodes: List<VPNNode> get() = nodes.value.filter { it.source == NodeSource.PLATFORM }
    val manualNodes: List<VPNNode> get() = nodes.value.filter { it.source == NodeSource.MANUAL }

    companion object {
        val DEFAULT_CONFIG = """
            [Interface]
            PrivateKey = yPDHiay/NDkJE9OyUT0J8qhuJXpihZw1aD7Xl4JJEVw=
            Address = 10.88.0.2/24
            DNS = 1.1.1.1, 1.0.0.1

            [Peer]
            PublicKey = XXFzbjDln02y/aWfo2RFVZ/foiMC/NEo9QKXDdk9SXk=
            Endpoint = 172.16.203.128:51820
            AllowedIPs = 0.0.0.0/0
            PersistentKeepalive = 25
        """.trimIndent()
    }
}

/** Simple Tunnel implementation for wireguard-android. */
class WgTunnel(private val tunnelName: String) : Tunnel {
    override fun getName(): String = tunnelName
    override fun onStateChange(newState: Tunnel.State) {}
}
