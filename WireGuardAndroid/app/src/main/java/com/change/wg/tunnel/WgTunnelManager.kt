package com.change.wg.tunnel

import android.app.Application
import android.content.Intent
import android.net.VpnService
import android.util.Log
import com.change.wg.data.*
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.backend.Tunnel
import com.wireguard.config.Config
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.BufferedReader
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

    // ── Polar mesh join (auth + token + pull conf) ──────────────────────

    val meshJoinError = MutableStateFlow<String?>(null)
    val meshJoinInfo  = MutableStateFlow<String?>(null)
    val isJoiningMesh = MutableStateFlow(false)

    /**
     * Onboard this device into a Polar wg-mac mesh.
     *
     * The "skip login + paste conf" path is unaffected — this is an
     * additive flow. Sequence:
     *
     *   1. generate a Curve25519 keypair (wireguard-android.KeyPair)
     *   2. POST /v1/register with {token, pubkey, lan_addrs, ...}
     *   3. server returns device_ip + peers; render wg-quick conf
     *   4. save as a new VPNNode (selected); meta sidecar in prefs
     */
    private val meshScope = kotlinx.coroutines.CoroutineScope(
        kotlinx.coroutines.SupervisorJob() + Dispatchers.IO
    )

    fun joinMesh(token: String, serverUrl: String, listenPort: Int = 51820) {
        meshJoinError.value = null
        meshJoinInfo.value  = null
        isJoiningMesh.value = true
        meshScope.launch {
            try {
                val client = com.change.wg.data.MeshClient(serverUrl.trim())
                val (privB64, pubB64) = com.change.wg.data.MeshClient.newKeypair()

                val hostname = android.os.Build.MODEL.ifBlank { "android-${android.os.Build.ID}" }
                val req = com.change.wg.data.MeshRegisterRequest(
                    token     = token.trim(),
                    pubkey    = pubB64,
                    hostname  = hostname,
                    os        = "android",
                    arch      = android.os.Build.SUPPORTED_64_BIT_ABIS.firstOrNull() ?: "arm64",
                    agent_ver = "wg-mac-app-android-${android.os.Build.VERSION.SDK_INT}",
                    lan_addrs = com.change.wg.data.LanAddrs.enumerate(),
                    wg_listen = listenPort,
                )
                val resp = client.register(req)
                val conf = com.change.wg.data.MeshConfRenderer.render(resp, privB64, listenPort)

                val shortDev = resp.device_id.takeLast(8)
                val role = resp.role ?: "device"
                val node = com.change.wg.data.VPNNode(
                    name = "mesh-$role-$shortDev",
                    config = conf,
                    routeMode = com.change.wg.data.RouteMode.SPLIT,
                    dnsMode = com.change.wg.data.DNSMode.PLAIN,
                    splitInjectedRoutes = resp.mesh_cidr ?: "10.88.0.0/16",
                )
                withContext(Dispatchers.Main) {
                    nodes.value = nodes.value + node
                    selectedNodeId.value = node.id
                    repo.saveNodes(nodes.value)
                    repo.saveSelectedId(node.id)
                    applySelectedToEditor()
                    // Persist mesh metadata sidecar (token / device_id /
                    // server) for a future heartbeat agent. NodeRepository
                    // doesn't have a field for it so use raw prefs keyed
                    // by node id.
                    repo.saveMeshMeta(
                        nodeId = node.id,
                        deviceId = resp.device_id,
                        deviceIp = resp.device_ip,
                        token = resp.token ?: token.trim(),
                        server = serverUrl.trim(),
                        role = role,
                        hubSlug = resp.hub_slug ?: "",
                        siteId = resp.site_id ?: "",
                    )
                    meshJoinInfo.value  = "Joined: $role @ ${resp.device_ip}"
                }
            } catch (e: com.change.wg.data.MeshHttpError) {
                meshJoinError.value = "HTTP ${e.status} — ${e.body.take(180)}"
            } catch (_: com.change.wg.data.MeshBadUrlError) {
                meshJoinError.value = "Bad server URL (need https://…)"
            } catch (e: Throwable) {
                meshJoinError.value = e.message ?: e.toString()
            } finally {
                isJoiningMesh.value = false
            }
        }
    }

    suspend fun leaveMeshAndDeleteSelected() {
        val id = selectedNodeId.value ?: return
        val meta = repo.loadMeshMeta(id)
        if (meta != null) {
            try {
                com.change.wg.data.MeshClient(meta.server)
                    .leave(meta.deviceId, meta.token)
            } catch (_: Throwable) {}
            repo.deleteMeshMeta(id)
        }
        deleteSelectedNode()
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
            // Start our VpnService explicitly BEFORE setState — the
            // GoBackend's internal future needs a running VpnService
            // instance. It tries to start GoBackend.VpnService.class
            // but Android only knows about our WgVpnService subclass.
            val serviceIntent = Intent(app, WgVpnService::class.java)
            app.startService(serviceIntent)
            delay(500) // Give the service time to start and complete the future

            val config = Config.parse(BufferedReader(StringReader(node.config)))
            val tunnel = WgTunnel(node.name)
            activeTunnel = tunnel
            Log.i("WgTunnel", "Connecting to ${node.name}...")
            withContext(Dispatchers.IO) {
                backend.setState(tunnel, Tunnel.State.UP, config)
            }
            tunnelState.value = Tunnel.State.UP
            lastError.value = null
            Log.i("WgTunnel", "Connected!")
        } catch (e: Exception) {
            Log.e("WgTunnel", "Connect failed", e)
            lastError.value = "Connect failed: ${e.localizedMessage ?: e.toString()}"
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
