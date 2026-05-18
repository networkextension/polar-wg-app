package com.change.wg

import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.material3.LocalTextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import android.widget.Toast
import com.change.wg.data.flagEmoji
import com.change.wg.tunnel.WgTunnelManager
import com.wireguard.android.backend.Tunnel
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {

    private lateinit var tunnelManager: WgTunnelManager

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        tunnelManager = WgTunnelManager(application)
        tunnelManager.load()

        setContent {
            MaterialTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    MainScreen(tunnelManager)
                }
            }
        }
    }
}

@Composable
fun MainScreen(tm: WgTunnelManager) {
    val nodes by tm.nodes.collectAsState()
    val selectedId by tm.selectedNodeId.collectAsState()
    val state by tm.tunnelState.collectAsState()
    val error by tm.lastError.collectAsState()
    val isSkipped by tm.isSkippedLogin.collectAsState()
    val configText by tm.configText.collectAsState()
    var showConfig by remember { mutableStateOf(false) }
    var editableConfig by remember { mutableStateOf("") }

    if (!isSkipped) {
        // Simple skip-login screen
        Column(
            modifier = Modifier.fillMaxSize().padding(32.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Text("🛡️ WireGuard", style = MaterialTheme.typography.headlineLarge)
            Spacer(Modifier.height(16.dp))
            Text("Secure and fast VPN", style = MaterialTheme.typography.bodyMedium)
            Spacer(Modifier.height(32.dp))
            Button(onClick = { tm.skipLogin() }) {
                Text("Get Started")
            }
        }
        return
    }

    val selected = nodes.find { it.id == selectedId }
    val isConnected = state == Tunnel.State.UP
    val flag = selected?.let {
        if (it.country.isNotEmpty()) it.country else flagEmoji(it.name)
    } ?: "🌐"

    // VPN permission launcher — Android requires user consent before
    // establishing a VPN. VpnService.prepare() returns an Intent if
    // permission hasn't been granted yet; null if already granted.
    val vpnPermissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            // Permission granted — now actually connect
            tm.saveCurrentNode()
            CoroutineScope(Dispatchers.Main).launch { tm.connect() }
        } else {
            tm.lastError.value = "VPN permission denied"
        }
    }

    fun doConnect() {
        val prepareIntent: Intent? = tm.prepareVpn()
        if (prepareIntent != null) {
            // Need to ask user for VPN permission first
            vpnPermissionLauncher.launch(prepareIntent)
        } else {
            // Already have permission — connect directly
            tm.saveCurrentNode()
            CoroutineScope(Dispatchers.Main).launch { tm.connect() }
        }
    }

    Column(modifier = Modifier.fillMaxSize().padding(16.dp).verticalScroll(rememberScrollState())) {
        // Header
        Text("Connect to VPN", style = MaterialTheme.typography.headlineMedium)
        Text(
            "Secure and fast WireGuard VPN",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Spacer(Modifier.height(16.dp))

        // Hero card
        Card(
            modifier = Modifier.fillMaxWidth(),
            elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(flag, style = MaterialTheme.typography.headlineLarge)
                    Spacer(Modifier.width(12.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            selected?.name ?: "No Node",
                            style = MaterialTheme.typography.titleMedium
                        )
                        Text(
                            if (isConnected) "● Connected" else "● Disconnected",
                            style = MaterialTheme.typography.bodySmall,
                            color = if (isConnected)
                                MaterialTheme.colorScheme.primary
                            else
                                MaterialTheme.colorScheme.error
                        )
                    }
                }
                Spacer(Modifier.height(12.dp))
                Button(
                    onClick = {
                        if (isConnected) tm.disconnect()
                        else doConnect()
                    },
                    modifier = Modifier.fillMaxWidth().height(48.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = if (isConnected)
                            MaterialTheme.colorScheme.error
                        else
                            MaterialTheme.colorScheme.primary
                    )
                ) {
                    Text(if (isConnected) "Disconnect" else "Connect")
                }
            }
        }

        Spacer(Modifier.height(20.dp))

        // Error
        error?.let {
            Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
            Spacer(Modifier.height(8.dp))
        }

        // Node list
        Text("Nodes", style = MaterialTheme.typography.titleSmall)
        Spacer(Modifier.height(8.dp))

        nodes.forEach { node ->
            val isSelected = node.id == selectedId
            val nodeFlag = if (node.country.isNotEmpty()) node.country else flagEmoji(node.name)

            Card(
                onClick = { tm.selectNode(node.id) },
                modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                colors = CardDefaults.cardColors(
                    containerColor = if (isSelected)
                        MaterialTheme.colorScheme.primaryContainer
                    else
                        MaterialTheme.colorScheme.surfaceVariant
                )
            ) {
                Row(
                    modifier = Modifier.padding(12.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(nodeFlag, style = MaterialTheme.typography.titleMedium)
                    Spacer(Modifier.width(12.dp))
                    Text(node.name, modifier = Modifier.weight(1f))
                    if (isSelected && isConnected) {
                        Text("✅", style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }

        Spacer(Modifier.height(20.dp))

        // Polar Mesh join section
        MeshJoinSection(tm)

        Spacer(Modifier.height(20.dp))

        // Config editor toggle (paste-config path; works without login)
        OutlinedButton(
            onClick = {
                if (!showConfig) editableConfig = configText
                showConfig = !showConfig
            },
            modifier = Modifier.fillMaxWidth()
        ) {
            Text(if (showConfig) "Hide Config" else "Edit Config")
        }

        if (showConfig) {
            Spacer(Modifier.height(8.dp))
            OutlinedTextField(
                value = editableConfig,
                onValueChange = { editableConfig = it },
                modifier = Modifier.fillMaxWidth().height(250.dp),
                textStyle = LocalTextStyle.current.copy(fontFamily = FontFamily.Monospace),
                label = { Text("wg-quick config") }
            )
            Spacer(Modifier.height(8.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = {
                    tm.configText.value = editableConfig
                    tm.saveCurrentNode()
                }) {
                    Text("Save")
                }
                OutlinedButton(onClick = {
                    editableConfig = configText
                }) {
                    Text("Reset")
                }
            }
        }

        Spacer(Modifier.height(32.dp))
    }
}

/**
 * Polar Mesh onboarding section. The skip-login + paste-config path
 * stays usable above; this is additive. Token is admin-issued; on
 * submit the manager generates a keypair, calls /v1/register, renders
 * a wg-quick conf, and adds it as a new VPNNode.
 */
private enum class MeshTokenKind { Polar, Tailscale, Unknown }

private fun meshTokenKindOf(raw: String): MeshTokenKind {
    val t = raw.trim()
    return when {
        t.startsWith("polar_wg_") -> MeshTokenKind.Polar
        t.startsWith("tskey-")    -> MeshTokenKind.Tailscale
        else                      -> MeshTokenKind.Unknown
    }
}

@Composable
fun MeshJoinSection(tm: WgTunnelManager) {
    var server by remember { mutableStateOf("https://zen.4950.store") }
    var token by remember { mutableStateOf("") }
    val isJoining by tm.isJoiningMesh.collectAsState()
    val joinErr  by tm.meshJoinError.collectAsState()
    val joinInfo by tm.meshJoinInfo.collectAsState()
    var expanded by remember { mutableStateOf(false) }
    val tokenKind = meshTokenKindOf(token)
    val ctx = LocalContext.current

    OutlinedButton(
        onClick = { expanded = !expanded },
        modifier = Modifier.fillMaxWidth()
    ) {
        Text(if (expanded) "Hide Mesh Join" else "Join Polar Mesh")
    }
    if (!expanded) return

    Spacer(Modifier.height(8.dp))
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(12.dp)) {
            Text(
                "Paste an admin-issued token. The app generates a Curve25519 keypair on this device; the private key never leaves.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(Modifier.height(8.dp))
            OutlinedTextField(
                value = server,
                onValueChange = { server = it },
                label = { Text("Server URL") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(Modifier.height(8.dp))
            OutlinedTextField(
                value = token,
                onValueChange = { token = it },
                label = { Text("Mesh Token") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
                textStyle = LocalTextStyle.current.copy(fontFamily = FontFamily.Monospace),
            )
            Spacer(Modifier.height(8.dp))
            joinErr?.let {
                Text(it, color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall)
            }
            joinInfo?.let {
                Text(it, color = MaterialTheme.colorScheme.primary,
                    style = MaterialTheme.typography.bodySmall)
            }

            if (tokenKind == MeshTokenKind.Tailscale) {
                Spacer(Modifier.height(8.dp))
                TailscaleRedirectCard(ctx = ctx, server = server.trim(), token = token.trim())
            }

            Button(
                onClick = { tm.joinMesh(token = token, serverUrl = server) },
                enabled = !isJoining && token.isNotBlank() && server.isNotBlank()
                    && tokenKind != MeshTokenKind.Tailscale,
                modifier = Modifier.fillMaxWidth().padding(top = 4.dp)
            ) {
                Text(when {
                    isJoining -> "Joining…"
                    tokenKind == MeshTokenKind.Tailscale -> "Use Tailscale instead ↑"
                    else -> "Join"
                })
            }
        }
    }
}

@Composable
private fun TailscaleRedirectCard(ctx: Context, server: String, token: String) {
    val cmd = "tailscale up --login-server=$server --authkey=$token"
    Card(
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.tertiaryContainer,
            contentColor = MaterialTheme.colorScheme.onTertiaryContainer,
        ),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Text(
                "🪶 This is a Tailscale token (tskey-…), not a wg-mac token.",
                style = MaterialTheme.typography.bodyMedium,
            )
            Spacer(Modifier.height(6.dp))
            Text(
                "Install the official Tailscale app and run:",
                style = MaterialTheme.typography.bodySmall,
            )
            Spacer(Modifier.height(6.dp))
            Surface(
                color = MaterialTheme.colorScheme.surface,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(
                    cmd,
                    style = MaterialTheme.typography.bodySmall.copy(
                        fontFamily = FontFamily.Monospace,
                    ),
                    modifier = Modifier.padding(8.dp),
                )
            }
            Spacer(Modifier.height(8.dp))
            Row(modifier = Modifier.fillMaxWidth()) {
                OutlinedButton(
                    onClick = {
                        val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                        cm.setPrimaryClip(ClipData.newPlainText("tailscale up", cmd))
                        Toast.makeText(ctx, "Command copied", Toast.LENGTH_SHORT).show()
                    },
                    modifier = Modifier.weight(1f),
                ) { Text("Copy command") }
                Spacer(Modifier.width(8.dp))
                OutlinedButton(
                    onClick = { openTailscalePlayStore(ctx) },
                    modifier = Modifier.weight(1f),
                ) { Text("Open Play Store") }
            }
        }
    }
}

private fun openTailscalePlayStore(ctx: Context) {
    val pkg = "com.tailscale.ipn"
    val market = Intent(Intent.ACTION_VIEW, Uri.parse("market://details?id=$pkg"))
        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    try {
        ctx.startActivity(market)
    } catch (_: ActivityNotFoundException) {
        ctx.startActivity(
            Intent(Intent.ACTION_VIEW, Uri.parse("https://play.google.com/store/apps/details?id=$pkg"))
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        )
    }
}
