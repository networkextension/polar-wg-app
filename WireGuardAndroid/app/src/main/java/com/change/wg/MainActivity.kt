package com.change.wg

import android.app.Activity
import android.content.Intent
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

        // Config editor toggle
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
