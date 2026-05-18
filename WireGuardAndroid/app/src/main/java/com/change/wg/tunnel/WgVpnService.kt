package com.change.wg.tunnel

import com.wireguard.android.backend.GoBackend

/**
 * Android VPN Service that hosts the WireGuard Go backend.
 * This is the Android equivalent of iOS's PacketTunnelProvider.
 * The actual tunnel logic is in GoBackend; this service just
 * provides the Android VpnService framework integration.
 */
class WgVpnService : GoBackend.VpnService()
