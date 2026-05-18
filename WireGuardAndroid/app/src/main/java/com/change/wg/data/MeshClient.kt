package com.change.wg.data

// Polar wg-mac join client + login client (Android).
//
//   /api/login         — bearer cookie session (used by future
//                        per-user endpoints; not required for /v1/*)
//   /v1/register       — keypair join, returns peers + wg_ip
//   /v1/heartbeat      — best-effort, drives "online" in admin UI
//   /v1/leave          — voluntary deregister
//
// Mirrors WireGuardSampleApp/MeshClient.swift on iOS. Same conf
// renderer logic; same skip-login (paste config) path stays untouched.

import com.wireguard.crypto.Key
import com.wireguard.crypto.KeyPair
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import okhttp3.Cookie
import okhttp3.CookieJar
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.net.NetworkInterface
import java.util.concurrent.TimeUnit

private val JSON_MIME = "application/json".toMediaType()
private val jsonCodec = Json { ignoreUnknownKeys = true; encodeDefaults = true }

// --- wire types (match doc/wg-mac-api.md §1) ---------------------------------

@Serializable
data class MeshPeer(
    val pubkey: String = "",
    val wg_ip: String? = null,
    val endpoint: String? = null,
    val site_id: String? = null,
    val hostname: String? = null,
    val allowed_extra: List<String>? = null,
)

@Serializable
data class MeshHub(
    val slug: String? = null,
    val pubkey: String = "",
    val endpoint: String = "",
    val wg_ip: String = "",
)

@Serializable
data class MeshRegisterResponse(
    val device_id: String = "",
    val device_ip: String = "",
    val site_id: String? = null,
    val hub_slug: String? = null,
    val role: String? = null,
    val mesh_cidr: String? = null,
    val hub: MeshHub? = null,
    val peers: List<MeshPeer> = emptyList(),
    val keepalive_sec: Int? = null,
    val refresh_sec: Int? = null,
    val token: String? = null,
    val token_expires: String? = null,
)

@Serializable
data class LanAddr(val iface: String, val cidr: String)

@Serializable
data class MeshRegisterRequest(
    val token: String,
    val pubkey: String,
    val hostname: String,
    val os: String = "android",
    val arch: String = "arm64",
    val agent_ver: String = "wg-mac-app-android-1",
    val lan_addrs: List<LanAddr> = emptyList(),
    val wg_listen: Int = 51820,
    val site_slug: String = "",
)

@Serializable
data class HeartbeatStats(
    val rx_bytes: Long = 0L,
    val tx_bytes: Long = 0L,
    val last_handshake_sec: Int = 0,
)

@Serializable
data class HeartbeatRequest(
    val lan_addrs: List<LanAddr> = emptyList(),
    val wg_endpoint: String? = null,
    val stats: HeartbeatStats? = null,
)

// --- HTTP wrapper ------------------------------------------------------------

class MeshHttpError(val status: Int, val body: String) :
    RuntimeException("HTTP $status: ${body.take(200)}")

class MeshBadUrlError : RuntimeException("bad server URL (need https://…)")

/**
 * Persistent in-memory cookie jar so /api/login's Set-Cookie carries
 * into subsequent v1 calls if the operator ever flips them to
 * cookie-auth. Per-host.
 */
private class InMemoryCookieJar : CookieJar {
    private val store = mutableMapOf<String, MutableList<Cookie>>()
    @Synchronized
    override fun saveFromResponse(url: HttpUrl, cookies: List<Cookie>) {
        store.getOrPut(url.host) { mutableListOf() }.let { list ->
            list.removeAll { existing -> cookies.any { it.name == existing.name } }
            list.addAll(cookies)
        }
    }
    @Synchronized
    override fun loadForRequest(url: HttpUrl): List<Cookie> =
        store[url.host]?.toList() ?: emptyList()
}

class MeshClient(serverRaw: String) {

    private val baseUrl: HttpUrl

    init {
        val trimmed = serverRaw.trim().trimEnd('/')
        val parsed = trimmed.toHttpUrlOrNull() ?: throw MeshBadUrlError()
        baseUrl = parsed
    }

    private val client: OkHttpClient = OkHttpClient.Builder()
        .cookieJar(InMemoryCookieJar())
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(10, TimeUnit.SECONDS)
        .build()

    /** Generate a fresh Curve25519 keypair via wireguard-android's KeyPair.
     *  Returns (privateKeyBase64, publicKeyBase64). */
    companion object {
        fun newKeypair(): Pair<String, String> {
            val kp = KeyPair()
            return kp.privateKey.toBase64() to kp.publicKey.toBase64()
        }
    }

    // --- /v1/register -------------------------------------------------------

    suspend fun register(req: MeshRegisterRequest): MeshRegisterResponse =
        withContext(Dispatchers.IO) {
            val body = jsonCodec.encodeToString(MeshRegisterRequest.serializer(), req)
                .toRequestBody(JSON_MIME)
            val r = Request.Builder()
                .url(baseUrl.newBuilder().addPathSegments("v1/register").build())
                .post(body)
                .build()
            client.newCall(r).execute().use { resp ->
                val s = resp.body?.string() ?: ""
                if (!resp.isSuccessful) throw MeshHttpError(resp.code, s)
                jsonCodec.decodeFromString(MeshRegisterResponse.serializer(), s)
            }
        }

    // --- /v1/heartbeat (best-effort) ---------------------------------------

    suspend fun heartbeat(
        deviceId: String,
        token: String,
        req: HeartbeatRequest,
    ): Boolean = withContext(Dispatchers.IO) {
        val body = jsonCodec.encodeToString(HeartbeatRequest.serializer(), req)
            .toRequestBody(JSON_MIME)
        val r = Request.Builder()
            .url(baseUrl.newBuilder().addPathSegments("v1/heartbeat").build())
            .header("Authorization", "Bearer $token")
            .header("X-Device-Id", deviceId)
            .post(body)
            .build()
        try {
            client.newCall(r).execute().use { it.isSuccessful }
        } catch (_: Throwable) { false }
    }

    // --- /v1/leave ---------------------------------------------------------

    suspend fun leave(deviceId: String, token: String) = withContext(Dispatchers.IO) {
        val r = Request.Builder()
            .url(baseUrl.newBuilder().addPathSegments("v1/leave").build())
            .header("Authorization", "Bearer $token")
            .header("X-Device-Id", deviceId)
            .post(ByteArray(0).toRequestBody())
            .build()
        try { client.newCall(r).execute().close() } catch (_: Throwable) {}
    }

    // --- /api/login (cookie session, optional path) -----------------------

    suspend fun login(email: String, password: String): Boolean = withContext(Dispatchers.IO) {
        @Serializable data class LoginReq(val email: String, val password: String)
        val body = jsonCodec.encodeToString(LoginReq.serializer(), LoginReq(email, password))
            .toRequestBody(JSON_MIME)
        val r = Request.Builder()
            .url(baseUrl.newBuilder().addPathSegments("api/login").build())
            .post(body).build()
        client.newCall(r).execute().use { it.isSuccessful }
    }
}

// --- LAN address enumeration -------------------------------------------------

object LanAddrs {
    /** IPv4 non-loopback, non-link-local interfaces with their CIDR prefix. */
    fun enumerate(): List<LanAddr> {
        val out = mutableListOf<LanAddr>()
        try {
            for (nif in NetworkInterface.getNetworkInterfaces()) {
                if (!nif.isUp || nif.isLoopback) continue
                for (ia in nif.interfaceAddresses) {
                    val addr = ia.address ?: continue
                    val host = addr.hostAddress ?: continue
                    if (host.contains(":")) continue  // IPv6 for v0.2
                    if (host.startsWith("127.") || host.startsWith("169.254.")) continue
                    out.add(LanAddr(iface = nif.name, cidr = "$host/${ia.networkPrefixLength}"))
                }
            }
        } catch (_: Throwable) {}
        return out
    }
}

// --- conf renderer -----------------------------------------------------------

object MeshConfRenderer {
    fun render(
        resp: MeshRegisterResponse,
        privateKeyB64: String,
        listenPort: Int,
    ): String {
        val sb = StringBuilder()
        sb.appendLine("[Interface]")
        sb.appendLine("PrivateKey = $privateKeyB64")
        // /24 for both hub and device — same reason as iOS renderer:
        // /32 leaves the rest of the mesh unreachable without an
        // explicit kernel route.
        sb.appendLine("Address    = ${resp.device_ip}/24")
        sb.appendLine("ListenPort = $listenPort")
        sb.appendLine()
        val keepalive = resp.keepalive_sec ?: 25
        for (p in resp.peers) {
            if (p.pubkey.isBlank()) continue
            val aips = mutableListOf<String>()
            p.wg_ip?.let {
                aips += if (it.contains("/")) it else "$it/32"
            }
            p.allowed_extra?.let { aips += it }
            if (aips.isEmpty()) continue
            sb.appendLine("[Peer]")
            sb.appendLine("PublicKey  = ${p.pubkey}")
            p.endpoint?.let { if (it.isNotBlank()) sb.appendLine("Endpoint   = $it") }
            sb.appendLine("AllowedIPs = ${aips.joinToString(", ")}")
            if (keepalive > 0) sb.appendLine("PersistentKeepalive = $keepalive")
            sb.appendLine()
        }
        return sb.toString()
    }
}

