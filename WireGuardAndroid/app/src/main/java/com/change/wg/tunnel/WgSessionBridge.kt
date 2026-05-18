package com.change.wg.tunnel

/**
 * Kotlin-side JNI bridge to the wg_session C library.
 * This is the Android equivalent of the Swift PacketTunnelProvider's
 * direct wg_session_* C function calls via the xcframework.
 *
 * The C side (wg_jni.c) calls back into onSendUdp / onDeliverIp / onLog
 * from the wg_session callbacks, allowing the Kotlin VPN service to
 * handle outer UDP and inner IP packet forwarding.
 */
abstract class WgSessionBridge {

    private var handle: Long = 0

    /** Called by the C library when it wants to send an outer UDP packet. */
    abstract fun onSendUdp(data: ByteArray)

    /** Called by the C library when it has decrypted an inner IP packet. */
    abstract fun onDeliverIp(data: ByteArray)

    /** Called by the C library for logging. */
    open fun onLog(message: String) {
        android.util.Log.i("WgSession", message)
    }

    fun create(config: String): Boolean {
        handle = nativeCreate(config)
        return handle != 0L
    }

    fun destroy() {
        if (handle != 0L) {
            nativeDestroy(handle)
            handle = 0
        }
    }

    /** Feed an inner IP packet (from VpnService tun) into the session. */
    fun handleTun(data: ByteArray): Int = nativeHandleTun(handle, data)

    /** Feed an outer UDP packet (from the peer) into the session. */
    fun handleUdp(data: ByteArray): Int = nativeHandleUdp(handle, data)

    /** Drive timers. Call every ~1 second. */
    fun tick() = nativeTick(handle)

    /** Trigger an immediate handshake initiation. */
    fun kick(): Int = nativeKick(handle)

    /** Get the canonical wg(8) UAPI GET response text. */
    fun getUapi(): String = nativeGetUapi(handle)

    /** Send a UAPI SET request. Returns 0 on success. */
    fun setUapi(request: String): Int = nativeSetUapi(handle, request)

    val isActive: Boolean get() = handle != 0L

    // ── Native methods (implemented in wg_jni.c) ───────────────────

    private external fun nativeCreate(config: String): Long
    private external fun nativeDestroy(handle: Long)
    private external fun nativeHandleTun(handle: Long, data: ByteArray): Int
    private external fun nativeHandleUdp(handle: Long, data: ByteArray): Int
    private external fun nativeTick(handle: Long)
    private external fun nativeKick(handle: Long): Int
    private external fun nativeGetUapi(handle: Long): String
    private external fun nativeSetUapi(handle: Long, request: String): Int

    companion object {
        init {
            System.loadLibrary("wg_session")
        }
    }
}
