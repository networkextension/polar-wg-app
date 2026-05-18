/* wg_jni.c — JNI bridge between Kotlin and wg_session C API.
 *
 * Exposes the wg_session_* functions to Kotlin via standard JNI.
 * The Kotlin side calls these through a WgSession class that wraps
 * the native pointer and manages the callback lifecycle.
 *
 * This is the Android equivalent of the Swift PacketTunnelProvider's
 * direct C function calls via the xcframework module map.
 */

#include <jni.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <android/log.h>
#include "wg_session.h"

#define TAG "WgSession"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

/* ── Callbacks from C → Java ────────────────────────────────────────── */
/* These are stored in a global struct so the C callbacks can reach
 * the JVM. In a production app you'd use per-session pointers; for
 * the sample app a singleton is fine. */

static JavaVM *g_jvm = NULL;
static jobject g_callback_obj = NULL;
static jmethodID g_onSendUdp = NULL;
static jmethodID g_onDeliverIp = NULL;
static jmethodID g_onLog = NULL;

static void jni_send_udp(void *ctx, const uint8_t *bytes, size_t len,
                         const struct sockaddr *to, socklen_t to_len)
{
    (void)ctx; (void)to; (void)to_len;
    JNIEnv *env;
    if (!g_jvm || !g_callback_obj) return;
    if ((*g_jvm)->GetEnv(g_jvm, (void**)&env, JNI_VERSION_1_6) != JNI_OK) return;

    jbyteArray arr = (*env)->NewByteArray(env, (jint)len);
    (*env)->SetByteArrayRegion(env, arr, 0, (jint)len, (const jbyte*)bytes);
    (*env)->CallVoidMethod(env, g_callback_obj, g_onSendUdp, arr);
    (*env)->DeleteLocalRef(env, arr);
}

static void jni_deliver_ip(void *ctx, const uint8_t *bytes, size_t len)
{
    (void)ctx;
    JNIEnv *env;
    if (!g_jvm || !g_callback_obj) return;
    if ((*g_jvm)->GetEnv(g_jvm, (void**)&env, JNI_VERSION_1_6) != JNI_OK) return;

    jbyteArray arr = (*env)->NewByteArray(env, (jint)len);
    (*env)->SetByteArrayRegion(env, arr, 0, (jint)len, (const jbyte*)bytes);
    (*env)->CallVoidMethod(env, g_callback_obj, g_onDeliverIp, arr);
    (*env)->DeleteLocalRef(env, arr);
}

static void jni_log(void *ctx, const char *msg)
{
    (void)ctx;
    LOGI("%s", msg);
    /* Also forward to Java if callback is set. */
    JNIEnv *env;
    if (!g_jvm || !g_callback_obj || !g_onLog) return;
    if ((*g_jvm)->GetEnv(g_jvm, (void**)&env, JNI_VERSION_1_6) != JNI_OK) return;

    jstring jmsg = (*env)->NewStringUTF(env, msg);
    (*env)->CallVoidMethod(env, g_callback_obj, g_onLog, jmsg);
    (*env)->DeleteLocalRef(env, jmsg);
}

/* ── JNI lifecycle ──────────────────────────────────────────────────── */

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved)
{
    (void)reserved;
    g_jvm = vm;
    return JNI_VERSION_1_6;
}

/* ── Native methods ─────────────────────────────────────────────────── */
/* Class: com.change.wg.tunnel.WgSessionBridge */

JNIEXPORT jlong JNICALL
Java_com_change_wg_tunnel_WgSessionBridge_nativeCreate(
    JNIEnv *env, jobject thiz, jstring config)
{
    const char *cfg = (*env)->GetStringUTFChars(env, config, NULL);
    if (!cfg) return 0;

    /* Store callback reference. */
    if (g_callback_obj) {
        (*env)->DeleteGlobalRef(env, g_callback_obj);
    }
    g_callback_obj = (*env)->NewGlobalRef(env, thiz);

    jclass cls = (*env)->GetObjectClass(env, thiz);
    g_onSendUdp  = (*env)->GetMethodID(env, cls, "onSendUdp", "([B)V");
    g_onDeliverIp = (*env)->GetMethodID(env, cls, "onDeliverIp", "([B)V");
    g_onLog       = (*env)->GetMethodID(env, cls, "onLog", "(Ljava/lang/String;)V");

    wg_session_callbacks cb = {
        .send_udp   = jni_send_udp,
        .deliver_ip = jni_deliver_ip,
        .log_line   = jni_log,
        .user_ctx   = NULL,
    };

    wg_session_t *s = wg_session_create(cfg, strlen(cfg), cb);
    (*env)->ReleaseStringUTFChars(env, config, cfg);

    return (jlong)(uintptr_t)s;
}

JNIEXPORT void JNICALL
Java_com_change_wg_tunnel_WgSessionBridge_nativeDestroy(
    JNIEnv *env, jobject thiz, jlong handle)
{
    (void)thiz;
    wg_session_t *s = (wg_session_t *)(uintptr_t)handle;
    if (s) wg_session_destroy(s);
    if (g_callback_obj) {
        (*env)->DeleteGlobalRef(env, g_callback_obj);
        g_callback_obj = NULL;
    }
}

JNIEXPORT jint JNICALL
Java_com_change_wg_tunnel_WgSessionBridge_nativeHandleTun(
    JNIEnv *env, jobject thiz, jlong handle, jbyteArray data)
{
    (void)thiz;
    wg_session_t *s = (wg_session_t *)(uintptr_t)handle;
    if (!s) return -1;

    jint len = (*env)->GetArrayLength(env, data);
    jbyte *bytes = (*env)->GetByteArrayElements(env, data, NULL);
    int rc = wg_session_handle_tun(s, (const uint8_t *)bytes, (size_t)len);
    (*env)->ReleaseByteArrayElements(env, data, bytes, JNI_ABORT);
    return rc;
}

JNIEXPORT jint JNICALL
Java_com_change_wg_tunnel_WgSessionBridge_nativeHandleUdp(
    JNIEnv *env, jobject thiz, jlong handle, jbyteArray data)
{
    (void)thiz;
    wg_session_t *s = (wg_session_t *)(uintptr_t)handle;
    if (!s) return -1;

    jint len = (*env)->GetArrayLength(env, data);
    jbyte *bytes = (*env)->GetByteArrayElements(env, data, NULL);

    /* Pass a zeroed sockaddr since Android VpnService doesn't give us
     * the source address in the same way NWUDPSession does. The C
     * library uses it only for roaming bookkeeping. */
    struct sockaddr_in sin = { .sin_family = 2 /* AF_INET */ };
    int rc = wg_session_handle_udp(s, (const uint8_t *)bytes, (size_t)len,
                                   (struct sockaddr *)&sin, sizeof(sin));
    (*env)->ReleaseByteArrayElements(env, data, bytes, JNI_ABORT);
    return rc;
}

JNIEXPORT void JNICALL
Java_com_change_wg_tunnel_WgSessionBridge_nativeTick(
    JNIEnv *env, jobject thiz, jlong handle)
{
    (void)env; (void)thiz;
    wg_session_t *s = (wg_session_t *)(uintptr_t)handle;
    if (s) wg_session_tick(s);
}

JNIEXPORT jint JNICALL
Java_com_change_wg_tunnel_WgSessionBridge_nativeKick(
    JNIEnv *env, jobject thiz, jlong handle)
{
    (void)env; (void)thiz;
    wg_session_t *s = (wg_session_t *)(uintptr_t)handle;
    return s ? wg_session_kick(s) : -1;
}

JNIEXPORT jstring JNICALL
Java_com_change_wg_tunnel_WgSessionBridge_nativeGetUapi(
    JNIEnv *env, jobject thiz, jlong handle)
{
    (void)thiz;
    wg_session_t *s = (wg_session_t *)(uintptr_t)handle;
    if (!s) return (*env)->NewStringUTF(env, "");

    int need = wg_session_get_uapi(s, NULL, 0);
    if (need <= 0) return (*env)->NewStringUTF(env, "");

    char *buf = (char *)malloc((size_t)need + 1);
    wg_session_get_uapi(s, buf, (size_t)need + 1);
    jstring result = (*env)->NewStringUTF(env, buf);
    free(buf);
    return result;
}

JNIEXPORT jint JNICALL
Java_com_change_wg_tunnel_WgSessionBridge_nativeSetUapi(
    JNIEnv *env, jobject thiz, jlong handle, jstring request)
{
    (void)thiz;
    wg_session_t *s = (wg_session_t *)(uintptr_t)handle;
    if (!s) return -1;

    const char *req = (*env)->GetStringUTFChars(env, request, NULL);
    int rc = wg_session_set_uapi(s, req, strlen(req));
    (*env)->ReleaseStringUTFChars(env, request, req);
    return rc;
}
