/* wgctl — macOS user-facing WireGuard CLI.
 *
 * Subcommands:
 *   genkey                generate a private key (clamped), print base64
 *   pubkey                read private key from stdin, print derived public
 *   genpsk                generate a 32-byte preshared key
 *   up    <iface>         start tunnel from /etc/wireguard/<iface>.conf
 *   down  <iface>         stop tunnel by PID file
 *   show  [iface]         dump status (one iface, or list all running)
 *
 * Conventions:
 *   /etc/wireguard/<iface>.conf       — wg-quick-style INI config
 *   /var/run/wireguard/<iface>.pid    — written by wg_core --logical-name <iface>
 *   /var/run/wireguard/<iface>.name   — kernel utun device, e.g. "utun5"
 *   /var/run/wireguard/<iface>.sock   — SOCK_STREAM, one-shot status dump
 *
 * Curve25519 calls go through libswift_crypto (Apple CryptoKit), the same
 * bridge libwg uses for handshake keys, so no duplicated crypto.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>     /* getentropy on macOS 10.12+ */
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* From libswift_crypto. */
extern void curve25519_generate_secret(uint8_t out[32]);
extern void curve25519_clamp_secret(uint8_t secret[32]);
extern int  curve25519_generate_public(uint8_t out[32], const uint8_t priv[32]);

#define WG_CONF_DIR    "/etc/wireguard"
#define WG_RUNTIME_DIR "/var/run/wireguard"
#define WG_CORE_BIN    "/usr/local/bin/wg_core"

/* ─────────────────────────────────────────────────────────────────────────
 * base64 (WireGuard's canonical 32-byte form, 44 chars including '=')
 * ───────────────────────────────────────────────────────────────────────── */

static const char B64_ENC[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void b64_encode_32(char out[45], const uint8_t in[32])
{
    int oi = 0;
    for (int i = 0; i < 30; i += 3) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i+1] << 8) | in[i+2];
        out[oi++] = B64_ENC[(v >> 18) & 0x3f];
        out[oi++] = B64_ENC[(v >> 12) & 0x3f];
        out[oi++] = B64_ENC[(v >>  6) & 0x3f];
        out[oi++] = B64_ENC[ v        & 0x3f];
    }
    uint32_t v = ((uint32_t)in[30] << 16) | ((uint32_t)in[31] << 8);
    out[oi++] = B64_ENC[(v >> 18) & 0x3f];
    out[oi++] = B64_ENC[(v >> 12) & 0x3f];
    out[oi++] = B64_ENC[(v >>  6) & 0x3f];
    out[oi++] = '=';
    out[oi]   = '\0';
}

static int b64_value(unsigned char c)
{
    if (c >= 'A' && c <= 'Z') return (int)(c - 'A');
    if (c >= 'a' && c <= 'z') return (int)(c - 'a') + 26;
    if (c >= '0' && c <= '9') return (int)(c - '0') + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static int b64_decode_32(const char *in, uint8_t out[32])
{
    size_t in_len = strlen(in);
    uint8_t tmp[64] = {0};
    int out_len = 0;

    if (in_len != 44) return -1;
    for (int i = 0; i < 44; i += 4) {
        int v0 = b64_value((unsigned char)in[i]);
        int v1 = b64_value((unsigned char)in[i + 1]);
        if (v0 < 0 || v1 < 0) return -1;
        tmp[out_len++] = (uint8_t)((v0 << 2) | (v1 >> 4));
        if (in[i + 2] == '=') break;
        int v2 = b64_value((unsigned char)in[i + 2]);
        if (v2 < 0) return -1;
        tmp[out_len++] = (uint8_t)(((v1 & 0x0f) << 4) | (v2 >> 2));
        if (in[i + 3] == '=') break;
        int v3 = b64_value((unsigned char)in[i + 3]);
        if (v3 < 0) return -1;
        tmp[out_len++] = (uint8_t)(((v2 & 0x03) << 6) | v3);
    }
    if (out_len != 32) return -1;
    memcpy(out, tmp, 32);
    return 0;
}

/* ─────────────────────────────────────────────────────────────────────────
 * keygen subcommands
 * ───────────────────────────────────────────────────────────────────────── */

static int cmd_genkey(void)
{
    uint8_t sk[32];
    char out[45];
    curve25519_generate_secret(sk);
    /* generate_secret already returns a CryptoKit-clamped key, but call
     * clamp explicitly to match `wg genkey` semantics regardless of how
     * the bridge evolves. */
    curve25519_clamp_secret(sk);
    b64_encode_32(out, sk);
    printf("%s\n", out);
    return 0;
}

static int cmd_pubkey(void)
{
    char line[128];
    if (!fgets(line, sizeof(line), stdin)) {
        fprintf(stderr, "wgctl pubkey: read stdin failed\n");
        return 1;
    }
    /* Strip trailing newline / whitespace. */
    size_t n = strlen(line);
    while (n > 0 && (line[n-1] == '\n' || line[n-1] == '\r' ||
                     line[n-1] == ' '  || line[n-1] == '\t')) {
        line[--n] = '\0';
    }
    uint8_t sk[32], pk[32];
    if (b64_decode_32(line, sk) != 0) {
        fprintf(stderr, "wgctl pubkey: not a valid 44-char base64 key\n");
        return 1;
    }
    if (!curve25519_generate_public(pk, sk)) {
        fprintf(stderr, "wgctl pubkey: derivation failed\n");
        return 1;
    }
    char out[45];
    b64_encode_32(out, pk);
    printf("%s\n", out);
    return 0;
}

static int cmd_genpsk(void)
{
    /* getentropy(3) is the canonical macOS source for cryptographic
     * randomness; capped at 256 bytes per call. */
    uint8_t psk[32];
    if (getentropy(psk, sizeof(psk)) != 0) {
        perror("getentropy");
        return 1;
    }
    char out[45];
    b64_encode_32(out, psk);
    printf("%s\n", out);
    return 0;
}

/* ─────────────────────────────────────────────────────────────────────────
 * up/down/show helpers
 * ───────────────────────────────────────────────────────────────────────── */

static void make_paths(const char *iface,
                       char conf[256], char pidp[256],
                       char namep[256], char sockp[256])
{
    snprintf(conf,  256, "%s/%s.conf", WG_CONF_DIR,    iface);
    snprintf(pidp,  256, "%s/%s.pid",  WG_RUNTIME_DIR, iface);
    snprintf(namep, 256, "%s/%s.name", WG_RUNTIME_DIR, iface);
    snprintf(sockp, 256, "%s/%s.sock", WG_RUNTIME_DIR, iface);
}

static int read_pid(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    int pid = 0;
    if (fscanf(f, "%d", &pid) != 1) pid = -1;
    fclose(f);
    return pid > 0 ? pid : -1;
}

static int file_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

/* Validate iface name: lowercase letters, digits, underscore, hyphen,
 * 1-15 chars. Anything else could be a shell injection vector since we
 * later build /etc paths and pass it to system commands. */
static int validate_iface(const char *iface)
{
    size_t n = strlen(iface);
    if (n < 1 || n > 15) return -1;
    for (size_t i = 0; i < n; i++) {
        char c = iface[i];
        if (!((c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') ||
              c == '_' || c == '-')) return -1;
    }
    return 0;
}

static int cmd_up(int argc, char *argv[])
{
    if (argc < 1) {
        fprintf(stderr, "usage: wgctl up <iface>\n");
        return 1;
    }
    const char *iface = argv[0];
    if (validate_iface(iface) != 0) {
        fprintf(stderr, "wgctl up: invalid iface name (lowercase a-z, 0-9, _-, 1-15 chars)\n");
        return 1;
    }
    if (geteuid() != 0) {
        fprintf(stderr, "wgctl up: must run as root (sudo)\n");
        return 1;
    }

    char conf[256], pidp[256], namep[256], sockp[256];
    make_paths(iface, conf, pidp, namep, sockp);

    if (!file_exists(conf)) {
        fprintf(stderr, "wgctl up: config %s not found\n", conf);
        return 1;
    }
    if (file_exists(pidp)) {
        int pid = read_pid(pidp);
        if (pid > 0 && kill(pid, 0) == 0) {
            fprintf(stderr, "wgctl up: %s already running (pid %d)\n",
                    iface, pid);
            return 1;
        }
        /* Stale pid file from a crash — let wg_core overwrite it. */
        fprintf(stderr, "wgctl up: stale pid file, restarting\n");
    }

    if (!file_exists(WG_CORE_BIN)) {
        fprintf(stderr, "wgctl up: %s not found — run `sudo make install`\n",
                WG_CORE_BIN);
        return 1;
    }

    /* Foreground exec: wg_core handles its own signals and we want the
     * caller (shell, or launchd) to own the tunnel lifecycle. Callers who
     * want background can fork or use launchd's KeepAlive. */
    execl(WG_CORE_BIN, "wg_core",
          "--tunnel", "--logical-name", iface, conf, (char *)NULL);
    perror("execl wg_core");
    return 127;
}

/* SIGTERM the wg_core process for an iface, wait briefly for it to clean
 * up its own runtime files, then force-remove any leftovers. */
static int cmd_down(int argc, char *argv[])
{
    if (argc < 1) {
        fprintf(stderr, "usage: wgctl down <iface>\n");
        return 1;
    }
    const char *iface = argv[0];
    if (validate_iface(iface) != 0) {
        fprintf(stderr, "wgctl down: invalid iface name\n");
        return 1;
    }
    if (geteuid() != 0) {
        fprintf(stderr, "wgctl down: must run as root (sudo)\n");
        return 1;
    }

    char conf[256], pidp[256], namep[256], sockp[256];
    make_paths(iface, conf, pidp, namep, sockp);

    int pid = read_pid(pidp);
    if (pid <= 0) {
        fprintf(stderr, "wgctl down: %s not running (no pid file)\n", iface);
        /* Still clean up any orphan files. */
        (void)unlink(pidp);
        (void)unlink(namep);
        (void)unlink(sockp);
        return 1;
    }

    if (kill(pid, SIGTERM) != 0) {
        if (errno == ESRCH) {
            fprintf(stderr, "wgctl down: pid %d already gone; cleaning up\n", pid);
        } else {
            perror("kill");
            return 1;
        }
    }

    /* Wait up to 3 s for the process to exit (signal handler unlinks
     * runtime files). Poll with 100 ms granularity. */
    for (int i = 0; i < 30; i++) {
        if (kill(pid, 0) != 0 && errno == ESRCH) break;
        struct timespec ts = { 0, 100 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }
    if (kill(pid, 0) == 0) {
        fprintf(stderr, "wgctl down: pid %d still alive after 3s, sending SIGKILL\n", pid);
        (void)kill(pid, SIGKILL);
    }

    /* Force-remove leftover files in case the signal handler didn't run
     * (e.g., SIGKILL skips atexit). */
    (void)unlink(pidp);
    (void)unlink(namep);
    (void)unlink(sockp);
    printf("wgctl: %s stopped\n", iface);
    return 0;
}

/* Connect to /var/run/wireguard/<iface>.sock and pipe the dump to stdout. */
static int dump_one(const char *iface)
{
    char conf[256], pidp[256], namep[256], sockp[256];
    make_paths(iface, conf, pidp, namep, sockp);

    int pid = read_pid(pidp);
    if (pid <= 0) {
        printf("interface: %s  (not running)\n", iface);
        return 0;
    }
    if (kill(pid, 0) != 0 && errno == ESRCH) {
        printf("interface: %s  (stale pid file: %d)\n", iface, pid);
        return 0;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return 1; }
    struct sockaddr_un un;
    memset(&un, 0, sizeof(un));
    un.sun_family = AF_UNIX;
    strncpy(un.sun_path, sockp, sizeof(un.sun_path) - 1);
    if (connect(fd, (struct sockaddr *)&un, sizeof(un)) != 0) {
        fprintf(stderr, "wgctl show: connect %s: %s\n", sockp, strerror(errno));
        close(fd);
        return 1;
    }

    /* Drain to stdout. */
    char buf[4096];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        if (write(STDOUT_FILENO, buf, (size_t)n) != n) break;
    }
    close(fd);
    return 0;
}

/* Iterate runtime dir for *.pid files and dump each. */
static int dump_all(void)
{
    DIR *d = opendir(WG_RUNTIME_DIR);
    if (!d) {
        if (errno == ENOENT) {
            printf("(no interfaces running)\n");
            return 0;
        }
        perror("opendir " WG_RUNTIME_DIR);
        return 1;
    }
    int any = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        const char *name = de->d_name;
        size_t n = strlen(name);
        if (n < 5 || strcmp(name + n - 4, ".pid") != 0) continue;
        char iface[64];
        if (n - 4 >= sizeof(iface)) continue;
        memcpy(iface, name, n - 4);
        iface[n - 4] = '\0';
        if (any) printf("\n");
        dump_one(iface);
        any = 1;
    }
    closedir(d);
    if (!any) printf("(no interfaces running)\n");
    return 0;
}

static int cmd_show(int argc, char *argv[])
{
    if (argc == 0) return dump_all();
    if (validate_iface(argv[0]) != 0) {
        fprintf(stderr, "wgctl show: invalid iface name\n");
        return 1;
    }
    return dump_one(argv[0]);
}

/* ─────────────────────────────────────────────────────────────────────────
 * Entry point
 * ───────────────────────────────────────────────────────────────────────── */

static void usage(void)
{
    fprintf(stderr,
        "usage: wgctl <subcommand> [args]\n"
        "\n"
        "subcommands:\n"
        "  genkey                generate a private key, print base64\n"
        "  pubkey                derive public key (private on stdin)\n"
        "  genpsk                generate a 32-byte preshared key\n"
        "  up    <iface>         bring up tunnel (reads /etc/wireguard/<iface>.conf)\n"
        "  down  <iface>         stop tunnel\n"
        "  show  [iface]         show status (all interfaces, or one)\n"
        "\n"
        "iface must be lowercase a-z, 0-9, _-, 1-15 chars (e.g. wg0).\n"
        "up/down/show <iface> require root.\n");
}

int main(int argc, char *argv[])
{
    if (argc < 2) { usage(); return 1; }
    const char *cmd = argv[1];

    if (strcmp(cmd, "genkey") == 0) return cmd_genkey();
    if (strcmp(cmd, "pubkey") == 0) return cmd_pubkey();
    if (strcmp(cmd, "genpsk") == 0) return cmd_genpsk();
    if (strcmp(cmd, "up")     == 0) return cmd_up(argc - 2, argv + 2);
    if (strcmp(cmd, "down")   == 0) return cmd_down(argc - 2, argv + 2);
    if (strcmp(cmd, "show")   == 0) return cmd_show(argc - 2, argv + 2);
    if (strcmp(cmd, "-h") == 0 || strcmp(cmd, "--help") == 0 ||
        strcmp(cmd, "help") == 0) { usage(); return 0; }

    fprintf(stderr, "wgctl: unknown subcommand '%s'\n", cmd);
    usage();
    return 1;
}
