#!/usr/bin/env bash
# Automated WireGuard-over-KCP device debug loop for a real iPhone.
#
# Pipeline:  device xcframework (device-only) → xcodegen → signed build
#            → install (devicectl) → launch → go-ios syslog stream (filtered).
# Deliberately DEVICE-ONLY (generic iphoneos, no simulator target).
#
# Usage:
#   scripts/ios-device-debug.sh [build|install|run|log|all]   (default: all)
# Env:
#   UDID   target device (default: Astris)
#   SKIP_XCFW=1   reuse existing build/xcframework
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
APPDIR=$ROOT/WireGuardSampleApp
UDID=${UDID:-00008130-0016403C3A60001C}        # Astris (iPhone 15 Pro Max)
SCHEME=WireGuardSampleApp-iOS
PROJ=$APPDIR/WireGuardSampleApp-iOS.xcodeproj
DD=$APPDIR/build/dd-ios
APP_BUNDLE=com.change.wg
APP_PATH=$DD/Build/Products/Debug-iphoneos/WireGuardSampleApp-iOS.app
# os_log subsystem from PacketTunnelProvider.swift + KCP/WG keywords
FILTER='com.example.wireguard|wireguard|WireGuardTunnel|[Kk][Cc][Pp]|handshake|initiation'

cmd=${1:-all}

build_xcfw() {
    [[ "${SKIP_XCFW:-0}" == 1 && -d "$ROOT/build/xcframework/WireGuardCore.xcframework" ]] && return
    echo "▸ device-only xcframework"
    "$ROOT/scripts/build-xcframework-ios-device.sh" >/dev/null
    rm -rf "$ROOT/build/xcframework/WireGuardCore.xcframework"
    mkdir -p "$ROOT/build/xcframework"
    cp -R "$ROOT/build/xcframework-ios-device/WireGuardCore.xcframework" "$ROOT/build/xcframework/"
}

gen() { echo "▸ xcodegen"; (cd "$APPDIR" && xcodegen generate --spec project-ios.yml >/dev/null); }

build() {
    build_xcfw; gen
    echo "▸ signed build → $UDID"
    xcodebuild -project "$PROJ" -scheme "$SCHEME" -configuration Debug \
        -destination "id=$UDID" -derivedDataPath "$DD" \
        -allowProvisioningUpdates build 2>&1 \
        | grep -iE 'error:|BUILD SUCCEEDED|BUILD FAILED|Signing Identity' | tail -8
    [[ -d "$APP_PATH" ]] || { echo "no .app produced"; exit 1; }
}

install() {
    echo "▸ install → $UDID"
    xcrun devicectl device install app --device "$UDID" "$APP_PATH" 2>&1 \
        | grep -iE 'App installed|bundleID|error' | tail -4
}

launch() {
    echo "▸ launch $APP_BUNDLE"
    xcrun devicectl device process launch --device "$UDID" "$APP_BUNDLE" 2>&1 \
        | grep -iE 'launched|processIdentifier|error' | tail -3 || true
}

logstream() {
    echo "▸ syslog stream (go-ios) — filter: kcp/wireguard/handshake. Ctrl-C to stop."
    echo "  (现在去 app 里粘配置并点 Connect,握手日志会实时打这里)"
    ios syslog --udid="$UDID" 2>/dev/null | grep --line-buffered -iE "$FILTER"
}

case "$cmd" in
    build)   build ;;
    install) install ;;
    run)     launch ;;
    log)     logstream ;;
    all)     build; install; launch; logstream ;;
    *) echo "usage: $0 [build|install|run|log|all]"; exit 1 ;;
esac
