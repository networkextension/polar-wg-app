#!/bin/bash
# SPDX-License-Identifier: MIT
#
# Build a WireGuardCore.xcframework that Swift can import on:
#   - macOS (arm64 + x86_64)
#   - iOS device (arm64)
#   - iOS simulator (arm64 + x86_64)
#   - tvOS device (arm64)
#   - tvOS simulator (arm64 + x86_64)
#   - visionOS device (arm64)
#   - visionOS simulator (arm64)
#
# Output layout:
#   build/xcframework/WireGuardCore.xcframework/
#     Info.plist
#     macos-arm64_x86_64/
#       WireGuardCore.framework/
#     ios-arm64/
#       WireGuardCore.framework/
#     ios-arm64_x86_64-simulator/
#       WireGuardCore.framework/
#     tvos-arm64/
#       WireGuardCore.framework/
#     tvos-arm64_x86_64-simulator/
#       WireGuardCore.framework/
#     xros-arm64/
#       WireGuardCore.framework/
#     xros-arm64-simulator/
#       WireGuardCore.framework/
#         WireGuardCore           ← static lib, renamed as a framework binary
#         Headers/
#           wg_session.h
#         Modules/
#           module.modulemap
#
# Usage: ./scripts/build-xcframework.sh
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BUILD=$ROOT/build/xcframework
SRC=$ROOT/src
MODMAP=$ROOT/NetworkExtension/WireGuardKit/module.modulemap

CC=${CC:-cc}
AR=${AR:-ar}
SWIFTC=${SWIFTC:-swiftc}

MACOS_SDK=$(xcrun --sdk macosx --show-sdk-path)
IOS_SDK=$(xcrun --sdk iphoneos --show-sdk-path)
IOS_SIM_SDK=$(xcrun --sdk iphonesimulator --show-sdk-path)
TVOS_SDK=$(xcrun --sdk appletvos --show-sdk-path)
TVOS_SIM_SDK=$(xcrun --sdk appletvsimulator --show-sdk-path)
XROS_SDK=$(xcrun --sdk xros --show-sdk-path)
XROS_SIM_SDK=$(xcrun --sdk xrsimulator --show-sdk-path)
MACOS_MIN=11.0
IOS_MIN=15.0
TVOS_MIN=17.0
XROS_MIN=1.0
ENABLE_XROS=${ENABLE_XROS:-1}

CORE_SRCS=(
    "$SRC/wg_noise.c"
    "$SRC/wg_cookie.c"
    "$SRC/wg_crypto.c"
    "$SRC/wg_crypto_impl.c"
    "$SRC/allowedips.c"
    "$SRC/wg_session.c"
)

XROS_SUPPORTED=0
if [[ "$ENABLE_XROS" == "1" ]]; then
    if $SWIFTC -target "arm64-apple-xros$XROS_MIN" -sdk "$XROS_SDK" -typecheck "$SRC/crypto_bridge.swift" >/dev/null 2>&1; then
        XROS_SUPPORTED=1
    else
        echo "  [warn] visionOS toolchain check failed; building xcframework without visionOS slices."
        echo "         Set ENABLE_XROS=0 to silence this warning."
    fi
fi

build_slice() {
    local slice_id=$1
    local arch=$2
    local swift_target=$3
    local sdk=$4
    local min_flag=$5
    local out=$6
    local objdir=$BUILD/$slice_id/$arch/obj
    mkdir -p "$objdir"
    local cflags="-std=c11 -O2 -Wall -Wextra -fPIC \
        -Wno-unused-parameter -Wno-pointer-sign \
        $min_flag \
        -isysroot $sdk \
        -DCOMPAT_NEED_BLAKE2S \
        -I$SRC/macos_stubs -I$SRC"

    echo "  [$slice_id/$arch] compiling C sources"
    local objs=()
    for src in "${CORE_SRCS[@]}"; do
        local name=$(basename "$src" .c)
        local obj="$objdir/$name.o"
        $CC $cflags -arch "$arch" -c "$src" -o "$obj"
        objs+=("$obj")
    done

    echo "  [$slice_id/$arch] compiling Swift bridge"
    local swift_lib="$objdir/libswift_crypto.a"
    $SWIFTC -target "$swift_target" \
            -sdk "$sdk" \
            -emit-library -static \
            -o "$swift_lib" \
            "$SRC/crypto_bridge.swift"

    # Unpack the swift .a so we can ar-merge everything into one archive.
    local tmpunpack=$objdir/swift_unpack
    mkdir -p "$tmpunpack"
    (cd "$tmpunpack" && $AR -x "$swift_lib")
    objs+=("$tmpunpack"/*.o)

    echo "  [$slice_id/$arch] archiving → $out"
    $AR rcs "$out" "${objs[@]}"
}

# ── 1. Build per-arch static archives ──────────────────────────────────
rm -rf "$BUILD"
mkdir -p "$BUILD/macos" "$BUILD/ios-device" "$BUILD/ios-sim" "$BUILD/tvos-device" "$BUILD/tvos-sim"
if [[ "$XROS_SUPPORTED" == "1" ]]; then
    mkdir -p "$BUILD/xros-device" "$BUILD/xros-sim"
fi

build_slice macos arm64  "arm64-apple-macosx$MACOS_MIN" "$MACOS_SDK" "-mmacosx-version-min=$MACOS_MIN" "$BUILD/macos/arm64/libwg_combined.a"
build_slice macos x86_64 "x86_64-apple-macosx$MACOS_MIN" "$MACOS_SDK" "-mmacosx-version-min=$MACOS_MIN" "$BUILD/macos/x86_64/libwg_combined.a"
build_slice ios-device arm64 "arm64-apple-ios$IOS_MIN" "$IOS_SDK" "-miphoneos-version-min=$IOS_MIN" "$BUILD/ios-device/arm64/libwg_combined.a"
build_slice ios-sim arm64 "arm64-apple-ios$IOS_MIN-simulator" "$IOS_SIM_SDK" "-mios-simulator-version-min=$IOS_MIN" "$BUILD/ios-sim/arm64/libwg_combined.a"
build_slice ios-sim x86_64 "x86_64-apple-ios$IOS_MIN-simulator" "$IOS_SIM_SDK" "-mios-simulator-version-min=$IOS_MIN" "$BUILD/ios-sim/x86_64/libwg_combined.a"
build_slice tvos-device arm64 "arm64-apple-tvos$TVOS_MIN" "$TVOS_SDK" "-mtvos-version-min=$TVOS_MIN" "$BUILD/tvos-device/arm64/libwg_combined.a"
build_slice tvos-sim arm64 "arm64-apple-tvos$TVOS_MIN-simulator" "$TVOS_SIM_SDK" "-mtvos-simulator-version-min=$TVOS_MIN" "$BUILD/tvos-sim/arm64/libwg_combined.a"
build_slice tvos-sim x86_64 "x86_64-apple-tvos$TVOS_MIN-simulator" "$TVOS_SIM_SDK" "-mtvos-simulator-version-min=$TVOS_MIN" "$BUILD/tvos-sim/x86_64/libwg_combined.a"
if [[ "$XROS_SUPPORTED" == "1" ]]; then
    build_slice xros-device arm64 "arm64-apple-xros$XROS_MIN" "$XROS_SDK" "-mtargetos=xros$XROS_MIN" "$BUILD/xros-device/arm64/libwg_combined.a"
    build_slice xros-sim arm64 "arm64-apple-xros$XROS_MIN-simulator" "$XROS_SIM_SDK" "-mtargetos=xros$XROS_MIN-simulator" "$BUILD/xros-sim/arm64/libwg_combined.a"
fi

# ── 2. lipo per-platform archives ───────────────────────────────────────
echo "  [lipo] stitching macOS arm64 + x86_64"
MACOS_UNI=$BUILD/macos/libwg_combined.a
lipo -create \
     "$BUILD/macos/arm64/libwg_combined.a" \
     "$BUILD/macos/x86_64/libwg_combined.a" \
     -output "$MACOS_UNI"

echo "  [lipo] stitching iOS simulator arm64 + x86_64"
IOS_SIM_UNI=$BUILD/ios-sim/libwg_combined.a
lipo -create \
     "$BUILD/ios-sim/arm64/libwg_combined.a" \
     "$BUILD/ios-sim/x86_64/libwg_combined.a" \
     -output "$IOS_SIM_UNI"

IOS_DEVICE_LIB=$BUILD/ios-device/arm64/libwg_combined.a
echo "  [lipo] stitching tvOS simulator arm64 + x86_64"
TVOS_SIM_UNI=$BUILD/tvos-sim/libwg_combined.a
lipo -create \
     "$BUILD/tvos-sim/arm64/libwg_combined.a" \
     "$BUILD/tvos-sim/x86_64/libwg_combined.a" \
     -output "$TVOS_SIM_UNI"

TVOS_DEVICE_LIB=$BUILD/tvos-device/arm64/libwg_combined.a
if [[ "$XROS_SUPPORTED" == "1" ]]; then
    XROS_DEVICE_LIB=$BUILD/xros-device/arm64/libwg_combined.a
    XROS_SIM_LIB=$BUILD/xros-sim/arm64/libwg_combined.a
fi

create_framework_slice() {
    local library_id=$1
    local lib_path=$2
    local platform=$3
    local min_version=$4
    local fw="$BUILD/WireGuardCore.xcframework/$library_id/WireGuardCore.framework"

    mkdir -p "$fw/Headers" "$fw/Modules" "$fw/Resources"
    cp "$lib_path" "$fw/WireGuardCore"
    cp "$SRC/wg_session.h" "$fw/Headers/"
    cp "$MODMAP" "$fw/Modules/module.modulemap"

    cat > "$fw/Resources/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key>        <string>en</string>
  <key>CFBundleExecutable</key>                <string>WireGuardCore</string>
  <key>CFBundleIdentifier</key>                <string>com.example.wireguard.core</string>
  <key>CFBundleInfoDictionaryVersion</key>     <string>6.0</string>
  <key>CFBundleName</key>                      <string>WireGuardCore</string>
  <key>CFBundlePackageType</key>               <string>FMWK</string>
  <key>CFBundleShortVersionString</key>        <string>0.1.0</string>
  <key>CFBundleVersion</key>                   <string>1</string>
  <key>MinimumOSVersion</key>                  <string>$min_version</string>
  <key>CFBundleSupportedPlatforms</key>
  <array>
    <string>$platform</string>
  </array>
</dict>
</plist>
PLIST
}

# ── 3. Lay out framework slices in the xcframework bundle ───────────────
create_framework_slice "macos-arm64_x86_64" "$MACOS_UNI" "MacOSX" "$MACOS_MIN"
create_framework_slice "ios-arm64" "$IOS_DEVICE_LIB" "iPhoneOS" "$IOS_MIN"
create_framework_slice "ios-arm64_x86_64-simulator" "$IOS_SIM_UNI" "iPhoneSimulator" "$IOS_MIN"
create_framework_slice "tvos-arm64" "$TVOS_DEVICE_LIB" "AppleTVOS" "$TVOS_MIN"
create_framework_slice "tvos-arm64_x86_64-simulator" "$TVOS_SIM_UNI" "AppleTVSimulator" "$TVOS_MIN"
if [[ "$XROS_SUPPORTED" == "1" ]]; then
    create_framework_slice "xros-arm64" "$XROS_DEVICE_LIB" "XROS" "$XROS_MIN"
    create_framework_slice "xros-arm64-simulator" "$XROS_SIM_LIB" "XRSimulator" "$XROS_MIN"
fi

# ── 4. xcframework Info.plist for all slices ────────────────────────────
PLIST_PATH="$BUILD/WireGuardCore.xcframework/Info.plist"
cat > "$PLIST_PATH" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundlePackageType</key>              <string>XFWK</string>
  <key>XCFrameworkFormatVersion</key>         <string>1.0</string>
  <key>AvailableLibraries</key>
  <array>
    <dict>
      <key>LibraryIdentifier</key>            <string>macos-arm64_x86_64</string>
      <key>LibraryPath</key>                  <string>WireGuardCore.framework</string>
      <key>SupportedArchitectures</key>
      <array>
        <string>arm64</string>
        <string>x86_64</string>
      </array>
      <key>SupportedPlatform</key>            <string>macos</string>
    </dict>
    <dict>
      <key>LibraryIdentifier</key>            <string>ios-arm64</string>
      <key>LibraryPath</key>                  <string>WireGuardCore.framework</string>
      <key>SupportedArchitectures</key>
      <array>
        <string>arm64</string>
      </array>
      <key>SupportedPlatform</key>            <string>ios</string>
    </dict>
    <dict>
      <key>LibraryIdentifier</key>            <string>ios-arm64_x86_64-simulator</string>
      <key>LibraryPath</key>                  <string>WireGuardCore.framework</string>
      <key>SupportedArchitectures</key>
      <array>
        <string>arm64</string>
        <string>x86_64</string>
      </array>
      <key>SupportedPlatform</key>            <string>ios</string>
      <key>SupportedPlatformVariant</key>     <string>simulator</string>
    </dict>
    <dict>
      <key>LibraryIdentifier</key>            <string>tvos-arm64</string>
      <key>LibraryPath</key>                  <string>WireGuardCore.framework</string>
      <key>SupportedArchitectures</key>
      <array>
        <string>arm64</string>
      </array>
      <key>SupportedPlatform</key>            <string>tvos</string>
    </dict>
    <dict>
      <key>LibraryIdentifier</key>            <string>tvos-arm64_x86_64-simulator</string>
      <key>LibraryPath</key>                  <string>WireGuardCore.framework</string>
      <key>SupportedArchitectures</key>
      <array>
        <string>arm64</string>
        <string>x86_64</string>
      </array>
      <key>SupportedPlatform</key>            <string>tvos</string>
      <key>SupportedPlatformVariant</key>     <string>simulator</string>
    </dict>
PLIST

if [[ "$XROS_SUPPORTED" == "1" ]]; then
cat >> "$PLIST_PATH" <<'PLIST'
    <dict>
      <key>LibraryIdentifier</key>            <string>xros-arm64</string>
      <key>LibraryPath</key>                  <string>WireGuardCore.framework</string>
      <key>SupportedArchitectures</key>
      <array>
        <string>arm64</string>
      </array>
      <key>SupportedPlatform</key>            <string>xros</string>
    </dict>
    <dict>
      <key>LibraryIdentifier</key>            <string>xros-arm64-simulator</string>
      <key>LibraryPath</key>                  <string>WireGuardCore.framework</string>
      <key>SupportedArchitectures</key>
      <array>
        <string>arm64</string>
      </array>
      <key>SupportedPlatform</key>            <string>xros</string>
      <key>SupportedPlatformVariant</key>     <string>simulator</string>
    </dict>
PLIST
fi

cat >> "$PLIST_PATH" <<'PLIST'
  </array>
</dict>
</plist>
PLIST

echo ""
echo "done. xcframework at:"
echo "  $BUILD/WireGuardCore.xcframework"
echo ""
echo "Drop it into your Xcode project (General → Frameworks) and"
echo "'import WireGuardCore' from Swift."
