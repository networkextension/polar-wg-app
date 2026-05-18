#!/bin/bash
# SPDX-License-Identifier: MIT
#
# Build a macOS-only WireGuardCore.xcframework that Swift can import.
#
# Output layout:
#   build/xcframework/WireGuardCore.xcframework/
#     Info.plist
#     macos-arm64_x86_64/
#       WireGuardCore.framework/
#         WireGuardCore           ← static lib, renamed as a framework binary
#         Headers/
#           wg_session.h
#         Modules/
#           module.modulemap
#
# Produces a universal (arm64 + x86_64) slice. If your Mac only has one
# architecture, the other slice is built via clang's built-in
# cross-compile (the C code has no arch-specific assembly so this works
# out of the box). The Swift CryptoKit bridge is arm64-only because
# it's built via `swiftc` on the host machine; if you need x86_64 too,
# install an x86_64 toolchain and add -target x86_64-apple-macosx to
# the SWIFTFLAGS below.
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

SDK=$(xcrun --sdk macosx --show-sdk-path)
MIN=11.0

CFLAGS="-std=c11 -O2 -Wall -Wextra -fPIC \
        -Wno-unused-parameter -Wno-pointer-sign \
        -mmacosx-version-min=$MIN \
        -isysroot $SDK \
        -DCOMPAT_NEED_BLAKE2S \
        -I$SRC/macos_stubs -I$SRC"

CORE_SRCS=(
    "$SRC/wg_noise.c"
    "$SRC/wg_cookie.c"
    "$SRC/wg_crypto.c"
    "$SRC/wg_crypto_impl.c"
    "$SRC/allowedips.c"
    "$SRC/wg_session.c"
)

build_slice() {
    local arch=$1
    local out=$2
    local objdir=$BUILD/$arch/obj
    mkdir -p "$objdir"

    echo "  [$arch] compiling C sources"
    local objs=()
    for src in "${CORE_SRCS[@]}"; do
        local name=$(basename "$src" .c)
        local obj="$objdir/$name.o"
        $CC $CFLAGS -arch "$arch" -c "$src" -o "$obj"
        objs+=("$obj")
    done

    echo "  [$arch] compiling Swift bridge"
    local swift_lib="$objdir/libswift_crypto.a"
    $SWIFTC -target "$arch-apple-macosx$MIN" \
            -emit-library -static \
            -o "$swift_lib" \
            "$SRC/crypto_bridge.swift"

    # Unpack the swift .a so we can ar-merge everything into one archive.
    local tmpunpack=$objdir/swift_unpack
    mkdir -p "$tmpunpack"
    (cd "$tmpunpack" && $AR -x "$swift_lib")
    objs+=("$tmpunpack"/*.o)

    echo "  [$arch] archiving → $out"
    $AR rcs "$out" "${objs[@]}"
}

# ── 1. Build per-arch static archives ──────────────────────────────────
rm -rf "$BUILD"
mkdir -p "$BUILD/arm64" "$BUILD/x86_64"

build_slice arm64  "$BUILD/arm64/libwg_combined.a"
build_slice x86_64 "$BUILD/x86_64/libwg_combined.a"

# ── 2. lipo them into one universal archive ────────────────────────────
echo "  [lipo] stitching arm64 + x86_64"
UNI=$BUILD/libwg_combined.a
lipo -create \
     "$BUILD/arm64/libwg_combined.a" \
     "$BUILD/x86_64/libwg_combined.a" \
     -output "$UNI"

# ── 3. Lay out the .framework under macos-arm64_x86_64/ ────────────────
FW=$BUILD/WireGuardCore.xcframework/macos-arm64_x86_64/WireGuardCore.framework
mkdir -p "$FW/Headers" "$FW/Modules" "$FW/Resources"

# The framework binary is just the renamed universal archive.
cp "$UNI" "$FW/WireGuardCore"

# Headers + module.modulemap.
cp "$SRC/wg_session.h" "$FW/Headers/"
cp "$MODMAP" "$FW/Modules/module.modulemap"

# Minimal framework Info.plist.
cat > "$FW/Resources/Info.plist" <<PLIST
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
  <key>MinimumOSVersion</key>                  <string>$MIN</string>
  <key>CFBundleSupportedPlatforms</key>
  <array>
    <string>MacOSX</string>
  </array>
</dict>
</plist>
PLIST

# ── 4. xcframework Info.plist that points at the macos-arm64_x86_64 slice ──
cat > "$BUILD/WireGuardCore.xcframework/Info.plist" <<'PLIST'
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
      <key>HeadersPath</key>                  <string>Headers</string>
      <key>SupportedArchitectures</key>
      <array>
        <string>arm64</string>
        <string>x86_64</string>
      </array>
      <key>SupportedPlatform</key>            <string>macos</string>
    </dict>
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
