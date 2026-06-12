#!/usr/bin/env bash
# Device-only WireGuardCore.xcframework — iOS arm64 ONLY.
# Deliberately builds NO simulator / tvOS / visionOS / macOS slice. Use this
# when targeting a real iPhone and you must not compile any simulator target.
# Output: build/xcframework-ios-device/WireGuardCore.xcframework (ios-arm64).
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BUILD=$ROOT/build/xcframework-ios-device
SRC=$ROOT/src
MODMAP=$ROOT/NetworkExtension/WireGuardKit/module.modulemap
CC=${CC:-cc}
AR=${AR:-/usr/bin/ar}
SWIFTC=${SWIFTC:-swiftc}
IOS_SDK=$(xcrun --sdk iphoneos --show-sdk-path)
IOS_MIN=15.0

CORE_SRCS=(
    "$SRC/wg_noise.c" "$SRC/wg_cookie.c" "$SRC/wg_crypto.c"
    "$SRC/wg_crypto_impl.c" "$SRC/allowedips.c" "$SRC/wg_session.c"
)

rm -rf "$BUILD"
objdir=$BUILD/ios-device/arm64/obj
mkdir -p "$objdir"
cflags="-std=c11 -O2 -Wall -Wextra -fPIC -Wno-unused-parameter -Wno-pointer-sign \
    -miphoneos-version-min=$IOS_MIN -isysroot $IOS_SDK -DCOMPAT_NEED_BLAKE2S \
    -I$SRC/macos_stubs -I$SRC"

echo "  [ios-device/arm64] compiling C sources"
objs=()
for src in "${CORE_SRCS[@]}"; do
    obj="$objdir/$(basename "$src" .c).o"
    $CC $cflags -arch arm64 -c "$src" -o "$obj"
    objs+=("$obj")
done

echo "  [ios-device/arm64] compiling Swift bridge"
swift_lib="$objdir/libswift_crypto.a"
$SWIFTC -target "arm64-apple-ios$IOS_MIN" -sdk "$IOS_SDK" \
        -emit-library -static -o "$swift_lib" "$SRC/crypto_bridge.swift"
tmpunpack=$objdir/swift_unpack; mkdir -p "$tmpunpack"
(cd "$tmpunpack" && $AR -x "$swift_lib")
objs+=("$tmpunpack"/*.o)

lib="$BUILD/ios-device/arm64/libwg_combined.a"
echo "  [ios-device/arm64] archiving → $lib"
$AR rcs "$lib" "${objs[@]}"

fw="$BUILD/WireGuardCore.xcframework/ios-arm64/WireGuardCore.framework"
mkdir -p "$fw/Headers" "$fw/Modules" "$fw/Resources"
cp "$lib" "$fw/WireGuardCore"
cp "$SRC/wg_session.h" "$fw/Headers/"
cp "$MODMAP" "$fw/Modules/module.modulemap"
cat > "$fw/Resources/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleDevelopmentRegion</key><string>en</string>
  <key>CFBundleExecutable</key><string>WireGuardCore</string>
  <key>CFBundleIdentifier</key><string>com.example.wireguard.core</string>
  <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
  <key>CFBundleName</key><string>WireGuardCore</string>
  <key>CFBundlePackageType</key><string>FMWK</string>
  <key>CFBundleShortVersionString</key><string>0.1.0</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>MinimumOSVersion</key><string>$IOS_MIN</string>
  <key>CFBundleSupportedPlatforms</key><array><string>iPhoneOS</string></array>
</dict></plist>
PLIST

# top-level xcframework Info.plist (single slice)
cat > "$BUILD/WireGuardCore.xcframework/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>AvailableLibraries</key><array><dict>
    <key>LibraryIdentifier</key><string>ios-arm64</string>
    <key>LibraryPath</key><string>WireGuardCore.framework</string>
    <key>SupportedArchitectures</key><array><string>arm64</string></array>
    <key>SupportedPlatform</key><string>ios</string>
  </dict></array>
  <key>CFBundlePackageType</key><string>XFWK</string>
  <key>XCFrameworkFormatVersion</key><string>1.0</string>
</dict></plist>
PLIST

echo "  OK  device-only xcframework → $BUILD/WireGuardCore.xcframework (ios-arm64)"
ls "$BUILD/WireGuardCore.xcframework"
