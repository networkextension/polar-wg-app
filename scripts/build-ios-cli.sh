#!/bin/bash
# build-ios-cli.sh — cross-compile wg_core + wgctl for iOS arm64 (NON-NE path).
#
# Output binaries run on an Apple Internal / jailbroken iOS device booted with
# cs_enforcement_disable=1 amfi_get_out_of_my_way=0x1 (or otherwise free of
# AMFI's adhoc-CT-policy gate). They are NOT Network Extensions — they open
# utun directly via PF_SYSTEM/SYSPROTO_CONTROL, same as the macOS build.
#
# Output: build/ios-arm64/{wg_core,wgctl}, ad-hoc codesigned.
#
# Why a separate script (not Makefile): the Makefile hardcodes
# -mmacosx-version-min and links against macOS frameworks. Reusing it via env
# overrides leaks macOS flags. Cleaner to specify the iOS flags explicitly.

set -euo pipefail

cd "$(dirname "$0")/.."   # repo root

SDK=$(xcrun --sdk iphoneos --show-sdk-path)
SDK_MAC=$(xcrun --sdk macosx --show-sdk-path)
CLANG=$(xcrun --sdk iphoneos -f clang)
SWIFTC=$(xcrun --sdk iphoneos -f swiftc)
AR=/usr/bin/ar
CODESIGN=/usr/bin/codesign

ARCH=arm64
MIN_IOS=15.0
OUT=build/ios-arm64
COMPAT=$OUT/compat
mkdir -p "$OUT" "$COMPAT/net" "$COMPAT/sys"

# Borrow macOS-private headers iPhoneOS SDK doesn't ship.
# Identical between SDKs — same struct layout, same constants — because
# the underlying kernel ABI is the same. We just copy them so we can keep
# -isysroot pointed at iPhoneOS (don't want any other macOS headers leaking).
for h in net/if_utun.h sys/kern_control.h sys/sys_domain.h sys/random.h; do
    cp "$SDK_MAC/usr/include/$h" "$COMPAT/$h"
done

CFLAGS=(
    -std=c11
    -O2
    -Wall -Wextra
    -Wno-unused-parameter
    -Wno-pointer-sign
    -arch "$ARCH"
    -miphoneos-version-min="$MIN_IOS"
    -isysroot "$SDK"
    -I "$COMPAT"
    -I src/macos_stubs
    -I src
    -DCOMPAT_NEED_BLAKE2S
    # Strip iOS availability gates — symbols exist in libSystem, Apple just
    # hides them for App Store compliance. Our process is not App Store bound.
    -D__IOS_PROHIBITED=
    -D__WATCHOS_PROHIBITED=
    -D__TVOS_PROHIBITED=
)

LIBWG_SRCS=(
    src/wg_noise.c
    src/wg_cookie.c
    src/wg_crypto.c
    src/wg_crypto_impl.c
    src/allowedips.c
    src/wg_session.c
)

echo "→ compile libwg.a sources"
LIBWG_OBJS=()
for s in "${LIBWG_SRCS[@]}"; do
    o="$OUT/$(basename "$s" .c).o"
    LIBWG_OBJS+=("$o")
    "$CLANG" "${CFLAGS[@]}" -c "$s" -o "$o"
done

echo "→ ar libwg.a"
rm -f "$OUT/libwg.a"
"$AR" rcs "$OUT/libwg.a" "${LIBWG_OBJS[@]}"

echo "→ swiftc libswift_crypto.a (iOS arm64)"
"$SWIFTC" \
    -target "${ARCH}-apple-ios${MIN_IOS}" \
    -sdk "$SDK" \
    -emit-library -static \
    -o "$OUT/libswift_crypto.a" \
    src/crypto_bridge.swift

SWIFT_COMPAT_DIR=$(dirname "$(dirname "$SWIFTC")")/lib/swift/iphoneos
LDFLAGS=(
    -arch "$ARCH"
    -miphoneos-version-min="$MIN_IOS"
    -isysroot "$SDK"
    -L "$OUT" -lwg -lswift_crypto
    -lpthread
    -framework Foundation -framework CryptoKit
    # Swift runtime path inside the iPhoneOS SDK.
    -L "$SDK/usr/lib/swift"
    -Wl,-rpath,/usr/lib/swift
    # Static compatibility shims (linker auto-links these from
    # libswift_crypto.a but doesn't know where to find them).
    -L "$SWIFT_COMPAT_DIR"
)

echo "→ link wg_core"
"$CLANG" "${CFLAGS[@]}" src/wg_core.c "${LDFLAGS[@]}" -o "$OUT/wg_core"

echo "→ link wgctl"
"$CLANG" "${CFLAGS[@]}" src/wgctl.c "${LDFLAGS[@]}" -o "$OUT/wgctl"

echo "→ adhoc codesign"
"$CODESIGN" -s - -f "$OUT/wg_core"
"$CODESIGN" -s - -f "$OUT/wgctl"

echo
echo "Built:"
ls -la "$OUT/wg_core" "$OUT/wgctl"
echo
file "$OUT/wg_core" "$OUT/wgctl"
echo
echo "CDHashes (needed for load_trust_cache if you ever want to whitelist):"
"$CODESIGN" -dvvv "$OUT/wg_core" 2>&1 | grep -E '^CDHash='
"$CODESIGN" -dvvv "$OUT/wgctl"   2>&1 | grep -E '^CDHash='
