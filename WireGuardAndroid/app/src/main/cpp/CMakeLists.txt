# CMakeLists.txt for building libwg as a shared library for Android.
#
# This produces libwg_session.so which exposes the wg_session_* API
# for Kotlin to call via JNI. The same C sources that build libwg.a
# on macOS/iOS are cross-compiled here via the Android NDK toolchain.
#
# Key difference from the Apple build:
#   - curve25519_portable.c replaces crypto_bridge.swift (no CryptoKit)
#   - macos_stubs/ headers have been made cross-platform (sys/endian.h
#     provides le32dec/le64enc on Android/Linux)

cmake_minimum_required(VERSION 3.22)
project(wg_session C)

set(CMAKE_C_STANDARD 11)

# Source root is the repo's src/ directory (relative to this CMakeLists.txt)
set(WG_SRC "${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src")

# All C sources that make up the WireGuard session library.
# Note: curve25519_portable.c replaces the Swift crypto_bridge.
set(WG_SOURCES
    ${WG_SRC}/wg_noise.c
    ${WG_SRC}/wg_cookie.c
    ${WG_SRC}/wg_crypto.c
    ${WG_SRC}/wg_crypto_impl.c
    ${WG_SRC}/allowedips.c
    ${WG_SRC}/wg_session.c
    ${WG_SRC}/curve25519_portable.c
)

# JNI bridge (Kotlin ↔ C)
set(JNI_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/wg_jni.c
)

# Build as a shared library so Kotlin can System.loadLibrary("wg_session")
add_library(wg_session SHARED ${WG_SOURCES} ${JNI_SOURCES})

# Include paths: macos_stubs (cross-platform now) + src root
target_include_directories(wg_session PRIVATE
    ${WG_SRC}/macos_stubs
    ${WG_SRC}
)

# Compiler flags matching the macOS Makefile
target_compile_definitions(wg_session PRIVATE
    COMPAT_NEED_BLAKE2S
)

target_compile_options(wg_session PRIVATE
    -Wall -Wextra
    -Wno-unused-parameter
    -Wno-pointer-sign
    -O2
)

# Link against Android's log library for __android_log_print
find_library(log-lib log)
target_link_libraries(wg_session ${log-lib})
