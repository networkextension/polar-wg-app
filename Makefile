# WireGuard – macOS userspace port
# Compiles FreeBSD wg_noise.c + wg_cookie.c on macOS via stub headers.

# ── Toolchain ────────────────────────────────────────────────────────────────
CC      := cc
# Pin to Apple's ar — Homebrew binutils' ar may shadow it on $PATH and
# produces GNU-format archives that the Apple linker rejects ("archive
# member '/' not a mach-o file").
AR      := /usr/bin/ar
ARFLAGS := rcs
SWIFTC  := swiftc

# ── Directories ──────────────────────────────────────────────────────────────
SRCDIR   := src
STUBDIR  := src/macos_stubs
BUILDDIR := build

# ── Flags ────────────────────────────────────────────────────────────────────
DEFS := \
    -DCOMPAT_NEED_BLAKE2S

INCLUDES := \
    -I$(STUBDIR) \
    -I$(SRCDIR)

CFLAGS := \
    -std=c11 \
    -O2 \
    -Wall -Wextra \
    -Wno-unused-parameter \
    -Wno-pointer-sign \
    -mmacosx-version-min=11.0 \
    $(DEFS) \
    $(INCLUDES)

# ── Source files compiled with stubs ─────────────────────────────────────────
# wg_crypto.c still depends on missing crypto implementations
# (chacha20poly1305_mbuf, curve25519) – add once those are wired up.
SRCS := \
    $(SRCDIR)/wg_noise.c    \
    $(SRCDIR)/wg_cookie.c   \
    $(SRCDIR)/wg_crypto.c   \
    $(SRCDIR)/wg_crypto_impl.c \
    $(SRCDIR)/allowedips.c  \
    $(SRCDIR)/wg_session.c

OBJS := $(patsubst $(SRCDIR)/%.c, $(BUILDDIR)/%.o, $(SRCS))

# wg_crypto_impl.c provides chacha20_poly1305_encrypt/decrypt and crypto_dispatch.
# It intentionally has no corresponding FreeBSD source file.

# ── Primary targets ───────────────────────────────────────────────────────────
.PHONY: all clean help test xcframework build-ios install uninstall

all: $(BUILDDIR)/libwg.a $(BUILDDIR)/libswift_crypto.a $(BUILDDIR)/wg_core $(BUILDDIR)/wgctl

test: $(BUILDDIR)/crypto_vector_test
	@echo "  RUN  $<"
	@$<

# Build the multi-platform xcframework (macOS/iOS/tvOS/visionOS when supported)
# that Swift NetworkExtension code imports.
# See scripts/build-xcframework.sh for the full explanation of what
# this produces and how to consume it from Xcode.
xcframework:
	@./scripts/build-xcframework.sh

# Build the xcframework and verify iOS slices are present.
build-ios: xcframework
	@test -f build/xcframework/WireGuardCore.xcframework/ios-arm64/WireGuardCore.framework/WireGuardCore
	@test -f build/xcframework/WireGuardCore.xcframework/ios-arm64_x86_64-simulator/WireGuardCore.framework/WireGuardCore
	@echo "  OK  iOS slices present in WireGuardCore.xcframework"

$(BUILDDIR)/libwg.a: $(OBJS)
	$(AR) $(ARFLAGS) $@ $^
	@echo "  AR  $@"

# ── Swift Curve25519 bridge (CryptoKit) ──────────────────────────────────────
# Provides the curve25519 / curve25519_generate_public / _secret / _clamp_secret
# symbols that wg_noise.c references. Must be linked alongside libwg.a by any
# consumer (see the wg_core target below).
$(BUILDDIR)/libswift_crypto.a: $(SRCDIR)/crypto_bridge.swift | $(BUILDDIR)
	@echo "  SWIFTC $<"
	$(SWIFTC) -emit-library -static -o $@ $<

# ── wg_core: minimal handshake self-test client ──────────────────────────────
# Links libwg.a + libswift_crypto.a + CryptoKit framework.
$(BUILDDIR)/wg_core: $(SRCDIR)/wg_core.c $(BUILDDIR)/libwg.a $(BUILDDIR)/libswift_crypto.a
	@echo "  CC/LD  $@"
	$(CC) $(CFLAGS) $(SRCDIR)/wg_core.c \
	    -L$(BUILDDIR) -lwg -lswift_crypto \
	    -lpthread \
	    -framework Foundation -framework CryptoKit \
	    -L/usr/lib/swift \
	    -o $@

# ── wgctl: user-facing CLI (genkey/pubkey/genpsk/up/down/show) ───────────────
# Only needs libswift_crypto for Curve25519 (genkey/pubkey). Linking libwg.a
# anyway keeps a single set of link flags and lets future subcommands reuse
# the noise/cookie code without rewiring the Makefile.
$(BUILDDIR)/wgctl: $(SRCDIR)/wgctl.c $(BUILDDIR)/libwg.a $(BUILDDIR)/libswift_crypto.a
	@echo "  CC/LD  $@"
	$(CC) $(CFLAGS) $(SRCDIR)/wgctl.c \
	    -L$(BUILDDIR) -lwg -lswift_crypto \
	    -lpthread \
	    -framework Foundation -framework CryptoKit \
	    -L/usr/lib/swift \
	    -o $@

# ── Install / uninstall ──────────────────────────────────────────────────────
PREFIX  ?= /usr/local
BINDIR  ?= $(PREFIX)/bin
CONFDIR ?= /etc/wireguard
RUNDIR  ?= /var/run/wireguard
LOGDIR  ?= /var/log

install: all
	@if [ "$$(id -u)" != "0" ]; then \
	    echo "install: must run as root (sudo)"; exit 1; fi
	install -d $(BINDIR) $(CONFDIR) $(RUNDIR) $(LOGDIR)
	install -m 0755 $(BUILDDIR)/wgctl   $(BINDIR)/wgctl
	install -m 0755 $(BUILDDIR)/wg_core $(BINDIR)/wg_core
	@chmod 0700 $(CONFDIR) $(RUNDIR)
	@echo ""
	@echo "  Installed wgctl + wg_core to $(BINDIR)"
	@echo "  Put your wg-quick-style config at $(CONFDIR)/wg0.conf"
	@echo "  Then run:  sudo wgctl up wg0   (or use scripts/install.sh"
	@echo "             for launchd auto-start)"

uninstall:
	@if [ "$$(id -u)" != "0" ]; then \
	    echo "uninstall: must run as root (sudo)"; exit 1; fi
	rm -f $(BINDIR)/wgctl $(BINDIR)/wg_core
	@echo "  Removed wgctl + wg_core. Configs in $(CONFDIR) left in place."

# ── crypto_vector_test: KAT suite (blake2s / curve25519 / chacha20-poly1305) ─
$(BUILDDIR)/crypto_vector_test: $(SRCDIR)/crypto_vector_test.c $(BUILDDIR)/libwg.a $(BUILDDIR)/libswift_crypto.a
	@echo "  CC/LD  $@"
	$(CC) $(CFLAGS) $(SRCDIR)/crypto_vector_test.c \
	    -L$(BUILDDIR) -lwg -lswift_crypto \
	    -lpthread \
	    -framework Foundation -framework CryptoKit \
	    -L/usr/lib/swift \
	    -o $@

# ── Compile rule ─────────────────────────────────────────────────────────────
$(BUILDDIR)/%.o: $(SRCDIR)/%.c | $(BUILDDIR)
	@echo "  CC  $<"
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

# ── Housekeeping ─────────────────────────────────────────────────────────────
clean:
	rm -rf $(BUILDDIR) $(SRCDIR)/wg_noise.o

help:
	@echo "Targets:"
	@echo "  all    – build libwg.a + libswift_crypto.a  (default)"
	@echo "  build-ios – build xcframework and verify iOS device/simulator slices"
	@echo "  clean  – remove build artefacts"
	@echo "  help   – this message"
	@echo ""
	@echo "Key variables (override on command line):"
	@echo "  CC      = $(CC)"
	@echo "  SWIFTC  = $(SWIFTC)"
	@echo "  CFLAGS  = (see Makefile)"
