# WireGuard – macOS userspace port
# Compiles FreeBSD wg_noise.c + wg_cookie.c on macOS via stub headers.

# ── Toolchain ────────────────────────────────────────────────────────────────
CC      := cc
AR      := ar
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
    $(SRCDIR)/wg_crypto_impl.c

OBJS := $(patsubst $(SRCDIR)/%.c, $(BUILDDIR)/%.o, $(SRCS))

# wg_crypto_impl.c provides chacha20_poly1305_encrypt/decrypt and crypto_dispatch.
# It intentionally has no corresponding FreeBSD source file.

# ── Primary targets ───────────────────────────────────────────────────────────
.PHONY: all clean help test

all: $(BUILDDIR)/libwg.a $(BUILDDIR)/libswift_crypto.a $(BUILDDIR)/wg_core $(BUILDDIR)/crypto_vector_test

test: $(BUILDDIR)/crypto_vector_test
	@echo "  RUN  $<"
	@$<

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
	@echo "  all    – build libwg.a + libswift_crypto.a + wg_core  (default)"
	@echo "  clean  – remove build artefacts"
	@echo "  help   – this message"
	@echo ""
	@echo "Key variables (override on command line):"
	@echo "  CC      = $(CC)"
	@echo "  SWIFTC  = $(SWIFTC)"
	@echo "  CFLAGS  = (see Makefile)"
