# WireGuard – macOS userspace port
# Compiles FreeBSD wg_noise.c + wg_cookie.c on macOS via stub headers.

# ── Toolchain ────────────────────────────────────────────────────────────────
CC      := cc
AR      := ar
ARFLAGS := rcs

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
    $(SRCDIR)/wg_noise.c  \
    $(SRCDIR)/wg_cookie.c

OBJS := $(patsubst $(SRCDIR)/%.c, $(BUILDDIR)/%.o, $(SRCS))

# ── Primary targets ───────────────────────────────────────────────────────────
.PHONY: all clean help

all: $(BUILDDIR)/libwg.a

$(BUILDDIR)/libwg.a: $(OBJS)
	$(AR) $(ARFLAGS) $@ $^
	@echo "  AR  $@"

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
	@echo "  all    – build $(BUILDDIR)/libwg.a  (default)"
	@echo "  clean  – remove build artefacts"
	@echo "  help   – this message"
	@echo ""
	@echo "Key variables (override on command line):"
	@echo "  CC      = $(CC)"
	@echo "  CFLAGS  = (see Makefile)"
