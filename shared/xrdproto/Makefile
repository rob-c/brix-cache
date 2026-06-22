# shared/xrdproto/Makefile — builds libxrdproto.a, the ngx-free XRootD protocol core.
#
# WHAT: Compiles the project's pure-C protocol kernels into a standalone static
#       library that the native clients (xrdcp/xrdfs) link, while the nginx module
#       keeps compiling the exact same source files via its own ./configure. The
#       wire vocabulary itself (opcodes/flags/structs) is header-only in
#       ../../src/protocol and needs no compilation.
# WHY:  One source of truth for both consumers (phase-37 §3). Building with
#       -DXRDPROTO_NO_NGX guarantees no ngx_* dependency leaks into the core;
#       `make check` enforces that on the built archive (invariant #2).
# HOW:  Build-in-place — the .c files stay under src/; this Makefile references
#       them directly. No files are moved and the module's `config` is untouched.

CC ?= cc
AR ?= ar

REPO   := ../..
COMPAT := $(REPO)/src/compat
PROTO  := $(REPO)/src/protocol

# Hardening flags — mirror the module's ./configure (repo-root `config`).
HARDEN := -D_GNU_SOURCE -D_FORTIFY_SOURCE=2 -fstack-protector-strong \
          -fstack-clash-protection -fcf-protection=full \
          -Wformat -Werror=format-security

# Optimize profile — same knob/default as the module (XROOTD_OPTIMIZE, default v2).
XROOTD_OPTIMIZE ?= v2
OPT_v2     := -O3 -march=x86-64-v2 -fno-plt
OPT_v3     := -O3 -march=x86-64-v3 -fno-plt
OPT_native := -O3 -march=native -fno-plt
OPT := $(OPT_$(XROOTD_OPTIMIZE))
ifeq ($(OPT),)
  OPT := $(OPT_v2)
endif

# Compression codecs (phase-42): compile-gate each backend on its dev lib, like
# the module's root `config`. Only -D + cflags belong here (a static archive
# links nothing); the consumer (client/Makefile) adds the matching -l libs.
CODEC_CFLAGS := -DXROOTD_HAVE_ZLIB=1
ifeq ($(shell pkg-config --exists libzstd 2>/dev/null && echo y),y)
  CODEC_CFLAGS += -DXROOTD_HAVE_ZSTD=1
endif
ifeq ($(shell pkg-config --exists liblzma 2>/dev/null && echo y),y)
  CODEC_CFLAGS += -DXROOTD_HAVE_LZMA=1
endif
ifeq ($(shell pkg-config --exists libbrotlienc libbrotlidec 2>/dev/null && echo y),y)
  CODEC_CFLAGS += -DXROOTD_HAVE_BROTLI=1
endif
ifeq ($(shell pkg-config --exists bzip2 2>/dev/null && echo y),y)
  CODEC_CFLAGS += -DXROOTD_HAVE_BZIP2=1
else ifeq ($(shell printf '\#include <bzlib.h>\n' | $(CC) -E - >/dev/null 2>&1 && echo y),y)
  CODEC_CFLAGS += -DXROOTD_HAVE_BZIP2=1
endif
# lz4 (phase-42 extension): an env hint (XROOTD_LZ4_CFLAGS) carries the -I for a
# non-system (conda) liblz4 header; else pkg-config.  Link libs are added by the
# consumer (client/Makefile).
ifneq ($(strip $(XROOTD_LZ4_CFLAGS)$(XROOTD_LZ4_LIBS)),)
  CODEC_CFLAGS += -DXROOTD_HAVE_LZ4=1 $(XROOTD_LZ4_CFLAGS)
else ifeq ($(shell pkg-config --exists liblz4 2>/dev/null && echo y),y)
  CODEC_CFLAGS += -DXROOTD_HAVE_LZ4=1 $(shell pkg-config --cflags liblz4 2>/dev/null)
endif

ALL_CFLAGS := -std=c11 -Wall -Wextra -fPIC $(HARDEN) $(OPT) \
              -DXRDPROTO_NO_NGX $(CODEC_CFLAGS) -I$(COMPAT) -I$(PROTO) $(CFLAGS)

BUILD := build
LIB   := libxrdproto.a

# Pure-C kernels. (crc32c: pgread/pgwrite + checksum; crc64: crc64 checksum types;
# hex: encode/display; crypto: HMAC-SHA256/SHA-256 for GSI sigver; error_mapping:
# errno/ns -> kXR; uri: RFC-3986 percent encode/decode (SigV4 canonical URI +
# WebDAV href decode); host_format: IPv6-aware host:port formatting; kxr_names:
# kXR opcode/status/error name tables.)
NAMES := crc32c crc64 crc32_ieee hex crypto error_mapping checksum_core uri \
         host_format host_split kxr_names sigv4 pgio vendor_ext sss_bf fattr_codec \
         subprocess \
         codec_core codec_zlib codec_zstd codec_lzma codec_brotli codec_bzip2 \
         codec_lz4
COMPAT_OBJS := $(addprefix $(BUILD)/,$(addsuffix .o,$(NAMES)))
# GSI/sigver crypto + wire kernels (shared with the module's src/gsi).
GSI   := $(REPO)/src/gsi
GSI_OBJS := $(BUILD)/gsi_core.o
# Token kernels shared with the module's src/token (WLCG scope authz + JWT
# base64url decode — the DECODE/scope core, not the JWKS signature-verify path).
TOKEN := $(REPO)/src/token
TOKEN_OBJS := $(BUILD)/scopes.o $(BUILD)/b64url.o
OBJS  := $(COMPAT_OBJS) $(GSI_OBJS) $(TOKEN_OBJS)

.PHONY: all check clean
all: $(LIB)

$(LIB): $(OBJS)
	$(AR) rcs $@ $^
	@echo " + built $@ ($(words $(OBJS)) objects, XROOTD_OPTIMIZE=$(XROOTD_OPTIMIZE))"

$(BUILD)/%.o: $(COMPAT)/%.c | $(BUILD)
	$(CC) $(ALL_CFLAGS) -c $< -o $@

$(BUILD)/gsi_core.o: $(GSI)/gsi_core.c | $(BUILD)
	$(CC) $(ALL_CFLAGS) -c $< -o $@

# Token kernels live under src/token; explicit rules (take precedence over the
# COMPAT pattern rule). The local "scopes.h"/"b64url.h" resolve via the .c's dir.
$(BUILD)/scopes.o: $(TOKEN)/scopes.c | $(BUILD)
	$(CC) $(ALL_CFLAGS) -c $< -o $@
$(BUILD)/b64url.o: $(TOKEN)/b64url.c | $(BUILD)
	$(CC) $(ALL_CFLAGS) -c $< -o $@

$(BUILD):
	mkdir -p $(BUILD)

# Enforce the ngx-free invariant on the built archive.
check: $(LIB)
	./check-ngx-free.sh $(LIB)

clean:
	rm -rf $(BUILD) $(LIB)
