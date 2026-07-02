# shared/xrdproto/Makefile — builds libxrdproto.a, the ngx-free XRootD protocol core.
#
# WHAT: Compiles the project's pure-C protocol kernels into a standalone static
#       library that the native clients (xrdcp/xrdfs) link, while the nginx module
#       keeps compiling the exact same source files via its own ./configure. The
#       wire vocabulary itself (opcodes/flags/structs) is header-only in
#       ../../src/protocols/root/protocol and needs no compilation.
# WHY:  One source of truth for both consumers (phase-37 §3). Building with
#       -DXRDPROTO_NO_NGX guarantees no ngx_* dependency leaks into the core;
#       `make check` enforces that on the built archive (invariant #2).
# HOW:  Build-in-place — the .c files stay under src/; this Makefile references
#       them directly. No files are moved and the module's `config` is untouched.

CC ?= cc
AR ?= ar

REPO   := ../..
COMPAT := $(REPO)/src/core/compat
PROTO  := $(REPO)/src/protocols/root/protocol

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

# NB: $(COMPAT) (src/core/compat) is added with -iquote, NOT -I. src/core/compat/time.h shares
# its basename with the system <time.h>; under -I it lands in the angle-bracket search
# path and shadows the real <time.h> (e.g. sd.h's `#include <time.h>` for struct
# timespec then self-resolves to compat/time.h and time_t goes undefined). -iquote
# serves only "..."-quoted includes (how every compat header here is referenced),
# leaving <...> system headers untouched.
# Phase-66: cross-dir includes in src/ are src-rooted (e.g. "compat/crypto.h"),
# so the src root itself is on the quoted-include path too (-iquote, same
# time.h-shadowing rationale as $(COMPAT)).
ALL_CFLAGS := -std=c11 -Wall -Wextra -fPIC $(HARDEN) $(OPT) \
              -DXRDPROTO_NO_NGX $(CODEC_CFLAGS) -iquote $(REPO)/src \
              -iquote $(COMPAT) -I$(PROTO) $(CFLAGS)

BUILD := build
LIB   := libxrdproto.a

# Pure-C kernels. (crc32c: pgread/pgwrite + checksum; crc64: crc64 checksum types;
# hex: encode/display; crypto: HMAC-SHA256/SHA-256 for GSI sigver; error_mapping:
# errno/ns -> kXR; uri: RFC-3986 percent encode/decode (SigV4 canonical URI +
# WebDAV href decode); host_format: IPv6-aware host:port formatting; kxr_names:
# kXR opcode/status/error name tables; json_min: dependency-free JSON value
# extractor for client JWT-claim display — NO jansson, the safe replacement for
# the old strstr() hack.  The module keeps its jansson src/auth/token/json.c for the
# security-critical JWKS path; this is the lightweight diagnostic core only.)
NAMES := crc32c crc64 crc32_ieee hex crypto error_mapping checksum_core uri \
         host_format host_split kxr_names sigv4 pgio vendor_ext sss_bf fattr_codec \
         subprocess json_min \
         codec_core codec_zlib codec_zstd codec_lzma codec_brotli codec_bzip2 \
         codec_lz4
COMPAT_OBJS := $(addprefix $(BUILD)/,$(addsuffix .o,$(NAMES)))
# GSI/sigver crypto + wire kernels (shared with the module's src/auth/gsi).
GSI   := $(REPO)/src/auth/gsi
# Phase-38: gsi_core.c split into single-responsibility siblings (all ngx-free).
GSI_OBJS := $(BUILD)/gsi_core.o $(BUILD)/gsi_buf.o $(BUILD)/gsi_dh.o \
            $(BUILD)/gsi_cipher.o $(BUILD)/gsi_rsa.o $(BUILD)/proxy_req.o
# Token kernels shared with the module's src/auth/token (WLCG scope authz + JWT
# base64url decode — the DECODE/scope core, not the JWKS signature-verify path).
TOKEN := $(REPO)/src/auth/token
TOKEN_OBJS := $(BUILD)/scopes.o $(BUILD)/b64url.o
# Storage Driver POSIX raw fd ops (src/fs/backend/sd_posix.c). Under
# -DXRDPROTO_NO_NGX only the worker-safe pread/pwrite/... slots + the driver
# descriptor compile (the namespace/instance/registry ops are nginx-coupled and
# #ifdef'd out), so checksum_core.c can route its fd reads through the same
# xrootd_sd_posix_driver the module uses, with no nginx dependency.
BACKEND := $(REPO)/src/fs/backend
BACKEND_OBJS := $(BUILD)/sd_posix.o $(BUILD)/sd_block.o $(BUILD)/sd_s3.o \
                $(BUILD)/meta_advisory.o
# ZIP central-directory parsing kernel (src/protocols/root/zip/zip_kernel.c): the pure-C,
# callback-driven, bounds-checked EOCD/ZIP64 parser shared with the module's
# src/protocols/root/zip. No nginx / OpenSSL / fixed I/O source — the client's clean-room ZIP
# reader (client/lib/zip.c) and the server's member-access path both link it.
ZIP   := $(REPO)/src/protocols/root/zip
ZIP_OBJS := $(BUILD)/zip_kernel.o
# SSS keytab text grammar (src/auth/sss/sss_keytab_kernel.c): the pure-C keytab line
# parser + file-permission check shared with the module's src/auth/sss. The crypto
# kernels (sss_bf) and hex codec are already shared above; this closes the gap.
SSS   := $(REPO)/src/auth/sss
SSS_OBJS := $(BUILD)/sss_keytab_kernel.o
# xrdwire per-opcode wire-body codec (src/protocols/root/protocol/codec/*.c): the shared
# pack/unpack of each opcode's fixed request/response body. ngx-free; the client
# and module both marshal through it so the wire offsets cannot drift.
PROTO_CODEC := $(REPO)/src/protocols/root/protocol/codec
CODEC_OBJS  := $(BUILD)/wire_codec_meta.o $(BUILD)/wire_codec_file.o \
               $(BUILD)/wire_codec_ns.o $(BUILD)/wire_codec_session.o
# Shared, ngx-free VFS I/O verb core (src/fs/core/vfs_core.c): the `vfs` layer of
# module->vfs_server->vfs->backend / client->vfs->backend. Backend-neutral byte
# I/O over the SD driver, shared by the server data plane and the userland tools.
FSCORE := $(REPO)/src/fs/core
FSCORE_OBJS := $(BUILD)/vfs_core.o
OBJS  := $(COMPAT_OBJS) $(GSI_OBJS) $(TOKEN_OBJS) $(BACKEND_OBJS) $(ZIP_OBJS) \
         $(SSS_OBJS) $(CODEC_OBJS) $(FSCORE_OBJS)

.PHONY: all check clean
all: $(LIB)

$(LIB): $(OBJS)
	$(AR) rcs $@ $^
	@echo " + built $@ ($(words $(OBJS)) objects, XROOTD_OPTIMIZE=$(XROOTD_OPTIMIZE))"

$(BUILD)/%.o: $(COMPAT)/%.c | $(BUILD)
	$(CC) $(ALL_CFLAGS) -c $< -o $@

$(BUILD)/gsi_core.o: $(GSI)/gsi_core.c | $(BUILD)
	$(CC) $(ALL_CFLAGS) -c $< -o $@
$(BUILD)/gsi_buf.o: $(GSI)/gsi_buf.c | $(BUILD)
	$(CC) $(ALL_CFLAGS) -c $< -o $@
$(BUILD)/gsi_dh.o: $(GSI)/gsi_dh.c | $(BUILD)
	$(CC) $(ALL_CFLAGS) -c $< -o $@
$(BUILD)/gsi_cipher.o: $(GSI)/gsi_cipher.c | $(BUILD)
	$(CC) $(ALL_CFLAGS) -c $< -o $@
$(BUILD)/proxy_req.o: $(GSI)/proxy_req.c | $(BUILD)
	$(CC) $(ALL_CFLAGS) -c $< -o $@
$(BUILD)/gsi_rsa.o: $(GSI)/gsi_rsa.c | $(BUILD)
	$(CC) $(ALL_CFLAGS) -c $< -o $@

# Token kernels live under src/auth/token; explicit rules (take precedence over the
# COMPAT pattern rule). The local "scopes.h"/"b64url.h" resolve via the .c's dir.
$(BUILD)/scopes.o: $(TOKEN)/scopes.c | $(BUILD)
	$(CC) $(ALL_CFLAGS) -c $< -o $@
$(BUILD)/b64url.o: $(TOKEN)/b64url.c | $(BUILD)
	$(CC) $(ALL_CFLAGS) -c $< -o $@

# Storage Driver POSIX raw fd ops live under src/fs/backend; explicit rule (its
# "sd.h" resolves via the .c's own dir; the ngx-coupled headers are #ifdef'd
# out under -DXRDPROTO_NO_NGX).
$(BUILD)/sd_posix.o: $(BACKEND)/posix/sd_posix.c | $(BUILD)
	$(CC) $(ALL_CFLAGS) -c $< -o $@
$(BUILD)/sd_block.o: $(BACKEND)/block/sd_block.c | $(BUILD)
	$(CC) $(ALL_CFLAGS) -c $< -o $@
$(BUILD)/sd_s3.o: $(BACKEND)/s3/sd_s3.c | $(BUILD)
	$(CC) $(ALL_CFLAGS) -c $< -o $@
$(BUILD)/meta_advisory.o: $(BACKEND)/meta_advisory.c | $(BUILD)
	$(CC) $(ALL_CFLAGS) -c $< -o $@

# ZIP parsing kernel lives under src/protocols/root/zip; explicit rule (its "zip_kernel.h"
# resolves via the .c's own dir). Pure C — no I/O source, no nginx deps.
$(BUILD)/zip_kernel.o: $(ZIP)/zip_kernel.c | $(BUILD)
	$(CC) $(ALL_CFLAGS) -c $< -o $@

# SSS keytab grammar lives under src/auth/sss; explicit rule (its "../compat/hex.h"
# resolves via the .c's own dir). Pure C — no nginx deps.
$(BUILD)/sss_keytab_kernel.o: $(SSS)/sss_keytab_kernel.c | $(BUILD)
	$(CC) $(ALL_CFLAGS) -c $< -o $@

# xrdwire codec family files live under src/protocols/root/protocol/codec; explicit rule (their
# "wire_codec.h" resolves via the .c's own dir). Pure C — no nginx deps.
$(BUILD)/wire_codec_%.o: $(PROTO_CODEC)/wire_codec_%.c | $(BUILD)
	$(CC) $(ALL_CFLAGS) -c $< -o $@

# Shared VFS core lives under src/fs/core; explicit rule (its "../backend/sd.h"
# resolves via the .c's own dir). Pure C — ngx-free fallback in sd.h.
$(BUILD)/vfs_core.o: $(FSCORE)/vfs_core.c | $(BUILD)
	$(CC) $(ALL_CFLAGS) -c $< -o $@

$(BUILD):
	mkdir -p $(BUILD)

# Enforce the ngx-free invariant on the built archive, and that no pure logic is
# stranded in the module (every ngx-free src/core/compat/*.c is shared or allowlisted).
check: $(LIB)
	./check-ngx-free.sh $(LIB)
	./check-shared-coverage.sh $(LIB)

clean:
	rm -rf $(BUILD) $(LIB)
