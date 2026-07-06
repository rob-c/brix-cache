# client/Makefile — native xrdcp/xrdfs built on libxrdproto (phase-37).
#
# WHAT: Builds libbrix.a (the root:// connection/session/ops layer) and the
#       CLI tools, linking the project's ngx-free protocol core (libxrdproto.a).
# WHY:  Tools "built atop the project's code" with NO libXrdCl / libXrdSec* — only
#       libxrdproto + OpenSSL.
# HOW:  Mirrors the module's hardening/optimize flags; pulls wire structs from the
#       in-tree src/protocols/root/protocol headers via -I$(SRC) (build-in-place, no file moves).

CC ?= cc
AR ?= ar

REPO      := ..
SRC       := $(REPO)/src
PROTO_DIR := $(REPO)/shared/xrdproto
PROTO_LIB := $(PROTO_DIR)/libxrdproto.a

# Hardening — mirror the module's ./configure (repo-root `config`).
HARDEN := -D_GNU_SOURCE -D_FORTIFY_SOURCE=2 -fstack-protector-strong \
          -fstack-clash-protection -fcf-protection=full -fPIE \
          -Wformat -Werror=format-security

# Optimize profile — same knob/default as the module (BRIX_OPTIMIZE, default v2).
BRIX_OPTIMIZE ?= v2
OPT_v2     := -O3 -march=x86-64-v2 -fno-plt
OPT_v3     := -O3 -march=x86-64-v3 -fno-plt
OPT_native := -O3 -march=native -fno-plt
OPT := $(OPT_$(BRIX_OPTIMIZE))
ifeq ($(OPT),)
  OPT := $(OPT_v2)
endif

# -MMD -MP: emit a .d per object listing every header it includes, so editing a
# header (e.g. lib/brix.h, which changes struct layout) reliably recompiles every
# dependent object — without this, incremental `make` leaves stale, mixed-ABI .o
# files that crash or read garbage. The generated .d files are -included below.
# krb5 (sec_krb5.c) is compile-gated like fuse3: when libkrb5 dev is present,
# arm -DBRIX_HAVE_KRB5 + its cflags/libs; otherwise sec_krb5.c is an inert stub
# and the auth driver simply skips krb5. Kept ngx-free (client-only).
HAVE_KRB5 := $(shell pkg-config --exists krb5 2>/dev/null && echo yes)
ifeq ($(HAVE_KRB5),yes)
  KRB5_CFLAGS := -DBRIX_HAVE_KRB5 $(shell pkg-config --cflags krb5 2>/dev/null)
  KRB5_LIBS   := $(shell pkg-config --libs krb5 2>/dev/null)
endif

# io_uring (phase-44): lib/core/aio/uring.c is ALWAYS in LIB_SRCS and stubs out under
# #ifndef BRIX_HAVE_LIBURING (the always-compiled-stub model, like sec_krb5.c),
# so the library API is stable regardless of build config. When liburing-dev is
# present, arm -DBRIX_HAVE_LIBURING + its cflags/libs; otherwise the disk ring
# and loop engine compile to inert stubs and the epoll/pread path is the only one
# in the binary (no -luring dependency). Kept ngx-free (client-only).
HAVE_LIBURING := $(shell pkg-config --exists liburing 2>/dev/null && echo yes)
ifeq ($(HAVE_LIBURING),yes)
  URING_CFLAGS := -DBRIX_HAVE_LIBURING $(shell pkg-config --cflags liburing 2>/dev/null)
  URING_LIBS   := $(shell pkg-config --libs liburing 2>/dev/null)
endif

# Compression codecs (phase-42): libxrdproto.a carries codec_*.o (compile-gated by
# shared/xrdproto/Makefile); here we add the matching link libs so the client
# binaries resolve them. zlib (-lz) is already linked below. Each is optional.
CODEC_LIBS :=
ifeq ($(shell pkg-config --exists libzstd 2>/dev/null && echo y),y)
  CODEC_LIBS += $(shell pkg-config --libs libzstd 2>/dev/null)
endif
ifeq ($(shell pkg-config --exists liblzma 2>/dev/null && echo y),y)
  CODEC_LIBS += $(shell pkg-config --libs liblzma 2>/dev/null)
endif
ifeq ($(shell pkg-config --exists libbrotlienc libbrotlidec 2>/dev/null && echo y),y)
  CODEC_LIBS += $(shell pkg-config --libs libbrotlienc libbrotlidec 2>/dev/null)
endif
ifeq ($(shell pkg-config --exists bzip2 2>/dev/null && echo y),y)
  CODEC_LIBS += $(shell pkg-config --libs bzip2 2>/dev/null)
else ifeq ($(shell printf '\#include <bzlib.h>\n' | $(CC) -E - >/dev/null 2>&1 && echo y),y)
  CODEC_LIBS += -lbz2
endif
# lz4 (phase-42 extension): an env hint (BRIX_LZ4_LIBS) supplies the link for a
# non-system liblz4 (default the bare soname from the default loader path); else
# pkg-config.  Never propagate a non-system -L (it would pull that prefix's other
# codec sonames, not on the runtime path) — see config's lz4 block.
ifneq ($(strip $(BRIX_LZ4_CFLAGS)$(BRIX_LZ4_LIBS)),)
  CODEC_LIBS += $(if $(strip $(BRIX_LZ4_LIBS)),$(BRIX_LZ4_LIBS),-l:liblz4.so.1)
else ifeq ($(shell pkg-config --exists liblz4 2>/dev/null && echo y),y)
  CODEC_LIBS += -l:liblz4.so.1
endif

# -DXRDPROTO_NO_NGX: the native client is an nginx-free consumer of the shared
# protocol core (libxrdproto), so dual-build headers (e.g. compat/error_mapping.h)
# resolve to their ngx-free variants exactly as the libxrdproto build does.
ALL_CFLAGS := -std=c11 -Wall -Wextra $(HARDEN) $(OPT) -pthread -Ilib -I$(SRC) -I../shared -DXRDPROTO_NO_NGX -MMD -MP $(KRB5_CFLAGS) $(URING_CFLAGS) $(CFLAGS)
# Inject the build-time version tag when set (overrides the "dev" fallback in
# client/lib/core/version.h).  Quote escaping: the outer \" are consumed by
# make, leaving the inner \' pair intact for the C preprocessor.
ifneq ($(BRIX_CLIENT_VERSION),)
ALL_CFLAGS += -DBRIX_CLIENT_VERSION=\"$(BRIX_CLIENT_VERSION)\"
endif

# OpenSSL: libssl (in-protocol TLS) + libcrypto (GSI/sigver + libxrdproto kernels +
# md5). zlib (-lz): adler32 for --cksum (the algorithm xrdcp historically uses).
# krb5 libs (when present) for the sec_krb5 AP-REQ path. CODEC_LIBS: zstd/lzma/
# brotli/bzip2 for the shared codec kernels (gzip/deflate already via -lz).
LDLIBS := -lssl -lcrypto -lz $(KRB5_LIBS) $(CODEC_LIBS) $(URING_LIBS)

# phase-69: client/lib reorganized into src-style concept buckets. Paths below are
# the single source of truth for the build; every .c must be listed (no wildcards).
LIB_SRCS   := \
  lib/core/aio/aio.c lib/core/aio/aio_buffers.c lib/core/aio/aio_conn.c lib/core/aio/aio_engine.c lib/core/aio/aio_io.c lib/core/aio/aio_mgr.c lib/core/aio/uring.c \
  lib/core/config/xrdrc.c lib/core/config/envalias.c \
  lib/core/types/status.c lib/core/types/units.c \
  lib/net/conn.c lib/net/netdiag.c lib/net/netpref.c lib/net/nettmo.c lib/net/pool.c lib/net/resilient.c lib/net/sock.c lib/net/streams.c lib/net/tls.c lib/net/url.c \
  ../shared/net/proxy_env.c ../shared/net/proxy_connect.c \
  lib/auth/auth.c lib/auth/sigver.c \
  lib/auth/cred/cred.c lib/auth/cred/cred_bearer.c lib/auth/cred/cred_krb5.c lib/auth/cred/cred_s3.c lib/auth/cred/cred_sss.c lib/auth/cred/cred_x509.c lib/auth/cred/credinfo.c lib/auth/cred/credrefresh.c \
  lib/auth/sec/sec_gsi.c lib/auth/sec/sec_host.c lib/auth/sec/sec_krb5.c lib/auth/sec/sec_pwd.c lib/auth/sec/sec_sss.c lib/auth/sec/sec_token.c lib/auth/sec/sec_unix.c \
  lib/auth/gsi/proxy.c \
  lib/auth/sss/sss_keytab.c \
  lib/fs/fattr.c lib/fs/glob.c lib/fs/iobuf.c lib/fs/overlay.c lib/fs/path.c lib/fs/rmtree.c lib/fs/vfs.c lib/fs/vfs_block.c lib/fs/vfs_posix.c lib/fs/walk.c \
  lib/fs/backend/s3/vfs_s3.c lib/fs/backend/s3/vfs_s3_http.c lib/fs/backend/s3/vfs_s3_io.c lib/fs/backend/s3/vfs_s3_transport.c \
  lib/protocols/root/frame.c lib/protocols/root/ops_ext.c lib/protocols/root/ops_file.c lib/protocols/root/ops_file_pg.c lib/protocols/root/ops_file_rw.c lib/protocols/root/ops_fs.c lib/protocols/root/ops_meta.c \
  lib/protocols/http/http.c lib/protocols/http/http_download.c lib/protocols/http/http_req.c lib/protocols/http/http_upload.c lib/protocols/http/webfile.c lib/protocols/http/webfile_io.c lib/protocols/http/weblist.c \
  lib/protocols/s3/s3.c \
  lib/protocols/shared/checksum.c lib/protocols/shared/cks_verify.c lib/protocols/shared/cksum_manifest.c lib/protocols/shared/zip.c lib/protocols/shared/zip_write.c \
  lib/xfer/copy.c lib/xfer/copy_block.c lib/xfer/copy_filter.c lib/xfer/copy_local.c lib/xfer/copy_pump.c lib/xfer/copy_recursive.c lib/xfer/copy_remote.c lib/xfer/copy_zip.c \
  lib/posix/fuse_ops.c lib/posix/posix_map.c \
  lib/cli/cli_cksum.c lib/cli/cli_conn.c lib/cli/cli_cred.c lib/cli/cli_hint.c lib/cli/cli_opts.c lib/cli/jsonout.c lib/cli/suggest.c lib/cli/xferjournal.c \
  lib/observability/capture.c lib/observability/trace.c \
  lib/observability/metabench/metabench.c lib/observability/metabench/metabench_run.c
LIB_OBJS   := $(LIB_SRCS:.c=.o)

# §14.1: the connection/session layer is the public libbrix — a clean-room,
# libXrdCl-free C client library. Shipped as libbrix.a + a versioned .so + a
# pkg-config file, so any C program can speak root:// with only libbrix +
# libxrdproto + OpenSSL/zlib.
CLIENT_LIB     := libbrix.a
BRIX_VERSION   := 0.1.0
BRIX_SOMAJOR   := 0
LIBBRIX_SO     := libbrix.so
LIBBRIX_SONAME := libbrix.so.$(BRIX_SOMAJOR)
LIBBRIX_REAL   := libbrix.so.$(BRIX_VERSION)
PIC_OBJS       := $(LIB_SRCS:.c=.pic.o)

PREFIX     ?= /usr/local
LIBDIR     ?= $(PREFIX)/lib
INCLUDEDIR ?= $(PREFIX)/include
PKGCONFDIR ?= $(LIBDIR)/pkgconfig

# All compiled executables land under bin/ (keeps the source tree clean — the whole
# dir is git-ignored). Libraries (.a/.so/.pc) stay in the build root. The bare names
# (xrd, xrdcp, fault-proxy, …) remain valid `make` targets via phony aliases below,
# so `make xrdcp` / `make -C client fault-proxy` keep working; the artifact is
# bin/<name>.
BINDIR := bin

# Every binary is a thin front-end: apps/<family>/<name>.o + the client lib + libxrdproto.
BINS := xrd xrdfs xrdcp xrdcksum xrdprep xrdgsiproxy xrddiag \
        xrdmapc xrdgsitest \
        xrdsssadmin xrdstorascan
BIN_EXES := $(addprefix $(BINDIR)/,$(BINS))

# Multi-call personalities: the stock tool names stay invocable as symlinks to
# their multi-call binary (xrdcksum dispatches on argv[0]/subcommand; xrddiag
# likewise absorbed the qstats/wait41/mpxstats micro-tools).
CKSUM_LINKS := xrdcrc32c xrdcrc64 xrdadler32 xrdckverify xrdcinfo
DIAG_LINKS  := xrdqstats wait41 mpxstats
LINK_EXES   := $(addprefix $(BINDIR)/,$(CKSUM_LINKS) $(DIAG_LINKS))

# §14.4: the FUSE mount + the LD_PRELOAD POSIX shim are built only when libfuse3
# is present. They are NOT in BINS (they need extra flags / a separate link rule).
HAVE_FUSE3   := $(shell pkg-config --exists fuse3 2>/dev/null && echo yes)
FUSE3_CFLAGS := $(shell pkg-config --cflags fuse3 2>/dev/null)
FUSE3_LIBS   := $(shell pkg-config --libs fuse3 2>/dev/null)
PRELOAD_SO   := libbrixposix_preload.so
OPT_BINS     := $(PRELOAD_SO)
OPT_EXES     :=
# The FUSE mount is ONE binary (xrootdfs) that contains both drivers: the
# async/resilient default and the simple synchronous fallback, selected at run
# time by `--legacy` (front-end apps/xrootdfs_main.c).
ifeq ($(HAVE_FUSE3),yes)
  OPT_EXES += $(BINDIR)/xrootdfs
  OPT_EXES += $(BINDIR)/brixMount
endif

# phase-69: apps regrouped into tool-family subdirs — each CLI's translation units
# are listed in a <name>_OBJS variable (the Phase-38 split siblings are just extra
# entries). The single link rule below expands these via .SECONDEXPANSION.
xrdcp_OBJS        := apps/copy/xrdcp.o apps/copy/xrdcp_transfer.o apps/copy/xrdcp_recursive.o
xrdfs_OBJS        := apps/fs/xrdfs.o apps/fs/xrdfs_data.o apps/fs/xrdfs_walk.o apps/fs/xrdfs_fmt.o apps/fs/xrdfs_meta.o apps/fs/xrdfs_web.o
xrd_OBJS          := apps/diag/xrd.o apps/diag/xrd_battery.o apps/diag/xrd_doctor.o apps/diag/xrd_clockskew.o apps/diag/xrd_mount.o
xrddiag_OBJS      := apps/diag/xrddiag.o apps/diag/diag_check.o apps/diag/diag_bench.o apps/diag/diag_metabench.o apps/diag/diag_watch.o apps/diag/diag_topology.o apps/diag/diag_compare.o apps/diag/diag_doctor.o apps/diag/diag_misc.o \
                     apps/diag/xrdqstats.o apps/diag/wait41.o apps/diag/mpxstats.o
xrdstorascan_OBJS := apps/scan/xrdstorascan.o apps/scan/storascan_core.o
xrdstorascan_LDLIBS := -lm
xrdcksum_OBJS     := apps/cksum/xrdcksum.o apps/cksum/xrdckverify.o apps/cksum/xrdcinfo.o apps/cksum/xrdcktree.o
xrdgsiproxy_OBJS  := apps/auth/xrdgsiproxy.o
xrdgsitest_OBJS   := apps/auth/xrdgsitest.o
xrdsssadmin_OBJS  := apps/auth/xrdsssadmin.o
xrdmapc_OBJS      := apps/diag/xrdmapc.o
xrdprep_OBJS      := apps/prep/xrdprep.o

ALL_OBJS := $(LIB_OBJS) $(foreach b,$(BINS),$($(b)_OBJS))
DEPS     := $(ALL_OBJS:.o=.d)

.PHONY: all proto clean lib install install-bin install-man install-completions example-test test libbrix.pc $(BINS) $(CKSUM_LINKS) $(DIAG_LINKS) xrootdfs brixMount
all: $(BIN_EXES) $(LINK_EXES) $(OPT_BINS) $(OPT_EXES)

# Keep intermediates (apps/*.o, lib/*.o built via the chained pattern rules). Without
# this, GNU make auto-deletes them after `make all`, so a later `make <tool>` must
# RELINK the binary — which fails (and make then deletes the binary) if that second
# invocation runs in an environment where pkg-config can't see the optional codecs.
# Marking everything secondary makes incremental `make <tool>` a no-op when up to date.
.SECONDARY:

# Build the shared core first (build-in-place; produces ../shared/xrdproto/libxrdproto.a).
proto:
	$(MAKE) -C $(PROTO_DIR)

$(BINDIR):
	@mkdir -p $(BINDIR)

# Phony aliases: `make xrdcp` (bare name) builds the real artifact bin/xrdcp, so
# existing `make -C client <name>` invocations keep working after the move to bin/.
$(BINS): %: $(BINDIR)/%
$(CKSUM_LINKS) $(DIAG_LINKS): %: $(BINDIR)/%
xrootdfs: $(BINDIR)/xrootdfs
brixMount: $(BINDIR)/brixMount

# Multi-call symlinks (stock tool names → their dispatcher binary).
$(addprefix $(BINDIR)/,$(CKSUM_LINKS)): $(BINDIR)/xrdcksum
	ln -sf xrdcksum $@
$(addprefix $(BINDIR)/,$(DIAG_LINKS)): $(BINDIR)/xrddiag
	ln -sf xrddiag $@

$(BIN_EXES): | proto $(BINDIR)

%.o: %.c
	$(CC) $(ALL_CFLAGS) -c $< -o $@

$(CLIENT_LIB): $(LIB_OBJS)
	$(AR) rcs $@ $^

# Link hardening defaults. Packagers can override by exporting LDFLAGS.
LDFLAGS ?= -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack
# Executables are PIE; the shared lib is already -shared (implicitly PIC).
LDFLAGS_PIE := -pie

# phase-69: ONE static-pattern link rule for every front-end. Secondary expansion
# resolves each target's own object set ($<name>_OBJS, defined above) as its
# prerequisites, so the Phase-38 split siblings and any per-tool $<name>_LDLIBS
# (e.g. xrdstorascan's -lm) fold in without a bespoke rule per binary.
.SECONDEXPANSION:
$(BIN_EXES): $(BINDIR)/%: $$($$*_OBJS) $(CLIENT_LIB) | $(BINDIR)
	$(CC) $(ALL_CFLAGS) $(LDFLAGS) $(LDFLAGS_PIE) $($*_OBJS) $(CLIENT_LIB) $(PROTO_LIB) $(LDLIBS) $($*_LDLIBS) -o $@
	@echo " + built $@ (no libXrdCl/libXrdSec*)"

# §14.4 unified xrootdfs (FUSE) — ONE binary linking the front-end
# (xrootdfs_main.c) + both drivers: xrootdfs.c (async default) and
# xrootdfs_legacy.c (synchronous, via --legacy). The two driver TUs share no
# symbols but main(), so they co-link cleanly. Needs the libfuse3 headers/libs.
apps/fs/xrootdfs.o: apps/fs/xrootdfs.c apps/fs/xrootdfs_drivers.h | proto
	$(CC) $(ALL_CFLAGS) $(FUSE3_CFLAGS) -c $< -o $@
apps/fs/xrootdfs_legacy.o: apps/fs/xrootdfs_legacy.c apps/fs/xrootdfs_drivers.h | proto
	$(CC) $(ALL_CFLAGS) $(FUSE3_CFLAGS) -c $< -o $@
apps/fs/xrootdfs_main.o: apps/fs/xrootdfs_main.c apps/fs/xrootdfs_drivers.h | proto
	$(CC) $(ALL_CFLAGS) -c $< -o $@
# Phase-38 split of the async driver: the siblings also need the fuse3 headers.
XROOTDFS_SPLIT := apps/fs/xrootdfs_meta.o apps/fs/xrootdfs_io.o apps/fs/xrootdfs_xattr.o
$(XROOTDFS_SPLIT): apps/fs/%.o: apps/fs/%.c apps/fs/xrootdfs_internal.h | proto
	$(CC) $(ALL_CFLAGS) $(FUSE3_CFLAGS) -c $< -o $@
$(BINDIR)/xrootdfs: apps/fs/xrootdfs_main.o apps/fs/xrootdfs.o apps/fs/xrootdfs_legacy.o $(XROOTDFS_SPLIT) $(CLIENT_LIB) | $(BINDIR)
	$(CC) $(ALL_CFLAGS) $(LDFLAGS) $(LDFLAGS_PIE) apps/fs/xrootdfs_main.o apps/fs/xrootdfs.o apps/fs/xrootdfs_legacy.o $(XROOTDFS_SPLIT) $(CLIENT_LIB) $(PROTO_LIB) $(LDLIBS) $(FUSE3_LIBS) -o $@
	@echo " + built $@ (libfuse3; unified async+legacy; no libXrdCl/libXrdSec*)"

# §14.5 brixMount (FUSE) — the umbrella front-end `brixMount <type> <endpoint>
# <mountdir>` that mounts CVMFS-brix (cvmfs) and XRootDFS-brix (eos/root). It
# links the shared ngx-free CVMFS core (../shared/cvmfs + ../shared/cache), the
# brixcvmfs driver (BRIXCVMFS_NO_MAIN — the umbrella owns main()), and the
# xrootdfs async driver (for its xrootdfs_aio_main entry). Needs libfuse3 +
# libcurl + libsqlite3 in addition to the usual client libs.
SHARED_DIR := ../shared
BRIX_CVMFS_OBJS := \
  $(SHARED_DIR)/cvmfs/grammar/classify.o  $(SHARED_DIR)/cvmfs/grammar/hash.o \
  $(SHARED_DIR)/cvmfs/signature/manifest.o $(SHARED_DIR)/cvmfs/signature/whitelist.o \
  $(SHARED_DIR)/cvmfs/signature/verify.o  $(SHARED_DIR)/cvmfs/config/repo.o \
  $(SHARED_DIR)/cvmfs/config/cvmfs_conf.o \
  $(SHARED_DIR)/cvmfs/failover/failover.o $(SHARED_DIR)/cvmfs/object/object.o \
  $(SHARED_DIR)/cvmfs/fetch/fetch.o       $(SHARED_DIR)/cvmfs/catalog/catalog.o \
  $(SHARED_DIR)/cvmfs/client/client.o     $(SHARED_DIR)/cache/cas_store.o

# shared cvmfs core: pure C, only needs -I../shared (no client/lib, no ngx).
$(BRIX_CVMFS_OBJS): %.o: %.c
	$(CC) -std=c11 -Wall -Wextra $(HARDEN) $(OPT) -I$(SHARED_DIR) -MMD -MP -c $< -o $@

apps/fs/brixcvmfs.o: apps/fs/brixcvmfs.c | proto
	$(CC) $(ALL_CFLAGS) $(FUSE3_CFLAGS) -I$(SHARED_DIR) -DBRIXCVMFS_NO_MAIN -c $< -o $@
apps/fs/brixcvmfs_rw.o: apps/fs/brixcvmfs_rw.c | proto
	$(CC) $(ALL_CFLAGS) $(FUSE3_CFLAGS) -I$(SHARED_DIR) -DBRIXCVMFS_NO_MAIN -c $< -o $@
apps/fs/brixmount.o: apps/fs/brixmount.c | proto
	$(CC) $(ALL_CFLAGS) $(FUSE3_CFLAGS) -I$(SHARED_DIR) -c $< -o $@

BRIXMOUNT_OBJS := apps/fs/brixmount.o apps/fs/brixcvmfs.o apps/fs/brixcvmfs_rw.o \
                  $(BRIX_CVMFS_OBJS) apps/fs/xrootdfs.o $(XROOTDFS_SPLIT)
$(BINDIR)/brixMount: $(BRIXMOUNT_OBJS) $(CLIENT_LIB) | $(BINDIR)
	$(CC) $(ALL_CFLAGS) $(LDFLAGS) $(LDFLAGS_PIE) $(BRIXMOUNT_OBJS) $(CLIENT_LIB) $(PROTO_LIB) $(LDLIBS) $(FUSE3_LIBS) -lcurl -lsqlite3 -lcrypto -lz -o $@
	@echo " + built $@ (CVMFS-brix + XRootDFS-brix; libfuse3/libcurl/libsqlite3)"

# A5 VFS S3 backend smoke test — exercises the brix_vfs S3 backend directly.
# Run against a live S3 server: S3_URL=s3://host:port/bucket/key AWS_* ./vfs_s3_smoke
.PHONY: vfs-s3-smoke
vfs-s3-smoke: tests/c/vfs_s3_smoke.c $(CLIENT_LIB) | $(BINDIR)
	$(CC) $(ALL_CFLAGS) tests/c/vfs_s3_smoke.c \
	    -Wl,--whole-archive $(CLIENT_LIB) -Wl,--no-whole-archive \
	    $(PROTO_LIB) $(LDLIBS) -o $(BINDIR)/vfs_s3_smoke
	@echo " + built $(BINDIR)/vfs_s3_smoke (no libXrdCl/libXrdSec*)"

# Shared sd_s3 driver object-metadata smoke (get_meta/set_meta/advisory).
# Run against a live S3 server: ./sd_s3_meta_smoke <host> <port> </bucket/key>
.PHONY: sd-s3-meta-smoke
sd-s3-meta-smoke: ../tests/c/sd_s3_meta_smoke.c $(CLIENT_LIB) | $(BINDIR)
	$(CC) $(ALL_CFLAGS) ../tests/c/sd_s3_meta_smoke.c \
	    -Wl,--whole-archive $(CLIENT_LIB) -Wl,--no-whole-archive \
	    $(PROTO_LIB) $(LDLIBS) -o $(BINDIR)/sd_s3_meta_smoke
	@echo " + built $(BINDIR)/sd_s3_meta_smoke"

# M1 async-core smoke test (tests/c/aio_smoke.c) — links the static client lib.
# Run against a live root:// server: ./aio_smoke root://host:port /scratch.bin
.PHONY: aio-smoke aio-resil
aio-smoke: ../tests/c/aio_smoke.c $(CLIENT_LIB) | $(BINDIR)
	$(CC) $(ALL_CFLAGS) ../tests/c/aio_smoke.c $(CLIENT_LIB) $(PROTO_LIB) $(LDLIBS) -o $(BINDIR)/aio_smoke
	@echo " + built $(BINDIR)/aio_smoke (no libXrdCl/libXrdSec*)"

# M2 resilience test — bounces the server mid-stream (set XRD_BOUNCE_CMD).
aio-resil: ../tests/c/aio_resil.c $(CLIENT_LIB) | $(BINDIR)
	$(CC) $(ALL_CFLAGS) ../tests/c/aio_resil.c $(CLIENT_LIB) $(PROTO_LIB) $(LDLIBS) -o $(BINDIR)/aio_resil
	@echo " + built $(BINDIR)/aio_resil (no libXrdCl/libXrdSec*)"

# Deferred-reply (kXR_waitresp → kXR_attn/asynresp) driver for the mock-server
# pytest (tests/test_aio_waitresp.py).
.PHONY: aio-waitresp
aio-waitresp: ../tests/c/aio_waitresp.c $(CLIENT_LIB) | $(BINDIR)
	$(CC) $(ALL_CFLAGS) ../tests/c/aio_waitresp.c $(CLIENT_LIB) $(PROTO_LIB) $(LDLIBS) -o $(BINDIR)/aio_waitresp
	@echo " + built $(BINDIR)/aio_waitresp (no libXrdCl/libXrdSec*)"

# M3 file-handle resumption test — read/write survive a mid-transfer bounce.
.PHONY: aio-mfile fault-proxy
aio-mfile: ../tests/c/aio_mfile.c $(CLIENT_LIB) | $(BINDIR)
	$(CC) $(ALL_CFLAGS) ../tests/c/aio_mfile.c $(CLIENT_LIB) $(PROTO_LIB) $(LDLIBS) -o $(BINDIR)/aio_mfile
	@echo " + built $(BINDIR)/aio_mfile (no libXrdCl/libXrdSec*)"

# M6 root-free TCP fault-injection proxy (latency/drop/outage) for the resilience
# pytest. Standalone — no libbrix needed.
fault-proxy: ../tests/c/fault_proxy.c | $(BINDIR)
	$(CC) -std=c11 -O2 -pthread ../tests/c/fault_proxy.c -o $(BINDIR)/fault_proxy
	@echo " + built $(BINDIR)/fault_proxy"

# IPv6→IPv4 auto-downgrade test (netpref.c) + its getaddrinfo LD_PRELOAD shim.
# Run: ./bin/netfb_test state ; LD_PRELOAD=./bin/gai_shim.so ./bin/netfb_test connect
.PHONY: netfb gai-shim
netfb: ../tests/c/netfb_test.c $(CLIENT_LIB) | $(BINDIR)
	$(CC) $(ALL_CFLAGS) ../tests/c/netfb_test.c $(CLIENT_LIB) $(PROTO_LIB) $(LDLIBS) -o $(BINDIR)/netfb_test
	@echo " + built $(BINDIR)/netfb_test"

gai-shim: ../tests/c/gai_shim.c | $(BINDIR)
	$(CC) -std=c11 -O2 -fPIC -shared ../tests/c/gai_shim.c -o $(BINDIR)/gai_shim.so -ldl
	@echo " + built $(BINDIR)/gai_shim.so"

# Network-timeout + retry-backoff unit test (nettmo.c).
.PHONY: nettmo
nettmo: ../tests/c/nettmo_test.c $(CLIENT_LIB) | $(BINDIR)
	$(CC) $(ALL_CFLAGS) ../tests/c/nettmo_test.c $(CLIENT_LIB) $(PROTO_LIB) $(LDLIBS) -o $(BINDIR)/nettmo_test
	@echo " + built $(BINDIR)/nettmo_test"

# §14.4 LD_PRELOAD POSIX shim — fold the PIC client + protocol kernels into a .so.
$(PRELOAD_SO): preload/brixposix_preload.pic.o $(PIC_OBJS) $(PROTO_LIB)
	$(CC) -shared $(LDFLAGS) -o $@ preload/brixposix_preload.pic.o $(PIC_OBJS) \
	    -Wl,--whole-archive $(PROTO_LIB) -Wl,--no-whole-archive $(LDLIBS) -ldl
	@echo " + built $@ (no libXrdCl/libXrdSec*)"

# ---- public library: libbrix.{a,so} + pkg-config (§14.1) ----
lib: $(CLIENT_LIB) $(LIBBRIX_SO) libbrix.pc

%.pic.o: %.c | proto
	$(CC) $(ALL_CFLAGS) -fPIC -c $< -o $@

# Fold the (PIC, ngx-free) protocol kernels into the .so so a single -lbrix links.
$(LIBBRIX_SO): $(PIC_OBJS) $(PROTO_LIB)
	$(CC) -shared -Wl,-soname,$(LIBBRIX_SONAME) -o $(LIBBRIX_REAL) \
	    $(PIC_OBJS) -Wl,--whole-archive $(PROTO_LIB) -Wl,--no-whole-archive $(LDLIBS)
	ln -sf $(LIBBRIX_REAL) $(LIBBRIX_SONAME)
	ln -sf $(LIBBRIX_SONAME) $(LIBBRIX_SO)
	@echo " + built $(LIBBRIX_REAL) (no libXrdCl/libXrdSec*)"

libbrix.pc:
	@printf '%s\n' \
	  'prefix=$(PREFIX)' \
	  'libdir=$(LIBDIR)' \
	  'includedir=$(INCLUDEDIR)' \
	  '' \
	  'Name: libbrix' \
	  'Description: Clean-room native XRootD root:// client library (libXrdCl-free)' \
	  'Version: $(BRIX_VERSION)' \
	  'Requires.private: libssl libcrypto zlib' \
	  'Libs: -L$${libdir} -lbrix' \
	  'Cflags: -I$${includedir}/brix -I$${includedir}/brix/xrdproto' > $@

# Install the lib, the public header, and the (self-contained) protocol headers it
# includes. libxrdproto.a ships alongside for static consumers.
install: lib
	install -d $(DESTDIR)$(LIBDIR) $(DESTDIR)$(PKGCONFDIR) \
	           $(DESTDIR)$(INCLUDEDIR)/brix $(DESTDIR)$(INCLUDEDIR)/brix/xrdproto/protocol \
	           $(DESTDIR)$(INCLUDEDIR)/brix/xrdproto/protocol/codec
	install -m644 $(CLIENT_LIB) $(PROTO_LIB) $(DESTDIR)$(LIBDIR)/
	install -m755 $(LIBBRIX_REAL) $(DESTDIR)$(LIBDIR)/
	cp -P $(LIBBRIX_SONAME) $(LIBBRIX_SO) $(DESTDIR)$(LIBDIR)/
	# brix.h is an umbrella that includes the split brix_net/auth/ops headers.
	install -m644 lib/brix.h lib/brix_net.h lib/brix_auth.h lib/brix_ops.h \
	              $(DESTDIR)$(INCLUDEDIR)/brix/
	install -m644 $(SRC)/protocol/*.h $(DESTDIR)$(INCLUDEDIR)/brix/xrdproto/protocol/
	# protocol.h pulls in codec/wire_codec.h — ship the codec subdir too.
	install -m644 $(SRC)/protocol/codec/*.h $(DESTDIR)$(INCLUDEDIR)/brix/xrdproto/protocol/codec/
	install -m644 libbrix.pc $(DESTDIR)$(PKGCONFDIR)/

# Install the CLI binaries + all man pages (build them first).
install-bin: $(BIN_EXES) $(OPT_BINS) $(OPT_EXES) install-completions
	install -d $(DESTDIR)$(PREFIX)/bin $(DESTDIR)$(PREFIX)/share/man/man1 \
	           $(DESTDIR)$(PREFIX)/share/man/man7
	install -m755 $(BIN_EXES) $(DESTDIR)$(PREFIX)/bin/
	for l in $(CKSUM_LINKS); do ln -sf xrdcksum $(DESTDIR)$(PREFIX)/bin/$$l; done
	for l in $(DIAG_LINKS); do ln -sf xrddiag $(DESTDIR)$(PREFIX)/bin/$$l; done
	[ -f $(BINDIR)/xrootdfs ] && install -m755 $(BINDIR)/xrootdfs $(DESTDIR)$(PREFIX)/bin/ || true
	for m in man/*.1; do install -m644 $$m $(DESTDIR)$(PREFIX)/share/man/man1/; done
	for m in man/*.7; do install -m644 $$m $(DESTDIR)$(PREFIX)/share/man/man7/; done

# ---------------------------------------------------------------------------
# Install man pages only (DESTDIR-aware; includes the .so link pages).
# Separate from install-bin so packaging can split docs from binaries.
install-man:
	install -d $(DESTDIR)$(PREFIX)/share/man/man1 \
	           $(DESTDIR)$(PREFIX)/share/man/man7
	for m in man/*.1; do install -m644 $$m $(DESTDIR)$(PREFIX)/share/man/man1/; done
	for m in man/*.7; do install -m644 $$m $(DESTDIR)$(PREFIX)/share/man/man7/; done

# Install shell completions (bash + zsh) only (DESTDIR-aware).
install-completions:
	install -d $(DESTDIR)$(PREFIX)/share/bash-completion/completions \
	           $(DESTDIR)$(PREFIX)/share/zsh/site-functions
	for n in xrdcp xrdfs xrddiag xrdcksum xrd xrdprep xrdgsiproxy xrdsssadmin brixMount xrdstorascan xrootdfs; do \
		install -m644 completions/brix-tools.bash \
			$(DESTDIR)$(PREFIX)/share/bash-completion/completions/$$n; \
	done
	install -m644 completions/_brix-client \
		$(DESTDIR)$(PREFIX)/share/zsh/site-functions/_brix-client

# ---------------------------------------------------------------------------
# `make test` — build + run every self-contained C unit test under tests/c/.
# vfs_s3_smoke is excluded (needs an external S3 endpoint; run it manually).
# Each test is a standalone main() linking the client lib + libxrdproto, the
# same recipe as the Build+run comment in each test's header.
CLIENT_UNIT_TESTS := cli_cred_unit cred_unit cred_store_unit vfs_posix_unit vfs_block_unit jsonout_unit copy_filter_unit xferjournal_unit relsafe_unit ckmanifest_unit envalias_unit xrdrc_defaults_unit suggest_unit
# The tests predate the phase-69 bucket reshuffle and include bucket-local
# headers bare ("cred.h"); add the bucket dirs rather than churning the tests.
TEST_INC := -Ilib/auth/cred -Ilib/auth/sss -Ilib/fs -Ilib/cli -Ilib/core/types -Ilib/core/config -Ilib/net
# The cred-handler and vfs-backend registries are weak-symbol accessors: a
# plain static-archive link would not extract their defining objects (weak
# refs do not force member extraction; the registry would see NULL slots), so
# those tests link --whole-archive. cred_store_unit instead OVERRIDES a strong
# lib symbol (brix_cred_s3keys) and must use the plain archive link.
WHOLEARCH_TESTS := cli_cred_unit cred_unit vfs_posix_unit vfs_block_unit
test: $(CLIENT_LIB) proto | $(BINDIR)
	@set -e; for t in $(CLIENT_UNIT_TESTS); do \
	  echo "== $$t"; \
	  case " $(WHOLEARCH_TESTS) " in \
	  *" $$t "*) lib='-Wl,--whole-archive $(CLIENT_LIB) -Wl,--no-whole-archive' ;; \
	  *)         lib='$(CLIENT_LIB)' ;; \
	  esac; \
	  $(CC) $(ALL_CFLAGS) $(TEST_INC) tests/c/$$t.c \
	    $$lib $(PROTO_LIB) $(LDLIBS) -o $(BINDIR)/$$t; \
	  $(BINDIR)/$$t; \
	done; echo "client unit tests: ALL PASS"
	@echo "== man page guard"
	@bash man/check_man.sh
	@echo "== completions guard"
	@bash completions/check_completions.sh

# Build the sample consumer against the INSTALLED library via pkg-config.
example-test:
	$(CC) -std=c11 examples/brix_stat_demo.c \
	    $$(PKG_CONFIG_PATH=$(DESTDIR)$(PKGCONFDIR) pkg-config --cflags --libs libbrix) \
	    -o $(DESTDIR)/brix_stat_demo

clean:
	rm -f $(LIB_OBJS) $(PIC_OBJS) $(LIB_OBJS:.o=.d) $(PIC_OBJS:.o=.d) apps/*/*.o apps/*/*.d \
	    preload/*.o preload/*.d \
	    $(CLIENT_LIB) $(LIBBRIX_SO) $(LIBBRIX_SONAME) $(LIBBRIX_REAL) libbrix.pc \
	    $(PRELOAD_SO)
	rm -rf $(BINDIR)

-include $(DEPS)
