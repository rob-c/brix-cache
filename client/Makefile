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
  lib/net/conn.c lib/net/cpool.c lib/net/netdiag.c lib/net/netpref.c lib/net/nettmo.c lib/net/pool.c lib/net/resilient.c lib/net/sock.c lib/net/streams.c lib/net/tls.c lib/net/url.c \
  ../shared/net/proxy_env.c ../shared/net/proxy_connect.c \
  lib/auth/auth.c lib/auth/sigver.c \
  lib/auth/cred/cred.c lib/auth/cred/cred_bearer.c lib/auth/cred/cred_krb5.c lib/auth/cred/cred_s3.c lib/auth/cred/cred_sss.c lib/auth/cred/cred_x509.c lib/auth/cred/credinfo.c lib/auth/cred/credrefresh.c \
  lib/auth/sec/sec_gsi.c lib/auth/sec/sec_host.c lib/auth/sec/sec_krb5.c lib/auth/sec/sec_pwd.c lib/auth/sec/sec_sss.c lib/auth/sec/sec_token.c lib/auth/sec/sec_unix.c \
  lib/auth/gsi/proxy.c \
  lib/auth/sss/sss_keytab.c \
  lib/fs/fattr.c lib/fs/glob.c lib/fs/iobuf.c lib/fs/overlay.c lib/fs/path.c lib/fs/rmtree.c lib/fs/vfs.c lib/fs/vfs_block.c lib/fs/vfs_posix.c lib/fs/walk.c \
  lib/fs/backend/s3/vfs_s3.c lib/fs/backend/s3/vfs_s3_http.c lib/fs/backend/s3/vfs_s3_io.c lib/fs/backend/s3/vfs_s3_transport.c \
  lib/protocols/root/frame.c lib/protocols/root/ops_ext.c lib/protocols/root/ops_file.c lib/protocols/root/ops_file_pg.c lib/protocols/root/ops_file_rw.c lib/protocols/root/ops_fs.c lib/protocols/root/ops_meta.c \
  lib/protocols/http/http.c lib/protocols/http/http_download.c lib/protocols/http/http_req.c lib/protocols/http/http_upload.c lib/protocols/http/web_ka.c lib/protocols/http/webfile.c lib/protocols/http/webfile_io.c lib/protocols/http/weblist.c \
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
# Python migration tools + their pymigrate package live under libexec; bin/
# gets *.py symlinks (relative, so DESTDIR staging keeps working).
LIBEXECDIR ?= $(PREFIX)/libexec/brix

# All compiled executables land under bin/ (keeps the source tree clean — the whole
# dir is git-ignored). Libraries (.a/.so/.pc) stay in the build root. The bare names
# (xrd, xrdcp, brix-fault-proxy, …) remain valid `make` targets via phony aliases
# below, so `make xrdcp` / `make -C client brix-fault-proxy` keep working; the
# artifact is bin/<name>.
BINDIR := bin

# Every binary is a thin front-end: apps/<family>/<name>.o + the client lib + libxrdproto.
BINS := xrd xrdfs xrdcp xrdcksum xrdprep xrdgsiproxy xrddiag \
        xrdmapc xrdgsitest \
        xrdsssadmin-brix xrdstorascan
BIN_EXES := $(addprefix $(BINDIR)/,$(BINS))

# Multi-call personalities: the micro-tools stay invocable as symlinks to
# their multi-call binary (xrdcksum dispatches on argv[0]/subcommand; xrddiag
# likewise absorbed the qstats/wait41/mpxstats micro-tools). wait41 and
# mpxstats carry a -brix suffix so the brix client RPM co-installs with the
# stock xrootd server RPMs (which own /usr/bin/wait41 and /usr/bin/mpxstats).
CKSUM_LINKS := xrdcrc32c xrdcrc64 xrdadler32 xrdckverify xrdcinfo
DIAG_LINKS  := xrdqstats wait41-brix mpxstats-brix
LINK_EXES   := $(addprefix $(BINDIR)/,$(CKSUM_LINKS) $(DIAG_LINKS))

# brix-fault-proxy: a shipped, first-class tool but STANDALONE — it links no
# client lib (pure pthread + sockets), so it can't ride the BIN_EXES static-
# pattern link rule. It has its own build rule (below) and its own install line,
# yet is built by default (`all`), installed, and carries a man page + completion.
STANDALONE_EXES := $(BINDIR)/brix-fault-proxy

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

# Ceph operator tools (apps/ceph/) — migration + rescue utilities linking
# librados directly (storage-plane, not root://). Compile-gated like fuse3:
# each tool joins OPT_EXES only when its own dev headers are present. The two
# C++ tools additionally need a C++ compiler. Header probes (not pkg-config —
# the striper/cephfs libs don't reliably ship .pc files) mirror the bzlib
# probe above.
CXX ?= g++
HAVE_CXX          := $(shell command -v $(CXX) >/dev/null 2>&1 && echo yes)
HAVE_RADOS        := $(shell $(CC) -E -x c -D_FILE_OFFSET_BITS=64 /dev/null -include rados/librados.h >/dev/null 2>&1 && echo yes)
HAVE_RADOSSTRIPER := $(shell $(CC) -E -x c -D_FILE_OFFSET_BITS=64 /dev/null -include radosstriper/libradosstriper.h >/dev/null 2>&1 && echo yes)
HAVE_CEPHFS       := $(shell $(CC) -E -x c -D_FILE_OFFSET_BITS=64 /dev/null -include cephfs/libcephfs.h >/dev/null 2>&1 && echo yes)
CEPH_EXES :=
ifeq ($(HAVE_RADOS),yes)
  CEPH_EXES += $(BINDIR)/xrdrados_rescue $(BINDIR)/xrdcephfs_rescue $(BINDIR)/xrdceph_migrate
  ifeq ($(HAVE_CXX)$(HAVE_CEPHFS),yesyes)
    CEPH_EXES += $(BINDIR)/xrdceph_striper_migrate
  endif
  ifeq ($(HAVE_CXX)$(HAVE_RADOSSTRIPER),yesyes)
    CEPH_EXES += $(BINDIR)/xrdceph_cephfs_to_striper
  endif
endif
OPT_EXES += $(CEPH_EXES)
CEPH_TOOL_NAMES := xrdrados_rescue xrdcephfs_rescue xrdceph_migrate \
                   xrdceph_striper_migrate xrdceph_cephfs_to_striper

# ---------------------------------------------------------------------------
# brix-cache-client-compat: the SAME name-agnostic binaries, presented under a
# "brix-" prefix so they co-install with the official xrootd client tools
# (which own /usr/bin/xrdcp, xrdfs, …). Each tool self-identifies from argv[0]
# (lib/core/progname.h), so a prefixed install name — or a symlink — needs no
# second compile: this is the git/busybox model, one build, zero drift.
#
# compat_name maps a stock tool/man base name to its compat spelling: drop a
# trailing "-brix" (the suffix existed only to dodge a stock /usr/bin name, which
# the prefix now does), then ensure exactly one leading "brix-". Idempotent for
# names already carrying the prefix (brix-fault-proxy, brix-env stay verbatim).
# The literal "brix-" is deliberately not a knob: it must match the compile-time
# BRIX_COMPAT_PREFIX in lib/core/progname.h that the tools strip at run time to
# route personalities, so a configurable prefix would only ever build broken.
compat_name = $(patsubst brix-brix-%,brix-%,brix-$(patsubst %-brix,%,$(1)))

# src-bin-name:compat-install-name pairs (real binary copies; FUSE excluded — the
# FUSE mounts are never prefixed). brix-fault-proxy is intentionally NOT here: it
# is a brix-original tool that already carries the prefix and collides with no
# stock name, so the base brix-cache-client package owns it — duplicating it in
# compat would add nothing.
COMPAT_BIN_PAIRS  := $(foreach b,$(BINS),$(b):$(call compat_name,$(b)))
# Multi-call personality link names under the prefix (targets: the compat
# dispatchers brix-xrdcksum / brix-xrddiag). Dispatch strips "brix-" at run time.
COMPAT_CKSUM_LINKS := $(foreach l,$(CKSUM_LINKS),$(call compat_name,$(l)))
COMPAT_DIAG_LINKS  := $(foreach l,$(DIAG_LINKS),$(call compat_name,$(l)))
# Ceph operator tools (only those actually built are installed — see the -e guard).
COMPAT_CEPH_PAIRS  := $(foreach c,$(CEPH_TOOL_NAMES),$(c):$(call compat_name,$(c)))
# Bash-completion recipients (non-FUSE base tools; personalities inherit nothing
# extra, matching install-completions).
COMPAT_COMPLETION_NAMES := $(foreach n,xrd xrdfs xrdcp xrdcksum xrdprep xrdgsiproxy \
                             xrddiag xrdmapc xrdgsitest xrdsssadmin-brix xrdstorascan \
                             $(CEPH_TOOL_NAMES),$(call compat_name,$(n)))

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
xrdsssadmin-brix_OBJS := apps/auth/xrdsssadmin.o
xrdmapc_OBJS      := apps/diag/xrdmapc.o
xrdprep_OBJS      := apps/prep/xrdprep.o

ALL_OBJS := $(LIB_OBJS) $(foreach b,$(BINS),$($(b)_OBJS))
DEPS     := $(ALL_OBJS:.o=.d)

.PHONY: all proto clean lib install install-bin install-man install-completions install-automount compat install-compat example-test test libbrix.pc $(BINS) $(CKSUM_LINKS) $(DIAG_LINKS) xrootdfs brixMount
all: $(BIN_EXES) $(LINK_EXES) $(OPT_BINS) $(OPT_EXES) $(STANDALONE_EXES)

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
  $(SHARED_DIR)/cvmfs/walk/walk.o \
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
apps/fs/brixautofs.o: apps/fs/brixautofs.c apps/fs/brixautofs.h | proto
	$(CC) $(ALL_CFLAGS) $(FUSE3_CFLAGS) -I$(SHARED_DIR) -c $< -o $@

BRIXMOUNT_OBJS := apps/fs/brixmount.o apps/fs/brixcvmfs.o apps/fs/brixcvmfs_rw.o \
                  apps/fs/brixautofs.o \
                  $(BRIX_CVMFS_OBJS) apps/fs/xrootdfs.o $(XROOTDFS_SPLIT)
$(BINDIR)/brixMount: $(BRIXMOUNT_OBJS) $(CLIENT_LIB) | $(BINDIR)
	$(CC) $(ALL_CFLAGS) $(LDFLAGS) $(LDFLAGS_PIE) $(BRIXMOUNT_OBJS) $(CLIENT_LIB) $(PROTO_LIB) $(LDLIBS) $(FUSE3_LIBS) -lcurl -lsqlite3 -lcrypto -lz -o $@
	@echo " + built $@ (CVMFS-brix + XRootDFS-brix; libfuse3/libcurl/libsqlite3)"

# --- Ceph operator tools (apps/ceph/) -------------------------------------
# Build recipes mirror tests/ceph/run_rescue_tools.sh and the RPM spec. The C
# tools force-include the ngx shim and compile the sd_ceph driver sources
# directly; the reverse C++ tool keeps its CephFS decoders as C objects (g++
# would treat the .c inputs as C++ and break their extern "C" boundary).
CEPH_RADOS_DIR := $(SRC)/fs/backend/rados
CEPH_C_FLAGS   := -std=c11 -Wall -Wextra -D_FILE_OFFSET_BITS=64 $(HARDEN) $(OPT) \
                  -DXRDPROTO_NO_NGX -DBRIX_HAVE_CEPH \
                  -I$(SRC) -I$(SRC)/fs/backend -I$(CEPH_RADOS_DIR) -Iapps/ceph \
                  -include apps/ceph/ngx_shim.h $(CFLAGS)
CEPH_CXX_FLAGS := -std=c++17 -Wall -Wextra -D_FILE_OFFSET_BITS=64 $(HARDEN) $(OPT) \
                  -Iapps/ceph $(CFLAGS)

# The driver's translation units, named ONCE.  These tools link no library for
# the backend — they compile the driver sources straight in — so this list must
# be the full symbol closure, and it drifts silently: a split TU that nobody adds
# here fails only at LINK time, and only when librados headers are installed (so
# a box without them never notices).  That is exactly what happened when the
# phase-79 file-size work split sd_ceph.c -> +sd_ceph_io.c +sd_ceph_cred.c
# +sd_ceph_object.c and sd_cephfs_ro.c -> +sd_cephfs_ro_dir.c
# +sd_cephfs_ro_resolve.c: three recipes each kept their own stale copy of the
# old two-file list, and every ceph tool failed with `undefined reference to
# sd_ceph_*`, breaking `make -C client` and the RPM's build-time assertion.
# Keep these as variables so the next split is a one-line change here, not three
# drifting copies. Deliberately NOT sd_ceph_striper.c: nothing in these tools
# references it and pulling it in would add a libradosstriper link dependency.
CEPH_CORE_SRCS := $(CEPH_RADOS_DIR)/sd_ceph.c \
                  $(CEPH_RADOS_DIR)/sd_ceph_compat.c \
                  $(CEPH_RADOS_DIR)/sd_ceph_io.c \
                  $(CEPH_RADOS_DIR)/sd_ceph_cred.c \
                  $(CEPH_RADOS_DIR)/sd_ceph_object.c
CEPHFS_RO_SRCS := $(CEPH_RADOS_DIR)/sd_cephfs_ro.c \
                  $(CEPH_RADOS_DIR)/sd_cephfs_ro_dir.c \
                  $(CEPH_RADOS_DIR)/sd_cephfs_ro_resolve.c \
                  $(CEPH_RADOS_DIR)/cephfs_denc.c \
                  $(CEPH_RADOS_DIR)/cephfs_layout.c

$(BINDIR)/xrdrados_rescue: apps/ceph/xrdrados_rescue.c $(CEPH_CORE_SRCS) \
		apps/ceph/ngx_shim.h | $(BINDIR)
	$(CC) $(CEPH_C_FLAGS) $(LDFLAGS) $(LDFLAGS_PIE) $(filter %.c,$^) -lrados -o $@
	@echo " + built $@ (librados)"

$(BINDIR)/xrdceph_migrate: apps/ceph/xrdceph_migrate.c $(CEPH_CORE_SRCS) \
		apps/ceph/ngx_shim.h | $(BINDIR)
	$(CC) $(CEPH_C_FLAGS) $(LDFLAGS) $(LDFLAGS_PIE) $(filter %.c,$^) -lrados -o $@
	@echo " + built $@ (librados)"

$(BINDIR)/xrdcephfs_rescue: apps/ceph/xrdcephfs_rescue.c $(CEPHFS_RO_SRCS) \
		$(CEPH_CORE_SRCS) apps/ceph/ngx_shim.h | $(BINDIR)
	$(CC) $(CEPH_C_FLAGS) $(LDFLAGS) $(LDFLAGS_PIE) $(filter %.c,$^) -lrados -o $@
	@echo " + built $@ (librados; cephfsro core)"

apps/ceph/cephfs_denc.o: $(CEPH_RADOS_DIR)/cephfs_denc.c
	$(CC) -std=c11 -Wall -Wextra -D_FILE_OFFSET_BITS=64 $(OPT) -I$(CEPH_RADOS_DIR) $(CFLAGS) -c $< -o $@
apps/ceph/cephfs_layout.o: $(CEPH_RADOS_DIR)/cephfs_layout.c
	$(CC) -std=c11 -Wall -Wextra -D_FILE_OFFSET_BITS=64 $(OPT) -I$(CEPH_RADOS_DIR) $(CFLAGS) -c $< -o $@

$(BINDIR)/xrdceph_striper_migrate: apps/ceph/xrdceph_striper_migrate.cpp \
		apps/ceph/xrdceph_migrate_config.h | $(BINDIR)
	$(CXX) $(CEPH_CXX_FLAGS) $(LDFLAGS) $(LDFLAGS_PIE) \
	    apps/ceph/xrdceph_striper_migrate.cpp -lrados -lcephfs -pthread -o $@
	@echo " + built $@ (librados/libcephfs; C++17)"

$(BINDIR)/xrdceph_cephfs_to_striper: apps/ceph/xrdceph_cephfs_to_striper.cpp \
		apps/ceph/xrdceph_migrate_config.h apps/ceph/cephfs_denc.o apps/ceph/cephfs_layout.o | $(BINDIR)
	$(CXX) $(CEPH_CXX_FLAGS) -I$(CEPH_RADOS_DIR) $(LDFLAGS) $(LDFLAGS_PIE) \
	    apps/ceph/xrdceph_cephfs_to_striper.cpp \
	    apps/ceph/cephfs_denc.o apps/ceph/cephfs_layout.o \
	    -lrados -lradosstriper -o $@
	@echo " + built $@ (librados/libradosstriper; C++17)"

# `make -C client ceph-tools` — build exactly this group (used by the RPM spec).
.PHONY: ceph-tools
ceph-tools: $(CEPH_EXES)
ifeq ($(strip $(CEPH_EXES)),)
	@echo "ceph-tools: skipped — librados dev headers not found" \
	     "(need librados-devel; + libradosstriper-devel/libcephfs-devel and a C++ compiler for the migration pair)"
endif

# Bare-name aliases (`make -C client xrdrados_rescue`), like $(BINS).
.PHONY: $(CEPH_TOOL_NAMES)
$(CEPH_TOOL_NAMES): %: $(BINDIR)/%

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
.PHONY: aio-mfile brix-fault-proxy
aio-mfile: ../tests/c/aio_mfile.c $(CLIENT_LIB) | $(BINDIR)
	$(CC) $(ALL_CFLAGS) ../tests/c/aio_mfile.c $(CLIENT_LIB) $(PROTO_LIB) $(LDLIBS) -o $(BINDIR)/aio_mfile
	@echo " + built $(BINDIR)/aio_mfile (no libXrdCl/libXrdSec*)"

# brix-fault-proxy — root-free TCP fault-injection proxy ("toxiproxy-lite") for
# the resilience suites and field debugging. A first-class shipped tool, but
# STANDALONE (links no libbrix — pure pthread + sockets), so it gets its own rule
# rather than riding the BIN_EXES pattern. Compiled with the house hardening
# flags; pulls only lib/core/version.h for --version. Bare name `make
# brix-fault-proxy` builds the artifact via the phony alias above.
brix-fault-proxy: $(BINDIR)/brix-fault-proxy
$(BINDIR)/brix-fault-proxy: apps/diag/brix_fault_proxy.c lib/core/version.h | $(BINDIR)
	$(CC) $(ALL_CFLAGS) $(LDFLAGS) $(LDFLAGS_PIE) apps/diag/brix_fault_proxy.c -o $@
	@echo " + built $@ (standalone; no libbrix)"

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

# Install the CLI binaries, optional FUSE/preload artifacts, completions, and
# all man pages (build them first).
install-bin: $(BIN_EXES) $(OPT_BINS) $(OPT_EXES) $(STANDALONE_EXES) install-completions
	install -d $(DESTDIR)$(PREFIX)/bin $(DESTDIR)$(PREFIX)/share/man/man1 \
	           $(DESTDIR)$(PREFIX)/share/man/man7 $(DESTDIR)$(LIBDIR)
	install -m755 $(BIN_EXES) $(STANDALONE_EXES) $(DESTDIR)$(PREFIX)/bin/
	for l in $(CKSUM_LINKS); do ln -sf xrdcksum $(DESTDIR)$(PREFIX)/bin/$$l; done
	for l in $(DIAG_LINKS); do ln -sf xrddiag $(DESTDIR)$(PREFIX)/bin/$$l; done
	for e in $(OPT_EXES); do [ -f $$e ] && install -m755 $$e $(DESTDIR)$(PREFIX)/bin/ || true; done
	for so in $(OPT_BINS); do [ -f $$so ] && install -m755 $$so $(DESTDIR)$(LIBDIR)/ || true; done
	for m in man/*.1; do install -m644 $$m $(DESTDIR)$(PREFIX)/share/man/man1/; done
	for m in man/*.7; do install -m644 $$m $(DESTDIR)$(PREFIX)/share/man/man7/; done
	install -d $(DESTDIR)$(LIBEXECDIR)/pymigrate/shim
	install -m755 apps/ceph/xrdceph_striper_migrate.py \
	              apps/ceph/xrdceph_cephfs_to_striper.py $(DESTDIR)$(LIBEXECDIR)/
	install -m644 apps/ceph/pymigrate/__init__.py apps/ceph/pymigrate/common.py \
	              apps/ceph/pymigrate/cephfs_meta.py apps/ceph/pymigrate/radosbridge.py \
	              $(DESTDIR)$(LIBEXECDIR)/pymigrate/
	install -m644 apps/ceph/pymigrate/shim/rados_manifest_shim.cpp \
	              $(DESTDIR)$(LIBEXECDIR)/pymigrate/shim/
	ln -sf ../libexec/brix/xrdceph_striper_migrate.py $(DESTDIR)$(PREFIX)/bin/xrdceph_striper_migrate.py
	ln -sf ../libexec/brix/xrdceph_cephfs_to_striper.py $(DESTDIR)$(PREFIX)/bin/xrdceph_cephfs_to_striper.py

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
	for n in xrdcp xrdfs xrddiag xrdcksum xrd xrdprep xrdgsiproxy xrdsssadmin-brix brixMount xrdstorascan xrootdfs \
	         brix-fault-proxy \
	         xrdceph_striper_migrate xrdceph_cephfs_to_striper xrdrados_rescue xrdcephfs_rescue xrdceph_migrate; do \
		install -m644 completions/brix-tools.bash \
			$(DESTDIR)$(PREFIX)/share/bash-completion/completions/$$n; \
	done
	install -m644 completions/_brix-client \
		$(DESTDIR)$(PREFIX)/share/zsh/site-functions/_brix-client

# ---------------------------------------------------------------------------
# brix-cache-client-compat build target: materialise the "brix-"-prefixed names
# as in-tree symlinks to the real, name-agnostic binaries. This is the official
# build target CI / the compat tests use to invoke the prefixed tools without a
# second compile (the binaries derive their identity from argv[0]). FUSE mounts
# are never prefixed.
compat: all
	@for p in $(COMPAT_BIN_PAIRS); do \
		src=$${p%%:*}; dst=$${p##*:}; \
		[ "$$src" = "$$dst" ] || ln -sf $$src $(BINDIR)/$$dst; \
	done
	@for l in $(COMPAT_CKSUM_LINKS); do ln -sf xrdcksum $(BINDIR)/$$l; done
	@for l in $(COMPAT_DIAG_LINKS);  do ln -sf xrddiag  $(BINDIR)/$$l; done
	@for p in $(COMPAT_CEPH_PAIRS); do \
		src=$${p%%:*}; dst=$${p##*:}; \
		[ -e $(BINDIR)/$$src ] && ln -sf $$src $(BINDIR)/$$dst || true; \
	done

# ---------------------------------------------------------------------------
# Install the compat flavour: the SAME binaries under "brix-" names, prefixed
# multi-call personality symlinks (whose targets are the prefixed dispatchers),
# prefixed man pages (with the .so redirect stubs retargeted), and prefixed bash
# completions. Paths are disjoint from install-bin (the prefix guarantees it), so
# both packages' files coexist in one buildroot. FUSE artifacts are excluded.
install-compat: $(BIN_EXES) $(OPT_EXES)
	install -d $(DESTDIR)$(PREFIX)/bin $(DESTDIR)$(PREFIX)/share/man/man1 \
	           $(DESTDIR)$(PREFIX)/share/man/man7 \
	           $(DESTDIR)$(PREFIX)/share/bash-completion/completions \
	           $(DESTDIR)$(PREFIX)/share/zsh/site-functions
	# Real CLI + standalone binaries under their brix- names.
	@for p in $(COMPAT_BIN_PAIRS); do \
		src=$${p%%:*}; dst=$${p##*:}; \
		echo "install -m755 $(BINDIR)/$$src -> bin/$$dst"; \
		install -m755 $(BINDIR)/$$src $(DESTDIR)$(PREFIX)/bin/$$dst; \
	done
	# Multi-call personality symlinks -> the prefixed dispatchers.
	@for l in $(COMPAT_CKSUM_LINKS); do \
		ln -sf $(call compat_name,xrdcksum) $(DESTDIR)$(PREFIX)/bin/$$l; done
	@for l in $(COMPAT_DIAG_LINKS); do \
		ln -sf $(call compat_name,xrddiag) $(DESTDIR)$(PREFIX)/bin/$$l; done
	# Ceph operator binaries (only those built) under their brix- names.
	@for p in $(COMPAT_CEPH_PAIRS); do \
		src=$${p%%:*}; dst=$${p##*:}; \
		if [ -f $(BINDIR)/$$src ]; then \
			install -m755 $(BINDIR)/$$src $(DESTDIR)$(PREFIX)/bin/$$dst; fi; \
	done
	# Man pages under brix- names; FUSE pages skipped, .so redirect stubs retargeted.
	@for m in man/*.1; do \
		base=$$(basename $$m .1); \
		case "$$base" in brixMount|xrootdfs|brix-fault-proxy) continue;; esac; \
		cn=$${base%-brix}; case "$$cn" in brix-*) : ;; *) cn=brix-$$cn;; esac; \
		if head -1 $$m | grep -q '^\.so '; then \
			sed -e 's#man1/xrdcksum\.1#man1/brix-xrdcksum.1#' \
			    -e 's#man1/xrddiag\.1#man1/brix-xrddiag.1#' \
			    $$m > $(DESTDIR)$(PREFIX)/share/man/man1/$$cn.1; \
			chmod 644 $(DESTDIR)$(PREFIX)/share/man/man1/$$cn.1; \
		else \
			install -m644 $$m $(DESTDIR)$(PREFIX)/share/man/man1/$$cn.1; \
		fi; \
	done
	# brix-env(7) is already prefix-conforming and shared verbatim (its name does
	# not collide with any stock page), so ship it under the compat package too.
	install -m644 man/brix-env.7 $(DESTDIR)$(PREFIX)/share/man/man7/brix-env.7
	# Bash completions under the brix- names.
	@for n in $(COMPAT_COMPLETION_NAMES); do \
		install -m644 completions/brix-tools.bash \
			$(DESTDIR)$(PREFIX)/share/bash-completion/completions/$$n; \
	done
	# zsh: one family file, installed under a compat-distinct name (no overlap
	# with brix-cache-client's _brix-client).
	install -m644 completions/_brix-client \
		$(DESTDIR)$(PREFIX)/share/zsh/site-functions/_brix-client-compat

# ---------------------------------------------------------------------------
# Install the CVMFS automount stack (helpers + autofs map + default config/keys
# + systemd units). One canonical file list, two entry points: this target is
# invoked both by the RPM %install and by deploy/cvmfs/install-automount.sh's
# packaged sibling. DESTDIR/UNITDIR-aware; config lands as plain files —
# %config(noreplace) / cp -n semantics are the packager's job, not ours.
UNITDIR   ?= $(PREFIX)/lib/systemd/system
DEPLOY_CVMFS := ../deploy/cvmfs
install-automount:
	install -d $(DESTDIR)/sbin $(DESTDIR)/etc/auto.master.d \
	           $(DESTDIR)/etc/cvmfs/default.d $(DESTDIR)/etc/cvmfs/domain.d \
	           $(DESTDIR)/etc/cvmfs/config.d $(DESTDIR)$(UNITDIR) \
	           $(DESTDIR)/var/lib/brixcvmfs $(DESTDIR)/cvmfs
	install -m755 $(DEPLOY_CVMFS)/mount.cvmfs $(DESTDIR)/sbin/mount.cvmfs
	install -m755 $(DEPLOY_CVMFS)/auto.cvmfs $(DESTDIR)/etc/auto.cvmfs
	printf '/cvmfs /etc/auto.cvmfs\n' > $(DESTDIR)/etc/auto.master.d/cvmfs.autofs
	install -m644 $(DEPLOY_CVMFS)/etc/cvmfs/default.d/*.conf \
		$(DESTDIR)/etc/cvmfs/default.d/
	install -m644 $(DEPLOY_CVMFS)/etc/cvmfs/domain.d/*.conf \
		$(DESTDIR)/etc/cvmfs/domain.d/
	install -m644 $(DEPLOY_CVMFS)/etc/cvmfs/config.d/README \
		$(DESTDIR)/etc/cvmfs/config.d/README
	for d in cern.ch egi.eu opensciencegrid.org; do \
		install -d $(DESTDIR)/etc/cvmfs/keys/$$d; \
		install -m644 $(DEPLOY_CVMFS)/etc/cvmfs/keys/$$d/*.pub \
			$(DESTDIR)/etc/cvmfs/keys/$$d/; \
	done
	install -m644 $(DEPLOY_CVMFS)/etc/cvmfs/keys/README.md \
		$(DESTDIR)/etc/cvmfs/keys/README.md
	install -m644 ../packaging/brixcvmfs-automount.service \
	              ../packaging/brixcvmfs@.service $(DESTDIR)$(UNITDIR)/

# ---------------------------------------------------------------------------
# `make test` — build + run every self-contained C unit test under tests/c/.
# vfs_s3_smoke is excluded (needs an external S3 endpoint; run it manually).
# Each test is a standalone main() linking the client lib + libxrdproto, the
# same recipe as the Build+run comment in each test's header.
CLIENT_UNIT_TESTS := cli_opts_unit cli_cred_unit cred_unit cred_store_unit vfs_posix_unit vfs_block_unit jsonout_unit copy_filter_unit xferjournal_unit relsafe_unit ckmanifest_unit envalias_unit xrdrc_defaults_unit suggest_unit
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
