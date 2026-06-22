# client/Makefile — native xrdcp/xrdfs built on libxrdproto (phase-37).
#
# WHAT: Builds libxrdc.a (the root:// connection/session/ops layer) and the
#       CLI tools, linking the project's ngx-free protocol core (libxrdproto.a).
# WHY:  Tools "built atop the project's code" with NO libXrdCl / libXrdSec* — only
#       libxrdproto + OpenSSL.
# HOW:  Mirrors the module's hardening/optimize flags; pulls wire structs from the
#       in-tree src/protocol headers via -I$(SRC) (build-in-place, no file moves).

CC ?= cc
AR ?= ar

REPO      := ..
SRC       := $(REPO)/src
PROTO_DIR := $(REPO)/shared/xrdproto
PROTO_LIB := $(PROTO_DIR)/libxrdproto.a

# Hardening — mirror the module's ./configure (repo-root `config`).
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

# -MMD -MP: emit a .d per object listing every header it includes, so editing a
# header (e.g. lib/xrdc.h, which changes struct layout) reliably recompiles every
# dependent object — without this, incremental `make` leaves stale, mixed-ABI .o
# files that crash or read garbage. The generated .d files are -included below.
# krb5 (sec_krb5.c) is compile-gated like fuse3: when libkrb5 dev is present,
# arm -DXROOTD_HAVE_KRB5 + its cflags/libs; otherwise sec_krb5.c is an inert stub
# and the auth driver simply skips krb5. Kept ngx-free (client-only).
HAVE_KRB5 := $(shell pkg-config --exists krb5 2>/dev/null && echo yes)
ifeq ($(HAVE_KRB5),yes)
  KRB5_CFLAGS := -DXROOTD_HAVE_KRB5 $(shell pkg-config --cflags krb5 2>/dev/null)
  KRB5_LIBS   := $(shell pkg-config --libs krb5 2>/dev/null)
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
# lz4 (phase-42 extension): an env hint (XROOTD_LZ4_LIBS) supplies the link for a
# non-system liblz4 (default the bare soname from the default loader path); else
# pkg-config.  Never propagate a non-system -L (it would pull that prefix's other
# codec sonames, not on the runtime path) — see config's lz4 block.
ifneq ($(strip $(XROOTD_LZ4_CFLAGS)$(XROOTD_LZ4_LIBS)),)
  CODEC_LIBS += $(if $(strip $(XROOTD_LZ4_LIBS)),$(XROOTD_LZ4_LIBS),-l:liblz4.so.1)
else ifeq ($(shell pkg-config --exists liblz4 2>/dev/null && echo y),y)
  CODEC_LIBS += -l:liblz4.so.1
endif

ALL_CFLAGS := -std=c11 -Wall -Wextra $(HARDEN) $(OPT) -pthread -Ilib -I$(SRC) -MMD -MP $(KRB5_CFLAGS) $(CFLAGS)

# OpenSSL: libssl (in-protocol TLS) + libcrypto (GSI/sigver + libxrdproto kernels +
# md5). zlib (-lz): adler32 for --cksum (the algorithm xrdcp historically uses).
# krb5 libs (when present) for the sec_krb5 AP-REQ path. CODEC_LIBS: zstd/lzma/
# brotli/bzip2 for the shared codec kernels (gzip/deflate already via -lz).
LDLIBS := -lssl -lcrypto -lz $(KRB5_LIBS) $(CODEC_LIBS)

LIB_SRCS   := lib/sock.c lib/netpref.c lib/nettmo.c lib/url.c lib/status.c lib/trace.c lib/frame.c lib/zip.c \
              lib/conn.c lib/pool.c lib/aio.c lib/aio_mgr.c lib/streams.c lib/ops_meta.c lib/ops_file.c lib/ops_fs.c \
              lib/copy.c lib/glob.c lib/xrdrc.c lib/weblist.c lib/webfile.c lib/checksum.c lib/fattr.c lib/ops_ext.c lib/proxy.c lib/http.c lib/s3.c lib/tls.c lib/auth.c \
              lib/sigver.c lib/sss_keytab.c lib/credinfo.c lib/credrefresh.c lib/capture.c lib/netdiag.c \
              lib/cli_cksum.c lib/cli_opts.c lib/cli_conn.c lib/resilient.c lib/posix_map.c lib/iobuf.c lib/fuse_ops.c \
              lib/path.c lib/units.c \
              lib/sec/sec_token.c lib/sec/sec_unix.c lib/sec/sec_gsi.c lib/sec/sec_sss.c \
              lib/sec/sec_krb5.c
LIB_OBJS   := $(LIB_SRCS:.c=.o)

# §14.1: the connection/session layer is the public libxrdc — a clean-room,
# libXrdCl-free C client library. Shipped as libxrdc.a + a versioned .so + a
# pkg-config file, so any C program can speak root:// with only libxrdc +
# libxrdproto + OpenSSL/zlib.
CLIENT_LIB     := libxrdc.a
XRDC_VERSION   := 0.1.0
XRDC_SOMAJOR   := 0
LIBXRDC_SO     := libxrdc.so
LIBXRDC_SONAME := libxrdc.so.$(XRDC_SOMAJOR)
LIBXRDC_REAL   := libxrdc.so.$(XRDC_VERSION)
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

# Every binary is a thin front-end: apps/<name>.o + the client lib + libxrdproto.
BINS := xrd xrdfs xrdcp xrdcrc32c xrdcrc64 xrdadler32 xrdqstats wait41 xrdprep xrdgsiproxy xrddiag \
        xrdmapc xrdgsitest mpxstats \
        xrdsssadmin
BIN_EXES := $(addprefix $(BINDIR)/,$(BINS))

# §14.4: the FUSE mount + the LD_PRELOAD POSIX shim are built only when libfuse3
# is present. They are NOT in BINS (they need extra flags / a separate link rule).
HAVE_FUSE3   := $(shell pkg-config --exists fuse3 2>/dev/null && echo yes)
FUSE3_CFLAGS := $(shell pkg-config --cflags fuse3 2>/dev/null)
FUSE3_LIBS   := $(shell pkg-config --libs fuse3 2>/dev/null)
PRELOAD_SO   := libxrdposix_preload.so
OPT_BINS     := $(PRELOAD_SO)
OPT_EXES     :=
# The FUSE mount is ONE binary (xrootdfs) that contains both drivers: the
# async/resilient default and the simple synchronous fallback, selected at run
# time by `--legacy` (front-end apps/xrootdfs_main.c).
ifeq ($(HAVE_FUSE3),yes)
  OPT_EXES += $(BINDIR)/xrootdfs
endif

ALL_OBJS := $(LIB_OBJS) $(addprefix apps/,$(addsuffix .o,$(BINS)))
DEPS     := $(ALL_OBJS:.o=.d)

.PHONY: all proto clean lib install install-bin example-test libxrdc.pc $(BINS) xrootdfs
all: $(BIN_EXES) $(OPT_BINS) $(OPT_EXES)

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
xrootdfs: $(BINDIR)/xrootdfs

$(BIN_EXES): | proto $(BINDIR)

%.o: %.c
	$(CC) $(ALL_CFLAGS) -c $< -o $@

$(CLIENT_LIB): $(LIB_OBJS)
	$(AR) rcs $@ $^

# One uniform link rule for every front-end.  $(LDFLAGS) lets a packager inject
# link hardening (e.g. RPM's %{build_ldflags}: RELRO / BIND_NOW); empty by default.
$(BINDIR)/%: apps/%.o $(CLIENT_LIB) | $(BINDIR)
	$(CC) $(ALL_CFLAGS) $(LDFLAGS) apps/$*.o $(CLIENT_LIB) $(PROTO_LIB) $(LDLIBS) -o $@
	@echo " + built $@ (no libXrdCl/libXrdSec*)"

# §14.4 unified xrootdfs (FUSE) — ONE binary linking the front-end
# (xrootdfs_main.c) + both drivers: xrootdfs.c (async default) and
# xrootdfs_legacy.c (synchronous, via --legacy). The two driver TUs share no
# symbols but main(), so they co-link cleanly. Needs the libfuse3 headers/libs.
apps/xrootdfs.o: apps/xrootdfs.c apps/xrootdfs_drivers.h | proto
	$(CC) $(ALL_CFLAGS) $(FUSE3_CFLAGS) -c $< -o $@
apps/xrootdfs_legacy.o: apps/xrootdfs_legacy.c apps/xrootdfs_drivers.h | proto
	$(CC) $(ALL_CFLAGS) $(FUSE3_CFLAGS) -c $< -o $@
apps/xrootdfs_main.o: apps/xrootdfs_main.c apps/xrootdfs_drivers.h | proto
	$(CC) $(ALL_CFLAGS) -c $< -o $@
$(BINDIR)/xrootdfs: apps/xrootdfs_main.o apps/xrootdfs.o apps/xrootdfs_legacy.o $(CLIENT_LIB) | $(BINDIR)
	$(CC) $(ALL_CFLAGS) $(LDFLAGS) apps/xrootdfs_main.o apps/xrootdfs.o apps/xrootdfs_legacy.o $(CLIENT_LIB) $(PROTO_LIB) $(LDLIBS) $(FUSE3_LIBS) -o $@
	@echo " + built $@ (libfuse3; unified async+legacy; no libXrdCl/libXrdSec*)"

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

# M3 file-handle resumption test — read/write survive a mid-transfer bounce.
.PHONY: aio-mfile fault-proxy
aio-mfile: ../tests/c/aio_mfile.c $(CLIENT_LIB) | $(BINDIR)
	$(CC) $(ALL_CFLAGS) ../tests/c/aio_mfile.c $(CLIENT_LIB) $(PROTO_LIB) $(LDLIBS) -o $(BINDIR)/aio_mfile
	@echo " + built $(BINDIR)/aio_mfile (no libXrdCl/libXrdSec*)"

# M6 root-free TCP fault-injection proxy (latency/drop/outage) for the resilience
# pytest. Standalone — no libxrdc needed.
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
$(PRELOAD_SO): preload/xrdposix_preload.pic.o $(PIC_OBJS) $(PROTO_LIB)
	$(CC) -shared $(LDFLAGS) -o $@ preload/xrdposix_preload.pic.o $(PIC_OBJS) \
	    -Wl,--whole-archive $(PROTO_LIB) -Wl,--no-whole-archive $(LDLIBS) -ldl
	@echo " + built $@ (no libXrdCl/libXrdSec*)"

# ---- public library: libxrdc.{a,so} + pkg-config (§14.1) ----
lib: $(CLIENT_LIB) $(LIBXRDC_SO) libxrdc.pc

%.pic.o: %.c | proto
	$(CC) $(ALL_CFLAGS) -fPIC -c $< -o $@

# Fold the (PIC, ngx-free) protocol kernels into the .so so a single -lxrdc links.
$(LIBXRDC_SO): $(PIC_OBJS) $(PROTO_LIB)
	$(CC) -shared -Wl,-soname,$(LIBXRDC_SONAME) -o $(LIBXRDC_REAL) \
	    $(PIC_OBJS) -Wl,--whole-archive $(PROTO_LIB) -Wl,--no-whole-archive $(LDLIBS)
	ln -sf $(LIBXRDC_REAL) $(LIBXRDC_SONAME)
	ln -sf $(LIBXRDC_SONAME) $(LIBXRDC_SO)
	@echo " + built $(LIBXRDC_REAL) (no libXrdCl/libXrdSec*)"

libxrdc.pc:
	@printf '%s\n' \
	  'prefix=$(PREFIX)' \
	  'libdir=$(LIBDIR)' \
	  'includedir=$(INCLUDEDIR)' \
	  '' \
	  'Name: libxrdc' \
	  'Description: Clean-room native XRootD root:// client library (libXrdCl-free)' \
	  'Version: $(XRDC_VERSION)' \
	  'Requires.private: libssl libcrypto zlib' \
	  'Libs: -L$${libdir} -lxrdc' \
	  'Cflags: -I$${includedir}/xrdc -I$${includedir}/xrdc/xrdproto' > $@

# Install the lib, the public header, and the (self-contained) protocol headers it
# includes. libxrdproto.a ships alongside for static consumers.
install: lib
	install -d $(DESTDIR)$(LIBDIR) $(DESTDIR)$(PKGCONFDIR) \
	           $(DESTDIR)$(INCLUDEDIR)/xrdc $(DESTDIR)$(INCLUDEDIR)/xrdc/xrdproto/protocol
	install -m644 $(CLIENT_LIB) $(PROTO_LIB) $(DESTDIR)$(LIBDIR)/
	install -m755 $(LIBXRDC_REAL) $(DESTDIR)$(LIBDIR)/
	cp -P $(LIBXRDC_SONAME) $(LIBXRDC_SO) $(DESTDIR)$(LIBDIR)/
	install -m644 lib/xrdc.h $(DESTDIR)$(INCLUDEDIR)/xrdc/
	install -m644 $(SRC)/protocol/*.h $(DESTDIR)$(INCLUDEDIR)/xrdc/xrdproto/protocol/
	install -m644 libxrdc.pc $(DESTDIR)$(PKGCONFDIR)/

# Install the CLI binaries + the xrootdfs man page (build them first).
install-bin: $(BIN_EXES) $(OPT_BINS) $(OPT_EXES)
	install -d $(DESTDIR)$(PREFIX)/bin $(DESTDIR)$(PREFIX)/share/man/man1
	install -m755 $(BIN_EXES) $(DESTDIR)$(PREFIX)/bin/
	[ -f $(BINDIR)/xrootdfs ] && install -m755 $(BINDIR)/xrootdfs $(DESTDIR)$(PREFIX)/bin/ || true
	[ -f man/xrootdfs.1 ] && install -m644 man/xrootdfs.1 $(DESTDIR)$(PREFIX)/share/man/man1/ || true

# Build the sample consumer against the INSTALLED library via pkg-config.
example-test:
	$(CC) -std=c11 examples/xrdc_stat_demo.c \
	    $$(PKG_CONFIG_PATH=$(DESTDIR)$(PKGCONFDIR) pkg-config --cflags --libs libxrdc) \
	    -o $(DESTDIR)/xrdc_stat_demo

clean:
	rm -f $(LIB_OBJS) $(PIC_OBJS) apps/*.o apps/*.d lib/*.d lib/sec/*.d \
	    preload/*.o preload/*.d \
	    $(CLIENT_LIB) $(LIBXRDC_SO) $(LIBXRDC_SONAME) $(LIBXRDC_REAL) libxrdc.pc \
	    $(PRELOAD_SO)
	rm -rf $(BINDIR)

-include $(DEPS)
