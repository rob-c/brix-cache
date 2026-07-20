%global upstream_name brix
# Version: the single source of truth is BRIX_SERVER_VERSION_BARE in
# src/core/ident.h (what the server reports at runtime).
# build-rpm-container.sh and the builder Dockerfiles derive version_override
# from it automatically; the literal fallback below is only for a bare
# rpmbuild invocation and must be kept in sync with ident.h.
%global upstream_version %{?version_override}%{!?version_override:1.1.1}

# --- phase-42 optional compression codecs (gzip/deflate via zlib are always on) ---
# Each non-zlib codec is compile-gated by ./configure's pkg-config probe and
# degrades to available=0 when absent, so the SRPM builds on minimal hosts.
# zstd and lz4 default ON (disable with rpmbuild --without zstd --without lz4);
# enable the rest with: rpmbuild --with lzma --with brotli --with bzip2
%bcond_without zstd
%bcond_with lzma
%bcond_with brotli
%bcond_with bzip2
%bcond_without lz4

# --- phase-44 io_uring disk-I/O + loop engine (default ON; disable with
# rpmbuild --without uring). Compiles the io_uring backends into both the
# nginx modules (via the BRIX_ENABLE_IO_URING configure gate) and the client
# tools (client Makefile pkg-config probe); runtime selection still defaults
# to the thread-pool/epoll paths.
%bcond_without uring

# --- SELinux policy module (default ON; disable with rpmbuild --without selinux).
# Ships packaging/selinux/brix.{te,fc,if} as the noarch -selinux subpackage so
# the gateway runs under SELinux enforcing (hardened EL hosts) without
# audit2allow one-offs, broad httpd booleans, or permissive mode.
%bcond_without selinux
%global selinuxtype targeted
%global selinuxmodule brix
# TCP ports labelled brix_port_t in the -selinux %%post: root:// cleartext +
# TLS (1094/1095), S3 (9001), metrics (9100).  443/8443 are already
# http_port_t.  Keep in sync with brix.te's header comment.
%global brix_ports 1094 1095 9001 9100

Name:           nginx-mod-brix-cache
Version:        %{upstream_version}
Release:        25%{?dist}
Summary:        BriX-Cache — XRootD, WebDAV, S3, CMS, and metrics dynamic modules for nginx

# Rebrand (gnuBall -> BriX-Cache, 0.1.0-5): same modules, new product name.
# Provides + Obsoletes give dnf a clean upgrade path from the old package name.
Provides:       nginx-mod-xrootd = %{version}-%{release}
Obsoletes:      nginx-mod-xrootd < 0.1.0-5

License:        AGPL-3.0-only
URL:            https://github.com/HEP-x/nginx-xrootd
Source0:        %{url}/archive/refs/tags/v%{version}/%{upstream_name}-%{version}.tar.gz

# --- toolchain ---
BuildRequires:  gcc
BuildRequires:  gcc-c++
BuildRequires:  make
BuildRequires:  pkgconfig
BuildRequires:  nginx-mod-devel
# --- nginx module link deps (find-requires turns these into runtime deps) ---
BuildRequires:  openssl-devel
BuildRequires:  pcre2-devel
BuildRequires:  zlib-devel
BuildRequires:  libxml2-devel
BuildRequires:  jansson-devel
BuildRequires:  libcurl-devel
BuildRequires:  krb5-devel
BuildRequires:  libcom_err-devel
BuildRequires:  libxcrypt-devel
BuildRequires:  sqlite-devel
# %%systemd_post/preun/postun + %%systemd_requires (brix-cvmfs-automount)
BuildRequires:  systemd-rpm-macros
# --- phase-42 optional compression codecs (off by default; see %%bcond above).
# When enabled, ./configure links the lib and find-requires turns it into a
# runtime dep automatically; when disabled, the codec reports available=0. ---
%{?with_zstd:BuildRequires:  libzstd-devel}
%{?with_lzma:BuildRequires:  xz-devel}
%{?with_brotli:BuildRequires:  libbrotli-devel}
%{?with_bzip2:BuildRequires:  bzip2-devel}
%{?with_lz4:BuildRequires:  lz4-devel}
%{?with_uring:BuildRequires:  liburing-devel}
%{?with_selinux:BuildRequires:  selinux-policy-devel}
# --- native client (brix-cache-client subpackage) extra link deps ---
# fuse3-devel: the xrootdfs and brixMount FUSE mounts; libcom_err-devel above
# resolves the -lcom_err pulled in by `pkg-config --libs krb5`; sqlite-devel
# backs the CVMFS catalog reader linked into brixMount.
BuildRequires:  fuse3-devel
# --- Ceph/XrdCeph migration operator tools (brix-tools) ---
# libradospp-devel carries <rados/librados.hpp> on EL9-style Ceph packaging;
# libradosstriper-devel and libcephfs-devel provide the data-plane APIs used by
# the two compiled migration tools.
BuildRequires:  librados-devel
BuildRequires:  libradospp-devel
BuildRequires:  libradosstriper-devel
BuildRequires:  libcephfs-devel

# nginx-mod-stream provides the stream {} core that our modules load into.
# openssl-libs: directly linked (-lssl -lcrypto) — auto-detected by find-requires
# but listed explicitly for clarity.
# VOMS: loaded at runtime via dlopen(libvomsapi.so.1); not a link-time dep so
# find-requires cannot detect it.  Required for VOMS VO/FQAN ACL enforcement.
# Require the soname directly rather than a package name: the C VOMS library is
# packaged as voms-libs on EL8 but as voms on EL9+, and both Provide
# libvomsapi.so.1()(64bit), so this one line resolves on every supported EL.
# curl: used to be fork/exec'd, now primarily used via libcurl, but kept for
# compatibility with site scripts.
Requires:       nginx-mod-stream%{?_isa}
Requires:       openssl-libs%{?_isa}
Requires:       libvomsapi.so.1()(64bit)
Requires:       curl
# Ceph storage backends (sd_ceph / sd_cephfs_ro) are always compiled in.
# find-requires already turns the linked sonames (librados.so.2,
# libradosstriper.so.1) into deps, but the library packages are listed
# explicitly so Ceph support is a stated contract of this RPM.
Requires:       librados2%{?_isa}
Requires:       libradosstriper1%{?_isa}
# Hardened hosts: install the SELinux policy module automatically whenever the
# targeted policy is present (rich boolean dep — a no-op on SELinux-less
# hosts, so the module package still installs cleanly there).
%if %{with selinux}
Requires:       (%{name}-selinux = %{version}-%{release} if selinux-policy-%{selinuxtype})
%endif

%description
BriX-Cache: dynamic nginx modules that serve files over the native XRootD
stream protocol, WebDAV over HTTPS, and an S3-compatible HTTP subset, with CMS
management-listener and Prometheus metrics support.

# ---------------------------------------------------------------------------
# Subpackage 2: native clean-room client tools (CLI + FUSE + LD_PRELOAD shim)
# ---------------------------------------------------------------------------
%package -n brix-cache-client
Summary:        BriX-Cache clean-room native XRootD client tools (xrdcp, xrdfs, ...)
Provides:       nginx-xrootd-client = %{version}-%{release}
Obsoletes:      nginx-xrootd-client < 0.1.0-5
# 1.1.1-23: the two FUSE mounts split out into their own subpackages
# (brix-xrootdfs-fuse, brix-cvmfs-fuse) so sites can deploy/test a mount tier
# without the full CLI suite.  Recommends keeps the default `dnf install
# brix-cache-client` surface unchanged while --setopt=install_weak_deps=False
# (or a plain rpm -e) gives the slim CLI-only install.
Recommends:     brix-xrootdfs-fuse = %{version}-%{release}
Recommends:     brix-cvmfs-fuse = %{version}-%{release}

%description -n brix-cache-client
Native command-line XRootD clients built clean-room on the in-tree protocol
core (libbrix + libxrdproto) with NO libXrdCl / libXrdSec dependency:
xrdcp, xrdfs, xrd, xrdcksum and checksum personalities, xrdqstats, xrdprep,
xrdgsiproxy, xrddiag, xrdmapc, xrdgsitest, xrdstorascan, mpxstats-brix,
xrdsssadmin-brix and wait41-brix, plus brix-fault-proxy (a root-free TCP
fault-injection proxy for resilience testing) and the libbrixposix_preload.so
LD_PRELOAD POSIX shim.  The FUSE mounts live in the brix-xrootdfs-fuse and
brix-cvmfs-fuse subpackages (installed by default via weak deps).

# ---------------------------------------------------------------------------
# Subpackage 2c: brix-cache-client-compat — the SAME name-agnostic client
# binaries as brix-cache-client, presented under a "brix-" prefix (brix-xrdcp,
# brix-xrdfs, …) so they CO-INSTALL with the official xrootd-client tools that
# own the bare /usr/bin/xrdcp, xrdfs, … names.  One compile serves both flavours
# (git/busybox model): every tool derives its display name, multi-call
# personality, and sibling-exec target from argv[0] at run time, so no output
# ever prints a stock name when invoked under its brix- alias.
#
# Additive and independent: no Conflicts/Obsoletes against the official tools
# (the prefix makes the paths disjoint) and no dependency on brix-cache-client —
# the package is self-contained (ships its own brix-*.1 pages and brix-env(7)).
# ---------------------------------------------------------------------------
%package -n brix-cache-client-compat
Summary:        BriX-Cache native XRootD client tools under a brix- prefix (co-installable)

%description -n brix-cache-client-compat
The brix-cache-client tool set installed under a "brix-" prefix so it
co-exists with the official xrootd-client package on one host: brix-xrdcp,
brix-xrdfs, brix-xrd, brix-xrdcksum (and the checksum personalities
brix-xrdadler32/brix-xrdcrc32c/brix-xrdcrc64), brix-xrdqstats, brix-wait41,
brix-mpxstats, brix-xrdprep, brix-xrdgsiproxy, brix-xrddiag, brix-xrdmapc,
brix-xrdgsitest, brix-xrdsssadmin and brix-xrdstorascan.  The binaries are
byte-identical to brix-cache-client's; each self-identifies from argv[0], so
usage/version/man output names the brix- alias, never the stock tool.  The
Ceph operator tools ship prefixed in the brix-tools-compat subpackage; the
FUSE mounts are never prefixed and stay in brix-xrootdfs-fuse/brix-cvmfs-fuse.

# ---------------------------------------------------------------------------
# Subpackage 2a: the xrootdfs FUSE mount (root:// filesystem client)
# ---------------------------------------------------------------------------
%package -n brix-xrootdfs-fuse
Summary:        BriX-Cache xrootdfs FUSE mount — a root:// endpoint as a local filesystem
# fuse3: xrootdfs forks/execs fusermount3 at mount/unmount time — a runtime
# dependency that find-requires (which only sees libfuse3.so) misses.
Requires:       fuse3
# File move out of brix-cache-client (xrootdfs + man page + completion):
# force the old client to upgrade in the same transaction so the payloads
# never overlap on disk.
Conflicts:      brix-cache-client < 1.1.1-23

%description -n brix-xrootdfs-fuse
The xrootdfs FUSE mount: presents a root:// (XRootD-protocol) endpoint as a
local POSIX filesystem, built clean-room on the in-tree protocol core with no
libXrdCl/libXrdSec dependency.  One binary carries both drivers — the async
default and the synchronous --legacy engine.  Split out of brix-cache-client
so a mount-only node (batch worker, interactive login host) can deploy and
test it without the full CLI suite.

# ---------------------------------------------------------------------------
# Subpackage 2b: the brixMount CVMFS FUSE client
# ---------------------------------------------------------------------------
%package -n brix-cvmfs-fuse
Summary:        BriX-Cache brixMount FUSE client for cvmfs:// repositories
# fuse3: brixMount forks/execs fusermount3 at mount/unmount time (same
# find-requires blind spot as xrootdfs above).  sqlite backs the CVMFS
# catalog reader but is linked, so find-requires picks it up.
Requires:       fuse3
# File move out of brix-cache-client (brixMount + man page + completion).
Conflicts:      brix-cache-client < 1.1.1-23
# Virtual: satisfied by brix-cvmfs-config OR any stock cvmfs-config-* package —
# repositories mount zero-config once a provider ships /etc/cvmfs keys+domains.
Recommends:     cvmfs-config

%description -n brix-cvmfs-fuse
brixMount: the native BriX CVMFS FUSE client.  Mounts cvmfs:// repositories
(served by the BriX cvmfs:// site-cache protocol or stock stratum servers)
with CAS verification and an optional writable overlay (cvmfs-rw), and also
fronts the xrootdfs async driver via `brixMount xrootdfs <endpoint>`.  Split
out of brix-cache-client so a cache/mount tier can deploy and test it
standalone.

# ---------------------------------------------------------------------------
# Subpackage: /cvmfs automount stack (umbrella daemon service + mount helper)
# ---------------------------------------------------------------------------
%package -n brix-cvmfs-automount
Summary:        Automount /cvmfs via the brixMount autofs umbrella daemon
Requires:       brix-cvmfs-fuse = %{version}-%{release}
Requires:       fuse3
# The stock cvmfs RPM owns /sbin/mount.cvmfs, /etc/auto.cvmfs and the same
# /cvmfs automount role — two providers of one namespace is nonsensical.
Conflicts:      cvmfs
%{?systemd_requires}

%description -n brix-cvmfs-automount
Lazily mounts CVMFS repositories under /cvmfs on first access using the native
`brixMount autofs` umbrella daemon (no autofs/systemd map dependency; children
mount in a farm under /var/lib/brixcvmfs/.mnt and appear as symlinks).  Also
ships the classic integration points — /sbin/mount.cvmfs so `mount -t cvmfs`
works, an /etc/auto.cvmfs program map for sites that prefer stock autofs, and
a brixcvmfs@.service template for static per-repo mounts.  Enable with:
    systemctl enable --now brixcvmfs-automount

# ---------------------------------------------------------------------------
# Subpackage: default CVMFS configuration + master public keys (noarch)
# ---------------------------------------------------------------------------
%package -n brix-cvmfs-config
Summary:        Default CVMFS configuration and master keys for CVMFS-brix
BuildArch:      noarch
# Standard mutually-exclusive-providers pattern: the stock config packages
# provide the same virtual and lay the same /etc/cvmfs files.
Provides:       cvmfs-config = %{version}-%{release}
Conflicts:      cvmfs-config-default
Conflicts:      cvmfs-config-egi
Conflicts:      cvmfs-config-osg

%description -n brix-cvmfs-config
Default domain configuration (cern.ch, egi.eu, opensciencegrid.org stratum-1
sets) and the upstream-published master public keys, vendored byte-identical
from the stock cvmfs-config-default package (provenance and fingerprints in
/etc/cvmfs/keys/README.md).  Everything is %%config(noreplace): operator edits
and rotated keys survive upgrades.

# ---------------------------------------------------------------------------
# Subpackage 3: the pytest integration/conformance test-suite + its python deps
# ---------------------------------------------------------------------------
%package -n brix-cache-tests
Summary:        Integration and conformance test-suite for BriX-Cache
BuildArch:      noarch
Provides:       nginx-xrootd-tests = %{version}-%{release}
Obsoletes:      nginx-xrootd-tests < 0.1.0-5
# The system under test:
Requires:       nginx-mod-brix-cache = %{version}-%{release}
Requires:       brix-cache-client = %{version}-%{release}
Requires:       nginx
# Python packages the suite imports / drives pytest with:
Requires:       python3-pytest
Requires:       python3-pytest-timeout
Requires:       python3-pytest-xdist
Requires:       python3-cryptography
Requires:       python3-requests
Requires:       python3-urllib3
# python3-xrootd (official XRootD python bindings, from EPEL/WLCG) is only used
# by the cross-backend / reference-daemon comparison tests; recommend rather than
# hard-require it so the package installs where that repo is not enabled.
Recommends:     python3-xrootd
# The SELinux policy verification suite (tests/test_selinux_rpm.py, run as
# root on a host with the -selinux subpackage installed) drives semodule/
# restorecon (policycoreutils), matchpathcon (libselinux-utils), semanage
# (policycoreutils-python-utils) and sesearch (setools-console).  Weak deps:
# the rest of the suite runs without them and on SELinux-less hosts.
Recommends:     libselinux-utils
Recommends:     policycoreutils-python-utils
Recommends:     setools-console

%description -n brix-cache-tests
The full pytest integration, conformance, and adversarial test-suite for
BriX-Cache (root://, WebDAV, S3, CMS, metrics, FRM, TPC, ...), installed under
%{_datadir}/brix.  Run with, e.g.:
    cd %{_datadir}/brix && PYTHONPATH=tests python3 -m pytest tests/ -v

# ---------------------------------------------------------------------------
# Subpackage 4: Ceph/XrdCeph migration operator tools
# ---------------------------------------------------------------------------
%package -n brix-tools
Summary:        XrdCeph/CephFS migration + rescue operator tools for BriX-Cache
Provides:       brix-cache-ceph-tools = %{version}-%{release}
Obsoletes:      brix-cache-ceph-tools <= %{version}-%{release}
# The compiled tools link the Ceph client libraries directly; find-requires
# already adds the sonames (librados.so.2, libradosstriper.so.1,
# libcephfs.so.2), but the packages are listed explicitly as a stated contract.
Requires:       librados2%{?_isa}
Requires:       libradosstriper1%{?_isa}
Requires:       libcephfs2%{?_isa}
# The .py tool variants import the distro rados/cephfs python bindings at run
# time; the compiled tools need neither.
Recommends:     python3-rados
Recommends:     python3-cephfs

%description -n brix-tools
XrdCeph <-> CephFS migration tools with zero-move redirect mode,
rollback/finalize support, and site-profile configuration: compiled C++
primaries (xrdceph_striper_migrate, xrdceph_cephfs_to_striper) plus the
pure-Python variants (*.py, libexec-backed pymigrate package) with JSONL
output and resumable state, and the offline rescue utilities
xrdrados_rescue, xrdcephfs_rescue, and xrdceph_migrate. Source of truth:
client/apps/ceph/ (build: make -C client ceph-tools).

# ---------------------------------------------------------------------------
# Subpackage 4b: brix-tools-compat — the brix-tools Ceph/CephFS operator
# binaries under the "brix-" prefix (brix-xrdceph_migrate, brix-xrdrados_rescue,
# …), co-installable with any stock-named equivalents.  Kept separate from
# brix-cache-client-compat for the same reason brix-tools is separate from
# brix-cache-client: only these binaries link the Ceph client libraries, so the
# rados/cephfs runtime deps stay off the plain client package.
# ---------------------------------------------------------------------------
%package -n brix-tools-compat
Summary:        BriX-Cache XrdCeph/CephFS operator tools under a brix- prefix (co-installable)
Requires:       librados2%{?_isa}
Requires:       libradosstriper1%{?_isa}
Requires:       libcephfs2%{?_isa}

%description -n brix-tools-compat
The compiled brix-tools Ceph/CephFS migration + rescue operators installed
under a "brix-" prefix so they co-install with any stock-named counterparts:
brix-xrdceph_striper_migrate, brix-xrdceph_cephfs_to_striper,
brix-xrdrados_rescue, brix-xrdcephfs_rescue and brix-xrdceph_migrate.  Each
self-identifies from argv[0].  The pure-Python migration variants are not
prefixed and remain in brix-tools.

# ---------------------------------------------------------------------------
# Subpackage 5: SELinux policy module (targeted)
# ---------------------------------------------------------------------------
%if %{with selinux}
%package selinux
Summary:        SELinux policy module (targeted) for the BriX-Cache gateway
BuildArch:      noarch
%{?selinux_requires}
# semanage(8) for the brix_port_t port labelling in %%post/%%postun —
# %%selinux_requires only pulls policycoreutils, which does not carry it.
Requires(post):   policycoreutils-python-utils
Requires(postun): policycoreutils-python-utils

%description selinux
SELinux targeted-policy module for BriX-Cache.  nginx (and therefore the BriX
modules) runs confined as httpd_t; this module extends httpd_t with the BriX
data plane — brix_port_t listeners/origins (root:// 1094/1095, S3 9001,
metrics 9100), the brix_var_lib_t export/stage tree and brix_cache_t cache
tree under /var/{lib,cache}/brix-cache (legacy /var/{lib,cache}/nginx-xrootd
spellings stay labelled), cert_t on /etc/grid-security, the
impersonation-broker setuid/setgid/capset rules, and outbound origin, Ceph,
and Kerberos connections — so the gateway runs enforcing on a hardened host
without broad httpd booleans.  Non-default export/stage paths: label them
with `semanage fcontext -a -t brix_var_lib_t '<path>(/.*)?'` + restorecon;
extra listener ports: `semanage port -a -t brix_port_t -p tcp <port>`.
%endif

%prep
%autosetup -n %{upstream_name}-%{version}

%build
# --- nginx dynamic modules ---
# The io_uring backend is double-gated in ./config: the env opt-in below plus a
# liburing pkg-config probe (BuildRequires above guarantees it when with_uring).
%{?with_uring:export BRIX_ENABLE_IO_URING=1}
%nginx_modconfigure --with-threads --with-stream=dynamic --with-stream_ssl_module --with-http_ssl_module --with-http_dav_module
%nginx_modbuild

# --- native client tools ---
# Build from clean so every object is (re)compiled with the distro optflags —
# %{build_ldflags} links the binaries as PIE, which fails on any object left
# over from a plain `make` (no -fPIE).  Build the shared protocol core first,
# explicitly, so it too carries the optflags (the client's own `proto` target
# does not forward CFLAGS).  The Makefiles apply $(CFLAGS) last and $(LDFLAGS)
# on every production link, so RPM policy (optflags + RELRO/BIND_NOW) wins.
make -C client clean
make -C shared/xrdproto clean
make -C shared/xrdproto %{?_smp_mflags} CFLAGS="%{optflags}"
make -C client %{?_smp_mflags} CFLAGS="%{optflags}" LDFLAGS="%{build_ldflags}"

# --- Ceph/XrdCeph migration + rescue operator tools ---
# Built by the client Makefile's dep-gated ceph-tools target (source of truth:
# client/apps/ceph/; the BuildRequires above guarantee librados/libradosstriper/
# libcephfs are present, so all five tools build). The main client make above
# already covers them via OPT_EXES; the explicit target plus the test loop is a
# build-time assertion that none were silently gate-skipped.
make -C client ceph-tools %{?_smp_mflags} CFLAGS="%{optflags}" LDFLAGS="%{build_ldflags}"
for t in xrdceph_striper_migrate xrdceph_cephfs_to_striper \
         xrdrados_rescue xrdcephfs_rescue xrdceph_migrate; do
    test -x client/bin/$t
done

# --- SELinux policy module (packaging/selinux/brix.{te,fc,if}) ---
%if %{with selinux}
make -f %{_datadir}/selinux/devel/Makefile -C packaging/selinux %{selinuxmodule}.pp
bzip2 -9 -f packaging/selinux/%{selinuxmodule}.pp
%endif

%install
# --- nginx dynamic modules ---
# phase-47 W1: the dynamic build emits exactly TWO .so files: one combined
# module (ngx_stream_brix_module.so, which contains stream+metrics+srr+webdav+
# s3+dashboard+cms) and the standalone HTTP AUX filter.  Bundling the formerly-
# separate modules into one .so makes their cross-module symbol references
# (dashboard<->webdav<->metrics<->stream) resolve at link time, so dlopen no
# longer trips on the cross-.so RTLD_NOW cycle that broke `nginx -t` before.
install -Dpm0755 %{_vpath_builddir}/ngx_stream_brix_module.so \
    %{buildroot}%{nginx_moddir}/ngx_stream_brix_module.so
install -Dpm0755 %{_vpath_builddir}/ngx_http_brix_xrdhttp_filter_module.so \
    %{buildroot}%{nginx_moddir}/ngx_http_brix_xrdhttp_filter_module.so

mkdir -p %{buildroot}%{nginx_modconfdir}
# Combined module first so its symbols back the filter via RTLD_GLOBAL.
{
    echo 'load_module "%{nginx_moddir}/ngx_stream_brix_module.so";'
    echo 'load_module "%{nginx_moddir}/ngx_http_brix_xrdhttp_filter_module.so";'
} > %{buildroot}%{nginx_modconfdir}/mod-xrootd.conf

# phase-47 W3: ship a heavily-commented example server config (installed as
# .example so it never auto-activates — the operator copies it to a .conf name)
# and a logrotate rule for the module's access logs.
install -Dpm0644 contrib/brix-cache.conf.example \
    %{buildroot}%{_sysconfdir}/nginx/conf.d/brix-cache.conf.example
install -Dpm0644 contrib/logrotate.d/brix \
    %{buildroot}%{_sysconfdir}/logrotate.d/brix

# phase-47 W4: ship a ready-made Grafana dashboard + Prometheus alert rules.
install -Dpm0644 contrib/grafana-dashboard.json \
    %{buildroot}%{_datadir}/brix/grafana-dashboard.json
install -Dpm0644 contrib/prometheus-alerts.yml \
    %{buildroot}%{_datadir}/brix/prometheus-alerts.yml

# Default export root + data dir (matches the hardened systemd unit's
# ReadWritePaths; packaging/brix-cache.service).  Owning them here makes the
# SELinux relabel deterministic at install time (brix.fc labels the tree
# brix_var_lib_t) instead of depending on the operator's mkdir inheriting a
# parent label.
install -d %{buildroot}%{_sharedstatedir}/brix-cache/data

# --- SELinux policy module (brix-cache -selinux) ---
%if %{with selinux}
install -Dpm0644 packaging/selinux/%{selinuxmodule}.pp.bz2 \
    %{buildroot}%{_datadir}/selinux/packages/%{selinuxtype}/%{selinuxmodule}.pp.bz2
install -Dpm0644 packaging/selinux/%{selinuxmodule}.if \
    %{buildroot}%{_datadir}/selinux/devel/include/distributed/%{selinuxmodule}.if
%endif

# --- native client tools (brix-cache-client) ---
# Use the in-tree install target so the RPM follows the current client tool set
# (xrd/xrdcksum/xrdstorascan/brixMount/etc.) instead of a stale spec-local list.
make -C client install-bin \
    DESTDIR=%{buildroot} \
    PREFIX=%{_prefix} \
    LIBDIR=%{_libdir}

# --- brix- prefixed client tools (brix-cache-client-compat + brix-tools-compat) ---
# The SAME name-agnostic binaries under a "brix-" prefix, staged into paths
# disjoint from install-bin above (the prefix guarantees it), so both flavours
# coexist in one buildroot.  brix-env(7) is installed by both targets as a
# byte-identical copy — RPM permits shared ownership of identical files.
make -C client install-compat \
    DESTDIR=%{buildroot} \
    PREFIX=%{_prefix} \
    LIBDIR=%{_libdir}

# --- CVMFS automount stack + default config/keys ---
# One canonical file list, maintained in the client Makefile (also used by the
# portable deploy/cvmfs/install-automount.sh path for non-RPM hosts).
make -C client install-automount \
    DESTDIR=%{buildroot} \
    PREFIX=%{_prefix} \
    UNITDIR=%{_unitdir}

# --- test-suite (brix-cache-tests, noarch data) ---
install -d %{buildroot}%{_datadir}/brix
cp -a tests %{buildroot}%{_datadir}/brix/tests
# Never ship the prebuilt test nginx binary, any python bytecode caches, or
# stray compiled test helpers (e.g. tests/fuzz/*) — the package is noarch, so
# any ELF object in the payload fails the build.
rm -f %{buildroot}%{_datadir}/brix/tests/nginx-bin
find %{buildroot}%{_datadir}/brix/tests -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || :
find %{buildroot}%{_datadir}/brix/tests -name '*.pyc' -delete
find %{buildroot}%{_datadir}/brix/tests -type f \
    -exec sh -c 'head -c4 "$1" | od -An -tx1 | grep -q "7f 45 4c 46"' _ {} \; -delete
install -Dpm0644 conftest.py      %{buildroot}%{_datadir}/brix/conftest.py
install -Dpm0644 pytest.ini       %{buildroot}%{_datadir}/brix/pytest.ini
install -Dpm0644 requirements.txt %{buildroot}%{_datadir}/brix/requirements.txt

# --- Ceph/XrdCeph migration + rescue operator tools (brix-tools) ---
# Already staged by `make -C client install-bin` above: the compiled tools via
# the OPT_EXES loop, the Python pair + pymigrate under %{_libexecdir}/brix with
# %{_bindir}/*.py symlinks, and their man pages/completions. Ownership is split
# in %%files so brix-cache-client keeps the generic client surface while
# brix-tools owns the Ceph/CephFS operator surface.

# Dedicated, non-root service account for the per-request impersonation broker.
# The broker only ever needs CAP_SETUID/CAP_SETGID (retained via the systemd
# CapabilityBoundingSet); running it as this account instead of root means its
# idle state, NSS lookups and path handling are unprivileged, and it owns nothing
# in any export.  Referenced from brix-cache.conf.example via
# `brix_impersonation_broker_user brix-broker;`.  Idempotent; a no-op on upgrade.
%pre
getent group brix-broker >/dev/null || groupadd -r brix-broker
getent passwd brix-broker >/dev/null || \
    useradd -r -g brix-broker -M -d /nonexistent -s /usr/sbin/nologin \
            -c "BriX-Cache impersonation broker (non-root)" brix-broker
exit 0

%if %{with selinux}
%pre selinux
%selinux_relabel_pre -s %{selinuxtype}

%post selinux
%selinux_modules_install -s %{selinuxtype} %{_datadir}/selinux/packages/%{selinuxtype}/%{selinuxmodule}.pp.bz2
# Label the BriX listener/origin ports.  1094/1095 (root://) are unassigned
# in the stock policy, so -a adds them; 9001 collides with tor_port_t and
# 9100 with hplip_port_t, so those fall through to -m, which records a
# local override.  Best-effort (|| :) so a site-managed port customisation
# never fails the transaction.
if test -x %{_sbindir}/selinuxenabled && %{_sbindir}/selinuxenabled; then
    for p in %{brix_ports}; do
        semanage port -a -t brix_port_t -p tcp "$p" 2>/dev/null || \
            semanage port -m -t brix_port_t -p tcp "$p" 2>/dev/null || :
    done
fi

%postun selinux
if [ $1 -eq 0 ]; then
    # Drop the port labels BEFORE unloading the module: semodule refuses to
    # remove a module whose types are still referenced by local port
    # customisations.  -d removes our -a additions and reverts our -m
    # overrides to the stock policy assignment.
    if test -x %{_sbindir}/selinuxenabled && %{_sbindir}/selinuxenabled; then
        for p in %{brix_ports}; do
            semanage port -d -p tcp "$p" 2>/dev/null || :
        done
    fi
    %selinux_modules_uninstall -s %{selinuxtype} %{selinuxmodule}
fi

%posttrans selinux
%selinux_relabel_post -s %{selinuxtype}
%endif

%post -n brix-cvmfs-automount
%systemd_post brixcvmfs-automount.service

%preun -n brix-cvmfs-automount
%systemd_preun brixcvmfs-automount.service

%postun -n brix-cvmfs-automount
%systemd_postun_with_restart brixcvmfs-automount.service

%files
%license LICENSE
%doc README.md docs/
# Default export root; brix.fc labels it brix_var_lib_t on SELinux hosts.
%dir %attr(0750,nginx,nginx) %{_sharedstatedir}/brix-cache
%dir %attr(0750,nginx,nginx) %{_sharedstatedir}/brix-cache/data
%{nginx_moddir}/ngx_stream_brix_module.so
%{nginx_moddir}/ngx_http_brix_xrdhttp_filter_module.so
%{nginx_modconfdir}/mod-xrootd.conf
%config(noreplace) %{_sysconfdir}/nginx/conf.d/brix-cache.conf.example
%config(noreplace) %{_sysconfdir}/logrotate.d/brix
%{_datadir}/brix/grafana-dashboard.json
%{_datadir}/brix/prometheus-alerts.yml

%files -n brix-cache-client
%license LICENSE
%{_bindir}/xrd
%{_bindir}/xrdfs
%{_bindir}/xrdcp
%{_bindir}/xrdcksum
%{_bindir}/xrdcrc32c
%{_bindir}/xrdcrc64
%{_bindir}/xrdadler32
%{_bindir}/xrdckverify
%{_bindir}/xrdcinfo
%{_bindir}/xrdqstats
%{_bindir}/wait41-brix
%{_bindir}/xrdprep
%{_bindir}/xrdgsiproxy
%{_bindir}/xrddiag
%{_bindir}/xrdmapc
%{_bindir}/xrdgsitest
%{_bindir}/mpxstats-brix
%{_bindir}/xrdsssadmin-brix
%{_bindir}/xrdstorascan
%{_bindir}/brix-fault-proxy
%{_libdir}/libbrixposix_preload.so
%{_mandir}/man1/mpxstats-brix.1*
%{_mandir}/man1/wait41-brix.1*
%{_mandir}/man1/xrd.1*
%{_mandir}/man1/xrdadler32.1*
%{_mandir}/man1/xrdcinfo.1*
%{_mandir}/man1/xrdcksum.1*
%{_mandir}/man1/xrdckverify.1*
%{_mandir}/man1/xrdcp.1*
%{_mandir}/man1/xrdcrc32c.1*
%{_mandir}/man1/xrdcrc64.1*
%{_mandir}/man1/xrddiag.1*
%{_mandir}/man1/xrdfs.1*
%{_mandir}/man1/xrdgsiproxy.1*
%{_mandir}/man1/xrdgsitest.1*
%{_mandir}/man1/xrdmapc.1*
%{_mandir}/man1/xrdprep.1*
%{_mandir}/man1/xrdqstats.1*
%{_mandir}/man1/xrdsssadmin-brix.1*
%{_mandir}/man1/xrdstorascan.1*
%{_mandir}/man1/brix-fault-proxy.1*
%{_mandir}/man7/brix-env.7*
%{_datadir}/bash-completion/completions/xrd
%{_datadir}/bash-completion/completions/xrdcp
%{_datadir}/bash-completion/completions/xrdfs
%{_datadir}/bash-completion/completions/xrddiag
%{_datadir}/bash-completion/completions/xrdcksum
%{_datadir}/bash-completion/completions/xrdprep
%{_datadir}/bash-completion/completions/xrdgsiproxy
%{_datadir}/bash-completion/completions/xrdsssadmin-brix
%{_datadir}/bash-completion/completions/xrdstorascan
%{_datadir}/bash-completion/completions/brix-fault-proxy
%{_datadir}/zsh/site-functions/_brix-client

%files -n brix-xrootdfs-fuse
%license LICENSE
%{_bindir}/xrootdfs
%{_mandir}/man1/xrootdfs.1*
%{_datadir}/bash-completion/completions/xrootdfs

%files -n brix-cvmfs-fuse
%license LICENSE
%{_bindir}/brixMount
%{_mandir}/man1/brixMount.1*
%{_datadir}/bash-completion/completions/brixMount

%files -n brix-cvmfs-automount
%license LICENSE
/sbin/mount.cvmfs
%config(noreplace) %{_sysconfdir}/auto.cvmfs
%config(noreplace) %{_sysconfdir}/auto.master.d/cvmfs.autofs
%{_unitdir}/brixcvmfs-automount.service
%{_unitdir}/brixcvmfs@.service
%dir %attr(0700,root,root) %{_sharedstatedir}/brixcvmfs
%dir /cvmfs

%files -n brix-cvmfs-config
%license LICENSE
%dir %{_sysconfdir}/cvmfs
%dir %{_sysconfdir}/cvmfs/default.d
%dir %{_sysconfdir}/cvmfs/domain.d
%dir %{_sysconfdir}/cvmfs/config.d
%dir %{_sysconfdir}/cvmfs/keys
%dir %{_sysconfdir}/cvmfs/keys/cern.ch
%dir %{_sysconfdir}/cvmfs/keys/egi.eu
%dir %{_sysconfdir}/cvmfs/keys/opensciencegrid.org
%config(noreplace) %{_sysconfdir}/cvmfs/default.d/60-brix.conf
%config(noreplace) %{_sysconfdir}/cvmfs/domain.d/cern.ch.conf
%config(noreplace) %{_sysconfdir}/cvmfs/domain.d/egi.eu.conf
%config(noreplace) %{_sysconfdir}/cvmfs/domain.d/opensciencegrid.org.conf
%doc %{_sysconfdir}/cvmfs/config.d/README
%doc %{_sysconfdir}/cvmfs/keys/README.md
%config(noreplace) %{_sysconfdir}/cvmfs/keys/cern.ch/*.pub
%config(noreplace) %{_sysconfdir}/cvmfs/keys/egi.eu/*.pub
%config(noreplace) %{_sysconfdir}/cvmfs/keys/opensciencegrid.org/*.pub

%files -n brix-cache-tests
%license LICENSE
%dir %{_datadir}/brix
%{_datadir}/brix/tests
%{_datadir}/brix/conftest.py
%{_datadir}/brix/pytest.ini
%{_datadir}/brix/requirements.txt

%files -n brix-tools
%license LICENSE
%doc docs/10-reference/xrdceph-cephfs-bidirectional-migration.md
%doc docs/10-reference/cephfs-migration-glasgow-ral.md
%doc docs/10-reference/cephfs-to-xrdceph-migration.md
%doc docs/10-reference/xrdceph-cephfs-migration-test-record.md
%{_bindir}/xrdceph_striper_migrate
%{_bindir}/xrdceph_cephfs_to_striper
%{_bindir}/xrdrados_rescue
%{_bindir}/xrdcephfs_rescue
%{_bindir}/xrdceph_migrate
%{_bindir}/xrdceph_striper_migrate.py
%{_bindir}/xrdceph_cephfs_to_striper.py
%dir %{_libexecdir}/brix
%{_libexecdir}/brix/xrdceph_striper_migrate.py
%{_libexecdir}/brix/xrdceph_cephfs_to_striper.py
%dir %{_libexecdir}/brix/pymigrate
%{_libexecdir}/brix/pymigrate/__init__.py
%{_libexecdir}/brix/pymigrate/common.py
%{_libexecdir}/brix/pymigrate/cephfs_meta.py
%{_libexecdir}/brix/pymigrate/radosbridge.py
%dir %{_libexecdir}/brix/pymigrate/shim
%{_libexecdir}/brix/pymigrate/shim/rados_manifest_shim.cpp
%{_mandir}/man1/xrdceph_cephfs_to_striper.1*
%{_mandir}/man1/xrdceph_migrate.1*
%{_mandir}/man1/xrdceph_striper_migrate.1*
%{_mandir}/man1/xrdcephfs_rescue.1*
%{_mandir}/man1/xrdrados_rescue.1*
%{_datadir}/bash-completion/completions/xrdceph_striper_migrate
%{_datadir}/bash-completion/completions/xrdceph_cephfs_to_striper
%{_datadir}/bash-completion/completions/xrdrados_rescue
%{_datadir}/bash-completion/completions/xrdcephfs_rescue
%{_datadir}/bash-completion/completions/xrdceph_migrate

%files -n brix-cache-client-compat
%license LICENSE
%{_bindir}/brix-xrd
%{_bindir}/brix-xrdfs
%{_bindir}/brix-xrdcp
%{_bindir}/brix-xrdcksum
%{_bindir}/brix-xrdcrc32c
%{_bindir}/brix-xrdcrc64
%{_bindir}/brix-xrdadler32
%{_bindir}/brix-xrdckverify
%{_bindir}/brix-xrdcinfo
%{_bindir}/brix-xrdqstats
%{_bindir}/brix-wait41
%{_bindir}/brix-xrdprep
%{_bindir}/brix-xrdgsiproxy
%{_bindir}/brix-xrddiag
%{_bindir}/brix-xrdmapc
%{_bindir}/brix-xrdgsitest
%{_bindir}/brix-mpxstats
%{_bindir}/brix-xrdsssadmin
%{_bindir}/brix-xrdstorascan
%{_mandir}/man1/brix-mpxstats.1*
%{_mandir}/man1/brix-wait41.1*
%{_mandir}/man1/brix-xrd.1*
%{_mandir}/man1/brix-xrdadler32.1*
%{_mandir}/man1/brix-xrdcinfo.1*
%{_mandir}/man1/brix-xrdcksum.1*
%{_mandir}/man1/brix-xrdckverify.1*
%{_mandir}/man1/brix-xrdcp.1*
%{_mandir}/man1/brix-xrdcrc32c.1*
%{_mandir}/man1/brix-xrdcrc64.1*
%{_mandir}/man1/brix-xrddiag.1*
%{_mandir}/man1/brix-xrdfs.1*
%{_mandir}/man1/brix-xrdgsiproxy.1*
%{_mandir}/man1/brix-xrdgsitest.1*
%{_mandir}/man1/brix-xrdmapc.1*
%{_mandir}/man1/brix-xrdprep.1*
%{_mandir}/man1/brix-xrdqstats.1*
%{_mandir}/man1/brix-xrdsssadmin.1*
%{_mandir}/man1/brix-xrdstorascan.1*
# brix-env(7): identical content to brix-cache-client's copy; RPM permits two
# packages to own the same file when byte-identical, so either package alone
# satisfies the "man brix-env" footer reference.
%{_mandir}/man7/brix-env.7*
%{_datadir}/bash-completion/completions/brix-xrd
%{_datadir}/bash-completion/completions/brix-xrdcp
%{_datadir}/bash-completion/completions/brix-xrdfs
%{_datadir}/bash-completion/completions/brix-xrddiag
%{_datadir}/bash-completion/completions/brix-xrdcksum
%{_datadir}/bash-completion/completions/brix-xrdprep
%{_datadir}/bash-completion/completions/brix-xrdgsiproxy
%{_datadir}/bash-completion/completions/brix-xrdgsitest
%{_datadir}/bash-completion/completions/brix-xrdmapc
%{_datadir}/bash-completion/completions/brix-xrdsssadmin
%{_datadir}/bash-completion/completions/brix-xrdstorascan
%{_datadir}/zsh/site-functions/_brix-client-compat

%files -n brix-tools-compat
%license LICENSE
%{_bindir}/brix-xrdceph_striper_migrate
%{_bindir}/brix-xrdceph_cephfs_to_striper
%{_bindir}/brix-xrdrados_rescue
%{_bindir}/brix-xrdcephfs_rescue
%{_bindir}/brix-xrdceph_migrate
%{_mandir}/man1/brix-xrdceph_cephfs_to_striper.1*
%{_mandir}/man1/brix-xrdceph_migrate.1*
%{_mandir}/man1/brix-xrdceph_striper_migrate.1*
%{_mandir}/man1/brix-xrdcephfs_rescue.1*
%{_mandir}/man1/brix-xrdrados_rescue.1*
%{_datadir}/bash-completion/completions/brix-xrdceph_striper_migrate
%{_datadir}/bash-completion/completions/brix-xrdceph_cephfs_to_striper
%{_datadir}/bash-completion/completions/brix-xrdrados_rescue
%{_datadir}/bash-completion/completions/brix-xrdcephfs_rescue
%{_datadir}/bash-completion/completions/brix-xrdceph_migrate

%if %{with selinux}
%files selinux
%license LICENSE
%{_datadir}/selinux/packages/%{selinuxtype}/%{selinuxmodule}.pp.bz2
%{_datadir}/selinux/devel/include/distributed/%{selinuxmodule}.if
%ghost %verify(not md5 size mode mtime) %{_sharedstatedir}/selinux/%{selinuxtype}/active/modules/200/%{selinuxmodule}
%endif

%changelog
* Sun Jul 19 2026 Rob Currie <rob.currie@ed.ac.uk> - 1.1.1-25
- New co-installable subpackages brix-cache-client-compat and brix-tools-compat:
  the SAME native client + Ceph-operator binaries as brix-cache-client /
  brix-tools, installed under a "brix-" prefix (brix-xrdcp, brix-xrdfs,
  brix-xrdceph_migrate, ...) so a host can carry both the official
  xrootd-client tools and the brix tools side-by-side with no /usr/bin path
  collisions.
- One name-agnostic compile serves both flavours: every tool derives its
  display name, multi-call personality, and sibling-exec target from argv[0]
  at run time, so usage/version/man output always names the brix- alias, never
  the stock tool.  Additive and independent -- no Conflicts/Obsoletes and no
  dependency on the base packages; the compat tools ship their own brix-*.1
  man pages and share brix-env(7) as a byte-identical copy.  FUSE mounts are
  never prefixed and stay in brix-xrootdfs-fuse/brix-cvmfs-fuse.

* Fri Jul 17 2026 Rob Currie <rob.currie@ed.ac.uk> - 1.1.1-24
- New subpackage brix-cvmfs-automount: the native `brixMount autofs` umbrella
  automounts /cvmfs on first access (children mount in a farm under
  /var/lib/brixcvmfs/.mnt and appear as symlinks — no autofs kernel module,
  no systemd map).  Ships brixcvmfs-automount.service, a brixcvmfs@.service
  static-mount template, /sbin/mount.cvmfs (`mount -t cvmfs` compatible) and
  an /etc/auto.cvmfs program map for stock-autofs sites.  Conflicts: cvmfs
  (both own the /cvmfs automount role and /sbin/mount.cvmfs).
- New noarch subpackage brix-cvmfs-config: default domain config (cern.ch,
  egi.eu, opensciencegrid.org stratum-1 sets) + upstream master public keys
  vendored byte-identical from cvmfs-config-default (provenance and sha256
  fingerprints in /etc/cvmfs/keys/README.md).  Provides: cvmfs-config,
  Conflicts with the stock cvmfs-config-* providers; everything
  %%config(noreplace).  brix-cvmfs-fuse now Recommends: cvmfs-config.
- Fix whitelist/manifest body-binding to stock CVMFS hash coverage: the
  signed hash line covers the body up to but EXCLUDING the "--\n" separator
  (verified against live stratum-1 artifacts); previously the verifier
  included the separator and rejected every genuine repository with
  trust/catalog error -5.

* Fri Jul 17 2026 Rob Currie <rob.currie@ed.ac.uk> - 1.1.1-23
- Split the two FUSE mounts out of brix-cache-client into standalone
  subpackages so a mount/cache tier can deploy and test them without the full
  CLI suite: brix-xrootdfs-fuse (xrootdfs binary + man page + completion) and
  brix-cvmfs-fuse (brixMount + man page + completion).  Each Requires fuse3
  (fusermount3 is fork/exec'd, invisible to find-requires) and carries
  Conflicts: brix-cache-client < 1.1.1-23 so the file move upgrades cleanly
  in one transaction; brix-cache-client Recommends both, keeping the default
  install surface unchanged (install_weak_deps=False for a CLI-only node) and
  drops its own fuse3 dependency.
- SELinux policy verification suite: tests/test_selinux_rpm.py (ships in
  brix-cache-tests) — run as root on an SELinux host with the -selinux
  subpackage installed:
      cd /usr/share/brix && sudo python3 -m pytest tests/test_selinux_rpm.py
  Asserts the brix module is loaded in the module store, the file-context
  database and on-disk labels for /var/{lib,cache}/brix-cache (+ legacy
  nginx-xrootd spellings), /etc/brix-cache and /etc/grid-security, the
  brix_port_t labels on tcp 1094/1095/9001/9100, and the httpd_t allow rules
  (brix_port_t bind/connect, data-plane manage+map, impersonation-broker
  capabilities/setcap, outbound http/kerberos, corecmd exec).  brix-cache-tests
  Recommends the driving tools (libselinux-utils, policycoreutils-python-utils,
  setools-console).

* Fri Jul 17 2026 Rob Currie <rob.currie@ed.ac.uk> - 1.1.1-22
- SELinux support for hardened (enforcing) hosts: new noarch
  nginx-mod-brix-cache-selinux subpackage shipping a targeted-policy module
  (packaging/selinux/brix.{te,fc,if}) built per the Fedora SELinux packaging
  guidelines (priority-200 module store install, relabel scriptlets).
  nginx+BriX runs as httpd_t; the module adds exactly the BriX data plane:
  brix_port_t on tcp 1094/1095 (root://), 9001 (S3, local override of
  tor_port_t) and 9100 (metrics, local override of hplip_port_t) with
  httpd_t bind+connect (name_connect covers cache/stage-tier origins and
  native TPC); brix_var_lib_t on /var/lib/brix-cache (export root + stage)
  and brix_cache_t on /var/cache/brix-cache with full manage + mmap;
  httpd_config_t on /etc/brix-cache (JWKS/authdb); cert_t on
  /etc/grid-security (replaces the manual semanage remedy in the docs);
  impersonation-broker rules (setuid/setgid/setcap + chown/fowner/fsetid/
  dac_override/dac_read_search for multiuser stage-file ownership); outbound
  http/ceph/kerberos port connects (WebDAV TPC via fork/exec'd curl included
  — corecmd_exec_bin, no domain transition).  The main module package pulls
  the policy automatically via a rich dep when selinux-policy-targeted is
  installed; rpmbuild --without selinux disables the whole surface.  The main
  package now also owns /var/lib/brix-cache{,/data} (0750 nginx:nginx) so
  the install-time relabel is deterministic.  io_uring rules are documented
  but intentionally omitted (opt-in feature; the io_uring object class does
  not exist in the EL8 base policy).
- packaging/ rebrand: nginx-xrootd -> brix-cache for everything under
  packaging/ that is not an upgrade-path compatibility name — the hardened
  systemd unit is now packaging/brix-cache.service (pid /run/brix-cache.pid,
  config /etc/nginx/brix-cache.conf, ReadWritePaths /var/lib/brix-cache),
  the container builder image tags are brix-cache-rpm-builder:*, and the
  canonical data/config trees are /var/{lib,cache}/brix-cache +
  /etc/brix-cache.  Provides/Obsoletes on the old nginx-xrootd-* package
  names and the github.com/HEP-x/nginx-xrootd source URL are unchanged.

* Mon Jul 13 2026 Rob Currie <rob.currie@ed.ac.uk> - 1.1.1-21
- Co-installability with stock XRootD server RPMs: rename the three client
  binaries whose names collide with files owned by the xrootd packages —
  mpxstats -> mpxstats-brix, wait41 -> wait41-brix and
  xrdsssadmin -> xrdsssadmin-brix (binaries, man pages and bash completion).
  The bare spellings stay available as xrddiag subcommands
  (`xrddiag wait41`, `xrddiag mpxstats`). The remaining client/FUSE tools
  keep their stock names by design: they are drop-in replacements and are
  intentionally NOT co-installable with the official xrootd client tooling.

* Thu Jul 09 2026 Rob Currie <rob.currie@ed.ac.uk> - 1.1.1-20
- Fast `systemctl restart`: mark every per-worker BriX maintenance timer
  cancelable (CRL reload, stage scheduler, cache stale-dirty + watermark reapers,
  pending-locate reaper, stage-out reaper). nginx's ngx_event_no_timers_left()
  ignores cancelable timers, so on SIGQUIT a gracefully draining worker exits the
  instant its real work is done instead of looping in ep_poll until
  worker_shutdown_timeout. On xrd1 the STOP phase sat ~2-3s (workers idle-but-
  armed, force-terminated at the timeout) — this drops it to sub-second, cutting a
  full restart from ~9s toward ~2.5s. Pairs with the -19 config guidance to keep
  worker_shutdown_timeout below the systemd unit's TimeoutStopSec.
* Thu Jul 09 2026 Rob Currie <rob.currie@ed.ac.uk> - 1.1.1-19
- Faster startup + restart guidance. (1) Memoise the expensive IGTF CA/CRL
  X509_STORE by its inputs (brix_build_ca_store_cached): a real grid CA
  distribution's hundreds of *.r0 CRLs take ~1s to load, and BriX used to pay
  that once PER brix_auth-gsi server block at config load; blocks sharing a
  trusted_ca/CRL dir now build it once and share it (refcounted), while the
  per-worker CRL hot-reload timer still rebuilds from fresh CRLs (uncached
  scope). (2) contrib/brix-cache.conf.example now warns that
  worker_shutdown_timeout MUST stay below the systemd unit's TimeoutStopSec
  (stock nginx.service = 5s) or every restart is SIGKILLed at the timeout;
  recommends worker_shutdown_timeout 2s for fast restarts and `systemctl reload`
  for config-only changes. Regression guard: tests/run_gsi_store_memo.sh.
* Thu Jul 09 2026 Rob Currie <rob.currie@ed.ac.uk> - 1.1.1-18
- Clean release closing the remote-origin credential saga (full writeup in
  docs/09-developer-guide/postmortem-origin-credential-shadowing.md). Strips the
  -14/-16/-17 diagnostic NOTICEs; adds coherent, actionable warnings instead:
  (1) config load WARNs when a brix_credential NAME is defined more than once in
  one configuration — brix_credential is a single global name-keyed registry
  shared across stream{}/http{}, so the last block silently wins; this shadowing
  (a stream x509_proxy block vs an http/conf.d x509_cert+key block) broke origin
  GSI auth. A benign reload re-parse does NOT warn (cf->cycle scoped). (2) origin
  GSI auth WARNs up-front when the credential is a single certificate (bare host
  cert, not a proxy): a stock XRootD requires a >=2-cert proxy chain, so it names
  the voms-proxy-init remedy rather than leaving the operator to decode
  "received: 1, expected: >= 2". (3) the "no credential set" origin error now
  points at the likely cause (unset or shadowed brix_storage_credential).
  Retains the load-bearing fixes -12 (sd_xroot logs the real origin error), -13
  (tier_resolve_creds honours x509_cert+x509_key), -16 (per-worker credential
  re-apply in init_process). New regression guards: tests/run_credential_dup_warn.sh,
  tests/run_credential_xroot_gsi_writeback.sh.

* Wed Jul 08 2026 Rob Currie <rob.currie@ed.ac.uk> - 1.1.1-13
- Fix root:// remote-origin auth failing with "cache origin requires
  authentication (no credential set)" (EIO on the write-back flush) when the
  backend is composed as a cache/stage TIER over a storage_backend and the
  brix_credential supplies a separate x509_cert + x509_key (rather than a single
  combined x509_proxy).  The tier credential resolver (tier_resolve_creds) only
  read x509_proxy and hardcoded the key to NULL, silently dropping cert+key on
  the tier build path — so the sd_xroot origin login was attempted with no
  credential and the origin rejected it.  tier_resolve_creds now applies the
  same cert-chain + separate-key fallback used elsewhere and threads the key
  into create_origin; all three origin-build paths (backend registry, tier
  build, legacy cache fetch) now honour cert+key.  A one-line config-load NOTICE
  reports the resolved backend credential so an empty/misconfigured origin
  credential is obvious.  New e2e test: run_credential_xroot_gsi_writeback.sh
  (write-through to a GSI origin with a cert+key credential; fails without the
  fix).  Also carries the -12 diagnostics (sd_xroot now logs the real origin
  failure reason).

* Wed Jul 08 2026 Rob Currie <rob.currie@ed.ac.uk> - 1.1.1-12
- Diagnostics: sd_xroot now LOGS the real origin failure reason (the
  brix_cache_fill err_msg + kXR code) when a remote root:// open or staged
  flush to the origin fails, instead of hiding it behind the caller's generic
  "Input/output error".  This surfaces auth/TLS/protocol failures (e.g. "cache
  origin requires TLS", "no credential set", GSI handshake errors) in the nginx
  error log so origin-side misconfigurations are diagnosable without guesswork.

* Wed Jul 08 2026 Rob Currie <rob.currie@ed.ac.uk> - 1.1.1-11
- Fix root:// backend (sd_xroot) writes/flushes to a GSI origin failing with EIO:
  a brix_credential that supplied x509_cert + x509_key SEPARATELY (rather than a
  single combined x509_proxy PEM) was silently ignored — those two fields were
  dead, so the origin GSI login was never attempted, the connection was dropped
  before login, and staged flushes to the origin failed with "staged_open ...
  Input/output error" (data stranded in the stage, never reaching the origin).
  x509_cert (cert chain) + x509_key (private key) are now threaded through the
  backend credential and the in-process XrdSecgsi handshake (separate key load),
  so a plain host cert/key authenticates outbound without hand-concatenating them
  into a proxy.  A combined x509_proxy still takes precedence.  Regression test:
  tests/run_credential_xroot_gsi.sh gains a cert+key node (fills only with the fix).

* Wed Jul 08 2026 Rob Currie <rob.currie@ed.ac.uk> - 1.1.1-10
- Fix the root:// upload wedge at pipeline_depth x write-chunk (the "8 MiB
  stall" seen on a remote client): when the write pipeline saturates, recv
  suspends into XRD_ST_SENDING and relies on the write event to drain the
  parked acks and resume — but the ack-park path only POSTED the write event
  when wev->ready was already set.  With a remote peer wev->ready can be a
  stale 0 while the socket is writable, and under edge-triggered epoll no fresh
  writable edge arrives for an already-writable socket, so the acks stranded
  and recv never resumed (every worker idle in epoll_wait, the staged .part
  frozen).  Parked output now forces the write event via a new
  brix_ensure_write_event() (unconditional post); the post-real-send NGX_AGAIN
  paths keep the wev->ready guard so they cannot busy-loop.  This is a
  pipeline-layer fix and applies whether io_uring is on or off (io_uring stays
  off by default per -9).  Diagnostic tooling added under tools/diag/.

* Wed Jul 08 2026 Rob Currie <rob.currie@ed.ac.uk> - 1.1.1-9
- Default the io_uring backend to OFF (was auto): it is now strictly opt-in via
  `brix_io_uring on`.  The startup probe cannot prove that real buffered file
  writes complete on a given kernel+filesystem (only that opcodes and eventfd
  NOP delivery work), and on an EL9 elrepo 6.15 host with plain local storage
  io_uring writes never completed — transfers wedged after queue_depth in-flight
  ops (8 MiB) and a torn-down connection's in-flight ops crashed the worker.
  The thread pool is correct there and faster.  io_uring stays available for
  operators who verify it on their platform; the earlier under-load self-test,
  driver-backed guard, and teardown-orphan fixes remain for that opt-in path.

* Wed Jul 08 2026 Rob Currie <rob.currie@ed.ac.uk> - 1.1.1-8
- io_uring: strengthen the startup self-test to an UNDER-LOAD burst — fill the
  ring with queue_depth ops and require every completion to arrive via the
  registered eventfd.  A kernel that signals the eventfd for a single op but
  stops once the ring saturates (observed on an EL9 elrepo 6.15 host: transfers
  wedged after exactly queue_depth x 32 KiB = 8 MiB, one worker spinning) now
  fails the probe and falls back to the thread pool instead of hanging.
- io_uring: orphan in-flight ops via a CONNECTION-POOL CLEANUP rather than only
  brix_on_disconnect.  A connection torn down by an nginx-core path (read
  error / RST / stream timeout / worker exit) bypassed the disconnect hook, so
  a late CQE posted a completion event into the freed+reused pool and crashed
  the worker in ngx_event_process_posted (confirmed by core inspection).  The
  cleanup runs on ngx_destroy_pool, which every teardown path funnels through.

* Wed Jul 08 2026 Rob Currie <rob.currie@ed.ac.uk> - 1.1.1-7
- Fix io_uring silent stall after queue_depth in-flight ops (256 x 32 KiB =
  8 MiB): the startup self-test now proves the registered eventfd actually
  delivers completions before enabling the backend, and falls back to the
  thread pool on a kernel where it does not (the reaper would otherwise never
  run and every transfer would wedge).
- Fix io_uring data corruption on driver-backed backends: a write to a remote
  root:// / HTTP / Ceph / pblock export with a thread pool configured was
  routed onto a raw IORING_OP_WRITE against the handle's placeholder fd,
  landing 0 bytes on the origin.  io_uring now handles only plain POSIX fds;
  driver-backed handles fall to the thread pool (which routes through the
  driver).  New coverage: tests/run_io_uring_backend.sh.

* Wed Jul 08 2026 Rob Currie <rob.currie@ed.ac.uk> - 1.1.1-6
- Fix io_uring completion/teardown race (worker SIGSEGV in
  ngx_event_process_posted): a late CQE for a connection already torn down
  posted a completion event living in the freed connection pool, corrupting
  the posted-event queue.  Slots now carry their owning connection and are
  orphaned at disconnect; the reaper drops orphaned CQEs without touching the
  dead task.  Also honour the deferred-teardown guard on the AIO
  resume-failure path, which could previously finalize a session while
  sibling completions were still queued.

* Wed Jul 08 2026 Rob Currie <rob.currie@ed.ac.uk> - 1.1.1-5
- Fix worker SIGSEGV crash-loop on cache/stage-tier I/O: storage-driver
  instances were allocated from ngx_cycle->pool, which during configuration
  parse is the TRANSIENT init cycle destroyed at startup — the first request
  through a composed tier then dereferenced freed memory.  Instances now come
  from a private process-lifetime registry pool (brix_sd_instance_create no
  longer takes a pool argument).

* Wed Jul 08 2026 Rob Currie <rob.currie@ed.ac.uk> - 1.1.1-4
- Fix GSI against real-world CA chains: the kXGS_init sec token now advertises
  the CA name-hash list derived from the server certificate's verified chain
  (intermediates + root).  Previously the hash was PEM-parsed from
  brix_trusted_ca — silently empty when that names a CA DIRECTORY — so the
  token said ca:00000000 and stock XrdSecgsi clients aborted with "unknown CA:
  cannot verify server certificate" whenever the host cert hangs off an
  intermediate CA (the IGTF / UK eScience shape).  Regression test:
  tests/run_gsi_intermediate_ca.sh (stock-client end-to-end).

* Wed Jul 08 2026 Rob Currie <rob.currie@ed.ac.uk> - 1.1.1-3
- Fix the DYNAMIC combined module: ngx_http_brix_common_module (unified
  brix_export/brix_storage_backend/tier grammar) and ngx_http_brix_guard_module
  were compiled into the .so but missing from its module registration list, so
  their directives were rejected ("not allowed here") on RPM installs while
  static test builds worked.

* Tue Jul 07 2026 Rob Currie <rob.currie@ed.ac.uk> - 1.1.1-2
- Fix the VOMS runtime dependency: require the libvomsapi.so.1 soname instead
  of the voms-libs package name, which does not exist on EL9 (EPEL 9 ships
  the library in the `voms` package). Fixes dnf install on stock EL9 hosts.

* Tue Jul 07 2026 Rob Currie <rob.currie@ed.ac.uk> - 1.1.1-1
- Version 1.1.1; RPM version now derives from src/core/ident.h (-v overrides).
- cvmfs:// site-cache protocol: CAS verify-on-fill + quarantine, multi-origin
  geo/RTT selection with health failover, forward-proxy mode, never-drop
  fills, per-repository metrics; experimental scvmfs:// (TLS).
- brixMount native CVMFS FUSE client, including a writable overlay (cvmfs-rw).
- Bad-actor guard: HTTP + stream request classification with fail2ban jails.
- WLCG conformance hardening: 510-case token RFC suite and 500+ clause x509
  suite; new signing_policy/crl_mode directives, RFC 3820 limited-proxy
  monotonicity, token crit/NumericDate/aud-wildcard/kid-rotation fixes.
- S3: WLCG bearer-token authentication with scope enforcement.
- WebDAV: native authdb + VO-ACL read authorization (root:// parity), VOMS VO
  extraction, RFC 3820 proxy acceptance on davs://.
- Cache/stage serve now runs full per-user authorization (no cross-user leak).
- io_uring disk-I/O and event-loop engines (server modules + client tools),
  compiled in by default (rpmbuild --without uring to disable).
- kTLS on by default across root://, WebDAV, S3; CSI checksum-at-rest on by
  default with the record cached at open.
- xmeta unified cache-metadata record (cinfo, CSI block CRCs, sidecars).
- Pluggable storage-driver seam under the VFS; Ceph RADOS backend data plane;
  writable remote root:// backend.
- Ceph operator tools (brix-tools): striper<->CephFS migration + rescue,
  compiled C++ and Python variants.
- Client suite: xrdcp sync/mirror/resume journal/filters, xrdfs rm -r,
  tail -f, --json, recursive checksum manifests, shell completions, man
  pages, ~/.xrdrc defaults.
- Session lifecycle logging across all protocol handlers.
- Unified brix configuration grammar (xrootd_* -> brix_* directives) with
  one-protocol-per-port enforcement.
- zstd and lz4 codecs enabled by default; --without zstd/lz4 to disable.
- Ceph client libraries are explicit Requires (librados2, libradosstriper1;
  brix-tools also libcephfs2).
- Fix container RPM builds: missing errno.h in sd_ceph_striper, io_uring
  helpers now gated on BRIX_HAVE_LIBURING, spec payload files restored to
  the docker build context.

* Tue Jul 07 2026 Rob Currie <rob.currie@ed.ac.uk> - 0.1.0-9
- Rename source tree and install paths from nginx-xrootd to brix: upstream_name
  is now brix (tarballs unpack as brix-{version}/), installed data lands under
  %%{_datadir}/brix, and the logrotate rule is %%{_sysconfdir}/logrotate.d/brix.
- Remove unused sd_ceph_is_striped static function (dead code since open path
  inlines the striper-stat probe directly); eliminates -Wunused-function warning.
- Add -D_FILE_OFFSET_BITS=64 to the Ceph module CFLAGS so libcephfs/librados
  headers compile correctly on all targets.

* Tue Jul 07 2026 Rob Currie <rob.currie@ed.ac.uk> - 0.1.0-8
- Ceph operator tools promoted to client/apps/ceph/: brix-tools now builds via
  the dep-gated `make -C client ceph-tools` target and is staged by the client
  install-bin target (no more spec-local compile/install recipes).
- brix-tools gains the offline rescue utilities (xrdrados_rescue,
  xrdcephfs_rescue, xrdceph_migrate), the Python migration variants (*.py on
  PATH, pymigrate under %%{_libexecdir}/brix; Recommends python3-rados/
  python3-cephfs), their bash completions, and the five Ceph operator man pages.
  brix-cache-client now lists its own man pages explicitly so brix-tools owns
  the full Ceph/CephFS operator surface.

* Tue Jul 07 2026 Rob Currie <rob.currie@ed.ac.uk> - 0.1.0-7
- Package brix-tools as compiled C++ XrdCeph/CephFS migration
  binaries instead of the Python reference/operator scripts.
- Provide/obsolete the temporary brix-cache-ceph-tools package name.
- Add the Ceph development build requirements needed for the binary tools.

* Tue Jul 07 2026 Rob Currie <rob.currie@ed.ac.uk> - 0.1.0-6
- Package the current client install surface from client/Makefile so xrd,
  xrdcksum personalities, xrdstorascan, brixMount, all man pages, completions,
  and libbrixposix_preload.so are included.
- Add brix-cache-ceph-tools with the Python XrdCeph/CephFS migration tools and
  their pymigrate helper package.
- Update the module payload for the current BriX artifact names.
- Ship the renamed brix-cache.conf.example reference config.

* Fri Jul 03 2026 Rob Currie <rob.currie@ed.ac.uk> - 0.1.0-5
- Rebrand: the product is now BriX-Cache (server identity string, docs, site).
  Package renames: nginx-mod-xrootd -> nginx-mod-brix-cache,
  nginx-xrootd-client -> brix-cache-client, nginx-xrootd-tests -> brix-cache-tests,
  each with Provides/Obsoletes on the old name for a clean dnf upgrade path.
  Installed compatibility names (mod-xrootd.conf and %%{_datadir}/nginx-xrootd)
  are unchanged, so existing active configs keep working as-is.
- Server now reports "BriX-Cache" in kXR_query Qconfig version, stats XML pgm/name,
  /healthz service, SRR implementation, and the dashboard (src/core/ident.h)

* Sun Jun 21 2026 nginx-xrootd maintainers <maintainers@example.com> - 0.1.0-4
- phase-47 W1: bundle the dynamic modules into a single combined stream .so
  plus the standalone HTTP AUX filter, so cross-module symbols resolve at link
  time and `nginx -t` loads cleanly — fixes the dlopen failure that the previous
  8-separate-.so layout hit on stock nginx (cross-.so RTLD_NOW symbol cycle).
  mod-xrootd.conf now writes 2 load_module lines (combined first)

* Mon Jun 15 2026 nginx-xrootd maintainers <maintainers@example.com> - 0.1.0-3
- Build and package the native client tools as nginx-xrootd-client
  (xrdcp/xrdfs/... + xrootdfs FUSE + LD_PRELOAD shim; Requires fuse3)
- Add the pytest test-suite as the noarch nginx-xrootd-tests subpackage with its
  python dependencies (pytest, pytest-timeout, pytest-xdist, cryptography,
  requests, urllib3; Recommends python3-xrootd)
- Add fuse3-devel, libcom_err-devel, and pkgconfig build dependencies
- Thread RPM optflags/build_ldflags through the client build (PIE/RELRO/BIND_NOW)
- Link external libs (libxml2/jansson/libcurl/krb5) into each module .so via
  ngx_module_libs so the DYNAMIC modules load on stock nginx and the RPM
  auto-requires them (previously only in CORE_LIBS = the static nginx binary)
- Make the dashboard Cookie: header read portable to nginx < 1.23.0 (the
  headers_in.cookies array) so the modules build against EL stock nginx (1.20.x)

* Sun Jun 14 2026 nginx-xrootd maintainers <maintainers@example.com> - 0.1.0-2
- Add SRR, XrdHttp filter, and dashboard modules
- Add libcurl, krb5, and libxcrypt build dependencies
- Update module loading order in mod-xrootd.conf

* Tue Apr 21 2026 nginx-xrootd maintainers <maintainers@example.com> - 0.1.0-1
- Initial nginx dynamic module package
