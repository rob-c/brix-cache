%global upstream_name nginx-xrootd
%global upstream_version %{?version_override}%{!?version_override:0.1.0}

# --- phase-42 optional compression codecs (gzip/deflate via zlib are always on) ---
# Each non-zlib codec is compile-gated by ./configure's pkg-config probe and
# degrades to available=0 when absent, so the SRPM builds on minimal hosts.
# Enable extra codecs with: rpmbuild --with zstd --with lzma --with brotli --with bzip2 --with lz4
%bcond_with zstd
%bcond_with lzma
%bcond_with brotli
%bcond_with bzip2
%bcond_with lz4

Name:           nginx-mod-brix-cache
Version:        %{upstream_version}
Release:        8%{?dist}
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
# --- phase-42 optional compression codecs (off by default; see %%bcond above).
# When enabled, ./configure links the lib and find-requires turns it into a
# runtime dep automatically; when disabled, the codec reports available=0. ---
%{?with_zstd:BuildRequires:  libzstd-devel}
%{?with_lzma:BuildRequires:  xz-devel}
%{?with_brotli:BuildRequires:  libbrotli-devel}
%{?with_bzip2:BuildRequires:  bzip2-devel}
%{?with_lz4:BuildRequires:  lz4-devel}
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
# voms-libs: loaded at runtime via dlopen(libvomsapi.so.1); not a link-time dep
# so find-requires cannot detect it.  Required for VOMS VO/FQAN ACL enforcement.
# curl: used to be fork/exec'd, now primarily used via libcurl, but kept for
# compatibility with site scripts.
Requires:       nginx-mod-stream%{?_isa}
Requires:       openssl-libs%{?_isa}
Requires:       voms-libs%{?_isa}
Requires:       curl

%description
BriX-Cache: dynamic nginx modules that serve files over the native XRootD
stream protocol, WebDAV over HTTPS, and an S3-compatible HTTP subset, with CMS
management-listener and Prometheus metrics support.

# ---------------------------------------------------------------------------
# Subpackage 2: native clean-room client tools (CLI + FUSE + LD_PRELOAD shim)
# ---------------------------------------------------------------------------
%package -n brix-cache-client
Summary:        BriX-Cache clean-room native XRootD client tools (xrdcp, xrdfs, xrootdfs, ...)
Provides:       nginx-xrootd-client = %{version}-%{release}
Obsoletes:      nginx-xrootd-client < 0.1.0-5
# fuse3: xrootdfs forks/execs fusermount3 at mount/unmount time —
# a runtime dependency that find-requires (which only sees libfuse3.so) misses.
# All other shared-library deps (openssl-libs, krb5-libs, libcom_err, zlib,
# fuse3-libs) are picked up automatically from the ELF link records.
Requires:       fuse3

%description -n brix-cache-client
Native command-line XRootD clients built clean-room on the in-tree protocol
core (libbrix + libxrdproto) with NO libXrdCl / libXrdSec dependency:
xrdcp, xrdfs, xrd, xrdcksum and checksum personalities, xrdqstats, xrdprep,
xrdgsiproxy, xrddiag, xrdmapc, xrdgsitest, xrdstorascan, mpxstats,
xrdsssadmin and wait41, plus xrootdfs, brixMount, and the
libbrixposix_preload.so LD_PRELOAD POSIX shim.

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

%description -n brix-cache-tests
The full pytest integration, conformance, and adversarial test-suite for
BriX-Cache (root://, WebDAV, S3, CMS, metrics, FRM, TPC, ...), installed under
%{_datadir}/nginx-xrootd.  Run with, e.g.:
    cd %{_datadir}/nginx-xrootd && PYTHONPATH=tests python3 -m pytest tests/ -v

# ---------------------------------------------------------------------------
# Subpackage 4: Ceph/XrdCeph migration operator tools
# ---------------------------------------------------------------------------
%package -n brix-tools
Summary:        XrdCeph/CephFS migration + rescue operator tools for BriX-Cache
Provides:       brix-cache-ceph-tools = %{version}-%{release}
Obsoletes:      brix-cache-ceph-tools <= %{version}-%{release}
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

%prep
%autosetup -n %{upstream_name}-%{version}

%build
# --- nginx dynamic modules ---
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
install -Dpm0644 contrib/logrotate.d/nginx-xrootd \
    %{buildroot}%{_sysconfdir}/logrotate.d/nginx-xrootd

# phase-47 W4: ship a ready-made Grafana dashboard + Prometheus alert rules.
install -Dpm0644 contrib/grafana-dashboard.json \
    %{buildroot}%{_datadir}/nginx-xrootd/grafana-dashboard.json
install -Dpm0644 contrib/prometheus-alerts.yml \
    %{buildroot}%{_datadir}/nginx-xrootd/prometheus-alerts.yml

# --- native client tools (brix-cache-client) ---
# Use the in-tree install target so the RPM follows the current client tool set
# (xrd/xrdcksum/xrdstorascan/brixMount/etc.) instead of a stale spec-local list.
make -C client install-bin \
    DESTDIR=%{buildroot} \
    PREFIX=%{_prefix} \
    LIBDIR=%{_libdir}

# --- test-suite (brix-cache-tests, noarch data) ---
install -d %{buildroot}%{_datadir}/nginx-xrootd
cp -a tests %{buildroot}%{_datadir}/nginx-xrootd/tests
# Never ship the prebuilt test nginx binary, any python bytecode caches, or
# stray compiled test helpers (e.g. tests/fuzz/*) — the package is noarch, so
# any ELF object in the payload fails the build.
rm -f %{buildroot}%{_datadir}/nginx-xrootd/tests/nginx-bin
find %{buildroot}%{_datadir}/nginx-xrootd/tests -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || :
find %{buildroot}%{_datadir}/nginx-xrootd/tests -name '*.pyc' -delete
find %{buildroot}%{_datadir}/nginx-xrootd/tests -type f \
    -exec sh -c 'head -c4 "$1" | od -An -tx1 | grep -q "7f 45 4c 46"' _ {} \; -delete
install -Dpm0644 conftest.py      %{buildroot}%{_datadir}/nginx-xrootd/conftest.py
install -Dpm0644 pytest.ini       %{buildroot}%{_datadir}/nginx-xrootd/pytest.ini
install -Dpm0644 requirements.txt %{buildroot}%{_datadir}/nginx-xrootd/requirements.txt

# --- Ceph/XrdCeph migration + rescue operator tools (brix-tools) ---
# Already staged by `make -C client install-bin` above: the compiled tools via
# the OPT_EXES loop, the Python pair + pymigrate under %{_libexecdir}/brix with
# %{_bindir}/*.py symlinks, and their man pages/completions. Ownership is split
# in %%files: binaries/python/completions go to brix-tools, man pages ride the
# brix-cache-client man1 glob.

%files
%license LICENSE
%doc README.md docs/
%{nginx_moddir}/ngx_stream_brix_module.so
%{nginx_moddir}/ngx_http_brix_xrdhttp_filter_module.so
%{nginx_modconfdir}/mod-xrootd.conf
%config(noreplace) %{_sysconfdir}/nginx/conf.d/brix-cache.conf.example
%config(noreplace) %{_sysconfdir}/logrotate.d/nginx-xrootd
%{_datadir}/nginx-xrootd/grafana-dashboard.json
%{_datadir}/nginx-xrootd/prometheus-alerts.yml

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
%{_bindir}/wait41
%{_bindir}/xrdprep
%{_bindir}/xrdgsiproxy
%{_bindir}/xrddiag
%{_bindir}/xrdmapc
%{_bindir}/xrdgsitest
%{_bindir}/mpxstats
%{_bindir}/xrdsssadmin
%{_bindir}/xrdstorascan
%{_bindir}/xrootdfs
%{_bindir}/brixMount
%{_libdir}/libbrixposix_preload.so
%{_mandir}/man1/*.1*
%{_mandir}/man7/brix-env.7*
%{_datadir}/bash-completion/completions/xrd
%{_datadir}/bash-completion/completions/xrdcp
%{_datadir}/bash-completion/completions/xrdfs
%{_datadir}/bash-completion/completions/xrddiag
%{_datadir}/bash-completion/completions/xrdcksum
%{_datadir}/bash-completion/completions/xrdprep
%{_datadir}/bash-completion/completions/xrdgsiproxy
%{_datadir}/bash-completion/completions/xrdsssadmin
%{_datadir}/bash-completion/completions/brixMount
%{_datadir}/bash-completion/completions/xrdstorascan
%{_datadir}/bash-completion/completions/xrootdfs
%{_datadir}/zsh/site-functions/_brix-client

%files -n brix-cache-tests
%license LICENSE
%dir %{_datadir}/nginx-xrootd
%{_datadir}/nginx-xrootd/tests
%{_datadir}/nginx-xrootd/conftest.py
%{_datadir}/nginx-xrootd/pytest.ini
%{_datadir}/nginx-xrootd/requirements.txt

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
%{_libexecdir}/brix/
%{_datadir}/bash-completion/completions/xrdceph_striper_migrate
%{_datadir}/bash-completion/completions/xrdceph_cephfs_to_striper
%{_datadir}/bash-completion/completions/xrdrados_rescue
%{_datadir}/bash-completion/completions/xrdcephfs_rescue
%{_datadir}/bash-completion/completions/xrdceph_migrate

%changelog
* Tue Jul 07 2026 Rob Currie <rob.currie@ed.ac.uk> - 0.1.0-8
- Ceph operator tools promoted to client/apps/ceph/: brix-tools now builds via
  the dep-gated `make -C client ceph-tools` target and is staged by the client
  install-bin target (no more spec-local compile/install recipes).
- brix-tools gains the offline rescue utilities (xrdrados_rescue,
  xrdcephfs_rescue, xrdceph_migrate), the Python migration variants (*.py on
  PATH, pymigrate under %%{_libexecdir}/brix; Recommends python3-rados/
  python3-cephfs), and their bash completions. The five new man pages ride the
  brix-cache-client man1 glob.

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
