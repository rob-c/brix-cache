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

Name:           nginx-mod-xrootd
Version:        %{upstream_version}
Release:        4%{?dist}
Summary:        XRootD, WebDAV, S3, CMS, and metrics dynamic modules for nginx

License:        AGPL-3.0-only
URL:            https://github.com/HEP-x/nginx-xrootd
Source0:        %{url}/archive/refs/tags/v%{version}/%{upstream_name}-%{version}.tar.gz

# --- toolchain ---
BuildRequires:  gcc
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
# --- phase-42 optional compression codecs (off by default; see %bcond above).
# When enabled, ./configure links the lib and find-requires turns it into a
# runtime dep automatically; when disabled, the codec reports available=0. ---
%{?with_zstd:BuildRequires:  libzstd-devel}
%{?with_lzma:BuildRequires:  xz-devel}
%{?with_brotli:BuildRequires:  libbrotli-devel}
%{?with_bzip2:BuildRequires:  bzip2-devel}
%{?with_lz4:BuildRequires:  lz4-devel}
# --- native client (nginx-xrootd-client subpackage) extra link deps ---
# fuse3-devel: the xrootdfs FUSE mount (default + --legacy mode); libcom_err-devel above
# resolves the -lcom_err pulled in by `pkg-config --libs krb5`.
BuildRequires:  fuse3-devel

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
Dynamic nginx modules that serve files over the native XRootD stream protocol,
WebDAV over HTTPS, and an S3-compatible HTTP subset, with CMS management-listener
and Prometheus metrics support.

# ---------------------------------------------------------------------------
# Subpackage 2: native clean-room client tools (CLI + FUSE + LD_PRELOAD shim)
# ---------------------------------------------------------------------------
%package -n nginx-xrootd-client
Summary:        Clean-room native XRootD client tools (xrdcp, xrdfs, xrootdfs, ...)
# fuse3: xrootdfs forks/execs fusermount3 at mount/unmount time —
# a runtime dependency that find-requires (which only sees libfuse3.so) misses.
# All other shared-library deps (openssl-libs, krb5-libs, libcom_err, zlib,
# fuse3-libs) are picked up automatically from the ELF link records.
Requires:       fuse3

%description -n nginx-xrootd-client
Native command-line XRootD clients built clean-room on the in-tree protocol
core (libxrdc + libxrdproto) with NO libXrdCl / libXrdSec dependency: xrdcp,
xrdfs, xrdcrc32c, xrdcrc64, xrdadler32, xrdqstats, xrdprep, xrdgsiproxy,
xrddiag, xrdmapc, xrdgsitest, mpxstats, xrdsssadmin and wait41, plus the
xrootdfs FUSE mount (default + --legacy mode) and an LD_PRELOAD POSIX shim.

# ---------------------------------------------------------------------------
# Subpackage 3: the pytest integration/conformance test-suite + its python deps
# ---------------------------------------------------------------------------
%package -n nginx-xrootd-tests
Summary:        Integration and conformance test-suite for nginx-xrootd
BuildArch:      noarch
# The system under test:
Requires:       nginx-mod-xrootd = %{version}-%{release}
Requires:       nginx-xrootd-client = %{version}-%{release}
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

%description -n nginx-xrootd-tests
The full pytest integration, conformance, and adversarial test-suite for
nginx-xrootd (root://, WebDAV, S3, CMS, metrics, FRM, TPC, ...), installed under
%{_datadir}/nginx-xrootd.  Run with, e.g.:
    cd %{_datadir}/nginx-xrootd && PYTHONPATH=tests python3 -m pytest tests/ -v

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

%install
# --- nginx dynamic modules ---
# phase-47 W1: the dynamic build emits exactly TWO .so files — one combined
# module (ngx_stream_xrootd_module.so, which contains stream+metrics+srr+webdav+
# s3+dashboard+cms) and the standalone HTTP AUX filter.  Bundling the formerly-
# separate modules into one .so makes their cross-module symbol references
# (dashboard<->webdav<->metrics<->stream) resolve at link time, so dlopen no
# longer trips on the cross-.so RTLD_NOW cycle that broke `nginx -t` before.
install -Dpm0755 %{_vpath_builddir}/ngx_stream_xrootd_module.so \
    %{buildroot}%{nginx_moddir}/ngx_stream_xrootd_module.so
install -Dpm0755 %{_vpath_builddir}/ngx_http_xrootd_xrdhttp_filter_module.so \
    %{buildroot}%{nginx_moddir}/ngx_http_xrootd_xrdhttp_filter_module.so

mkdir -p %{buildroot}%{nginx_modconfdir}
# Combined module first so its symbols back the filter via RTLD_GLOBAL.
{
    echo 'load_module "%{nginx_moddir}/ngx_stream_xrootd_module.so";'
    echo 'load_module "%{nginx_moddir}/ngx_http_xrootd_xrdhttp_filter_module.so";'
} > %{buildroot}%{nginx_modconfdir}/mod-xrootd.conf

# phase-47 W3: ship a heavily-commented example server config (installed as
# .example so it never auto-activates — the operator copies it to a .conf name)
# and a logrotate rule for the module's access logs.
install -Dpm0644 contrib/xrootd.conf.example \
    %{buildroot}%{_sysconfdir}/nginx/conf.d/xrootd.conf.example
install -Dpm0644 contrib/logrotate.d/nginx-xrootd \
    %{buildroot}%{_sysconfdir}/logrotate.d/nginx-xrootd

# phase-47 W4: ship a ready-made Grafana dashboard + Prometheus alert rules.
install -Dpm0644 contrib/grafana-dashboard.json \
    %{buildroot}%{_datadir}/nginx-xrootd/grafana-dashboard.json
install -Dpm0644 contrib/prometheus-alerts.yml \
    %{buildroot}%{_datadir}/nginx-xrootd/prometheus-alerts.yml

# --- native client tools (nginx-xrootd-client) ---
for b in xrdfs xrdcp xrdcrc32c xrdcrc64 xrdadler32 xrdqstats wait41 \
         xrdprep xrdgsiproxy xrddiag xrdmapc xrdgsitest mpxstats xrdsssadmin \
         xrootdfs; do
    install -Dpm0755 client/bin/$b %{buildroot}%{_bindir}/$b
done
install -Dpm0755 client/libxrdposix_preload.so \
    %{buildroot}%{_libdir}/libxrdposix_preload.so
install -Dpm0644 client/man/xrootdfs.1 \
    %{buildroot}%{_mandir}/man1/xrootdfs.1

# --- test-suite (nginx-xrootd-tests, noarch data) ---
install -d %{buildroot}%{_datadir}/nginx-xrootd
cp -a tests %{buildroot}%{_datadir}/nginx-xrootd/tests
# Never ship the prebuilt test nginx binary or any python bytecode caches.
rm -f %{buildroot}%{_datadir}/nginx-xrootd/tests/nginx-bin
find %{buildroot}%{_datadir}/nginx-xrootd/tests -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || :
find %{buildroot}%{_datadir}/nginx-xrootd/tests -name '*.pyc' -delete
install -Dpm0644 conftest.py      %{buildroot}%{_datadir}/nginx-xrootd/conftest.py
install -Dpm0644 pytest.ini       %{buildroot}%{_datadir}/nginx-xrootd/pytest.ini
install -Dpm0644 requirements.txt %{buildroot}%{_datadir}/nginx-xrootd/requirements.txt

%files
%license LICENSE
%doc README.md docs/
%{nginx_moddir}/ngx_stream_xrootd_module.so
%{nginx_moddir}/ngx_http_xrootd_xrdhttp_filter_module.so
%{nginx_modconfdir}/mod-xrootd.conf
%config(noreplace) %{_sysconfdir}/nginx/conf.d/xrootd.conf.example
%config(noreplace) %{_sysconfdir}/logrotate.d/nginx-xrootd
%{_datadir}/nginx-xrootd/grafana-dashboard.json
%{_datadir}/nginx-xrootd/prometheus-alerts.yml

%files -n nginx-xrootd-client
%license LICENSE
%{_bindir}/xrdfs
%{_bindir}/xrdcp
%{_bindir}/xrdcrc32c
%{_bindir}/xrdcrc64
%{_bindir}/xrdadler32
%{_bindir}/xrdqstats
%{_bindir}/wait41
%{_bindir}/xrdprep
%{_bindir}/xrdgsiproxy
%{_bindir}/xrddiag
%{_bindir}/xrdmapc
%{_bindir}/xrdgsitest
%{_bindir}/mpxstats
%{_bindir}/xrdsssadmin
%{_bindir}/xrootdfs
%{_libdir}/libxrdposix_preload.so
%{_mandir}/man1/xrootdfs.1*

%files -n nginx-xrootd-tests
%license LICENSE
%dir %{_datadir}/nginx-xrootd
%{_datadir}/nginx-xrootd/tests
%{_datadir}/nginx-xrootd/conftest.py
%{_datadir}/nginx-xrootd/pytest.ini
%{_datadir}/nginx-xrootd/requirements.txt

%changelog
* Sun Jun 21 2026 nginx-xrootd maintainers <maintainers@example.com> - 0.1.0-4
- phase-47 W1: bundle the dynamic modules into a single combined .so
  (ngx_stream_xrootd_module.so = stream+metrics+srr+webdav+s3+dashboard+cms)
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
