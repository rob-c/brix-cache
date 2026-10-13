%global upstream_name brix
%global upstream_version %{?version_override}%{!?version_override:2.0.0}

Name:           brix-cache-client-compat
Version:        %{upstream_version}
Release:        1%{?dist}
Summary:        BriX-Cache native clients for EL8 under brix-prefixed names
License:        AGPL-3.0-only
URL:            https://github.com/rob-c/brix-cache
Source0:        %{url}/archive/refs/tags/v%{version}/%{upstream_name}-%{version}.tar.gz

BuildRequires:  gcc
BuildRequires:  gcc-c++
BuildRequires:  make
BuildRequires:  pkgconfig
BuildRequires:  openssl3-devel
BuildRequires:  zlib-devel
BuildRequires:  libxml2-devel
BuildRequires:  jansson-devel
BuildRequires:  libcurl-devel
BuildRequires:  krb5-devel
BuildRequires:  libcom_err-devel
BuildRequires:  libxcrypt-devel
BuildRequires:  sqlite-devel
BuildRequires:  libseccomp-devel
BuildRequires:  liburing-devel
BuildRequires:  libzstd-devel
BuildRequires:  brotli-devel
BuildRequires:  xz-devel
BuildRequires:  bzip2-devel
BuildRequires:  lz4-devel
BuildRequires:  librados-devel
BuildRequires:  libradospp-devel
BuildRequires:  libradosstriper-devel
BuildRequires:  libcephfs-devel

Requires:       openssl3-libs%{?_isa}

%description
The clean-room BriX XRootD-compatible client, library, diagnostics and Ceph
operator tools for Enterprise Linux 8. Commands use brix-prefixed names so the
package co-installs with the distribution XRootD clients.

EL8's nginx is linked against OpenSSL 1.1.1 and cannot safely load the
OpenSSL-3-based BriX server module. This package intentionally contains no
nginx module; deploy the server on EL9 or newer.

%prep
%setup -q -n %{upstream_name}-%{version}

%build
make -C client clean
make -C shared/xrdproto clean
make -C shared/xrdproto %{?_smp_mflags} CFLAGS="%{optflags}"
make -C client %{?_smp_mflags} BRIX_CLIENT_VERSION="%{version}" \
    CFLAGS="%{optflags}" LDFLAGS="%{build_ldflags}"

%check
client/bin/xrdcp --version | grep -F "%{version}"
src_file="$(mktemp)"
dst_file="$(mktemp)"
printf 'brix-cache el8 package\n' > "$src_file"
client/bin/xrdcp -f "$src_file" "$dst_file"
cmp "$src_file" "$dst_file"

%install
make -C client install install-compat \
    DESTDIR=%{buildroot} PREFIX=%{_prefix} LIBDIR=%{_libdir} \
    INCLUDEDIR=%{_includedir} PKGCONFDIR=%{_libdir}/pkgconfig \
    LIBEXECDIR=%{_libexecdir}/brix
install -Dpm0644 LICENSE \
    %{buildroot}%{_licensedir}/%{name}/LICENSE
install -Dpm0755 packaging/rpm/alma-platform-warning.sh \
    %{buildroot}%{_libexecdir}/brix/alma-platform-warning

%post
%{_libexecdir}/brix/alma-platform-warning

%files
%license %{_licensedir}/%{name}/LICENSE
%{_bindir}/brix-*
%{_libdir}/libbrix.so*
%{_libdir}/libbrix.a
%{_libdir}/libxrdproto.a
%{_libdir}/pkgconfig/libbrix.pc
%{_includedir}/brix/
%{_mandir}/man1/brix-*.1*
%{_mandir}/man7/brix-env.7*
%{_datadir}/bash-completion/completions/brix-*
%{_datadir}/zsh/site-functions/_brix-client-compat
%{_libexecdir}/brix/alma-platform-warning

%changelog
* Sun Oct 04 2026 BriX-Cache maintainers - 2.0.0-1
- Add the client-only EL8 compatibility package using EPEL OpenSSL 3.
