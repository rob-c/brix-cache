%global upstream_name nginx-xrootd
%global upstream_version %{?version_override}%{!?version_override:0.1.0}

Name:           nginx-mod-xrootd
Version:        %{upstream_version}
Release:        1%{?dist}
Summary:        XRootD, WebDAV, S3, CMS, and metrics dynamic modules for nginx

License:        AGPL-3.0-only
URL:            https://github.com/HEP-x/nginx-xrootd
Source0:        %{url}/archive/refs/tags/v%{version}/%{upstream_name}-%{version}.tar.gz

BuildRequires:  gcc
BuildRequires:  make
BuildRequires:  nginx-mod-devel
BuildRequires:  openssl-devel
BuildRequires:  pcre2-devel
BuildRequires:  zlib-devel
BuildRequires:  libxml2-devel
BuildRequires:  jansson-devel
BuildRequires:  libcurl-devel
BuildRequires:  krb5-devel
BuildRequires:  libxcrypt-devel

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

%prep
%autosetup -n %{upstream_name}-%{version}

%build
%nginx_modconfigure --with-threads --with-stream=dynamic --with-stream_ssl_module --with-http_ssl_module --with-http_dav_module
%nginx_modbuild

%install
install -Dpm0755 %{_vpath_builddir}/ngx_stream_xrootd_module.so \
    %{buildroot}%{nginx_moddir}/ngx_stream_xrootd_module.so
install -Dpm0755 %{_vpath_builddir}/ngx_stream_xrootd_cms_srv_module.so \
    %{buildroot}%{nginx_moddir}/ngx_stream_xrootd_cms_srv_module.so
install -Dpm0755 %{_vpath_builddir}/ngx_http_xrootd_metrics_module.so \
    %{buildroot}%{nginx_moddir}/ngx_http_xrootd_metrics_module.so
install -Dpm0755 %{_vpath_builddir}/ngx_http_xrootd_srr_module.so \
    %{buildroot}%{nginx_moddir}/ngx_http_xrootd_srr_module.so
install -Dpm0755 %{_vpath_builddir}/ngx_http_xrootd_webdav_module.so \
    %{buildroot}%{nginx_moddir}/ngx_http_xrootd_webdav_module.so
install -Dpm0755 %{_vpath_builddir}/ngx_http_xrootd_xrdhttp_filter_module.so \
    %{buildroot}%{nginx_moddir}/ngx_http_xrootd_xrdhttp_filter_module.so
install -Dpm0755 %{_vpath_builddir}/ngx_http_xrootd_s3_module.so \
    %{buildroot}%{nginx_moddir}/ngx_http_xrootd_s3_module.so
install -Dpm0755 %{_vpath_builddir}/ngx_http_xrootd_dashboard_module.so \
    %{buildroot}%{nginx_moddir}/ngx_http_xrootd_dashboard_module.so

mkdir -p %{buildroot}%{nginx_modconfdir}
{
    echo 'load_module "%{nginx_moddir}/ngx_stream_xrootd_module.so";'
    echo 'load_module "%{nginx_moddir}/ngx_http_xrootd_metrics_module.so";'
    echo 'load_module "%{nginx_moddir}/ngx_http_xrootd_srr_module.so";'
    echo 'load_module "%{nginx_moddir}/ngx_http_xrootd_webdav_module.so";'
    echo 'load_module "%{nginx_moddir}/ngx_http_xrootd_xrdhttp_filter_module.so";'
    echo 'load_module "%{nginx_moddir}/ngx_http_xrootd_s3_module.so";'
    echo 'load_module "%{nginx_moddir}/ngx_http_xrootd_dashboard_module.so";'
    echo 'load_module "%{nginx_moddir}/ngx_stream_xrootd_cms_srv_module.so";'
} > %{buildroot}%{nginx_modconfdir}/mod-xrootd.conf

%files
%license LICENSE
%doc README.md docs/
%{nginx_moddir}/ngx_stream_xrootd_module.so
%{nginx_moddir}/ngx_stream_xrootd_cms_srv_module.so
%{nginx_moddir}/ngx_http_xrootd_metrics_module.so
%{nginx_moddir}/ngx_http_xrootd_srr_module.so
%{nginx_moddir}/ngx_http_xrootd_webdav_module.so
%{nginx_moddir}/ngx_http_xrootd_xrdhttp_filter_module.so
%{nginx_moddir}/ngx_http_xrootd_s3_module.so
%{nginx_moddir}/ngx_http_xrootd_dashboard_module.so
%{nginx_modconfdir}/mod-xrootd.conf

%changelog
* Sun Jun 14 2026 nginx-xrootd maintainers <maintainers@example.com> - 0.1.0-2
- Add SRR, XrdHttp filter, and dashboard modules
- Add libcurl, krb5, and libxcrypt build dependencies
- Update module loading order in mod-xrootd.conf

* Tue Apr 21 2026 nginx-xrootd maintainers <maintainers@example.com> - 0.1.0-1
- Initial nginx dynamic module package
