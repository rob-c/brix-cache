# Debian/Ubuntu Package Build

Building and distributing BriX-Cache as .deb packages for Ubuntu servers
(22.04 jammy, 24.04 noble) — the deb counterpart of
[RPM Package Build](rpm-package-build.md).  The packaging lives in
`packaging/deb/`; its [README](../../packaging/deb/README.md) is the full
reference (package split, nginx version lock, runtime dependencies,
divergences from the RPM).

## 1. Build the packages

The build runs inside a container, so the host needs only docker or podman:

```bash
# Ubuntu 24.04, against nginx.org stable (default — mirrors the RPM
# builders, which use the nginx.org EL repo):
packaging/deb/build-deb-container.sh

# Ubuntu 24.04, against the Ubuntu-archive nginx (1.24.0 on noble):
packaging/deb/build-deb-container.sh -f distro

# Ubuntu 22.04:
packaging/deb/build-deb-container.sh -d ubuntu22
```

Built packages appear in `dist/`:

```
dist/
  nginx-mod-brix-cache_1.4.0-1~noble1_amd64.deb
  brix-cache-client_1.4.0-1~noble1_amd64.deb
  brix-cache-client-compat_1.4.0-1~noble1_amd64.deb
  brix-xrootdfs-fuse_1.4.0-1~noble1_amd64.deb
  brix-cvmfs-fuse_1.4.0-1~noble1_amd64.deb
  brix-cvmfs-automount_1.4.0-1~noble1_all.deb
  brix-cvmfs-config_1.4.0-1~noble1_all.deb
  brix-cache-tests_1.4.0-1~noble1_all.deb
  brix-tools_1.4.0-1~noble1_amd64.deb
  brix-tools-compat_1.4.0-1~noble1_amd64.deb
```

**The module package is locked to the nginx version it was built against**
(nginx refuses dynamic modules from any other version at startup); rebuild
`nginx-mod-brix-cache` whenever the fleet's nginx updates.  The client,
FUSE, and tools packages are not version-locked.

## 2. Install

```bash
# nginx.org flavor: add the nginx.org apt repo first
# (https://nginx.org/en/linux_packages.html#Ubuntu), then:
sudo apt install ./dist/nginx-mod-brix-cache_*.deb ./dist/brix-cache-client_*.deb
```

On Ubuntu-archive nginx the module is activated automatically via
`/etc/nginx/modules-enabled/60-mod-brix-cache.conf`; on nginx.org installs
add the two `load_module` lines the postinst prints to the top of
`/etc/nginx/nginx.conf`.  Verify:

```bash
ls /usr/lib/nginx/modules/ngx_stream_brix_module.so \
   /usr/lib/nginx/modules/ngx_http_brix_xrdhttp_filter_module.so
sudo nginx -t
```

## 3. Configure

Follow [RPM Package Build](rpm-package-build.md) from §2 (PKI, data
directory, server configuration, verification with `xrdcp`/`xrdfs`) — the
steps are identical on Ubuntu, with two substitutions: package commands use
`apt` instead of `dnf`, and the nginx worker user is `www-data` on
Ubuntu-archive nginx (`nginx` on nginx.org installs) wherever the guide
chowns files to `nginx:nginx`.  There is no SELinux section on Ubuntu
(AppArmor hosts need no policy module for the standard paths).
