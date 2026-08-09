# Debian/Ubuntu packaging

This directory contains .deb packaging for Ubuntu 22.04 (jammy) and
Ubuntu 24.04 (noble) — the deb counterpart of `packaging/rpm/` (AlmaLinux).
One debhelper source package (`debian/`) builds **ten** binary packages from
one source tree, mirroring the RPM subpackage split:

| Package | Arch | Contents |
|---|---|---|
| `nginx-mod-brix-cache` | any | The combined BriX nginx dynamic module, the xrdhttp filter module, the modules-available loader snippet, example config, logrotate rule, Grafana dashboard + Prometheus alerts |
| `brix-cache-client` | any | The clean-room native CLI tools (`xrdcp`, `xrdfs`, `xrd`, `xrdcksum`, `xrdstorascan`, …), the `libbrixposix_preload.so` POSIX shim, completions, man pages; `Recommends:` the two FUSE packages |
| `brix-cache-client-compat` | any | The SAME tools under a `brix-` prefix (`brix-xrdcp`, …), co-installable with the official xrootd-client tools |
| `brix-xrootdfs-fuse` | any | The `xrootdfs` FUSE mount (async + `--legacy` drivers in one binary) |
| `brix-cvmfs-fuse` | any | `brixMount`, the native CVMFS FUSE client (+ the `brixcvmfs` alias) |
| `brix-cvmfs-automount` | all | `/cvmfs` automount stack: `brixMount autofs` umbrella service, `mount.cvmfs`, `/etc/auto.cvmfs` program map, `brixcvmfs@.service` template; `Conflicts: cvmfs` |
| `brix-cvmfs-config` | all | Default CVMFS domain config + master public keys; `Provides: cvmfs-config` |
| `brix-cache-tests` | all | The full pytest integration/conformance suite under `/usr/share/brix` |
| `brix-tools` | any | XrdCeph/CephFS migration + rescue operator tools (compiled C++ pair, Python variants, rescue utilities) |
| `brix-tools-compat` | any | The compiled Ceph operator tools under a `brix-` prefix |

There is **no SELinux subpackage**: Ubuntu confines services with AppArmor,
not SELinux.  The RPM's `-selinux` policy module has no deb counterpart.

## Building

The normal path is the container build (host needs only docker or podman):

```bash
# Ubuntu 24.04 against nginx.org stable (default):
packaging/deb/build-deb-container.sh

# Ubuntu 24.04 against the Ubuntu-archive nginx (1.24.0 on noble):
packaging/deb/build-deb-container.sh -f distro

# Ubuntu 22.04:
packaging/deb/build-deb-container.sh -d ubuntu22
```

Built packages appear in `dist/` (override with `-o`).  Ubuntu-style
`.ddeb` debug-symbol packages are produced alongside the `.deb`s.

Note: the deb filenames carry the codename (`~noble1` / `~jammy1`) but NOT
the nginx flavor, so building both flavors of one release into the same
outdir overwrites the module package — pass a distinct `-o` per flavor
(e.g. `-o dist/noble-distro`) when you need both.

Ubuntu 22.04 caveat: jammy's archive Ceph is quincy (17.2), whose librados
lacks `rados_read_op_stat2` (needed by the cephfs-rescue core), so
`Dockerfile.ubuntu22` takes the Ceph dev packages from the upstream
`download.ceph.com` apt repo (`--build-arg BRIX_CEPH_RELEASE=reef`, same
knob as the EL builders' Storage SIG repo) — and jammy *hosts* likewise
need that repo for the matching `librados2`/`libcephfs2` at install time.
Noble's archive Ceph (squid, 19.2) is new enough as-is.  Similarly,
io_uring has liburing floors that jammy's 2.1 misses: the nginx-module
disk-I/O backend needs >= 2.2 (`io_uring_sqe_set_data64`) and the client
engine needs >= 2.4 (buf-ring helpers), so on jammy both compile to their
inert stubs (thread-pool / epoll+pread paths) while noble (2.5) keeps them
enabled.

To build natively on a matching Ubuntu host instead, install the
Build-Depends (`sudo apt-get build-dep ./packaging/deb`, or read
`debian/control`) plus `debhelper`/`dpkg-dev`, then:

```bash
packaging/deb/build-deb.sh [-f org|distro] [-n <nginx-version>] [-o dist/]
```

The package version derives from `BRIX_SERVER_VERSION_BARE` in
`src/core/ident.h` (the same single source of truth the RPM build uses) and
is suffixed with the target codename, e.g. `1.4.0-1~noble1`.

## The nginx version lock (read this before deploying)

nginx **refuses to dlopen a dynamic module built against any other nginx
version** — the loader checks the exact version at startup.  The tooling
therefore builds the module against the nginx source of a specific version
and pins the package's `Depends:` to it (e.g. `nginx (>= 1.30.4),
nginx (<< 1.30.4.1~)`).  When the target hosts pick up a new nginx version,
rebuild the module package; the client/FUSE/tools packages are not
version-locked.

Two target flavors select which nginx the module package tracks (`-f`):

- **`org`** (default) — the [nginx.org packages for Ubuntu]
  (https://nginx.org/en/linux_packages.html), stable branch.  Mirrors the
  RPM builders, which take `nginx-mod-devel` from the nginx.org EL repo.
  Stream support is compiled into the nginx.org binary, so the module
  package depends only on `nginx`.  The builder container adds the
  nginx.org apt repo and resolves the current stable version from it;
  `build-deb.sh` falls back to a pinned version when the repo is absent
  (see `org_nginx_fallback` in the script).
- **`distro`** — the Ubuntu-archive nginx (1.24.0 on noble, 1.18.0 on
  jammy).  Adds `libnginx-mod-stream` to `Depends:` (the stream core is a
  separate dynamic module there, and `50-mod-stream.conf` must load before
  our `60-mod-brix-cache.conf` — the names are chosen so the
  `modules-enabled` include glob orders them correctly).

Both nginx flavors are built `--with-compat` (verified: Ubuntu noble's
`nginx -V` shows `--with-compat`, nginx.org always builds with it), so one
module binary per nginx *version* serves either package source; the flavor
only changes the generated `Depends:` line.  The module is compiled from
the vanilla nginx.org source tarball of the matching version — Ubuntu's
packaging patches do not change the module ABI.

## Module activation

- **Ubuntu-archive nginx**: postinst symlinks
  `/usr/share/nginx/modules-available/60-mod-brix-cache.conf` into
  `/etc/nginx/modules-enabled/` (the `libnginx-mod-*` convention); the
  snippet loads the combined stream module first so its symbols back the
  http filter via `RTLD_GLOBAL`.  Removal deletes the symlink.
- **nginx.org nginx**: there is no `modules-enabled` include; postinst
  prints the two `load_module` lines to add at the top (main context) of
  `/etc/nginx/nginx.conf`.

After activation: `nginx -t && systemctl reload nginx`.

## Runtime dependencies

`dpkg-shlibdeps` auto-detects the linked libraries (openssl, krb5, jansson,
libcurl, libfuse3, sqlite, zstd, lz4, liburing, Ceph sonames, …).  Declared
explicitly, mirroring the RPM spec, because they are invisible to ELF
analysis:

| Package | Explicit dep | Why |
|---|---|---|
| `nginx-mod-brix-cache` | `nginx` (version-pinned range) | exact-version dlopen check; substvar `brix:nginx-abi` generated by `debian/rules` from the nginx source built against |
| `nginx-mod-brix-cache` | `libnginx-mod-stream` (distro flavor only) | provides the `stream {}` core the module loads into |
| `nginx-mod-brix-cache` | `libvomsapi1t64 \| libvomsapi1v5 \| libvomsapi1` | `dlopen("libvomsapi.so.1")` for VOMS VO/FQAN ACLs — one soname, three Ubuntu package spellings (t64 on noble, v5 on jammy, the bare name upstream/Debian) |
| `nginx-mod-brix-cache` | `curl` | `curl(1)` kept for site-script compatibility |
| `nginx-mod-brix-cache`, `brix-tools`, `*-compat` | `librados2`, `libradosstriper1`, `libcephfs2` | stated contract for the compiled-in Ceph backends/tools (sonames are also auto-detected) |
| `brix-xrootdfs-fuse`, `brix-cvmfs-fuse`, `brix-cvmfs-automount` | `fuse3` | `fusermount3(1)` is fork/exec'd at mount/unmount |

Divergences from the RPM, forced by deb semantics:

- `brix-env(7)` ships **only** in `brix-cache-client` (rpm lets two packages
  own byte-identical copies; dpkg does not).  `brix-cache-client-compat`
  carries `Suggests: brix-cache-client` and a note in its description.
- The upgrade/rename shims (`Obsoletes: nginx-mod-xrootd`,
  `Conflicts: brix-cache-client < 1.1.1-23`) are dropped — no pre-rebrand
  debs ever shipped.  The `Provides:` aliases are kept.
- The tests package's `python3-xrootd` is `Suggests` (not in the Ubuntu
  archive) and the SELinux-verification recommendations are dropped.
- `mount.cvmfs` installs to `/usr/sbin` (Debian forbids shipping in the
  aliased `/sbin`); `mount -t cvmfs` still finds it via merged-usr.

`brixcvmfs-automount.service` is installed **disabled** (parity with the
RPM's preset-driven `%systemd_post`); enable with
`systemctl enable --now brixcvmfs-automount`.  On jammy, debhelper 13.6
does not generate maintscript snippets for units under
`/usr/lib/systemd/system` — run `systemctl daemon-reload` once after
install there.

The `brix-broker` system account (impersonation broker) is created by the
module package's postinst, and `/var/lib/brix-cache` is chowned to the
nginx worker user — `nginx` when that account exists (nginx.org packages),
else `www-data` (Ubuntu-archive packages) — unless a `dpkg-statoverride`
says otherwise.

## Optional codecs

zstd, lz4 and io_uring are ON (Build-Depends carry the dev packages;
`BRIX_ENABLE_IO_URING=1` is exported by `debian/rules`), matching the RPM
defaults.  lzma/brotli/bzip2 are OFF; `./configure` probes via pkg-config,
so to enable one add its dev package (`liblzma-dev`, `libbrotli-dev`,
`libbz2-dev`) to `debian/control` Build-Depends (and the builder
Dockerfile) — it then compiles in and `dpkg-shlibdeps` picks up the runtime
dependency automatically.

## Install

```bash
sudo apt install ./dist/nginx-mod-brix-cache_1.4.0-1~noble1_amd64.deb \
                 ./dist/brix-cache-client_1.4.0-1~noble1_amd64.deb
# mount/cache tiers:
sudo apt install ./dist/brix-xrootdfs-fuse_*.deb ./dist/brix-cvmfs-fuse_*.deb
# /cvmfs automount (conflicts with the stock cvmfs package):
sudo apt install ./dist/brix-cvmfs-automount_*.deb ./dist/brix-cvmfs-config_*.deb
sudo systemctl enable --now brixcvmfs-automount
```

Then follow `docs/03-configuration/rpm-package-build.md` from §2 (PKI,
data directory, server config) — the configuration steps are identical on
Ubuntu; only the package-manager commands differ.
