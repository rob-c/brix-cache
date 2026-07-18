# RPM packaging

This directory contains RPM packaging for AlmaLinux 9 / EPEL 9 and
AlmaLinux 10 / EPEL 10 style nginx dynamic module builds.

A single spec (`nginx-mod-brix-cache.spec`) builds **seven** packages from one
source tree:

| Package | Arch | Contents |
|---|---|---|
| `nginx-mod-brix-cache` | arch | The combined BriX nginx dynamic module, the xrdhttp filter module, and the `mod-xrootd.conf` loader |
| `brix-cache-client` | arch | The clean-room native CLI tools (`xrdcp`, `xrdfs`, `xrd`, `xrdcksum`, `xrdstorascan`, …), the `libbrixposix_preload.so` POSIX shim, completions, and their man pages; `Recommends:` the two FUSE packages below so a default install keeps the full surface |
| `brix-xrootdfs-fuse` | arch | The `xrootdfs` FUSE mount (async + `--legacy` drivers in one binary): a `root://` endpoint as a local POSIX filesystem — deployable standalone on mount-only nodes |
| `brix-cvmfs-fuse` | arch | `brixMount`, the native CVMFS FUSE client (CAS verification, writable `cvmfs-rw` overlay, plus the `brixMount xrootdfs` front-end) — deployable standalone on cache/mount tiers |
| `brix-cache-tests` | noarch | The full pytest integration/conformance suite under `%{_datadir}/brix`, pulling in the python packages it needs |
| `brix-tools` | arch | XrdCeph/CephFS operator tools from `client/apps/ceph/`: the compiled C++ migration pair (`xrdceph_striper_migrate`, `xrdceph_cephfs_to_striper`), their Python variants (`*.py` + `pymigrate` under `%{_libexecdir}/brix`), and the offline rescue utilities (`xrdrados_rescue`, `xrdcephfs_rescue`, `xrdceph_migrate`) |
| `nginx-mod-brix-cache-selinux` | noarch | The `brix` targeted-policy SELinux module (`packaging/selinux/brix.{te,fc,if}`) for hardened (enforcing) hosts; pulled in automatically by the module package when `selinux-policy-targeted` is installed |

The module package builds against the distribution nginx source exposed by
`nginx-mod-devel`, installs the module `.so` files under the nginx module
directory, and drops a loader snippet into the nginx module configuration
directory.  The client tools are built by the in-tree `client/Makefile` (no
`libXrdCl` / `libXrdSec` — clean-room, asserted with `ldd`).

## Runtime dependencies

Most shared-library dependencies are auto-detected from the ELF link records by
`rpmbuild`'s `find-requires` (openssl-libs, krb5-libs, libcom_err, zlib,
libxml2, jansson, libcurl, libxcrypt, fuse3-libs, …).  The following cannot be
auto-detected and are therefore declared explicitly.

**`nginx-mod-brix-cache` (modules):**

| Package | Why explicit |
|---|---|
| `nginx-mod-stream` | Provides the `stream {}` core the modules load into |
| `libvomsapi.so.1()(64bit)` | Loaded at runtime via `dlopen()` for VOMS VO/FQAN ACL enforcement; no ELF dependency. Required by soname — on EL9 the provider is the EPEL `voms` package (the old `voms-libs` package name does not exist there) |
| `librados2`, `libradosstriper1` | The compiled-in Ceph storage backends link these; the sonames are auto-detected, the package names are stated explicitly as a contract |
| `curl` | The `curl(1)` binary is `fork/exec`'d by the WebDAV HTTP-TPC handler; not a library dependency |
| `openssl-libs` | Directly linked (`-lssl -lcrypto`) and auto-detected, but listed explicitly for clarity |

**`brix-xrootdfs-fuse` / `brix-cvmfs-fuse` (FUSE mounts):**

| Package | Why explicit |
|---|---|
| `fuse3` | `xrootdfs` and `brixMount` `fork/exec` the `fusermount3(1)` helper at mount/unmount; the libraries (`libfuse3`, OpenSSL, krb5, sqlite, …) are auto-detected from the ELF |

Both carry `Conflicts: brix-cache-client < 1.1.1-23`: the binaries moved out of
`brix-cache-client` in that release, so the old client must upgrade in the same
transaction (dnf resolves this automatically from one repo).

**`brix-tools` (operator tools):**

The compiled C/C++ tools link directly to Ceph's native libraries:
`librados`, `libcephfs`, and `libradosstriper`.  `rpmbuild` auto-detects the
runtime shared-library requirements from the ELF records; the matching
development packages are build-time requirements.  The Python migration
entrypoints are shipped as weakly coupled operator variants and therefore use
`Recommends: python3-rados` and `Recommends: python3-cephfs` instead of hard
runtime dependencies.  `librados2`, `libradosstriper1`, and `libcephfs2` are
stated explicitly as hard requirements alongside the auto-detected sonames.

**`brix-cache-tests` (suite, noarch):** depends on the system under test
(`nginx-mod-brix-cache`, `brix-cache-client`, `nginx`) plus the python packages
the suite drives pytest with: `python3-pytest`, `python3-pytest-timeout`,
`python3-pytest-xdist`, `python3-cryptography`, `python3-requests`,
`python3-urllib3`.  `python3-xrootd` (the official XRootD python bindings, from
EPEL/WLCG) is a *weak* dependency (`Recommends`) — it is only needed by the
cross-backend / reference-daemon comparison tests, so the package still installs
where the WLCG repo is not enabled.

The build additionally needs `fuse3-devel`, `sqlite-devel`, `libcom_err-devel`,
and `pkgconfig` at build time for the client tools (`pkg-config` gates the
FUSE/krb5 features; `sqlite-devel` backs the CVMFS catalog reader in
`brixMount`; `libcom_err-devel` resolves the `-lcom_err` pulled in by
`pkg-config --libs krb5`).  The compiled Ceph migration tools additionally
need `gcc-c++`, `librados-devel`, `libradospp-devel`,
`libradosstriper-devel`, and `libcephfs-devel`; enable your site Ceph/RHCS/SIG
repository before building if those packages are not in the base distro repos.

### Target-host repositories (EL9)

Two dependencies come from add-on repositories; enable them once before
installing the RPMs:

```bash
# libvomsapi.so.1 (the EPEL `voms` package):
dnf install -y epel-release

# libradosstriper1 / libcephfs2 (EPEL carries only librados2; the striper and
# cephfs client libraries come from the CentOS Storage SIG Ceph repo, enabled
# by a release package in the distro extras repo — pick the release matching
# the builder's BRIX_CEPH_RELEASE, default reef):
dnf install -y centos-release-ceph-reef

dnf install -y ./nginx-mod-brix-cache-*.rpm ./brix-tools-*.rpm
```

The WLCG repository's `voms-libs` also satisfies the VOMS dependency (it
provides the same `libvomsapi.so.1` soname) for sites that already run it.

## SELinux (hardened / enforcing hosts)

nginx — and therefore every BriX module — runs confined as `httpd_t` under
the targeted policy.  The `nginx-mod-brix-cache-selinux` subpackage
(installed automatically alongside the module package whenever
`selinux-policy-targeted` is present) loads the `brix` policy module, which
extends `httpd_t` with exactly the BriX data plane.  No `setenforce 0`, no
`httpd_can_network_connect`/`httpd_unified` booleans, no `audit2allow`
one-offs.

What the module provides:

| Surface | Label / rule |
|---|---|
| root:// listeners + cache/stage-tier origins + native TPC (tcp 1094, 1095) | `brix_port_t`, `httpd_t` may `name_bind` + `name_connect` |
| S3 listener (tcp 9001) | `brix_port_t` (local override — the stock policy assigns 9001 to `tor_port_t`) |
| Metrics listener (tcp 9100) | `brix_port_t` (local override of `hplip_port_t`) |
| WebDAV listeners 443 / 8443 | already `http_port_t` in the stock policy |
| Export root + stage dir `/var/lib/brix-cache` | `brix_var_lib_t` (full manage + mmap) |
| Cache tree `/var/cache/brix-cache` | `brix_cache_t` |
| JWKS / authdb `/etc/brix-cache` | `httpd_config_t` |
| Grid credentials `/etc/grid-security` (hostcert/key, IGTF CAs, CRLs, vomsdir) | `cert_t` — replaces the manual `semanage fcontext` remedy previously documented |
| Impersonation broker + multiuser ownership | `setuid setgid` + `setcap`, `chown fowner fsetid dac_override dac_read_search` on `httpd_t` |
| WebDAV HTTP-TPC (`fork`/`exec` of `curl`) and https origins | `corecmd_exec_bin` + connect to `http_port_t` |
| Ceph backends (`sd_ceph` / `sd_cephfs_ro`) | connect to `ceph_port_t` (mon 3300/6789, OSD/MDS 6800–7300) |
| Kerberos auth | connect to the kerberos ports |

Site-specific deviations from the defaults:

```bash
# Export root or stage dir outside /var/lib/brix-cache:
semanage fcontext -a -t brix_var_lib_t '/mnt/fastcache/xrd-stage(/.*)?'
restorecon -Rv /mnt/fastcache/xrd-stage

# Additional listener ports (e.g. a second root:// endpoint, CMS listener):
semanage port -a -t brix_port_t -p tcp 1096
```

The io_uring backends (`brix_io_uring on`, strictly opt-in and OFF by
default) need two extra rules that are deliberately not in the shipped module
because the `io_uring` object class does not exist in the EL8 base policy —
opt-in sites load them as a small local module (see the note at the bottom of
`packaging/selinux/brix.te`).

`rpmbuild --without selinux` skips the policy build and subpackage entirely.

### Verifying the shipped policy

`brix-cache-tests` ships an SELinux verification suite. As root, on the host
where the RPMs are installed:

```bash
dnf install -y brix-cache-tests libselinux-utils policycoreutils-python-utils setools-console
cd /usr/share/brix && python3 -m pytest tests/test_selinux_rpm.py -v
```

It asserts the `brix` module is loaded (priority 200, enabled), the
file-context database and the actual on-disk labels match `brix.fc`
(canonical + legacy trees), the `%post` port labels (1094/1095/9001/9100 →
`brix_port_t`) are present, and the loaded policy contains the `httpd_t`
allow rules from `brix.te` (port bind/connect, data-plane manage+mmap,
impersonation-broker capabilities, grid-credential reads, outbound
http/kerberos connects, `curl` exec).  The suite self-skips on hosts without
SELinux, root, or the policy module, so it is safe to run as part of the full
installed test-suite.

## Local build (host)

Install the local build prerequisites:

```bash
sudo dnf install -y epel-release
sudo dnf install -y gcc gcc-c++ make pkgconfig rpm-build rpmdevtools redhat-rpm-config \
    nginx-mod-devel openssl-devel pcre2-devel zlib-devel libxml2-devel \
    jansson-devel libcurl-devel krb5-devel libcom_err-devel libxcrypt-devel \
    fuse3-devel sqlite-devel librados-devel libradospp-devel \
    libradosstriper-devel libcephfs-devel selinux-policy-devel
```

Build from the current checkout:

```bash
packaging/rpm/build-rpm.sh
```

The helper writes build products under `.rpmbuild/` in the repository root.
The version defaults to the one baked into the source
(`BRIX_SERVER_VERSION_BARE` in `src/core/ident.h`); pass one explicitly to
override it:

```bash
packaging/rpm/build-rpm.sh 1.2.3
```

## Container-based build (AlmaLinux 9 or 10)

`build-rpm-container.sh` wraps the Docker/Podman build so the host does not
need any RPM build toolchain installed.

```bash
# AlmaLinux 9 (default), version from src/core/ident.h:
packaging/rpm/build-rpm-container.sh

# AlmaLinux 10, explicit version override, output to /tmp/rpms:
packaging/rpm/build-rpm-container.sh -d alma10 -v 1.2.3 -o /tmp/rpms

# Options:
#   -v VERSION   Version embedded in the RPM (default: derived from
#                BRIX_SERVER_VERSION_BARE in src/core/ident.h)
#   -d DISTRO    alma9 or alma10 (default: alma9)
#   -o OUTDIR    Directory for built RPMs (default: dist/)
#   -e ENGINE    docker or podman (auto-detected)
```

The corresponding Dockerfiles are:

| File | Target |
|---|---|
| `Dockerfile.alma8` | AlmaLinux 8 / EPEL 8 |
| `Dockerfile.alma9` | AlmaLinux 9 / EPEL 9 |
| `Dockerfile.alma10` | AlmaLinux 10 / EPEL 10 |
| `Dockerfile.alma11` | AlmaLinux 11 / EPEL 11 (speculative) |

These Dockerfiles install the Ceph development packages required by
`brix-tools`.  If your target Alma image does not expose
`librados-devel`, `libradospp-devel`, `libradosstriper-devel`, and
`libcephfs-devel` from its enabled repos, add your site Ceph/RHCS/SIG repo to
the Dockerfile before the `dnf install` step.

### AlmaLinux 8 notes

- Based on RHEL 8 (EL8).  GCC 8 toolchain by default.
- `nginx-mod-devel` is available via EPEL 8.  If absent, uncomment the nginx
  stable upstream repo block in `Dockerfile.alma8`.
- The built RPM carries the `.el8` dist tag.
- Enable the WLCG EL8 repository for `voms-libs` on the installation target:
  `dnf install -y https://linuxsoft.cern.ch/wlcg/el8/x86_64/wlcg-repo-*.noarch.rpm`

### AlmaLinux 10 notes

- Based on RHEL 10 (CS1); uses GCC 14 by default.
- `nginx-mod-devel` should be available via EPEL 10.  If not yet published,
  uncomment the nginx stable upstream repo block in `Dockerfile.alma10`.
- The built RPM carries the `.el10` dist tag.
- The `voms-libs` runtime dependency requires the WLCG EL10 repository on
  the installation target.  If the WLCG EL10 repo is not yet available, test
  against the EL9 WLCG package under compatibility — verify before production.

### AlmaLinux 11 notes

- AlmaLinux 11 / RHEL 11 is pre-release; the `almalinux:11` container image
  and EPEL 11 may not yet be publicly available.
- If `nginx-mod-devel` is absent from EPEL 11, uncomment the nginx stable
  upstream repo block in `Dockerfile.alma11`.
- The built RPM carries the `.el11` dist tag.
- The WLCG EL11 repository for `voms-libs` does not yet exist.  Monitor
  https://linuxsoft.cern.ch/wlcg/ for availability.

## Release build (mock)

For a Fedora/EPEL-style build, create a matching upstream tag (`v` + BRIX_SERVER_VERSION_BARE from `src/core/ident.h`, e.g. `v1.1.1`),
then build `packaging/rpm/nginx-mod-brix-cache.spec` in `mock`:

```bash
mock -r epel-9-x86_64 --buildsrpm \
    --spec packaging/rpm/nginx-mod-brix-cache.spec \
    --sources .
mock -r epel-9-x86_64 --rebuild result/nginx-mod-brix-cache-*.src.rpm
```

The spec expects the release source archive to unpack as
`brix-<version>/`.
