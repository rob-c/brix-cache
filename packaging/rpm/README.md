# RPM packaging

This directory contains RPM packaging for AlmaLinux 9 / EPEL 9 and
AlmaLinux 10 / EPEL 10 style nginx dynamic module builds.

The package builds against the distribution nginx source exposed by
`nginx-mod-devel`, installs the module `.so` files under the nginx module
directory, and drops a loader snippet into the nginx module configuration
directory.

## Runtime dependencies

The following runtime requirements are declared in the spec but cannot be
auto-detected by `rpmbuild`'s `find-requires` script:

| Package | Why explicit |
|---|---|
| `voms-libs` | Loaded at runtime via `dlopen(libvomsapi.so.1)` for VOMS VO/FQAN ACL enforcement; no ELF dependency |
| `curl` | The `curl(1)` binary is `fork/exec`'d by the WebDAV HTTP-TPC handler; not a library dependency |
| `openssl-libs` | Directly linked (`-lssl -lcrypto`) and auto-detected, but listed explicitly for clarity |

`voms-libs` comes from the WLCG repository.  On the target host, enable it
before installing this RPM:

```bash
# AlmaLinux 9 / EL9
dnf install -y https://linuxsoft.cern.ch/wlcg/el9/x86_64/wlcg-repo-*.noarch.rpm

# AlmaLinux 10 / EL10 (once the WLCG EL10 repo is published)
dnf install -y https://linuxsoft.cern.ch/wlcg/el10/x86_64/wlcg-repo-*.noarch.rpm
```

## Local build (host)

Install the local build prerequisites:

```bash
sudo dnf install -y epel-release
sudo dnf install -y gcc make rpm-build rpmdevtools redhat-rpm-config \
    nginx-mod-devel openssl-devel pcre2-devel zlib-devel
```

Build from the current checkout:

```bash
packaging/rpm/build-rpm.sh
```

The helper writes build products under `.rpmbuild/` in the repository root.
Pass a version if you want the generated source tarball and RPM metadata to use
something other than `0.1.0`:

```bash
packaging/rpm/build-rpm.sh 0.1.0
```

## Container-based build (AlmaLinux 9 or 10)

`build-rpm-container.sh` wraps the Docker/Podman build so the host does not
need any RPM build toolchain installed.

```bash
# AlmaLinux 9 (default), version 0.1.0:
packaging/rpm/build-rpm-container.sh

# AlmaLinux 10, version 1.2.3, output to /tmp/rpms:
packaging/rpm/build-rpm-container.sh -d alma10 -v 1.2.3 -o /tmp/rpms

# Options:
#   -v VERSION   Version embedded in the RPM (default: 0.1.0)
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

For a Fedora/EPEL-style build, create a matching upstream tag such as `v0.1.0`,
then build `packaging/rpm/nginx-mod-xrootd.spec` in `mock`:

```bash
mock -r epel-9-x86_64 --buildsrpm \
    --spec packaging/rpm/nginx-mod-xrootd.spec \
    --sources .
mock -r epel-9-x86_64 --rebuild result/nginx-mod-xrootd-*.src.rpm
```

The spec expects the release source archive to unpack as
`nginx-xrootd-<version>/`.
