# BUILD.md — Local RPM build of BriX-Cache

Log of building the `nginx-mod-brix-cache` RPM (and its sibling packages) locally
on this host, against the host's distribution nginx via `nginx-mod-devel`.

- **Host:** AlmaLinux 9.8 (`platform:el9`), x86_64
- **Target nginx:** `nginx-1.20.1-28.el9_8.4.alma.1` (distro), built against the
  matching `nginx-mod-devel` of the same version — the module is ABI-locked to it.
- **Spec:** `packaging/rpm/nginx-mod-brix-cache.spec` (current Version 2.0.0, Release 1;
  the earlier build recorded in §2 used Version 0.1.0, Release 8)
- **Build driver:** `packaging/rpm/build-rpm.sh`

The spec builds **four** packages from one source tree:

| Package | Arch | Contents |
|---|---|---|
| `nginx-mod-brix-cache` | x86_64 | Combined BriX nginx dynamic module (`ngx_stream_brix_module.so`) + xrdhttp filter module + `mod-xrootd.conf` loader |
| `brix-cache-client` | x86_64 | Clean-room native CLI tools (`xrdcp`, `xrdfs`, `xrd`, …), FUSE mounts, POSIX preload shim, man pages |
| `brix-cache-tests` | noarch | Full pytest suite under `%{_datadir}/nginx-xrootd` |
| `brix-tools` | x86_64 | XrdCeph/CephFS migration + rescue operator tools |

---

## 1. Prerequisites installed via dnf

All package installs done with `sudo dnf install -y`. Repos already enabled on
this host: **BaseOS, AppStream, CRB, EPEL, centos-ceph-reef, WLCG**.

### 1a. Build dependencies (compile the module + tools)

Already present before we started: `gcc`, `make`, `openssl-devel`,
`libxcrypt-devel`, `pkgconfig` (via `pkgconf-pkg-config`).

Installed:

```bash
sudo dnf install -y \
  gcc-c++ pkgconfig pcre2-devel zlib-devel libxml2-devel jansson-devel \
  libcurl-devel krb5-devel libcom_err-devel sqlite-devel fuse3-devel libseccomp-devel \
  brotli-devel xz-devel bzip2-devel lz4-devel \
  librados-devel libradospp-devel libradosstriper-devel libcephfs-devel \
  libzstd-devel
```

Notes:
- `jansson-devel` comes from **CRB**; the Ceph `-devel` stack from **centos-ceph-reef**.
- These match `BuildRequires:` in the spec and the tested `Dockerfile.alma9`.
- `libzstd-devel` and `brotli-devel` are required: the module always builds
  with `BRIX_HAVE_ZSTD=1` and `BRIX_HAVE_BROTLI=1`; `./configure` exits with an
  actionable error if either library's `pkg-config` metadata is unavailable.
- `xz-devel`, `bzip2-devel`, and `lz4-devel` are included for the full codec
  build/test matrix. Those three codecs remain optional in an ordinary build.

### 1b. RPM build toolchain + nginx module SDK

```bash
sudo dnf install -y rpm-build rpmdevtools redhat-rpm-config nginx-mod-devel
```

- `nginx-mod-devel-1.20.1-28.el9_8.4.alma.1` (from **CRB**) — matches the installed
  `nginx` exactly. It ships:
  - the nginx 1.20.1 source tree at `/usr/src/nginx-1.20.1-28.el9_8.4.alma.1/`
  - RPM macros `/usr/lib/rpm/macros.d/macros.nginxmods` providing
    `%nginx_modconfigure`, `%nginx_modbuild`, `%nginx_moddir`, etc.
- The `%nginx_modconfigure` macro copies that nginx source into a build dir and runs
  `./configure --with-compat --with-cc-opt="<optflags>" --add-dynamic-module=<repo>`
  then `make modules`. `--with-compat` is what makes the resulting `.so` loadable by
  the distro nginx (ABI compat layer). This is the "build against the host's
  nginx/nginx-devel" path — distinct from the CLAUDE.md dev flow that uses a
  vendored nginx source at `/tmp/nginx-1.28.3`.

### 1c. Runtime dependencies (for installing/running the built RPMs)

Already present: `nginx-mod-stream`, `openssl-libs`, `curl`, `fuse3`,
`python3-cryptography`, `python3-urllib3`, `python3-rados`, `python3-cephfs`.

Installed:

```bash
sudo dnf install -y xrootd-client python3-pytest python3-pytest-timeout \
  python3-pytest-xdist python3-requests
```

**VOMS.** No `voms` / `voms-libs` package is needed on any EL release: VOMS attribute
certificates are verified natively by the module (`shared/voms/`), and the spec carries
no VOMS dependency (§2d records the earlier soname workaround that this superseded).

### 1d. Ubuntu 24.04 source-build and test dependencies

For the development flow that builds the module statically into an upstream nginx
source tree (rather than producing the EL RPM), install the following packages:

```bash
sudo apt-get install -y \
  build-essential pkg-config libpcre2-dev zlib1g-dev libssl-dev \
  libxml2-dev libjansson-dev libcurl4-openssl-dev libkrb5-dev \
  libsqlite3-dev libfuse3-dev libseccomp-dev liburing-dev libbrotli-dev liblzma-dev libbz2-dev liblz4-dev \
  librados-dev libradospp-dev libradosstriper-dev libcephfs-dev \
  libzstd-dev xrootd-client xrootd-server xrootd-scitokens-plugins \
  xrootd-voms-plugins bubblewrap gfal2-util-scripts gfal2-plugin-xrootd \
  python3-venv python3-pytest python3-pytest-timeout python3-pytest-xdist \
  python3-brotli python3-cryptography python3-requests python3-zstandard python3-xrootd \
  krb5-kdc krb5-admin-server haproxy
```

`libzstd-dev` and `libbrotli-dev` are required build dependencies: the module
always enables `BRIX_HAVE_ZSTD=1` and `BRIX_HAVE_BROTLI=1`, and `./configure`
fails early if either library's `pkg-config` metadata is absent. `libseccomp-dev`
enables the `brix_seccomp audit|enforce` integration coverage; without it those
modes correctly refuse to start. `liburing-dev` enables the optional io_uring
client and its full-coverage test lane. The remaining runtime services/libraries are
required by the integration fleet:
Kerberos test realms use `krb5-kdc` and `krb5-admin-server`, and HAProxy is
used by the proxy scenarios (VOMS needs no package: the verifier is native). `python3-xrootd` is required for tests using real
XRootD Python bindings. `gfal2-util-scripts` and `gfal2-plugin-xrootd` provide
the independent GFAL2 XRootD client used by the differential conformance lane.
The forwarding matrix also needs `xrootd-scitokens-plugins` for stock XRootD
token authentication, `xrootd-voms-plugins` for its HTTPS GSI endpoint, and
`bubblewrap` to expose the test CA bundle to its isolated token origin.
The stock-XRootD token forwarding cells also require permission to create a
Bubblewrap user namespace. If `bwrap --dev-bind / / true` reports a permission
error, those cells report an environmental skip; installing the package alone
does not override the host's namespace policy. The brix-to-brix token tests do
not need Bubblewrap.

Ubuntu's system Python is PEP 668 externally managed. Create a virtual
environment that can reuse the Debian Python modules, then install the complete
declared test dependency set there (including the `lizard`, `complexipy`, and
`radon` analyzers that Ubuntu 24.04 does not package). Do not use
`--break-system-packages`:

```bash
python3 -m venv --system-site-packages .venv
.venv/bin/python -m pip install -r requirements.txt
```

Run pytest with `.venv/bin/python` after this step. Build the native test
clients before running pytest:

```bash
make -C client -j"$(nproc)"
```

If development libraries were installed after a previous client build, rebuild
all client objects with `make -B -C client -j"$(nproc)" all aio-smoke`. Dependency
autodetection can change compiler defines without changing source timestamps;
an ordinary incremental build can otherwise retain incompatible older objects.

In particular, this must produce `client/bin/xrdcp`; otherwise client-dependent
tests fail or are skipped. The upstream nginx source build used in this checkout is:

```bash
cd /tmp/nginx-1.28.3
./configure --with-stream --with-stream_ssl_module --with-http_ssl_module \
  --with-http_dav_module --with-http_auth_request_module --with-threads \
  --add-module=/path/to/brix-cache
make -j"$(nproc)"
```

Run the fleet-backed suite from the repository root with the resulting nginx binary:

```bash
NGINX_BIN=/tmp/nginx-1.28.3/objs/nginx PYTHONPATH=tests \
  .venv/bin/python -m cmdscripts.operator_runtime suite
```

### 1e. Ubuntu 24.04: dependencies for expanded test coverage

The September 2026 Lima-host skip audit found that the development libraries in
§1d were not sufficient for tests that invoke independent command-line clients,
package managers, or optional Python extensions. Install these additional tools:

```bash
sudo apt-get update
sudo apt-get install -y \
  globus-gass-copy-progs nordugrid-arc-client \
  rpm dnf createrepo-c nginx-core brotli lz4 unzip nghttp2-server \
  clang valgrind strace iproute2 nftables fail2ban squid varnish \
  libxrootd-dev libxrootd-client-dev libxrootd-server-dev libxrootd-private-dev \
  python3-rados python3-cephfs golang-go \
  podman podman-docker uidmap slirp4netns fuse-overlayfs
.venv/bin/python -m pip install -r requirements-optional.txt
.venv/bin/python -m pip check
```

`globus-gass-copy-progs` supplies `globus-url-copy`; `rpm` supplies `rpmbuild`;
`nghttp2-server` supplies `nghttpd`. `nginx-core` supplies the independent stock
nginx used by the RPM proxy recipe tests; it does not replace the separately
built module binary selected by `NGINX_BIN`. `libxrootd-private-dev` supplies
the `libXrdSsiLib.so` linker name missing from the public development packages.
Codec **development libraries do not install
the corresponding CLI decoders**. The optional Python requirements include
`xattr`, `crc32c`, the S3/STS clients, and the codec/TLS extensions. Keep these in
the same virtual environment as pytest; do not install them into Ubuntu's
externally managed system Python. This host uses
`/var/tmp/brix-cache-venv/bin/python` instead of `.venv/bin/python`.

The tests only need `fail2ban-regex`, not a running firewall daemon. Squid and
Varnish supply independent CVMFS cache comparators. On this host the new
Fail2ban, stock-nginx, Squid, Varnish, and varnishncsa services were
runtime-masked during installation, then unmasked and disabled; all remain
inactive. This avoids changing SSH/firewall behavior or opening unrelated
listeners. The Varnish package also creates its own system account.
`podman-docker` supplies Docker-compatible CLI entry points without installing
the Docker daemon. Rootless `podman info` succeeded after installation; raw
`unshare -Ur true` is still denied by host policy. Do not disable AppArmor or
globally relax namespace restrictions just to reduce a skip count.

Additional reference tools installed outside apt:

- **Helm v4.3.0**, `/usr/local/bin/helm`: downloaded from the
  [official Helm releases](https://helm.sh/docs/intro/install/) and checked
  against the published SHA-256 before installation. Used for local chart
  rendering; no Kubernetes cluster was installed or modified.
- **go-hep v0.40.0** `xrd-ls` / `xrd-cp`, `/usr/local/bin`: built with
  `go install go-hep.org/x/hep/xrootd/cmd/xrd-ls@v0.40.0
  go-hep.org/x/hep/xrootd/cmd/xrd-cp@v0.40.0` (one command). Go automatically
  downloaded Go 1.26.8 for this build; the distro Go 1.22 bootstrap
  alone is too old for this module. See the
  [reference client documentation](https://pkg.go.dev/go-hep.org/x/hep/xrootd/cmd/xrd-ls).
- **XRootD v5.6.9 sources**, matching Ubuntu's reference libraries, downloaded
  from the [upstream tag](https://github.com/xrootd/xrootd/releases/tag/v5.6.9).
  `/tmp/brix-src` points to the extracted tree under
  `/var/tmp/brix-skip-tools.Oz3EdP/xrootd-5.6.9`. The SSI interop compiler and
  client-surface inventory require this source tree as well as development
  libraries. Recreate the `/tmp/brix-src` link if VM temporary-file cleanup
  removes it.

The stock CVMFS client is not in Ubuntu's default package repositories. For
the independent-client benchmark tests, install CERN's repository release
package and the client (see the [official CVMFS quickstart](https://cvmfs.readthedocs.io/en/2.14/cpt-quickstart/)):

```bash
curl -fLO https://cvmrepo.s3.cern.ch/cvmrepo/apt/cvmfs-release-latest_all.deb
sudo dpkg -i cvmfs-release-latest_all.deb
sudo apt-get update
sudo apt-get install -y --no-install-recommends cvmfs
```

This host installed `cvmfs-release` 4.9 and `cvmfs`/`cvmfs-fuse3`/`cvmfs-libs`
2.14.1+ubuntu24.04. This adds CERN's signed apt repository and the package-owned
`cvmfs` system account. `--no-install-recommends` avoids installing autofs and
its NFS services; the tests manage their own mounts. No public repository
automounts were configured, and `/etc/fuse.conf` was not relaxed. Tests that
request `allow_other` need an approved privileged run on this host.
The fault-proxy benchmark also expects the project's built FUSE client at
`/tmp/brixcvmfs`; this host links that path to
`/home/rcurrie.guest/src/brix-cache/client/bin/brixcvmfs`. Rebuild the client
normally, and recreate the link after temporary-file cleanup if necessary.

Container images are separate from runtime packages. The local oracle tests
downloaded `registry.cern.ch/cvmfs/service:latest`; the MinIO STS tests also
need `podman pull quay.io/minio/minio:latest`. The MinIO image installed for
this audit has digest
`sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e`.
Images are cached locally, not started as persistent services.
The ARC interoperability fixture additionally needs
`podman pull docker.io/nordugrid/arc-ce-image:rocky9-arc7-atlas`
(installed digest
`sha256:dc7a36260c8ecfd8cfc9f6b3c82cc338351eee8d6936f4482279cb6cd72fe108`).

The four `test_brix_dynamic_modules.py` checks need a **second nginx source
tree**, not merely additional packages. Configure that clean tree with:

```bash
BRIX_ENABLE_IO_URING=1 ./configure \
  --with-compat --with-stream --with-stream_ssl_module --with-http_ssl_module \
  --with-http_dav_module --with-http_auth_request_module --with-threads \
  --add-dynamic-module=/path/to/brix-cache
make -j"$(nproc)"
```

Point `BRIX_DYN_NGINX` at this tree when running pytest. On this host it is
`/var/tmp/brix-nginx-dynamic.t7TM33`; the ordinary static `NGINX_BIN` remains
`/tmp/nginx-1.28.3/objs/nginx`. Installing `liburing-dev` does not itself enable
the module's io_uring backend: that also requires the configure-time
`BRIX_ENABLE_IO_URING=1` opt-in. The ordinary static build has not been changed
to enable it.

For lifecycle tests using this second build, select its nginx and both BRIX
modules together (the paths below are specific to this host):

```bash
NGINX_BIN=/var/tmp/brix-nginx-dynamic.t7TM33/objs/nginx \
TEST_NGINX_BIN=/var/tmp/brix-nginx-dynamic.t7TM33/objs/nginx \
TEST_NGINX_LOAD_MODULES=/var/tmp/brix-nginx-dynamic.t7TM33/objs/ngx_stream_brix_module.so:/var/tmp/brix-nginx-dynamic.t7TM33/objs/ngx_http_brix_xrdhttp_filter_module.so \
PYTHONPATH=tests .venv/bin/python -m pytest \
  tests/test_io_uring_runtime.py tests/test_audit15e_uring_tiers.py \
  -x -n 8 --dist loadgroup -v -ra
```

Do not load those BRIX modules into the ordinary statically linked BRIX binary.
Set both binary variables: standalone scripts read `NGINX_BIN`, while the
registry lifecycle launcher reads `TEST_NGINX_BIN`.
The second build above has nginx's stream core built in, so it does not need
an additional `ngx_stream_module.so`.

Valgrind's full live test is separate from merely installing `valgrind`:
`RUN_VALGRIND=1` enables it; use `--timeout=660` for that test because its
nested harness permits up to 600 seconds. The current committed Memcheck
template still contains the removed `brix_webdav_token_jwks` directive and
fails `nginx -t` before Memcheck starts. This is a fixture migration issue,
not a missing package or a reported memory defect.

Not every skip indicates a missing package. Real-account/setfsuid tests require
an explicitly approved root run with account cleanup; SELinux tests require an
SELinux-enabled OS; container labs may also require their named test images.
Retired protocol features, unavailable remote endpoints, and invalid fixture
configs cannot be enabled by installing packages. Keep these distinctions in
the test-results report rather than counting skipped tests as passing.
In particular, the real DNF installroot checks invoke `unshare -r`; on this Lima
host they require the approved privileged runner even after DNF is installed.
Run privileged groups serially (`-x -n 0`) with a separate `TEST_ROOT`; do not
run a second fleet-owning pytest session concurrently. Set that test directory
to mode `0755`: `mktemp -d` defaults to `0700`, which prevents de-escalated nginx
workers from traversing it and makes fleet startup fail. Before running, check
that the fixtures' `brixtest_*`, `brixgm_*`, and `brixpg_*` accounts/groups and
fixed IDs do not belong to existing users. Check account, mount, and network
namespace cleanup after failures as well as successful runs: some fixtures
provision resources before entering their teardown-protected block.
On this checkout, starting the entire reference fleet as root is blocked by
the CMS mesh launcher, which invokes stock `xrootd`/`cmsd` without a root-safe
run-as user. Start the shared reference fleet as the normal development user,
then use pytest's automatic attach mode for the root-only tests with the same
`TEST_ROOT`. The tests themselves and their dedicated privileged subjects still
run as root. Check shared-fleet health before attaching and stop that manually
started fleet explicitly afterward. Its `registry/` directory must also be
traversable (`0755`) by the de-escalated workers of privileged subjects.
Set these permissions **after** `start-all`: fleet preparation recreates
`TEST_ROOT` with mode `0700`. Pytest also recreates `--basetemp` with mode
`0700`; privileged fixtures exporting data below it need that private base
made traversable after pytest creates it. Limit permission adjustments to the
dedicated test tree, not home directories or production exports. In this audit,
correcting both ancestors made all four checkpoint-recovery tests pass,
including both previously skipped root-only cases; no module change was needed.
The client build-lock helper also needs to support mixed-UID callers: opening
an existing user-owned lock in sticky `/tmp` with `O_CREAT` is denied by
Ubuntu's `fs.protected_regular`, even for root. The harness now reopens the
same lock inode read-only without `O_CREAT`, retaining cross-process `flock`
serialization and refusing symlinks/non-regular files. Do not disable that
kernel protection or delete an active lock file as a workaround.

### 1f. Expanded-coverage audit results (Ubuntu/Lima, 2026-09-13)

The audit tracked the **943 original skips** (942 test items plus one
collection-level skip), retaining results across fail-fast batches. This was
a targeted skip audit, not a new full-suite run:

| Final outcome | Count |
|---|---:|
| Previously skipped, now passing | 200 |
| Still skipped, including the collection skip | 484 |
| Failed | 10 |
| Setup error | 4 |
| Blocked/not retested under the final host setup | 245 |

Unprivileged batches used `-x -n 8 --dist loadgroup`; privileged groups ran
serially with cleanup. The 245 blocked items share already-failing fixtures;
they are **not** counted as passing or as 245 observed failures. Four of those
only ran before `nginx-core` was installed, so their old missing-package skips
are not presented as final-host results.

New passing coverage includes GridFTP, WebDAV TPC, ARC rejection checks,
Kerberos forwarding, SSI, go-hep, codec CLIs, Helm rendering, RPM/CVMFS,
container/FUSE oracles, privileged fault-proxy controls, and four dynamic-module
checks. The io_uring-enabled build passed 9 of 10 live tests; the staged
`writev` case fails with `invalid file handle in writev`. Its root cause still
needs diagnosis. Separately, all four checkpoint-recovery tests and all ten
build-lock regression tests passed, as did the newly installed Squid/Varnish
comparators.

Remaining blockers are not solved by more apt packages. Examples include
Ubuntu-incompatible `user nobody;` fixtures (the group is `nogroup`), an
XrdAcc-format multi-user authdb passed to the native parser, retired directive
names, worker-inaccessible fixture cache directories, and hard-coded obsolete
ports. The 188 token-endpoint skips involve the reference client's refusal to
send bearer credentials over cleartext; do not weaken that protection.
SELinux-only tests need an appropriate OS. The Ceph tests still need their
`xrd-ceph-build` image and a running test cluster; that additional deployment
was not performed. Host AppArmor, FUSE, ptrace and io_uring restrictions were
not relaxed.

Detailed per-failure evidence and cleanup notes are in the host-local
`/var/tmp/brix-skip-results.md`; batch logs and JUnit XML are
`/var/tmp/brix-skip-*.log` / `*.xml`. Do not interpret the 14 observed failures
and errors as 14 confirmed nginx-module bugs: several are established fixture
defects, and the remaining runtime failures need further diagnosis.

---

## 2. Building the RPM

Driver: `packaging/rpm/build-rpm.sh [version]`. Without an override it reads the
version from `BRIX_SERVER_VERSION_BARE` in `src/core/ident.h`. It tars the current
checkout (VCS/build artifacts excluded) into `.rpmbuild/SOURCES/brix-<version>.tar.gz`,
copies the spec, and runs `rpmbuild -ba` with `_topdir=.rpmbuild`. **The tarball is
built from the working tree**, so uncommitted source fixes are picked up on rebuild.

```bash
packaging/rpm/build-rpm.sh
```

All build products land under `.rpmbuild/` in the repo root.

### 2a. Fix required to compile (missing include)

The first build **failed** compiling the Ceph striper backend:

```
src/fs/backend/rados/sd_ceph_striper.c:25:17: error: 'EINVAL' undeclared
src/fs/backend/rados/sd_ceph_striper.c:147:21: error: 'ERANGE' undeclared
```

The file uses `-EINVAL` / `-ERANGE` but only included `<string.h>`, not `<errno.h>`.
It only breaks in this (Ceph-enabled, `-DBRIX_HAVE_RADOSSTRIPER=1`) build path. Fixed
by adding `#include <errno.h>` — matching the include block its sibling `sd_ceph.c`
already uses:

```c
 #if defined(BRIX_HAVE_RADOSSTRIPER)

+#include <errno.h>
 #include <string.h>
```

(Working-tree edit to `src/fs/backend/rados/sd_ceph_striper.c` — not yet committed.)

### 2b. Successful build

Historical second run: **exit 0**, ~4m35s wall (`-j$(nproc)`). Nine RPMs were
produced in `.rpmbuild/RPMS/` and `.rpmbuild/SRPMS/` at version 0.1.0, release 8.
The sizes below describe that earlier build, not the current release:

| Package | Architecture | Recorded size | Notes |
|---|---|---|---|
| `nginx-mod-brix-cache` | x86_64 | 3.4 MB | the two module `.so`s + loader + docs |
| `brix-cache-client` | x86_64 | 0.8 MB | native CLI tools + FUSE mounts |
| `brix-cache-tests` | noarch | 1.9 MB | pytest suite |
| `brix-tools` | x86_64 | 0.2 MB | Ceph migration/rescue tools |
| `nginx-mod-brix-cache` | src | — | source RPM |
| `*-debuginfo` / `*-debugsource` | — | — | 4 debug packages |

Module RPM payload (key files):
- `/usr/lib64/nginx/modules/ngx_stream_brix_module.so` (combined stream+http module)
- `/usr/lib64/nginx/modules/ngx_http_brix_xrdhttp_filter_module.so`
- `/usr/share/nginx/modules/mod-xrootd.conf` (loader snippet)
- `/etc/nginx/conf.d/brix-cache.conf.example`, logrotate rule, Grafana/Prometheus contrib

Auto-detected + explicit key `Requires:` on the module RPM:
- **`nginx(abi) = 1.20.1`** ← ABI-locked to this host's nginx (the point of the exercise)
- `nginx-mod-stream(x86-64)`, `openssl-libs(x86-64)`, `curl`, `voms-libs(x86-64)`
- ELF-detected libs: `librados.so.2`, `libradosstriper.so.1`, `libssl/libcrypto.so.3`,
  `libkrb5.so.3`, `libxml2.so.2`, `libjansson.so.4`, `libcurl.so.4`, `libsqlite3.so.0`,
  `liblzma/libbz2/libbrotli*`, `libz.so.1`, `libcrypt.so.2`

### 2c. Validation — module loads into the host nginx

Proved the built `.so` is ABI-compatible with this host's nginx **without installing**
(a plain `dnf install` is blocked by the `voms-libs` naming issue below):

```bash
# minimal conf loading host stream module + both freshly built modules
load_module .../ngx_stream_module.so;              # from nginx-mod-stream
load_module .../redhat-linux-build/ngx_stream_brix_module.so;
load_module .../redhat-linux-build/ngx_http_brix_xrdhttp_filter_module.so;
...
$ nginx -p <work>/ -c <work>/nginx.conf -t
nginx: configuration file .../nginx.conf syntax is ok
nginx: configuration file .../nginx.conf test is successful
```

`nginx -t` passing confirms `dlopen()` + `--with-compat` ABI match against nginx 1.20.1.

### 2d. Fixed — `voms-libs` dependency did not resolve on EL9

**Before the fix**, `dnf install` of the historical module RPM (version 0.1.0,
release 8) failed because the solver reported `nothing provides voms-libs(x86-64)`.

Cause: same EL8-vs-EL9 naming as §1c — nothing on EL9 *Provides* `voms-libs` (the C
library ships as `voms`, which is installed and provides `libvomsapi.so.1`).

**Fix (applied to `packaging/rpm/nginx-mod-brix-cache.spec`):** require the soname the
module actually `dlopen`s instead of a package name that changed between EL releases —
`voms-libs` on EL8 and `voms` on EL9+ both Provide it, so one line works everywhere:

```diff
-Requires:       voms-libs%{?_isa}
+Requires:       libvomsapi.so.1()(64bit)
```

After that rebuild, the module RPM's VOMS requirement was `libvomsapi.so.1()(64bit)`,
provided on that host by `voms-2.1.3-1.el9`. The recorded `dnf install --assumeno`
check resolved dependencies without installing the historical RPM:

```text
Dependencies resolved.
...
Total size: 3.4 M
```

> **Historical installation decision.** The dev/test fleet already had the module
> at version 1.1.1, release 20, installed on 2026-07-09. The version 0.1.0, release 8
> build was therefore a downgrade and was not installed. Dependency resolution and
> the `nginx -t` load check above are the recorded validation; they do not claim
> that the historical RPM was installed or that a current release has passed those
> checks. Install the RPM produced by your current build with `sudo dnf install <rpm>`.

### 2e. Rebuilding

```bash
# incremental re-run (regenerates tarball from working tree each time)
packaging/rpm/build-rpm.sh

# custom version tag
packaging/rpm/build-rpm.sh 1.2.3
```

Build products are self-contained under `.rpmbuild/` — safe to `rm -rf .rpmbuild`
to start clean.

---

## 3. Summary

- ✅ Full build + runtime deps installed via dnf (§1).
- ✅ 4 primary + 5 debug/src RPMs built against the host's nginx 1.20.1 (§2b).
- ✅ Built module verified loadable by host nginx via `nginx -t` (§2c).

**Two bugs found and fixed (both in the working tree, uncommitted):**

| # | Bug | Fix | File |
|---|---|---|---|
| 1 | Ceph striper backend fails to compile — `EINVAL`/`ERANGE` undeclared (missing include; only hit on the Ceph-enabled RPM build path) | added `#include <errno.h>` | `src/fs/backend/rados/sd_ceph_striper.c` |
| 2 | Module RPM's `Requires: voms-libs` does not resolve on EL9 (package renamed to `voms`) | require the dlopen'd soname `libvomsapi.so.1()(64bit)` instead — works on EL8 and EL9+ | `packaging/rpm/nginx-mod-brix-cache.spec` |

Both fixes verified by a clean rebuild (exit 0): the RPM compiles the striper backend and
its VOMS dependency resolves against the installed `voms` package.

> Superseded: the module no longer dlopens any VOMS library — attribute
> certificates are verified natively (`shared/voms/`) and the spec has no VOMS
> `Requires:` line at all. §2b–2d above are the recorded validation of that
> earlier build and are kept as history.

---

## 4. CMake build (build + install without RPM, overwrites an installed brix RPM)

For a fast local edit→build→install loop (no `rpmbuild`, no packaging), the repo
now ships CMake build files:

- `CMakeLists.txt` — top-level: options, nginx-module build, install rules.
- `cmake/BrixClientTools.cmake` — the native client-tool build (feature probing,
  granular targets, post-build verification, clean + install hooks).
- `cmake/BrixVerifyBins.cmake` — `cmake -P` helper asserting expected binaries exist.

It is a **thin orchestrator**, not a from-scratch CMake port — it drives the same
two build streams the RPM does:

1. **nginx dynamic modules** — via nginx's own `./configure` against this host's
   `nginx-mod-devel` source (`/usr/src/nginx-1.20.1-…`) + the repo-root `./config`
   source list, exactly like the spec's `%nginx_modconfigure` / `%nginx_modbuild`.
2. **native client tools** — via the in-tree `client/` + `shared/xrdproto` Makefiles.

Install rules land on the **same absolute paths the RPM uses**, so a system
install overwrites an installed `nginx-mod-brix-cache` / `brix-cache-client`.

### 4a. Usage

```bash
# configure (auto-detects nginx source + module paths from nginx-mod-devel)
cmake -B build

# build modules + client tools (incremental; make -jN under the hood)
cmake --build build -j$(nproc)

# install onto the system (prefix defaults to /usr to match the RPM layout)
sudo cmake --install build
```

Staged/packaging install (nothing touched on the live system):

```bash
DESTDIR=/tmp/stage cmake --install build
```

Useful options (`-D…` at configure time):

| Option | Default | Meaning |
|---|---|---|
| `CMAKE_INSTALL_PREFIX` | `/usr` | client-tool prefix (forced to `/usr`, not `/usr/local`, so it overwrites the RPM) |
| `BRIX_BUILD_MODULES` | `ON` | build/install the nginx modules |
| `BRIX_BUILD_NGINX` | `OFF` | also build a matching nginx executable for testing, at `build/modules/nginx` |
| `BRIX_BUILD_JOBS` | detected CPU count | parallel jobs used by nginx's inner Make invocation |
| `BRIX_BUILD_CLIENT` | `ON` | build/install the client tools |
| `BRIX_BUILD_CEPH_TOOLS` | `ON` | build the Ceph migration/rescue tools |
| `NGINX_SRC_DIR` | auto | nginx source tree: distro SDK by default, or an unpacked upstream release |
| `NGINX_MOD_DIR` | `/usr/lib64/nginx/modules` | where the `.so`s install |
| `NGINX_MODCONF_DIR` | `/usr/share/nginx/modules` | where `mod-xrootd.conf` installs |
| `BRIX_MODULE_CFLAGS` / `BRIX_MODULE_LDFLAGS` | rpm `%{optflags}` / `%{build_ldflags}` | module cc-opt / ld-opt |
| `BRIX_CLIENT_CFLAGS` / `BRIX_CLIENT_LDFLAGS` | empty (Makefile defaults) | extra flags for the client tools; changing these needs a `brix-client-clean` |

Auto-detection details:
- nginx source dir, module dir, modconf dir, and ABI version are read from
  `/usr/lib/rpm/macros.d/macros.nginxmods` (shipped by `nginx-mod-devel`).
- module cc-opt/ld-opt default to the distro `rpm --eval %{optflags}` /
  `%{build_ldflags}` (same hardening the packaged build uses), `+ -Wl,-E` so the
  combined module exports symbols to the separately-loaded xrdhttp filter.
- `pcre-config --cflags` is appended when available (optional, matches the SDK macro).
- `project(brix-cache C)` enables C **only** so `GNUInstallDirs` picks `lib64` on
  this multilib host — CMake compiles nothing itself. (With `project(... NONE)`
  the libdir wrongly resolves to `lib`, mis-placing `libbrixposix_preload.so`.)

### 4b. Client-tool build targets

`cmake/BrixClientTools.cmake` builds `shared/xrdproto` + `client/` (CLI, FUSE
mounts, LD_PRELOAD shim, Ceph tools) by delegating to their in-tree Makefiles —
the authoritative, feature-gated source lists — and layers CMake conveniences on
top. At configure time it prints a build summary of what will build on this host:

```
-- client tools .......... core CLI (xrd, xrdcp, xrdfs, ...) always built
--   FUSE mounts (xrootdfs/brixMount) .. YES (libfuse3)
--   Ceph rescue tools ................. YES (rados/librados.h)
```

Targets (all part of `make all`; each is independently buildable with
`cmake --build build --target <name>`):

| Target | Builds |
|---|---|
| `brix-client-proto` | `shared/xrdproto` (protocol core) |
| `brix-client-tools` | `client/` — CLI + FUSE + preload shim; then **verifies** the 11 core binaries exist |
| `brix-ceph-tools` | Ceph migration/rescue tools; **verifies** the 3 rados rescue tools when `librados` is present |
| `brix-client` | aggregate of the above |
| `brix-client-clean` | `make clean` in `client/` and `shared/xrdproto/` |

Post-build verification (via `cmake/BrixVerifyBins.cmake`) fails the build with a
clear message if an expected binary is missing — the same guarantee as the RPM
spec's `test -x client/bin/$t` loop, catching a silently gate-skipped or
broken-link tool before install. If `BRIX_BUILD_CEPH_TOOLS=ON` but `librados`
headers are absent, configure emits a `WARNING` (the ceph target becomes a no-op)
rather than failing later.

### 4c. Verified end-to-end

- `cmake -B build` — OK, detects nginx 1.20.1 source, `lib64` libdir.
- `cmake --build build` — OK. Emits
  `build/modules/ngx_stream_brix_module.so` (18 MB) +
  `build/modules/ngx_http_brix_xrdhttp_filter_module.so`, and the full client tool
  set into `client/bin/`. The client targets report their verification:
  `core: verified 11 binaries present` / `ceph: verified 3 binaries present`.
  (LTO prints a benign, **pre-existing** `-Wlto-type-mismatch` on
  `brix_split_relative_parent` — not from these changes, not fatal.)
- Module load check: `nginx -t` with the host stream module + both cmake-built
  modules → *test is successful* (ABI-compatible with the host nginx).
- `DESTDIR=… cmake --install build` — OK. Staged tree matches the RPM layout:
  - `/usr/lib64/nginx/modules/ngx_{stream_brix,http_brix_xrdhttp_filter}_module.so`
  - `/usr/share/nginx/modules/mod-xrootd.conf` (combined module first)
  - `/etc/nginx/conf.d/brix-cache.conf.example`, `/etc/logrotate.d/nginx-xrootd`
  - `/usr/share/nginx-xrootd/{grafana-dashboard.json,prometheus-alerts.yml}`
  - `/usr/bin/*` (xrdcp, xrdfs, …), `/usr/lib64/libbrixposix_preload.so`,
    `/usr/libexec/brix/…`, man pages, shell completions

### 4d. Overwriting a running install

`cmake --install` writes files straight to the paths above; if a brix RPM is
installed they are overwritten **in place**. The RPM DB is not updated, so:
- `rpm -V nginx-mod-brix-cache` will list the changed files (expected).
- a later `dnf reinstall/update` of the RPM replaces your files again.

After installing modules over a live server:

```bash
sudo nginx -t && sudo systemctl reload nginx
```

Revert to the packaged build with
`sudo dnf reinstall nginx-mod-brix-cache brix-cache-client`.

> During that earlier build we did **not** run `sudo cmake --install`: the
> dev-fleet module was already installed at version 1.1.1, release 20 (§2d). All
> recorded CMake verification used a `DESTDIR` staging dir. `build/` is git-ignored.

---

## 5. Fresh-host module build — 2026-09-10

The earlier sections record a different installation state. On this fresh
AlmaLinux 9.8 host, GCC, Make and CMake were present, but nginx and most
development libraries were missing. Enabled CRB and installed the signed
`centos-release-ceph-reef` repository package, then installed the build and
runtime dependencies listed in §1. The matching distro packages are now
`nginx`, `nginx-mod-devel` and `nginx-mod-stream`, all at
`1.20.1-28.el9_8.5.alma.1`.

Also installed the newer feature dependencies: `libzstd-devel`, `lz4-devel`,
`liburing-devel`, `xz-devel`, `bzip2-devel`, `brotli-devel` and
`libseccomp-devel`, plus the current RPM build macros and SELinux development
package. On AlmaLinux 9 the Brotli development package is **`brotli-devel`**.
The installed package inventory and transaction output are saved locally in
`build/dependencies.txt` and `build/dependency-install.log`.

Build the two BriX dynamic modules against the SDK's nginx sources:

```bash
cmake -S . -B build \
  -DBRIX_BUILD_CLIENT=OFF -DBRIX_BUILD_CEPH_TOOLS=OFF
BRIX_ENABLE_IO_URING=1 cmake --build build --target nginx-modules -j$(nproc)
```

The SDK sources are `/usr/src/nginx-1.20.1-28.el9_8.5.alma.1`; CMake copies
them into `build/nginx-src`. Outputs are:

- `build/modules/ngx_stream_brix_module.so`
- `build/modules/ngx_http_brix_xrdhttp_filter_module.so`

Two fixes in `src/protocols/root/session/bind_migrate.c` were needed for this
distro build:

1. Before nginx 1.25.5, stream addresses carry their configuration in `ctx`,
   rather than `default_server->ctx`. Version-gate migrated-session setup,
   using the same boundary as `postconfiguration_proxy_acl.c`.
2. Initialize the migration channel's read/write event log pointers before
   registering with epoll. `ngx_get_connection()` leaves them unset, and
   distro nginx's `--with-debug` epoll logging otherwise crashes workers at
   startup when multiple workers enable migration.

For the existing migration regression tests, installed Python 3.12 and made
an isolated `build/test-venv` with pytest 9.1.1, pytest-xdist, pytest-timeout,
requests, cryptography, PyYAML, packaging and pluggy. The Python 3.9 / pytest
6 packages in the historical instructions do not support the current harness.
Run the dedicated two-worker tests without starting the full fleet:

```bash
env TEST_SKIP_SERVER_SETUP=1 \
  TEST_ROOT="$PWD/build/pytest-runtime" \
  TEST_NGINX_BIN=/usr/sbin/nginx \
  TEST_NGINX_LOAD_MODULES="/usr/lib64/nginx/modules/ngx_stream_module.so:$PWD/build/modules/ngx_stream_brix_module.so:$PWD/build/modules/ngx_http_brix_xrdhttp_filter_module.so" \
  PYTHONPATH=tests \
  build/test-venv/bin/python -m pytest tests/test_bind_migration.py -v -x
```

This invocation builds modules only. No BriX modules were installed into the
system module directory, and the system nginx service was not started.

Validation of the final build:

- `nginx -t` loads the distro stream module and both newly built BriX modules.
- All three `test_bind_migration.py` tests pass: cross-worker response offload,
  unknown-session rejection and restricted secondary-channel permissions.
- A private loopback instance serves byte-exact WebDAV and official `xrdcp`
  reads, returns 404 for a missing file, and refuses read-only PUT/DELETE/MKCOL
  with 403 while preserving the export.
- A second incremental build leaves both module timestamps unchanged; all
  linked shared-library dependencies resolve.

Local evidence is in `build/module-build-final.log`,
`build/migration-tests-final.log`, `build/module-smoke-final.log` and
`build/incremental-build.log`. The build still reports existing OpenSSL MD5
deprecation warnings and the `brix_split_relative_parent` LTO type warning
described in §4c. This was targeted build/runtime validation, not a full fleet
test run.

---

## 6. nginx compatibility matrix

`tools/ci/nginx_compat.py` builds and validates three independent targets:

| Target | nginx source and runtime |
|---|---|
| `alma9` | Installed AlmaLinux 9 nginx and the matching `nginx-mod-devel` source release; tested with the installed stream core |
| `1.28.3` | Official nginx 1.28.3 sources, with a matching locally built nginx executable and stream core |
| `latest` | Current **mainline** release from [nginx.org](https://nginx.org/en/download.html), resolved once per invocation; matching executable and modules built together |

On 2026-09-10 the upstream mainline target resolves to **1.31.5**. The stock
AlmaLinux 9 target is **1.20.1-28.el9_8.5.alma.1**. These are distinct module
ABIs: each runtime loads only the modules built against its own source tree.
The matrix does not install modules or start the system nginx service.

Use the module dependencies and Python 3.12 test environment from §5. Run all
three targets, or repeat `--target` to select specific targets:

```bash
build/test-venv/bin/python tools/ci/nginx_compat.py \
  --jobs "$(nproc)" --xrdcp /usr/bin/xrdcp

# Recheck only the latest mainline; a numeric target pins a reproducible release.
build/test-venv/bin/python tools/ci/nginx_compat.py --target latest
build/test-venv/bin/python tools/ci/nginx_compat.py --target 1.31.5
```

The matrix runner's `nginx_compat.py --xrdcp /usr/bin/xrdcp` option adds a
byte-exact read with that reference client. Without this option, the existing
cross-worker migration tests still exercise real root:// file reads using
their socket client. All targets check:

- Dynamic module loading with `nginx -t`.
- Byte-exact WebDAV reads, missing-file errors, and read-only mutation refusal.
- The three existing migration regressions: cross-worker reads, unknown
  session rejection, and restricted secondary-channel permissions.
- An incremental build that leaves the binary/module timestamps unchanged.

Source archives are downloaded over HTTPS into `build/nginx-sources/` and
unpacked with Python's data extraction filter. Each target keeps its generated
nginx tree, binaries and logs under `build/nginx-compat/<target>/`; upstream
folders use the resolved name, such as `nginx-1.31.5`. Its `result.json` records
the exact nginx version, configure arguments, source archive SHA-256, artifact
SHA-256 values and final status. A failing rerun replaces the previous verdict.

CMake can also build arbitrary local upstream sources directly using
`-DNGINX_SRC_DIR=/absolute/source/path -DBRIX_BUILD_NGINX=ON`. Use a separate
`-B` directory for each version. Changing the selected source path or compiler
flags invalidates that directory's private nginx copy and compiled outputs;
unchanged builds remain incremental. The supplied nginx source tree is never
modified. `BRIX_BUILD_NGINX` only adds a test binary, not an installation rule.

`.github/workflows/nginx-compat.yml` runs the same matrix on pull requests,
main-branch pushes, manual dispatch and weekly. Each job uses AlmaLinux 9,
installs the distro SDK and feature dependencies, and runs the build/tests as
an unprivileged user. The `latest` job discovers new mainline releases rather
than retaining a version hardcoded in the workflow. Version reports and logs
are uploaded for both passing and failing jobs.

## 7. AlmaLinux full-suite preparation — 2026-09-14

Recompiled both modules against the matching AlmaLinux 9.8 SDK in the isolated
`build/alma9-full-build` directory, with two compiler jobs. The stock
`/usr/sbin/nginx` successfully loads these modules; private WebDAV and official
XRootD client reads, missing-file handling, and read-only mutation refusal pass.
The six standalone impersonation configuration checks also pass with this build.

The full test environment requires more than the focused matrix dependencies.
The consolidated Alma9 package list is in [§10](#10-alma9-full-testsuite-dependencies--2026-09-14).

```bash
sudo dnf install -y python3.12-devel xrootd-devel xrootd-client-devel \
  xrootd-server-devel xrootd-private-devel lz4
python3.12 -m venv build/alma9-full-venv
build/alma9-full-venv/bin/python -m pip install \
  -r requirements.txt -r requirements-optional.txt
build/alma9-full-venv/bin/python -m pip check
```

This installs the declared XRootD Python bindings, runner plugins, analysis
tools, and optional codec, S3, checksum, xattr, and TLS test dependencies within
their declared bounds. The reference XRootD server and Kerberos server/client
packages must also be installed as described in §1. Native clients and the
`aio-smoke` and `ssi-client-smoke` helpers were built through
`brix_suite.client_build.client_make`, which holds the shared build lock.
The matching XRootD 5.9.7 reference sources were unpacked at `/tmp/brix-src` for
the client option inventory and SSI header consumers.

Module-only nginx builds omit core objects used by standalone C tests. For
this isolated CMake build, `nginx-src/objs` points to `../modules`; the generated
Makefile was used to compile `ngx_string.o`, `ngx_palloc.o`, `ngx_shmtx.o`, and
`ngx_alloc.o` without editing nginx sources or generated Makefiles. Set
`NGX_SRC` and `TEST_NGINX_SRC` to the configured `nginx-src` directory, and
`TEST_NGINX_OBJS` to its `objs` path when running those tests. Set `BRIX_SRC`
and `BRIX_SRC_DIR` to the reference XRootD source directory.

Full-suite preparation exposed two dynamic-module coverage gaps and a fleet
startup failure. Kerberos probing now checks the selected BriX modules as well
as nginx itself, and ELF hardening checks both selected BriX artifacts. Raw
standing-fleet nginx launches now apply the existing module and runtime-path
injectors and surface startup errors immediately. Previously, the hybrid mesh
omitted module loading and eventually failed the fleet readiness barrier before
test dispatch on stock nginx.

Validation at this checkpoint: 86 focused compatibility/probe/launcher pytest
tests and six CMake build-driver tests pass. Suite collection succeeded for
45,088 tests before the final launcher regression tests were added. The full
fleet run was interrupted amid competing test fleets and memory pressure; it
has **no completed passing verdict**. Upstream 1.28.3 and mainline 1.31.5 matrix
builds were also interrupted before their final runtime checks. The local
logs and per-process results remain under `build/`; neither incomplete run is
evidence of full compatibility or a passing release gate.

## 8. Local macOS-branch integration — 2026-09-14

Fast-forwarded local `main` from `940b3bf` to the rebased
`dev/macos-support` tip `05e2b82` (61 commits). The pre-merge tip is retained
as `backup/main-before-macos-merge-20260914`. This local integration is not
pushed to remote `main`.

The merged branch did not initially compile or load on Alma9. The repairs
select only the host's PAL sources, register missing implementation units,
restore complete Linux handlers displaced by Darwin stubs, finish state
accessor migrations, restore accidentally removed file-handle fields, and
repair undeclared constants and protocol helper extraction errors. The
shared client codec remains independent of nginx headers. Unbuilt prototype
implementations are preserved under `docs/09-developer-guide/drafts/` with
their limitations; standalone platform tests use the established
`*_unittest.c` naming convention.

The module rebuild uses a separate directory and the matching stock SDK:

```bash
cmake -S . -B build/alma9-merged \
  -DNGINX_SRC_DIR=/usr/src/nginx-1.20.1-28.el9_8.5.alma.1 \
  -DBRIX_BUILD_CLIENT=OFF -DBRIX_BUILD_CEPH_TOOLS=OFF \
  -DBRIX_BUILD_NGINX=OFF -DBRIX_BUILD_JOBS=4
BRIX_ENABLE_IO_URING=1 cmake --build build/alma9-merged \
  --target nginx-modules -j4
```

Both BriX modules are in `build/alma9-merged/modules/`. All module objects
were rebuilt after restoring the file-handle layout. Native clients and the
`aio-smoke`/`ssi-client-smoke` helpers were also rebuilt through the shared
client build lock, with two compiler jobs. Installed the missing matching
`libasan` package for the staged-commit native regression.

Observed validation on AlmaLinux 9.8:

- Stock nginx loads both modules with `nginx -t`. Private WebDAV reads and
  reads with both official `/usr/bin/xrdcp` and the rebuilt native client
  return exact data. Missing files return 404, and read-only PUT/DELETE/MKCOL
  requests return 403 without changing the export.
- All 27 live migration/dashboard/client-CA/identity-configuration tests
  pass. These include restricted secondary channels, dashboard auth and
  confinement, and rejection of an unrelated TLS client CA.
- Native PAL/registry tests: 27 pass. Page-write and identity-state tests:
  four pass. Cache registry tests: three pass. Proxy health tests: three
  pass. Subprocess tests: three pass. Build-driver/smoke tests: 58 pass.
- Native client units: 22 pass; one io_uring unit skips because the kernel
  cannot run it. Client proxy/OCI tests: 45 pass, with the external Podman
  oracle excluded. CAS and vendor wire-codec checks pass, as do the manual
  and completion coverage checks.
- Existing native error/recovery/publish, stage reconciliation and
  metrics/session/handle registry regressions pass. The staged-commit
  contract test runs under ASan. Module and client source-coverage guards
  pass without adding allowlist exceptions.
- An unchanged module build preserves both artifact timestamps. All linked
  libraries resolve, and every strong imported symbol is supplied by nginx,
  its stream core, or the linked libraries. Artifact hashes and package
  versions are recorded in `build/alma9-merged-artifacts.json`.

Logs are under `build/alma9-merged*.log` and `build/platform-checks/`.
The initial integration build reported OpenSSL MD5 deprecation and
`brix_split_relative_parent` LTO warnings; the latter is corrected in §9.
This is focused Alma9 integration validation:
the full fleet suite, upstream 1.28.3/latest matrix, and native macOS/Windows
builds are not certified by these results. No modules were installed into
the system module directory and no system nginx service was started.

## 9. Alma9 full-suite remediation checkpoint — 2026-09-14

The subsequent Python 3.12 run uses `build/alma9-full-venv`, stock
`nginx-1.20.1-28.el9_8.5.alma.1`, and private copies of both BriX modules.
The build remains under `build/alma9-merged`; no system module is replaced.
On this 8 GiB host, module compilation uses two jobs and pytest uses two
workers, with the harness's separate serial lanes preserved.

Additional dependencies installed for this verification were matching
`libubsan`, `strace`, and the declared optional Python `psutil` and `numpy`
packages. `gfal2-plugin-http` and `gfal2-plugin-gridftp` supply the GFAL
protocol handlers used by the DAVS and GridFTP interoperability cells.
Clang 21.1.8, `clang-tools-extra`, and `lcov` were installed for the
separate analysis/coverage jobs. CodeChecker 6.29.0 is isolated from the test
environment:

```bash
python3.12 -m venv build/alma9-analysis-venv
build/alma9-analysis-venv/bin/python -m pip install -r requirements-dev.txt
```

The full-run investigation repaired production defects in addition to test
portability problems:

- Correct function declarations remove the confined-parent LTO return-type
  mismatch. Histogram bounds and packet-mark flow-label encoding again match
  their existing wire/metric contracts.
- CMS and admin event registrations initialize their event logs and retain
  connection ownership through registration failure.
- CRL selection preserves full-CRL revocations; macaroon parsing preserves a
  trailing newline byte inside a binary signature.
- S3 query canonicalization again has a 1,024-byte encoding buffer rather
  than accidentally sharing the 32-byte timestamp buffer.
- Pipelined write completion constructs its reply under the completed
  request's ID, then restores the ID of the request still being received.
- Darwin exchange and exclusive-rename operations fail with `ENOTSUP` when
  unavailable instead of performing an ordinary rename. Native Linux behavior
  is preserved; compiled Darwin branches do not establish native macOS support.

Fixture repairs apply the canonical dynamic-module and private runtime-path
configuration helpers, keep GFAL's distro Python separate from the test venv,
retain SELinux labels when checking application xattrs, and match reference
CMS daemon address families to the configured mesh. Lifecycle cleanup now
recognizes the actual Python entrypoint rather than treating the parent
operator's test-selection arguments as daemon paths.

Current completed checkpoints:

- All 72 native suite jobs pass against the rebuilt stock-nginx objects
  (`native-final-frozen.xml`, 274.25 seconds).
- Stock nginx loads both modules; an unchanged build preserves artifact
  timestamps, all libraries resolve, and all strong imported symbols resolve.
  Current hashes are in `build/alma9-merged-artifacts.json`.
- Matching nginx 1.28.3 and 1.31.5 binaries, stream modules, and both BriX
  modules build and pass private `nginx -t`, dependency resolution, and
  unchanged incremental-build checks. The subsequent three-version live
  matrix also passes: five configuration/HTTP/root checks and three
  cross-worker migration cases per version, including stock Alma9 nginx.
  Build reports are under `build/nginx-compat/nginx-*/merged-build-result.json`;
  completed live evidence is in `build/alma9-full-suite-run/matrix-live-final/`.
- The example catalogue contains 375 entries; 56 applicable configurations
  passed real stock-nginx parsing. Two proxy-certificate-variable examples
  explicitly require nginx 1.21.0 or newer.

The broad run is diagnostic evidence, not a passing full-suite verdict. Its
first lane reported 41,597 passed, 395 failed, 45 errors, 582 skipped,
56 expected failures and eight unexpected passes; its serial lane reported
861 passed, 25 failed, 359 skipped and four expected failures. Those lanes used
module copies captured before the later repairs, so the original live cases
require a clean run against the final artifacts. The invocation, selection
manifest, per-controller results, failure dispositions and preserved fleet
logs are under `build/alma9-full-suite-run/attempt3/`.

The reviewed selection omits explicit attack, known-crash and host-file probes;
their exclusion is not a pass. Independent live jobs, user-namespace capability
checks, sanitizer/coverage jobs and analysis gates require separate accounting.
GCC 11 analyzed 1,202 module translation units with no compile errors but
reported five allocation-ownership diagnostics, so its zero-findings gate
remains failed. No diagnostic suppression or backlog expansion was added.
CodeChecker completed the same 1,202-source census with Clang 21.1.8 and
reported 34 new finding keys (1,313.32 seconds). These require individual
review; unchanged source alone does not prove a false positive. Its gate is
failed, with the full outcome preserved in `codechecker-actual.xml`. Targeted
rechecks after three corrections leave 31 keys; that narrower recheck does
not establish a passing full analyzer gate.

A focused recheck of the original failures completed 478 cases: 450 passed,
24 failed, and four skipped for the host io_uring restriction or the explicit
nginx 1.21 minimum. The remaining failures identified command helpers that
did not recognize a frozen nginx filename and missing GFAL protocol handlers.
Correcting the resilience prerequisite recovered 78 passing cases, with one
protocol-capability skip and 19 reviewed deselections. These are focused
results, not a clean full-suite rerun. TLS token-client coverage and the final
full run remain pending.

The fixture fixes also preserve all eight TLS byte-exact parameter identities,
generate all 520 certificate clauses under Alma9 without changing the server
crypto policy, and retain sanitizer reports emitted during fleet startup.
The static guard recheck passed 49 affected cases after the example helper
extraction; later edits still require their relevant checks. Local `main`
remains unpushed.

## 10. Alma9 full-testsuite dependencies — 2026-09-14

These additions were checked against this AlmaLinux 9.8 host's DNF history and
installed packages. Install the module/client build prerequisites in §1a–§1b
first, including the matching `nginx`, `nginx-mod-devel`, and
`nginx-mod-stream`. This run uses nginx **1.20.1-28.el9_8.5.alma.1** and XRootD
**5.9.7-1.el9**. **CRB and EPEL must be enabled** for the test additions below;
the Ceph development packages retain the repository requirements in §1a.

### 10a. Python, reference servers, and interoperability tools

Run these commands from the repository root:

```bash
sudo dnf install -y \
  nginx nginx-mod-devel nginx-mod-stream \
  python3.12 python3.12-pip python3.12-devel \
  xrootd-client xrootd-server xrootd-devel xrootd-client-devel \
  xrootd-server-devel xrootd-private-devel xrootd-scitokens xrootd-voms \
  krb5-server krb5-workstation haproxy bubblewrap \
  gfal2-util-scripts gfal2-plugin-file gfal2-plugin-xrootd \
  gfal2-plugin-http gfal2-plugin-gridftp globus-gass-copy-progs dpkg \
  python3-xrootd python3-brotli python3-zstandard \
  lz4 nghttp2 fail2ban-server helm

python3.12 -m venv build/alma9-full-venv
build/alma9-full-venv/bin/python -m pip install \
  -r requirements.txt -r requirements-optional.txt
build/alma9-full-venv/bin/python -m pip check
export PATH="$PWD/build/alma9-full-venv/bin:$PATH"
```

| Package or group | Test capability supplied |
|---|---|
| `python3.12-devel`, `xrootd-devel`, `xrootd-client-devel`, `xrootd-server-devel`, `xrootd-private-devel` | Build the Python XRootD bindings and compile native/SSI regression helpers against matching headers. XRootD server libraries are pulled in by the server packages. |
| `xrootd-server`, `krb5-server`, `krb5-workstation`, `haproxy` | Owned reference-server, Kerberos, forwarding, and HA fixtures. |
| `xrootd-scitokens` | SciTokens verification in the stock XRootD token origin; pulls in `scitokens-cpp`. The EL9 package name has no `-plugins` suffix. |
| `xrootd-voms` | `libXrdHttpVOMS-5.so`, used by the stock HTTPS forwarding origin. Its absence caused both HTTPS-backend forwarding cells to fail. The EL9 name is `xrootd-voms`. |
| `bubblewrap` | Isolated CA trust for the reference token-origin fixture. |
| `gfal2-util-scripts` and the four `gfal2-plugin-*` packages | GFAL commands plus local-file, XRootD, HTTP/DAVS, and GridFTP handlers. `gfal2-util-scripts` pulls in the distro Python GFAL bindings; HTTP/GridFTP plugins pull in their Davix/Globus libraries. |
| `globus-gass-copy-progs` | `globus-url-copy`, used directly by the GridFTP client interoperability tests. Installing the GFAL GridFTP plugin alone does not supply this executable. |
| `dpkg` | `dpkg-deb` for building and unpacking the local Debian packaging fixture; no Debian package is installed by that test. DNF pulls in `libmd`. |
| `python3-xrootd`, `python3-brotli`, `python3-zstandard` | Distro-Python helpers installed alongside the external clients. The Python 3.12 suite installs its own declared bindings and codecs in the venv. |
| `lz4` | The codec CLI, in addition to the `lz4-devel` build dependency. |
| `nghttp2` | `nghttpd`, needed for the real HTTP/2 origin parity case. On EL9 this is `nghttp2`, not Ubuntu's `nghttp2-server`. |
| `fail2ban-server` | `fail2ban-regex` for 12 offline sample-log checks. All 12 passed after installation; the fail2ban service is inactive. |
| `helm` | Local chart rendering. The GridFTP chart uses sibling `file://` dependencies. |

Keep the external GFAL commands on their distro Python interpreter; the
harness removes venv Python-library overrides for those subprocesses. Installing
the system `python3-*` packages alone does not populate the Python 3.12 venv.
`requirements-optional.txt` now includes `psutil` and `numpy`, which were also
needed to exercise the platform tests instead of skipping them.

The verified venv contains Python 3.12.14, pytest 9.1.1, pytest-xdist 3.8.0,
pytest-timeout 2.4.0, pytest-rerunfailures 16.6.1, XRootD 6.1.1,
cryptography 46.0.7, pyOpenSSL 25.3.0, psutil 7.2.2, and numpy 2.5.3.
`pip check` reports no broken requirements. Use the checked-in requirement
bounds when recreating it; do not substitute the stock Python 3.9 pytest stack.

Stock XRootD also requires bearer-token files with owner-only permissions.
The token generator now creates and tightens them to mode `0600`; the shared
token fixture supplies TLS. Packages alone did not resolve the former 188
token-endpoint health skips. The stock client's token health check now passes.

### 10b. Native checks, sanitizers, and static-analysis tooling

```bash
sudo dnf install -y liburing-devel libasan libubsan strace mingw64-gcc \
  clang clang-tools-extra lcov

python3.12 -m venv build/alma9-analysis-venv
build/alma9-analysis-venv/bin/python -m pip install -r requirements-dev.txt
build/alma9-analysis-venv/bin/python -m pip check
```

`libasan` and `libubsan` support the instrumented native regression tests and
the separate sanitizer build. `strace` was needed to diagnose fixture cleanup.
`mingw64-gcc` supplies the Windows cross-compiler and pulls in its MinGW CRT,
headers, binutils, and winpthreads; those checks do not establish Windows
runtime support. `clang-tools-extra` supplies `clang-tidy`; `lcov` supplies
coverage capture and HTML reporting. The installed versions are Clang 21.1.8,
lcov 1.14, and CodeChecker 6.29.0. Keep CodeChecker in its separate venv because
its Python dependencies differ from the test environment.

`gcc-toolset-14-gcc` was additionally installed for analyzer comparison:
`sudo dnf install -y gcc-toolset-14-gcc`. The ordinary module build still uses
the stock GCC 11.5 compiler. DNF resolves the analysis toolchain's transitive
packages; they are not additional manual test prerequisites.

### 10c. Independent go-hep reference clients

The two go-hep interoperability cases need `xrd-ls` and `xrd-cp`, which are not
provided by the installed XRootD RPMs. The following pinned build succeeded
with Alma9's Go **1.26.7**; go-hep v0.40.0 declares Go **1.25.0** as its minimum:

```bash
sudo dnf install -y golang
GOBIN="$PWD/build/gohep-bin" \
GOPATH="$PWD/build/gohep-work" GOCACHE="$PWD/build/gohep-cache" \
GOMAXPROCS=1 GOFLAGS=-p=1 go install \
  go-hep.org/x/hep/xrootd/cmd/xrd-ls@v0.40.0 \
  go-hep.org/x/hep/xrootd/cmd/xrd-cp@v0.40.0
export TEST_GOHEP_BIN="$PWD/build/gohep-bin"
```

### 10d. Remaining capability limits and installation evidence

Installing `liburing-devel` enables the build feature; this host's
`kernel.io_uring_disabled=2` still prevents runtime io_uring tests. Subordinate
UID mappings, native Darwin/Windows/ARM64 execution, container-based oracles,
and the optional official CVMFS client/keys are separate prerequisites. Docker,
Podman, and `cvmfs2` were not installed by this run. These omissions and host
limitations remain explicit skips, not passing tests.

The `nghttp2` install selected **1.43.0-6.el9_8.2** and upgraded `libnghttp2`
from **1.43.0-6.el9_8.1** to the matching release during the broad run. Fresh
HTTP/2 and three-version matrix checks against the final runtime libraries
subsequently passed, as recorded below.
Installing these dependencies is not a completed passing full-suite verdict.

The completed four-lane run also exposed missing `globus-url-copy` and
`dpkg-deb`. After its fleet stopped, DNF installed
`globus-gass-copy-progs-10.13-1.el9`, `dpkg-1.22.22-1.el9`, and the transitive
`libmd-1.2.0-1.el9` package from EPEL. Both executables are now present.
The subsequent dynamic-module checks below include real Debian package
creation, extraction and module loading on all three nginx versions.

Local installation evidence is retained under `build/alma9-full-suite-run/`:
`alma9-test-dnf-history.txt`, the `*-dependency.log` files,
`gfal-protocol-dependencies.log`, `analysis-dependencies.log`,
`gohep-client-build-result.json`, and `remaining-rpm-install.log`. Full runs and scoped rechecks
retain their own invocations and results there.

## 11. Completed dependency and runtime rechecks — 2026-09-14

The dependency/GSI recheck passed **12 tests with no skips in 416.96 seconds**:
the seven original stock-GSI setup failures, three HTTP/2/configuration cases,
and both independent go-hep client cases. The GSI fixtures now keep their
Unix control sockets in short, private directories while certificates,
exports and logs retain the deliberately long test-root paths. Four offline
fixture checks also pass. A separate shared mesh-fixture correction clamps
certificates/keys to `0644`/`0600` even with a permissive caller umask; three
offline checks pass for new identities, reused identities and generator failure.

Helm's original render check and six subprocess regression cases pass. The
chart dependency lock now matches its local sibling dependencies, and the
guard builds a temporary chart copy so validation preserves the checkout.
Dependency and rendering errors fail the check.

The isolated ASan/UBSan build completed the real sanitizer runner and its
ordinary byte-integrity I/O smoke: **one outer test and one inner test passed**,
with no skips and no sanitizer reports after fleet shutdown. Evidence is in
`build/alma9-sanitizer/runtime/verified-summary.json`, with both controller
streams, XML reports and the actual orchestrator output. This is one ordinary
sanitized I/O workload. A separate unmodified nginx 1.28.3 invalid-configuration
exit leaked its initial pool; that report remains in `wrapper-copy-review.json`
and is not covered by the clean I/O result. No new suppression was added.

The stock Alma9, 1.28.3 and 1.31.5 live matrix completed **15 smoke checks and
nine migration tests**, with no skips and unchanged binary/module hashes.
`matrix-live-final/verified-summary.json` validates the retained per-version
logs, XML and completed controller streams. The initial local report checker
mistook the smoke's final completion message for a sixth test; its original
failed wrapper result is retained alongside the corrected evidence accounting.

After the temporary-directory and CRL-readiness fixture repairs, **24 offline
regression tests passed**. The four dynamic-module checks also passed on each
of stock Alma9 nginx, 1.28.3 and 1.31.5: **12 passes with no skips**, including
actual `.deb` creation/extraction and `nginx -t`. Evidence is in
`dynamic-matrix-followup/verified-summary.json`. A separate standalone
follow-up passed **25 tests**, including all six CVMFS cases, credential replay
and Kerberos forwarding; see `focused-revalidation-standalone-followup/`.

The current non-slow CI and packaging checks completed with **205 passes and
no skips or failures**, recorded in `guard-docs-fixture-followup/`. The three
slow analyzer/coverage checks were deselected from this run and retain their
separate outcomes.

The broad attempt4 run was interrupted by a host restart. The subsequent
four-lane attempt5 completed with **44,398 passes, 15 failures, 920 skips,
58 expected failures and eight unexpected passes**. Its original failed
verdict remains under `build/alma9-full-suite-run/attempt5/`; later focused
passes do not replace it. The larger focused revalidation was interrupted
during fleet cleanup and also remains failed. Gateway upload fanout is still
unresolved. Final full-suite, coverage and separately scheduled live results
remain outstanding, and the analyzer limitations above remain open. Local
`main` remains unpushed.

## 12. macOS source build via Homebrew — 2026-09-15

Dependency audit for building the module and the native client on macOS.
Host: macOS 15 (Darwin 24.6.0), x86_64, Homebrew 7.0.1 at `/usr/local`,
Command Line Tools with pkg-config 3.0.7 (`pkgconf`). The step-by-step
build is in `docs/01-getting-started/macos-quickstart.md`; this section
records which libraries come from where.

The module's `config` locates each library through `pkg-config`, so the
question is which formulae put a usable `.pc` file on the default search
path (`/usr/local/lib/pkgconfig` plus Homebrew's macOS SDK shim directory).

### 12a. Required from Homebrew

```bash
brew install pkgconf openssl@3 pcre2 zstd brotli jansson krb5
export PKG_CONFIG_PATH="$(brew --prefix krb5)/lib/pkgconfig"
```

| `pkg-config` name | Formula | Verified version | Role |
|---|---|---|---|
| `openssl` | `openssl@3` | 3.6.4 | required, must be >= 3.0 |
| `libpcre2-8` | `pcre2` | 10.48 | nginx core |
| `libzstd` | `zstd` | 1.5.7 | mandatory codec |
| `libbrotlienc`/`libbrotlidec` | `brotli` | 1.2.0 | mandatory codec |
| `jansson` | `jansson` | 2.15.1 | required |
| `krb5`/`krb5-gssapi` | `krb5` | 1.22.2 | keg-only, needs `PKG_CONFIG_PATH` |

**krb5 is the one trap.** Homebrew's `krb5` is keg-only, so without
`PKG_CONFIG_PATH` the `pkg-config --exists krb5` probe fails and `config`
falls back to `/usr/bin/krb5-config`. That binary is Apple's Heimdal
("Kerberos 5 release 1.7-prerelease") and `krb5-config --libs gssapi`
returns only `-lkrb5`, so the MIT GSSAPI symbols the plugin uses are never
linked. With the keg on the path the probe yields
`-lgssapi_krb5 -lkrb5 -lk5crypto -lcom_err` as on Linux.

### 12b. Optional from Homebrew

| `pkg-config` name | Formula | Verified version | Role |
|---|---|---|---|
| `liblzma` | `xz` | 5.8.3 | lzma codec |
| `liblz4` | `lz4` | 1.10.0 | lz4 codec |
| `fuse3` | `macfuse` (cask) | 3.18.2 | client FUSE mounts; installs `/usr/local/lib/pkgconfig/fuse3.pc` |
| — | `xrootd` | — | reference `xrdcp`/`xrdfs` for differential tests |

### 12c. Satisfied by the macOS SDK

`zlib` (1.2.12), `bzip2` (1.0.8), `libxml-2.0` (2.9.13), `libcurl` (8.7.1)
and `sqlite3` (3.43.2) all resolve through Homebrew's SDK shim
`.pc` directory without any formula. The corresponding formulae (`zlib`,
`bzip2`, `libxml2`, `curl`, `sqlite`) are keg-only and are not needed;
installing them has no effect unless their kegs are also added to
`PKG_CONFIG_PATH`.

### 12d. Linux-only, no Homebrew equivalent

`liburing`, `libseccomp`, `librados`, `libradosstriper` and `libcephfs` do
not exist for macOS. `config` disables io_uring, seccomp and the Ceph
backend when their probes fail; the `BRIX_ENABLE_IO_URING` /
`BRIX_WITHOUT_CEPH` switches are not required. The `brix-tools` Ceph
migration utilities and the XrdCeph client tools cannot be built on macOS.

### 12e. Status — first macOS build and fleet run (2026-09-15)

The module, the native client and the pytest fleet now build and run on
this host. As recorded in §9 native macOS builds are still not certified
by the Alma9 validation; what follows is the state of the port, not a
certification.

**Build.** `./configure --add-module=$REPO` against nginx 1.28.3 with the
§12a environment; `make` links `objs/nginx` (5.1 MB). `objs/nginx -t`
without `-c` fails only because `/usr/local/nginx/conf/nginx.conf` does
not exist on a source build — test with a fleet config
(`objs/nginx -t -p <prefix> -c conf/nginx.conf`).

**Fleet.** `python3 -m cmdscripts.manage_test_servers start-all` boots
every registered member, `vo-acl` included: `brix_require_vo` is served by
the native VOMS verifier (`shared/voms/`), so it no longer needs a library
macOS lacks. `tests/brix_suite/host_caps.py` still drops any member whose
third-party daemon binary is missing instead of letting one launch failure
abort the collection-time barrier; tests that declare such a member are
skipped with the reason.

**Darwin defects fixed while bringing the suite up.** Each one was
invisible in the error log and only showed as a test failure:

| Area | Symptom on macOS | Fix |
|---|---|---|
| WebDAV / HTTP plane | Every `brix_webdav` request answered by nginx's static handler (plain 404/405); `nginx -t` clean | Six `#if !defined(__APPLE__)` "Phase 3" stubs (`src/protocols/webdav/{postconfig,postconfig_proxy_capath,module_directives_cert,auth_cert}.c`, `src/observability/dashboard/files.c`, `src/auth/krb5/carry.c`) compiled no-op bodies, so the postconfiguration never installed the phase handlers. Stubs removed; the real code builds against Homebrew MIT krb5 and nginx's SSL module. |
| Path confinement | `GET /brix/api/v1/download?path=../secret.txt` served the file (and every `brix_*_beneath` caller was unconfined) | `src/fs/path/beneath.c`: the Darwin arm was a bare `openat(2)`. Replaced by `brix_plat_openat2()` (`src/platform/darwin/path_wrapper.c`, `darwin_openat_resolve()`), a component walk emulating `RESOLVE_BENEATH` / `RESOLVE_IN_ROOT` / `RESOLVE_NO_SYMLINKS` (EXDEV / ELOOP verdicts as on Linux). |
| Atomic rename | create-if-absent and exchange renames failed closed with `ENOTSUP` | `renameatx_np(RENAME_EXCL)` / `renameatx_np(RENAME_SWAP)` in the Darwin arms of `brix_renameat_noreplace_fallback` / `beneath_two_path`. |
| `kXR_open_apnd` | A write at offset 0 on an append handle overwrote the head of the file | Darwin `pwrite(2)` honours the offset on an `O_APPEND` fd (Linux appends). `brix_sd_obj_t.append` + a `write(2)` path in `sd_posix_pwrite` keeps the wire semantic. |
| Dashboard file browser | `statx(2)` does not exist | `dashboard_entry_stat()` helper: `statx` on Linux, `fstatat` + `st_birthtimespec` elsewhere. |
| Credential store | no `/dev/shm` | default store is `/tmp/brix-creds` on Darwin (`shared_conf.h`, `cred_stage.c`). |

**Harness gaps closed.** No `/proc` (pid checks use `ps`), no `ss`
(`lsof`-backed listener table), helper scripts launched as bare `python3`
(Homebrew's interpreter has no `cryptography`; they now use
`sys.executable`), stock xrdcp 6.x rejecting `--allow-http` and lacking a
plugin config for `libXrdClHttp` (probed and generated by
`test_a_webdav_clients.py`), an unresolvable hostname aborting the
interop pair launcher, and the xrdcl worker probe caching a transient
spawn failure for the whole session.

**Known open items on macOS.** `nginx` workers log
`impersonate: worker capset failed (78: Function not implemented)` on
every start (no Linux capabilities; impersonation is effectively off);
each worker logs `open socket #10 left in connection 1` at shutdown (a
pipe registered as a connection is not closed on exit — cosmetic);
`fleet restart` once raced its own PKI regeneration
(`python3 fleet_prep.py` then `start-all` recovers); stock xrootd daemons
survive `stop-all` (`pkill -f /tmp/xrd-test`).

**Recorded runs (2026-09-15, attached to a `start-all` fleet).**

| Run | Files | Result |
|---|---|---|
| Core slice (write/readv/dirlist/checksum/credential-dir/open-flags/aio/acc + dashboard files, WebDAV clients, delegation two-step) | 11 | 78 passed, 5 failed before the confinement / xrdcp fixes; 75 passed, 3 failed after (remaining 3 were the 0000-mode stat, fixed next) |
| Confinement parity (`test_conf_stattypes*.py` interop pair vs stock xrootd 6.1.1, `test_dashboard_files.py`) | 3 | 116 passed, 1 skipped |
| Broad sample, every 5th test file | 291 | 2106 passed, 100 failed, 392 skipped, 2282 errors in 1h27m — **contaminated**: 42 minutes in, a concurrent `operator_runtime suite --fast -n 6` run from another terminal took fleet ownership, wiped `/tmp/xrd-test` (including pytest's basetemp) and restarted the fleet. The 16 files that completed before that point passed except `test_audit15f_cms_node_legs.py` (5: CMS perf-feed / dial-timeout expectations), `test_audit15h_dashboard_session_ttl.py` (3: no session cookie issued) and `test_audit15h_tpc_lifetime.py` (1: reads `/proc`). |

Two sessions must not both own the fleet: check
`ps -axo pid,lstart,command | grep -E 'pytest|operator_runtime'` before a
`start-all`/`stop-all` or a long sweep on a shared host.
