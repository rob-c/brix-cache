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
  libxrootd-dev libxrootd-client-dev libxrootd-server-dev \
  python3-rados python3-cephfs golang-go \
  podman podman-docker uidmap slirp4netns fuse-overlayfs
.venv/bin/python -m pip install -r requirements-optional.txt
.venv/bin/python -m pip check
```

`globus-gass-copy-progs` supplies `globus-url-copy`; `rpm` supplies `rpmbuild`;
`nghttp2-server` supplies `nghttpd`. `nginx-core` supplies the independent stock
nginx used by the RPM proxy recipe tests; it does not replace the separately
built module binary selected by `NGINX_BIN`. `libxrootd-private-dev` is no
longer required: the SSI interop test that linked `libXrdSsiLib.so` has been
removed (see below).
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
- **XRootD sources are no longer used by anything in this repository.** The two
  consumers that needed an XRootD source checkout have been removed: the SSI
  interop test compiled a C++ client against `XrdSsi/*.hh` and `-lXrdSsiLib
  -lXrdCl -lXrdUtils`, and `tests/clientconf/flag_inventory.py` parsed
  `XrdApps/XrdCpConfig.cc` / `XrdCl/XrdClFS.cc` to derive the stock client
  surface. The surface is now a pinned in-repo table and the SSI engine is
  covered by the raw-wire conformance tests in `tests/test_ssi_wire.py`. Do not
  reintroduce a dependency on the XRootD source tree — this is a clean-room
  implementation. `BRIX_SRC` / `BRIX_SRC_DIR` are no longer read.

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
  xrootd-server-devel lz4
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
(Historical: that run also unpacked XRootD 5.9.7 reference sources at
an XRootD source checkout for the client option inventory and SSI header consumers. Both
consumers have since been removed — see §1e — and no XRootD source tree is
needed.)

Module-only nginx builds omit core objects used by standalone C tests. For
this isolated CMake build, `nginx-src/objs` points to `../modules`; the generated
Makefile was used to compile `ngx_string.o`, `ngx_palloc.o`, `ngx_shmtx.o`, and
`ngx_alloc.o` without editing nginx sources or generated Makefiles. Set
`NGX_SRC` and `TEST_NGINX_SRC` to the configured `nginx-src` directory, and
`TEST_NGINX_OBJS` to its `objs` path when running those tests. `BRIX_SRC` /
`BRIX_SRC_DIR` are obsolete and no longer read by any test.

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
`libubsan`, `strace`, and Python `psutil` (now required) and optional `numpy`
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
  xrootd-server-devel xrootd-scitokens xrootd-voms \
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
| `python3.12-devel`, `xrootd-devel`, `xrootd-client-devel`, `xrootd-server-devel` | Build the Python XRootD bindings (`python3-xrootd`, used only to drive the reference server as an external oracle). `xrootd-private-devel` is no longer needed: nothing in the repo compiles or links against XRootD headers or libraries. |
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
At this checkpoint `requirements-optional.txt` gained `psutil` and `numpy`, which were also
needed to exercise the platform tests instead of skipping them.

The verified venv contains Python 3.12.14, pytest 9.1.1, pytest-xdist 3.8.0,
pytest-timeout 2.4.0, pytest-rerunfailures 16.6.1, XRootD 6.1.1,
cryptography 46.0.7, pyOpenSSL 25.3.0, psutil 7.2.2, and numpy 2.5.3.

`psutil` has since moved to `requirements.txt`: native interface discovery and
actual worker saved-identity inspection require it. Installing the declared
test requirements must enable those checks rather than silently skip them.
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
brew install pkgconf openssl@3 pcre2 zstd brotli jansson krb5 sqlite
export PKG_CONFIG_PATH="$(brew --prefix openssl@3)/lib/pkgconfig:$(brew --prefix krb5)/lib/pkgconfig:$(brew --prefix sqlite)/lib/pkgconfig"
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
and `sqlite3` (3.43.2, in the original September recording) resolve through Homebrew's SDK shim
`.pc` directory without any formula. The corresponding formulae (`zlib`,
`bzip2`, `libxml2`, `curl`, `sqlite`) are keg-only and are not needed;
installing them has no effect unless their kegs are also added to
`PKG_CONFIG_PATH`.

**October 2026 correction for the server's pblock backend:** use Homebrew
`sqlite` and put its keg on `PKG_CONFIG_PATH`, as in §12a above. On the tested
macOS 27.2 host, opening a pblock catalog in an nginx worker crashed inside
Apple's SQLite `openDatabase`/OS logging path. The same real cache/stage flow
passes with Homebrew SQLite 3.54.0. The module's configure probe now consumes
the selected SQLite headers and libraries together; the Darwin verifier
supplies the Homebrew keg. A successful SDK compile alone was not sufficient
runtime evidence.

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

**Known open items on macOS.** Linux capability operations are capability-gated
out on Darwin; requested confinement modes and saved-ID transitions fail closed,
and the worker sandbox denies process execution. Consequently the server rejects
subprocess-backed prepare/FRM/CMS and OIDC-agent/token-exchange configuration or
requests explicitly, while the standalone client retains its credential-helper
support. Each worker logs `open socket #10 left in connection 1` at shutdown (a
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

## 13. macOS v2.0 ARM64 validation (2026-10-04)

Native host: macOS 27.2 (26B5091g), arm64, Apple clang 21.0.0. Homebrew
inputs: nginx 1.31.6, OpenSSL 3.6.5 for BriX/client dependency probes and MIT
krb5 1.22.2. The platform verifier extracted Homebrew's content-addressed nginx
source archive, replayed its configure arguments, added `--with-threads` and
`--add-dynamic-module=$REPO`, then built with the module's `-Werror` policy.

| Gate | Result |
|---|---|
| matched nginx + both dynamic BriX modules | PASS; both modules loaded by the derived nginx |
| non-root live WebDAV smoke | PASS; `README.md` fetched through `brix_webdav` over a Unix socket and compared byte-for-byte |
| Darwin security / event / CMS sysload / AIO / CRC probes | PASS |
| native client build + C units + man/completion guards | PASS |
| targeted Darwin pytest contracts | 24 passed |
| file-size / documentation-link / build-coverage / PAL / DNS / VFS guards | PASS |
| AlmaLinux 9 ARM64 Linux PAL compile + CMS meter unit | PASS in Lima |

The verifier summary was `Success: 1, Failed: 0, Skipped: 0`. The generated
Darwin residue table contains 13 explicit `ENOTSUP`/`ENOSYS` sites; these are
documented unsupported contracts, not silent-success branches. An Intel runtime
claim still requires an Intel Homebrew nginx host and is not inferred from this
ARM64 result.

## 14. Cross-platform v2.0 validation — in progress (2026-10-17)

These are retained engineering baselines, **not a green release certification**.
Subsequent fixes and focused checks do not retroactively change their counts.
Fresh full reruns must establish the final result for each target.

| Completed baseline | Passed | Failed | Errors | Skipped | Total records |
|---|---:|---:|---:|---:|---:|
| macOS ARM64, latest completed frozen-source baseline | 45,770 | 3 | 0 | 2,105 | 47,878 |
| NixOS ARM64, latest completed frozen-source baseline | 46,644 | 8 | 21 | 1,210 | 47,883 |
| Alma8 ARM64 userland in Podman, latest frozen-source baseline | 46,316 | 9 | 13 | 1,545 | 47,883 |
| Alma9 ARM64, latest completed frozen-source baseline | 46,511 | 31 | 0 | 1,326 | 47,868 |
| Alma10 ARM64, latest completed baseline | 46,812 | 0 | 3 | 1,007 | 47,822 |
| Ubuntu24 ARM64, latest frozen-source baseline | 46,448 | 9 | 16 | 1,410 | 47,883 |
| Ubuntu26 ARM64, latest frozen-source baseline | 46,341 | 7 | 13 | 1,522 | 47,883 |
| Fedora Rawhide ARM64, latest completed frozen-source baseline | 46,600 | 11 | 26 | 1,246 | 47,883 |

These runs use the runner's four standard lanes, which include both fast and
slow tests. They exclude `suite_job` compiler/analyzer wrappers unless
`--include-suite-jobs` is enabled; `tests/userns` also needs a separate invocation.
Passing the standard lanes alone is not evidence that these omitted jobs passed.
Supplemental runs must retain their own collection, outcome and skip counts.

Five earlier macOS baseline failure areas subsequently passed a 41-test live rerun.
This includes deterministic JWT signature corruption with a positive clean-copy
control and a real fault-proxy replacement counter: random bit corruption is not
evidence that a short authentication credential was actually changed. Rawhide's
nine failure areas subsequently passed a 48-test rerun; its separate root-only
multi-user run passed 259 tests. Neither focused run replaces a fresh full run.
NixOS separately passed all nine standalone namespace tests and 259 root-only
multi-user tests. Its namespace fixtures now use the caller's actual subordinate
ID allocations and isolate the host nscd socket only inside private mounts.
The duplication guard still reports shared-helper extraction opportunities;
the native complexity, size, build-source coverage and documentation-link
guards pass separately.

The live Ceph follow-up passed all five oracle checks plus six harness-contract
checks. It uses a native ARM64 Linux build image with librados/striper/CephFS
and an x86-64 demo-cluster oracle in Docker; this is not native macOS Ceph
support. Drivers and rescue tools take their source closure from the client
Makefile. Path-native RADOS truncate atomically asserts existence before resizing,
so a missing object returns ENOENT instead of being created; caller-scoped CephX
write denial remains enforced by the actual cluster.

CMS interoperability follow-ups add the required manager LOGIN acknowledgment
after authentication/admission, strict mandatory scalar/string parsing, and
refusal of a repeated LOGIN during an outstanding SSS challenge. The challenge
bypass regression fails against the retained old module and passes after the
fix. Broader wire and reference-node reruns remain separate evidence.

Counts are JUnit testcase records across the four standard lanes, not deduplicated
test IDs or feature counts. Expected failures are included in skipped; unexpected
passes are included in passed. Setup/teardown error records can add a record for
an otherwise passing test. Root-only and focused runs are separate evidence and
must not simply be added to this table's totals. In particular, a 99% pass rate
among executed tests is not a 99% execution rate across collected tests.

An earlier macOS baseline failure was an auxiliary native binary without
external-SDK runtime paths; its corrected build and fanout checks pass. The
latest completed frozen-source run instead retains three source-quality failures:
two Python path-complexity checks and one CMS native-complexity check. Their
current-source repairs pass the corresponding guards separately.
Alma10's three remaining setup errors were native units linking a coarse nginx
string object without its allocation dependencies; units now compile the real
selected SDK string source with section garbage collection. An earlier Ubuntu24
baseline failure exposed an actual async-client use-after-free: queued CLOSE commands
freed connection pointers before the collected readiness batch was dispatched.
The deterministic regression fails against the old ordering and passes after
dispatch is moved before control commands. Real io_uring, TLS fallback, native
build-graph and deferred-reply follow-ups pass 69 checks (three macOS-only skips).
Fresh current-source full runs remain necessary; these repairs do not rewrite
the retained baseline counts.

Coverage follow-ups separate client and server bearer-file permissions: stock
ztn correctly refuses the shared worker-readable fixture, so client conformance
now receives an owner-only copy without changing the server's credential. The
previously skipped token tier ran 186 passing cases on Ubuntu24, with two explicit
checksum-capability skips. Security readiness marks are evaluated at execution
time instead of import, before fleet startup; a separate macOS main-server run
passed all 53 selected credential/XML/path checks. These are additional runs,
not replacements for baseline skip counts.

The CVMFS conformance consumer had grown to 29 twenty-port blocks plus 48 matrix
ports while its reservation still covered only 588 ports. Its last forty ports
overlapped differential interoperability listeners. The catalogue is now shared
with the ledger, its full 628-port reservation is derived from that catalogue,
and interoperability and mock allocations follow it. Boundary checks verify
the real consumers, not merely a self-consistent ledger. Earlier full snapshots
retain the old allocation and therefore cannot certify this coverage repair.

The Ubuntu24 CVMFS composition oracle subsequently passed all four live cases:
comparison with Podman's flattened tree, execution from the BriX FUSE rootfs,
unavailable-origin rejection, and corrupted-object rejection. Seven harness
regressions pass separately. The command-less fixture image needs an explicit
command for `podman create`; rootless access to the FUSE mount needs
`user_allow_other` in the dedicated VM's `/etc/fuse.conf`. The rootfs leg uses
a short private Podman runtime, resolves the OCI tag symlink before parsing
`:O`, and stops only its own pause namespace. It does not migrate shared
container state. BriX runs natively on ARM64; the official CVMFS service image
used as an independent oracle runs through QEMU x86-64 user-mode emulation.
Neither this focused result nor the emulator establishes native ARM64 support
for that external container image.

The independent Go-HEP v0.40.0 tools were built natively for Darwin ARM64 and
as static Linux ARM64 executables; all ten interoperability checks passed on
both macOS and Ubuntu24. Installing Go alone does not enable these cases:
`TEST_GOHEP_BIN` must point at the built `xrd-ls` and `xrd-cp` tools.
Separate privileged multi-user runs passed all 259 cases on each of Ubuntu24,
Ubuntu26, Alma10 and the Alma8 userland container.

The NixOS checksum/write interoperability follow-up passed all 181 checks;
180 had skipped in the frozen run after the undersized CVMFS band collided
with their listeners. Kerberos reference tests now discover the installed
security framework and its same-ABI plugin, including an explicit plugin
directory rather than assuming `/usr/lib64`. Both NixOS and macOS passed
nine live reference/delegation cases plus nineteen library-layout and runtime
readiness contracts (28/28 each). The Kerberos fixture's outer ceiling now
includes its existing 180-second native-build budget; wire operation deadlines
are unchanged. Native-client refresh/robustness marks likewise defer their
service and fixture checks until execution; ten live macOS cases pass separately.
Those ten native-client cases also passed separately on NixOS.

The standalone namespace suite subsequently passed all nine cases on each of
Alma8 userland, Alma9, Alma10, Ubuntu24 and Ubuntu26. On Ubuntu the stock global
AppArmor restriction initially skipped two cases. A temporary, explicitly entered
test-process profile used Ubuntu's documented
[per-application user-namespace permission](https://documentation.ubuntu.com/release-notes/24.04/)
to run the proofs as the ordinary validation user. The named profile was removed
after each run and the global restriction was verified unchanged. This is not
evidence that production packages bypass Ubuntu's namespace policy.

The upstream MinIO image tags were no longer anonymously downloadable from
Quay or Docker Hub during this validation. A local ARM64 oracle was built from
the official [RELEASE.2025-10-15T17-29-55Z source](https://github.com/minio/minio/releases/tag/RELEASE.2025-10-15T17-29-55Z),
whose checksum-verified Go module is
`v0.0.0-20251015172955-9e49d5e7a648`. `BRIX_MINIO_IMAGE` selects that cached,
versioned image explicitly; an absent requested image cannot silently fall
back to another tag. The standalone STS harness now compiles the complete
production STS/DNS-pin closure against the selected nginx SDK, rather than
skipping after a missing DNS symbol. Only the absent nginx loop/cache are
substituted; real hostname resolution still uses BriX's libc DNS seam.
All nine DNS, MinIO STS and live gateway checks passed on both Ubuntu24 and
macOS. The image is a local test oracle, not an upstream-provided binary or a
new BriX runtime dependency; its provenance does not establish ongoing MinIO
maintenance or suitability for production deployments.

GSI TPC follow-ups removed a hard-coded `/usr/lib64` plugin directory and
Linux-only `ss` readiness probes. The reference security library and GSI plugin
now come from the same installed ABI; they cannot mix Nix's ABI-5 server with
the Python wheel's ABI-6 libraries. All five delegation/outbound TPC cases
passed on Ubuntu24, macOS and NixOS (NixOS additionally passed four layout
contracts). These were actual protocol exchanges, not startup-only checks.
The GSI fixtures' outer ceilings now include their existing bounded PKI-tool
budgets (60/90 seconds per invocation), rather than cancelling certificate
generation at the default 30 seconds. Wire-operation deadlines are unchanged;
all five live cases pass separately after this fixture-budget correction.

The kill tracer's optional process-group discovery is now bounded to one
second; a stalled diagnostic must not prevent the original termination call.
NixOS's renewal/cleanup follow-up passed 15 cases. Rawhide's 13 OCI setup errors
and three timeout failures passed all 16 focused reproductions with unchanged
code after the guest logged scheduler lag and a backwards clock jump. Those
observations do not rewrite the failed full-run records or prove a universal
timing cause. Ubuntu24's unchanged rate-limit cases passed a separate rerun at
roughly 4,400 served requests/second; their 2,000-request/second acceptance
threshold was not lowered.

A subsequent NixOS follow-up reproduced two POSC conformance failures caused by
an uninitialized caller-owned status after successful client operations. The
probe now clears that status before starting, retaining real server refusals.
Four explicit success/error/authorization regressions, the two original failing
cases and fourteen collection checks passed together (20/20) on both NixOS and
macOS. Collection-only subprocesses now bound `--confcutdir` to their declared
root so pytest does not enumerate inaccessible ancestor directories. Rawhide's
six daemonized FUSE checks also passed an unchanged isolated rerun; the earlier
full-run write failure remains retained evidence, not retroactively green.

Stream-log follow-ups select a new transferred-byte session instead of the last
TCP readiness close, and wait for the current query's checksum row rather than
accepting an older session. The JSON observer uses the existing structured-log
decoder and a complete JSON decoder, enabling two previously skipped assertions;
missing access records now fail those checks. Ten observer regressions cover
delayed writes, stale evidence, malformed records and braces inside string values.
The combined logging/observer checks pass separately; these do not rewrite the
retained full-run logging failure or the earlier skip counts.

A later macOS full-run lane exposed stale GSI ownership-test models, four
intentional DNS/OCI literals missing the existing host-literal annotations,
and a historical cache-helper move check that did not replay the approved
client-build locking change. The move check now recognizes only that exact
transformation; deadline changes and rollback to unlocked execution still fail.
GSI fixture models follow the installed-library contract and explicitly reject
foreign-listener killing. All 79 related contracts pass in separate macOS and
Alma9 runs.
Directory-listing size comparisons now seed a private directory and compare
each server's individual stat result, avoiding unrelated concurrent root entries;
the two live reference comparisons and three isolation regressions pass together
on both macOS and Alma9.

Full-run source snapshots remain frozen. Repairs made after a run started are
verified separately in an independent source copy, with a rebuilt native client,
an explicit file/hash manifest, and separate JUnit reports. Those supplemental
counts do not replace failed full-run records or certify a new complete run.
Current-source Alma9 and Alma10 full reruns are queued behind their existing
fleets; other targets retain their full runs followed by these supplemental
checks. No second full fleet is started in an already occupied guest.

Alma8 uses a dedicated AlmaLinux 8 container on an Alma10 Linux 6.12 host kernel;
it does not certify an Alma8 kernel or broaden the existing EL8 client-package
support boundary. Native macOS uses Homebrew nginx 1.31.6 source and configure
arguments, both BriX modules, Homebrew SQLite 3.54.0, and the native client. Its
nginx/module OpenSSL ABI follows Homebrew nginx; the client independently uses
its selected OpenSSL 3 SDK. FSKit availability requires an actual mount probe,
not merely an installed or registered macFUSE bundle.

The follow-up work includes a bounded iterative WebDAV directory walk, native
TCP accounting and descriptor closure through the PAL, semaphore-free SHM mutex
creation, explicit standalone HTTPS trust selection, and malformed deferred-AIO
reply rejection. S3/XML HEAD replies now suppress their body and preserve header
send errors: wire-level regressions fail against the retained old module and
pass against the corrected module without disabling HTTP connection reuse.

EL8 follow-ups cover versioned glibc stat entry points in the preload PAL,
native-layout validation, original-libc fallback, and unchanged non-prefix path
semantics. Static consumers receive pthread and selected external SDK/runtime
paths from `libbrix.pc`; live FUSE consumers use that same dependency contract.
VOMS expiry fixtures no longer require new OpenSSL CLI date-setting options.
The private MIT Kerberos lab runs as its ordinary owner without an unnecessary
Linux namespace prerequisite, retaining wrong-password and wrong-principal tests.

VM listeners are isolated from Lima's host port forwarding so parallel fleets
do not capture one another's ports. Run only one full fleet in a guest at a
time: a follow-up Alma9 run was invalidated by kernel OOM kills when two fleets
shared 12 GiB. Its partial reports are retained but excluded from certification;
the guest was increased to 20 GiB and six CPUs for a clean rerun. Lifecycle-only
focused checks can prepare fixtures without booting another full fleet.
Reference XRootD also has a Unix admin-socket path-length limit: NixOS uses a
short private bind alias under the validation user's home rather than a deeply
nested test-root spelling. A startup-only run rejected by that limit is not a
completed test baseline.
On Linux, the complete listener reservation, including mock leases, must fit
below the kernel's outgoing source-port floor. A base of 30000 left named
listeners safe but caused later mock binds to collide; the import-time guard
now checks the complete reservation. Use the default base of 10000 for full
guest suites, not a range that overlaps ephemeral client ports.
The single-server lane-ownership proof reserves its own explicit sixteen-slot
mock budget for transient child-import readiness probes, rather than claiming
a second full mock fleet. Its complete interval is disjoint from the parent's
full reservation and below the ephemeral floor; excess draws still fail closed.
All twenty live and boundary checks passed separately on macOS and Alma10.
This does not shrink the default full-suite reservation or replace full-run
results. macOS FUSE coverage remains pending operator enablement of FSKit.
Linux validation trees use disk-backed XFS
where the suite exercises large xattrs; Rawhide's previous tmpfs-exhausted run
is not valid platform evidence. Ubuntu's stock `fusermount3` AppArmor profile
does not permit arbitrary `/var/tmp` mountpoints: bind the private XFS tree under
the validation user's home directory and set `TEST_ROOT` to that home path.
A real nested CVMFS automount passed all 13 checks there on Ubuntu26 without
relaxing AppArmor policy. Diagnostic environment fixtures must use pytest-owned
temporary paths and an explicit public-variable allowlist, never dump inherited
credentials into shared `/tmp` filenames. Source snapshots, per-lane XML, failure records,
skip reasons, disk telemetry and focused rerun logs are retained under the
ignored `build/release-validation` workspace and each VM's private validation
directories. No project Git write is authorized; the operator approved Git
writes only inside disposable test fixture repositories.

## 15. OpenSSL 1.1.1 and FreeBSD native targets — in progress

[OpenSSL 1.1.1 on Alma8](OPENSSL111.md) now has a version-neutral wrapper
backend, real full-server/client builds and native crypto/proxy proofs. The
AGPL licence is unchanged; legacy-linked release distribution remains gated
pending licensing review. Its canonical full-suite run is still in progress.

[FreeBSD 15+](FREEBSD.md) now has native server/client adapters, a repeatable
build-and-test entry point and dedicated ARM64/x86-64 CI lanes. Native ARM64
module-load and byte-exact transfer proofs also pass under the installed nginx
package. The target guide records the tested scope and explicit limitations;
it does not claim Linux capability/broker parity or a completed full-suite
certification.


## 16. Dependency refresh and macOS ARM64 build — 2026-11-06

This refresh updates the Python requirement bounds, Astro/npm lock, GitHub
Actions, nginx defaults, Kubernetes/Calico tools, GFAL2 source pin, immutable
Python helper images, and the NixOS 26.05 lock. Compatibility-matrix targets
(such as AlmaLinux 8/9/10/11 and Ubuntu 22/24/26) remain distinct targets;
package-manager dependencies use their distribution's supported packages.
The explicit old-nginx compatibility lane and the last available EL8 Ceph
repository are retained. They are compatibility coverage, not default builds.
BriXTest retains lower bounds for its supported older Python interpreters while
allowing the current dependency majors. The main suite uses Python 3.14 because
the released macOS XRootD 6.2.1 binary wheel is available for that interpreter.
No XRootD source was consulted or built for this validation.

### Device environment

The native build uses macOS 27.2 ARM64, Apple Clang 21, nginx 1.31.8, OpenSSL
4.1.0, curl 8.23.0, Python 3.14.10, pytest 9.2.0 and pytest-xdist 3.8.0.
The website uses Node 26.13, Astro 7.4.7, `@astrojs/check` 0.9.12 and
TypeScript 6.0.3. The checker supports TypeScript 5/6, so TypeScript 7 is
held back by its peer dependency. Native dependency headers and
libraries come from Homebrew. Install the build and local-test prerequisites:

```sh
brew install cmake ninja pkgconf nginx python@3.14 openssl@4 pcre2 \
  jansson krb5 curl libxml2 zlib zstd brotli xz bzip2 lz4 sqlite \
  xrootd haproxy nghttp2 go helm kubernetes-cli minikube llvm make
python3.14 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install --upgrade --only-binary=xrootd \
  -r requirements.txt -r requirements-optional.txt -r requirements-dev.txt \
  './brixtest[all,dev]'
.venv/bin/python -m pip check
```

The final Python audit leaves only upstream-constrained transitive updates:
CodeChecker 6.29.3 requires setuptools/types-setuptools 80, SQLAlchemy 2.0 and
portalocker 3; Radon 6 requires mando below 0.8; botocore requires python-
dateutil below 3. The environment passes `pip check`.

The Kubernetes tooling uses a separate virtual environment: Kubernetes 37 and
botocore currently require incompatible python-dateutil major versions.

```sh
python3 -m venv build/k8s-venv
build/k8s-venv/bin/python -m pip install -r k8s-tests/pytests/requirements.txt
```

Use Homebrew's nginx source archive and its configure arguments so the dynamic
modules match the installed nginx ABI. In this run the source and logs live in
`build/dependency-update/`, and `build/dependency-update/env.sh` selects the
built server, both modules, Python paths, and the private test root. The source
archive and configure arguments are installed under
`$(brew --prefix nginx)/share/nginx/src/`; extract the archive into a fresh build
directory and append `--with-threads --add-dynamic-module=<absolute-repo-path>`
to those arguments. Include the Homebrew jansson, Kerberos and libxml2 headers,
and provide their pkg-config paths along with OpenSSL, curl and SQLite. Build
with `make -j8`. Build clients with:

```sh
make -C client -j8 HOMEBREW_OPENSSL_PREFIX="$(brew --prefix openssl@4)" all aio-smoke
```

The Homebrew nginx package links OpenSSL 4; compiling its dynamic modules
against OpenSSL 3 does not produce a compatible module. The client Makefiles
and Homebrew formula now default to OpenSSL 4 too.

### Test runtime details

Put Homebrew's OpenSSL, Kerberos tools and curl before the system tools on
`PATH`. The stock Homebrew XRootD HTTP plugin otherwise loads the system curl
and LibreSSL 3.3.6; selecting `DYLD_LIBRARY_PATH=$(brew --prefix curl)/lib` for
the validation process fixes its TLS interoperability with the current stack.
This does not disable certificate verification. Set `XRDNET_IDENTITY=localhost`
for the stock client on macOS. Build the independent Go-HEP clients at v0.40.0
and point `TEST_GOHEP_BIN` at the directory containing `xrd-cp` and `xrd-ls`.

macOS has no Homebrew VOMS client formula. The validation environment provides
`voms-proxy-fake` and `voms-proxy-info` through a local AlmaLinux 9 container
with `voms-clients-cpp`. The wrappers stage only the disposable certificate
fixture inputs under the repository, preserve private-key permissions, disable
container networking, and use the fixture's own trust store. This staging avoids
Docker Desktop access failures for pytest's private temporary directories. They live in `build/dependency-update/bin` for this device.

The main suite loads its own harness: disable the separately installed BriXTest
pytest entry point using `PYTEST_ADDOPTS='-p no:brixtest -p no:platformdirs'`.
Run BriXTest separately from its subdirectory with
`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1`, an empty `PYTEST_ADDOPTS`, and explicit
`-p xdist.plugin -p pytest_timeout`; its conftest loads the BriXTest plugin.
Give these runs different `TEST_ROOT` values. Run full root-suite lanes alone;
nightly build jobs manage a fleet and reconfigure their selected nginx tree.
Keep `test_ci_asan_runner_green`, both analyzer cases and the coverage job in
separate runs with separate build trees.
Keep the device awake and powered throughout live tests. Use
`caffeinate -is -w <test-process-pid>` as a sibling watcher: launching the test
command through `/usr/bin/caffeinate` strips `DYLD_LIBRARY_PATH` and
`DYLD_FRAMEWORK_PATH` under macOS SIP, hiding the extracted macFUSE SDK. The
local `build/dependency-update/keep-awake.py` wrapper starts that watcher and
executes the test command with its original environment. Clamshell sleep
interrupted an earlier parallel run; its failures are not a clean result.

pytest 9.2 replaced the private string node-ID storage with structured IDs.
xdist 3.8 still writes the older field, silently losing `loadgroup` scheduling.
The suite's existing grouping helper now updates both representations; its
collection, fail-fast and live fixed-port tests verify the compatibility path.
Other repairs cover macOS process ownership and xattrs, broker backlog,
Mach-O library capture, certificate dates relative to the run date, isolated
mock cleanup, UDP readiness, and the current stock `xrdfs stat` time format.
The full-proxy cases now share one worker because their negative assertion
reads a shared server log. The installed-library consumer selects its staged
library through both ELF and Mach-O loader paths while preserving dependency
SDK paths. A fresh six-worker run passed all **49 focused cases**, including
these repairs, cluster/federation redirects, stock-client stress and MinIO STS.
Mesh cleanup also checks exact directory ownership through the existing process
inspection helper before stopping a mesh or sweeping its listeners. An empty
child registry uses the same port ladder as its parent; the old port-only sweep
killed the parent's CMS and hybrid meshes. The read-only diagnostic identified
85 parent-owned targets and no child-owned processes. All **53 ownership and
migration checks** pass, and the real child-teardown regression preserves the
main listener and both meshes with clean fleet conservation and final teardown.
The MinIO image registries denied anonymous pulls, so the test oracle was built
from the same checksum-verified official release recorded in §14 using Go
1.27.3. `env.sh` selects `BRIX_MINIO_IMAGE=brix-dependency-minio:20251015`;
its fixed-port cases stay on one worker. All **three serial STS gateway cases**
also pass, replacing their earlier missing-image skips.
The client-conformance run passes **85 tests with one existing xfail** against
both macOS XRootD 6.2.1 and EL9's packaged 5.9.8 binaries. Its timestamp
comparison permits only the current client's explicit UTC suffix; **22
regression cases** cover both native and Kubernetes helpers, preserving
differences in times, nonzero offsets, malformed values and other fields.
The Kubernetes lab reuses a healthy cluster only when its selected context,
driver, node count and pinned version match, then waits for ready nodes. This
avoids redundant `minikube start` calls fetching release metadata during every
scenario. Authority pods now have HTTP readiness probes, and short-lived probe
pods retain their logs until their exit status has been checked. Log EOF can
precede the kubelet's final status update, so probes wait for the terminated
state before reading the exit code; failed and missing status remain errors.
All **88 Kubernetes tooling tests** pass.

HAProxy health checks now perform the repo-defined root handshake, and the
failover test waits for observed backend health transitions. The connection-only
check on this device continued to report a stopped backend healthy. The repaired
HA and token-authentication checks pass **26 tests**, with one Linux procfs skip.
Expired-certificate fixtures use the shared date-relative certificate helpers;
OpenSSL 4 no longer accepts their former zero-day certificate command.

S3 POST now shares PUT's existing-parent probe before attempting parent creation.
This preserves child writes under a depth-zero lock on an existing parent, while
still rejecting writes to locked targets. Both root and nested parent cases fail
against the previous build and pass with the fix. All **21 S3/cross-protocol lock
checks** also pass against the rebuilt ASan/UBSan server. The **11 network-fault
stream and client recovery checks** pass in an isolated run.

Storage durability calls now use the existing `brix_plat_fsync_data` adapter.
This keeps Linux's data-sync behavior and uses the Darwin adapter's full-sync
operation with its fsync fallback. Upstream Clang rejects the former direct
`fdatasync` calls against the macOS SDK. Hand-linked metadata tests use the same
real PAL implementation as the module. The final native storage integration run
passes **66 tests**, with one capability skip; the CSI scrub and cinfo native
checks pass too.

The SigV4 comparator initializes its encoded bytes explicitly for GCC's
uninlined coverage build. The optimized native machine code is unchanged;
all **36 presigned-request, authentication-oracle and canonicalizer checks**
pass against the rebuilt ASan/UBSan server. The EL9 Ceph build uses the supported
`rados_read_op_stat` API for version-only probes; it does not consume the
timestamp, so the high-resolution variant is unnecessary. The Ceph path,
metadata and client-build checks pass **44 tests**.

### Validation evidence

Logs and JUnit results are retained under `build/dependency-update/`. Validation
completed on 2026-11-08: native nginx/modules and clients build; repeated incremental builds
are no-ops; the six CMake tests and native client tests pass; the website check
reports zero errors/warnings across 26 files, builds 15 pages, and npm audit
reports no vulnerabilities. The site workflow now runs its declared check before
building. All 111 focused harness checks,
38 grouping checks, 23 live grouping tests, six stock-client WebDAV tests and
88 Kubernetes tooling tests pass. All 15 Kubernetes end-to-end cases have passed,
including the remote suite and all seven lab image builds. The final full run
passed 14 cases; the fleet case passed separately after fixture teardown cleared
a pending Helm upgrade left by an interrupted run. The Linux ARM64
server image also builds.
The initial guard run passed 156 tests with two capability skips.

BriXTest completed with **1,253 passed and 10 skipped**. All 14 libFuzzer
corpus dry runs passed using Homebrew LLVM; Apple Clang does not ship
`libclang_rt.fuzzer_osx.a`. The macFUSE 5.5.0 package was verified against its
Homebrew SHA-256 and its SDK extracted locally; no system driver was installed.
`PKG_CONFIG_PATH`, `CPATH`, `DYLD_LIBRARY_PATH` and `DYLD_FRAMEWORK_PATH` in
`env.sh` select its headers, libraries and MFMount framework. Both FUSE clients
build and launch. OpenSSL 4.1 ASN.1 length compatibility preserves signed bounds;
all 13 native crypto compatibility tests pass against both OpenSSL 3 and 4.
The separate ASan/UBSan server and client builds pass a byte-exact transfer
with no reports. The sanitizer orchestrator passes all 30 tests and its
standing-fleet smoke performs a real read; Darwin explicitly disables the
unsupported LeakSanitizer runtime while retaining address and UB checks.
The full GCC 11 and supported Clang 21.1.8/CodeChecker 6.29.3 analyzer runs in
the AlmaLinux 9 ARM64 build image both pass with **zero findings across 1,232
source files**. The complete Ceph-enabled Linux server also compiles and links
against EL9's real librados. The VFS storage probe now states
its existing null-context precondition locally so separately analyzed helper
paths preserve the public confinement guard's contract. An additional macOS
LLVM 23.1.5 analysis reported 107 diagnostics before the include-guard repair,
including third-party macro expansion and Darwin-specific reports; that extra
analysis is not clean. Its reports are retained in
`build/dependency-update/codechecker-portability-diagnostics/`. No analyzer
baseline was expanded. gcov/lcov coverage runs separately from the native
functional lanes. The Docker validation root must live on disk-backed XFS:
Docker Desktop's overlay filesystem rejected a direct 4 KiB xattr write, while
the protocol boundary check requires 64 KiB. A private sparse XFS image in a
task-owned Docker volume accepts that boundary; no conformance assertion is
relaxed. Standalone C tests now detect coverage runtimes in linked
objects and archives, as they already did for sanitizer runtimes. This preserves
the instrumented objects instead of failing on unresolved gcov symbols. Four
native regression cases and the original Linux CVMFS link case pass.
The complete instrumented fleet exceeded Docker Desktop's 8 GiB VM budget:
the kernel recorded an OOM kill of a pytest worker. Coverage therefore uses a
separate task-owned Lima VZ VM with 24 GiB RAM, eight CPUs and an 80 GiB disk,
running the same AlmaLinux image with four test workers and private XFS storage.
It selects that VM's Docker socket explicitly, leaving the user's Docker
context and existing containers untouched. The failed run's partial coverage
is diagnostic only; the required line-coverage floor remains 67%.
Run this fleet and its build as the same unprivileged user. A root-launched
nginx drops privileges, so it cannot write gcov counters into root-owned object
directories or update owner-only test fixtures. The local validation image
uses a dedicated `brixbuild` user and includes `iproute` and `lsof` for real
connection-count observations. All **119 preflight checks** pass, including
checksum backpressure, owner-only xattrs, CMS connection count, extended wire
boundaries, native Linux PAL units, enforced/audited seccomp, rejected exec calls
and purge-policy deadlines. The preflight also verifies worker-owned gcov output
before zeroing counters for the complete run. The external reference bind
adapter declares GNU feature support before its headers so glibc exposes
`RTLD_NEXT`; all seven wildcard, loopback and forbidden-address checks pass.
The native `wait41` timeout case now leases an unused test port instead of
assuming port 12977 is closed. A full parallel run showed another worker had
legitimately leased that port for its live TPC mock; readiness and timeout
checks both pass with the infrastructure-assigned port.
Install `libseccomp-devel` and `liburing-devel` before configuring the Linux
coverage build (`libseccomp-dev` and `liburing-dev` on Ubuntu). The native PAL
tests compile against both libraries, and live seccomp tests require an enabled
filter implementation. A build without libseccomp correctly refuses to start
enforced workers; installing the headers afterward requires reconfiguration and
rebuilding. The coverage workflow now declares both development dependencies.

The completed Linux coverage run exits **0**: **24,566 passed, 500 skipped,
31 xfailed and 8 non-strict xpassed**, with **67.7% line coverage**
(123,018/181,712 lines) and 75.4% function coverage. Its log is
`build/dependency-update/coverage-linux-final.log`; the HTML report is
`build/dependency-update/lima-share/linux-final-report/html/index.html`, and
JUnit is under `lima-share/linux-final-observer/`. This result starts with
zeroed counters and meets the unchanged 67% floor. The private XFS mount and
loop device were released, and the Lima VM was stopped after validation;
its build image and reports remain available for reuse.

The standalone `tests/userns` suite has **7 passed and 2 skipped**; the two
namespace end-to-end cases require Linux's `newuidmap`/`newgidmap`. For this
standalone root, create `$TEST_ROOT/tmp` before invoking pytest; its conftest
does not run the main suite's environment preparation.

Additional Linux checks install `rpm-build`, `rpmdevtools`, `redhat-rpm-config`,
`fail2ban-server`, `zstd` and `gnupg2`, and give the unprivileged test user a
supplementary group. Those checks pass **210 tests** covering RPM creation and
native mirroring, fail2ban patterns, group resolution and compression. The five
DNF mirror cases then pass with the built nginx directory on `PATH`: installation,
offline cache reads, cache hits, rejected writes, expired metadata and wrong-key
signature rejection. Their private DNF install roots use `unshare -r`; the
isolated VM container receives `SYS_ADMIN` for that namespace operation. Both
supplemental runs exit 0. Logs are `linux-supplement-final.log` and
`linux-rpm-mirror-final.log` under `build/dependency-update/`.

The final native parallel run exits **0**, including fleet conservation and
teardown. Both CMS and hybrid meshes are reachable in its pre-teardown snapshot,
and the ownership check finds no remaining processes after shutdown. The final
Linux test container exits 0 and the task-owned Lima VM is stopped; build images,
environment scripts and reports remain available for reuse.

| Completed lane | Result | Evidence under `build/dependency-update/` |
|---|---|---|
| Native parallel, six workers | 41,046 passed; 1,376 skipped; 45 xfailed; 8 non-strict xpassed | `native-clean-final.log`, `native-clean-observer/full-suite-65598.xml` |
| Native serial | 5,853 passed; 403 skipped; 4 xfailed | `full-suite-43023.xml` |
| Native destructive | 160 passed; 26 skipped | `full-suite-67241.xml` |
| Client conformance | 1,034 passed | Final lane in `full-suite-isolated-final.log` |
| BriXTest | 1,253 passed; 10 skipped | `brixtest-patches-final.log` |
| Linux instrumented suite | 24,566 passed; 500 skipped; 31 xfailed; 8 non-strict xpassed; 67.7% line coverage | `coverage-linux-final.log` |
| Additional Linux capability checks | 210 passed, followed by all five DNF mirror cases passing | `linux-supplement-final.log`, `linux-rpm-mirror-final.log` |
| Kubernetes end-to-end | All 15 cases passed across the full run and isolated fleet rerun | `k8s-e2e-isolated-final.log`, `k8s-fleet-isolated-final.log` |

Counts are per lane; focused and supplemental checks can overlap the full suite.
The full project test workflow is complete with its declared skips and existing
expected failures. Platform requirements such as an active macFUSE/FUSE-T mount
and Linux-only kernel features remain capability-gated. The two analyzer cases,
coverage job and ASan job that mutate build trees were validated separately,
as required by the agent guide. Earlier interrupted and failing attempts are
retained as diagnostics; the table identifies the completed validation evidence.

## 17. Full-suite C coverage — 2026-11-08

The coverage lane now runs the canonical parallel, serial, destructive and
client-conformance phases, including standalone C jobs. The two analyzer cases,
recursive coverage case and ASan case remain separate because they replace the
build under measurement. `COVERAGE_PRIVILEGED=1` appends the Linux root contract
group through noninteractive sudo; use it only on a disposable test host because
the existing fixtures provision accounts and exercise network namespaces.

Coverage means executable C lines under `src/` and `client/` in the instrumented
production build. It does not measure Python coverage. An initial `.gcno`
capture fixes the complete production denominator before testing, including
unexecuted files. Standalone compiler wrappers retain counters outside temporary
pytest directories, and the final merge applies their measured hits only to
that initial inventory. Test harness lines and unit-only preprocessor branches
cannot increase the measured scope. The floor compares the unrounded percentage;
a failed suite, missing collector prerequisite or failed capture cannot pass it.

New finite-process tests exercise the real fault-proxy control, relay and oracle
implementations, and the impersonation broker's namespace, metadata, xattr and
authorization paths. They exit normally so gcov can flush counters. Existing
native C regression units now retain their counters through fixture cleanup.
Success, syscall failure and security refusal cases all contribute real
execution. The privileged tests exposed a worker initialization bug: capability
bounding bits were dropped after `CAP_SETPCAP` had already been removed. The
worker now clears and verifies the bounding set first, while preserving the
current identity-transition capabilities until the existing de-escalation step.

The local Linux environment uses the private `brixcov` Lima VM and a disposable
AlmaLinux container with GCC 11, the updated nginx 1.31.8 build, the full Python
requirements, reference clients, GFAL, Globus, FUSE 3, capability/seccomp/uring
development libraries, and `iproute`, `iproute-tc` and `nftables`. An XFS test root
supports the filesystem contract tests. The container receives `/dev/fuse` and
`SYS_ADMIN`, `SYS_PTRACE`, `DAC_READ_SEARCH` and `NET_ADMIN`; its test accounts,
mounts and network changes are isolated from the macOS host.

Ubuntu's restriction on unprivileged user namespaces also applies to an
otherwise unconfined container. The private VM uses a task-specific AppArmor
profile selected only by the test container, with `userns` permitted. The CI
workflow instead loads `tools/ci/coverage_userns.apparmor` for the exact
`/usr/bin/unshare` launcher and removes it afterward. Neither setup changes the
host's global user-namespace restriction. These launchers are required by the
real DNF installroot test; FUSE mount/remount/cache/cleanup tests also pass in
the selected container profile.

On a prepared disposable Linux host, the permanent collector is invoked with:

```sh
export NGINX_SRC=/tmp/nginx-1.31.8
export TEST_ROOT=/tmp/brix-cov
export PYTHONPATH=tests
export PYTEST_ADDOPTS='-p no:brixtest -p no:platformdirs'
export PATH="$NGINX_SRC/objs:$PWD/.venv-coverage/bin:$PATH"
python3 tests/rpm/make_fixtures.py
COVERAGE_MIN=80 COVERAGE_PRIVILEGED=1 tools/ci/coverage.py
```

The full-suite measurement starts with zeroed counters. The ordinary and root
groups then contribute to one report without a counter reset between them.
Focused diagnostic merges from development are retained separately and are not
the final full-suite evidence.

### Completed measurement and validation

The final result is **80.22951724137931% C line coverage**: **145,416 of 181,250
lines**, across 1,709 production files. Function coverage is 89.6%
(12,065/13,467); this run does not collect branch coverage. The initial and final
production inventories match. The exact **80% floor passes**, and the completion
runner exits **0**. `.github/workflows/coverage.yml` now enforces that floor;
the hosted GitHub workflow itself was not dispatched from this device.

| Phase | Result |
|---|---|
| Parallel, four workers | 42,229 passed; 395 skipped; 48 xfailed; 8 non-strict xpassed; two repository guard failures corrected and rechecked below |
| Serial | 5,955 passed; 310 skipped; 4 xfailed |
| Destructive | 183 passed; 3 skipped |
| Client conformance | 1,034 passed |
| Corrective guard and timezone rechecks | 33 passed |
| Linux privileged group | 336 passed; no skips or failures |

The parallel run identified an untracked coverage helper and a hard-coded host
in the new timezone test. With explicit operator approval, only the four new
coverage support files were staged; no commit was made. The timezone fixture
now uses `settings.HOST`. Both guards and the timezone tests passed on macOS
and inside the Linux container, then passed again immediately before the root
group. No production source or binary changed during these corrections.

The ordinary suite's original nonzero result and its 79.5895% report remain
available. The completion runner audits all four ordinary JUnit reports,
accepts only those two identified failures for corrective rechecking, and
requires actual successful rechecks and root tests before the final verdict.
It appends execution to the same zeroed-run counters without resetting them;
the stopped container's build and counters were preserved in a disposable
image for this continuation. This is full-suite validation with corrective
rechecks, not a claim that the first invocation was entirely green.

Evidence under `build/dependency-update/`:

- `coverage80-final-v2.log`: the four ordinary phases and their original result.
- `coverage80-complete.log`: report audit, successful rechecks, privileged tests
  and the exact passing coverage verdict.
- `lima-share/coverage80-final-v2-observer/`: per-phase JUnit, the original
  failure records, `coverage80-corrective-rechecks.xml` and
  `coverage80-privileged.xml`.
- `lima-share/coverage80-final-v2-report/coverage.info` and `html/index.html`:
  final LCOV and HTML reports. `coverage.ordinary.info` preserves the report
  before the root group. The final LCOV SHA-256 is
  `a5fb0f38cd295a28de267e09ac58a110a12869339b398f600e0cb8e8eced0158`.
- `coverage80-native-smoke.log`: the updated native macOS build's `nginx -t`,
  boot and byte-exact read smoke test passed.

Both ordinary and privileged phases used the instrumented nginx SHA-256
`f88fc97b4c6a9983b77283b5177c14296ed8ac97160e4862bad350999775f47d`.
Counts are per phase; corrective and privileged checks can overlap tests
selected earlier. Skips and existing expected failures are retained as such.

The final native tooling/guard recheck passed 53 tests with four skips
(`coverage80-final-static.log`). Workflow YAML, the configured 80% floor,
documentation links and whitespace checks pass. All task-owned containers are
stopped; the temporary AppArmor profile was removed, the XFS fixture filesystem
unmounted, its loop device detached, and the private Lima VM shut down. Build
images, the filesystem backing image, logs and reports remain available for reuse.

## 18. 90% native coverage and v2.0.0 test packages — 2026-11-10

Fresh passing validation covers **165,061 / 183,151 lines
(90.12290405184793%)**, exceeding the requested 90% minimum. The inventory
contains executable Linux C/C++ lines under `src/` and `client/`, matching the
existing CI scope. It remains fixed throughout collection. These results use
only the fresh passing captures below; failed or interrupted sweeps and the
earlier focused-test checkpoint are excluded from the final rate.

| Validation lane | Passed | Skipped | Expected failures | Non-strict unexpected passes |
|---|---:|---:|---:|---:|
| Parallel, four workers | 51,912 | 442 | 48 | 8 |
| Privileged | 385 | 0 | 0 | 0 |
| Serial | 6,100 | 308 | 4 | 0 |
| Destructive/resilience | 183 | 3 | 0 | 0 |
| Client conformance | 1,034 | 0 | 0 | 0 |
| Standalone user namespaces | 9 | 0 | 0 | 0 |
| Quiesced Ceph reverse recovery | 2 | 0 | 0 | 0 |

All lanes exit zero. The ordinary, privileged and namespace groups alone
cover **90.02407849260992%**; the separately quiesced Ceph recovery cases bring
the final total to 90.1229%. The disposable MDS journal was flushed before
those cases, and the MDS was restarted and confirmed active afterward.
The instrumented nginx SHA-256 remains
`364fa8efa448766835525be99b76d24d7e6a6e0be0e9f05e635a9683fd816e65`.
All 2,843 production source/header files match the frozen v6 package snapshot.

CI now enforces `COVERAGE_MIN=90`. Its enabled privileged coverage path also
runs the standalone namespace suite as the invoking user, prepares private
subordinate IDs without replacing existing mappings, and preserves counters
through preparation and cleanup. Ubuntu uses a named AppArmor profile for
that test process; global namespace restrictions remain unchanged. Focused
Linux coverage-tool checks pass **92 tests** (four conditional skips), the
new orchestration passes all **nine actual namespace tests**, and the scoped
AppArmor profile permits a real unprivileged namespace. Python quality and
runtime-dependency guards pass.

All **24 v2.0.0 test package sets** are built and installation/runtime validated:
ARM64 and x86_64 for AlmaLinux 8–10, CentOS Stream 9–10, Fedora 43/44/Rawhide,
Ubuntu 24.04/26.04, NixOS 26.05 and macOS. AlmaLinux 8 and macOS contain client
tools; the other 20 sets contain server and client tools. Linux Intel runtime
checks used QEMU, macOS Intel used Rosetta, and ARM64 ran on this device's
native architecture. Each target's manifest records its exact source identity
and artifact hashes. This validates installation and selected runtime behavior
on each target, rather than a complete suite on every target.

Evidence is in `build/coverage90/{parallel17,completion14,userns19,reverse19}.log`
and `build/dependency-update/lima-share/coverage90-dev-report/final90/`.
Package bundles, installation instructions, full validation evidence and
checksums are under `dist/test-v2.0.0/`. Source-only test and validation-support
overlays record changes made after the immutable package snapshot. No Git
commit, tag or release was created.

### GitHub coverage host isolation — 2026-11-12

The coverage workflow checkpoints preparation, the complete ordinary suite,
privileged contracts and standalone user-namespace contracts in separate steps.
Preparation freezes the production inventory and resets counters once. Later
steps reuse the same SDK and standalone counter directory. The final report
requires every enabled phase to finish successfully as well as at least 90%
line coverage; interrupted phases and partial high-coverage runs fail. The
default local `tools/ci/coverage.py` command still performs all phases together.

Each CI phase runs as the original test user in a separate systemd service and
PID/proc namespace, with a memory ceiling of 75% of physical RAM and no swap.
Tini acts as namespace PID 1 and reaps exited descendants between test cases.
Networking remains shared for the Docker interoperability oracles. Only the
selected test/build environment reaches the service. Build and suite checkpoint
artifacts survive subsequent step failures; resource snapshots and systemd's
memory/exit summary accompany the logs. Unused Android and .NET SDKs are removed
only on the disposable hosted runner to reserve disk space for the instrumented
SDK and XFS test image.

The preceding GitHub run lost runner communication without leaving logs or a
coverage report; its exact cause is unconfirmed. Local validation of this repair
passes **97 coverage regressions on Ubuntu/GCC/LCOV**, including real captures
across separate steps. A real systemd probe confirms private PIDs, shared
networking, the invoking user's identity/environment, and propagation of a
nonzero exit. A controlled memory exhaustion kills only its bounded test
service while the supervising process survives. This is harness validation,
not a fresh full-suite coverage measurement.

The next hosted run completed all ordinary lanes: **58,648 passed and seven
failed**, followed by nine passing standalone namespace cases. The privileged
fleet could not start its reference daemon, and final capture encountered a
removed temporary nginx SDK, so this run establishes no new coverage rate.
The follow-up repairs wait for both access-log records, tolerate absent process
metadata while retaining exact daemon ownership checks, and delegate only a
generated reference configuration inside `TEST_ROOT` to its explicit runtime
account. The stock token-forwarding oracle uses a named `/fwd` namespace;
positive byte checks and denied-user/no-leaked-bytes checks use that same path.
Privileged grid-map fixtures retain the explicit unprivileged worker and derive
its primary group from the host account database. Listener-release and
privilege-refusal controls reuse the existing bounded port-collision helpers.
LCOV filters production sources before reading temporary SDK paths; missing
production sources and malformed counters remain fatal. Local regression
validation passes **192 Ubuntu tests**, all **37 live query-token cases**, all
**six FUSE daemon cases**, and all **six supported forwarding cells**. The complete privileged group passes
**385 cases** on the documented alternate port base (`TEST_PORT_START=2000`);
the initial local replay encountered older disposable oracle listeners on the
default mock-port band. The complete ten-case fault-proxy group also passes
with the real fleet.

FreeBSD contract jobs install the Rust-backed Python metric engine only for
the full suite, which actually uses it. The unchanged 36-case contract catalogue
has a finite 180-second pytest budget for native crypto fixture compilation on
emulated ARM64, while its crypto subprocesses retain their 30-second timeout.
This addresses the repeated runner's six-hour cancellation after dependency
compilation consumed most of its execution window. Earlier x86_64 and ARM64
native contract passes remain separate evidence from this follow-up.

Fresh hosted FreeBSD validation now passes both architecture builds and serving
smokes, with **35 contracts passed and one platform skip per architecture**.
The next complete coverage attempt finishes strict capture at **88.3302%**,
with **58,692 ordinary passes and four failures**; its root fleet still stops
before tests, so the 90% requirement remains unmet. A pressure diagnostic
reproduces those four routing failures: 512 unrelated shared-server connections
fill the documented best-effort offload table, leaving byte-exact primary
fallback available. Binding contracts now own a fresh single-worker subject on
the existing serialized binding-family reservation. All **26 cases pass with
the shared table saturated**, and all **29 binding/migration cases pass with
four workers**. The constrained send buffer also exercises queued replies.

Reference launchers retain pre-log startup diagnostics in a companion bootstrap
file and surface bounded tails if readiness fails. The focused hosted bootstrap
run passes **all 385 privileged cases**, after a real native serving smoke.
This establishes that focused path; the next complete ordinary/privileged/
namespace measurement must still pass every phase and the unchanged 90% floor.

The privileged-only counter probe passes all 385 cases but adds only 492 lines
to the preceding ordinary/namespace execution. A real broker reproduction
identifies a separate collection defect: after dropping DAC override, the
broker cannot traverse a different user's private counter ancestor. The same
four contracts pass in both layouts; the private layout records zero broker
lines, while search-only traversal records 156. Hosted reports now live under
`/tmp/brix-coverage-report`, and the standalone counter root permits search
without granting listing or modification. Real capability-drop and unrelated
UID regressions verify both recording and isolation.

The hosted lane also requires a separate disposable Ceph phase. It reuses the
existing Docker reference harness, seeds real CephFS bytes/xattrs/symlinks, and
runs the existing native data, CephX denial, recovery and forward migration
contracts in the host's instrumented build. Reverse migration runs only after
the journal is flushed and the owned MDS stops. The phase owns a unique
reference container and private fixture keyrings; a failed setup, contract or
missing phase remains fatal. The frozen production inventory and 90% floor
are unchanged. Fresh end-to-end hosted validation is pending.

The complete ordinary command now also runs `make -C ../client -j4 test`:
the pytest client conformance lane does not execute that separate native unit
target. All 27 self-contained client unit programs pass locally. The native
MinIO oracle is built from the pinned official release source
`v0.0.0-20251015172955-9e49d5e7a648`; the existing S3/STS/binding contracts pass
all 57 cases on GitHub without relying on the unavailable image tags.

Cache watermark fixtures reserve 3 GiB inside the disposable 24 GiB XFS image
so eviction contracts meet their existing 10–96% usage precondition. The root
selection also includes hardening, gateway and cache variants. Their fixtures
reuse the existing account provisioner and the worker's real primary group;
all 22 additional cases pass against the local seccomp-enabled SDK. CephFS
bootstrap uses explicit administrator POSIX credentials only to assign fixture
roots to the actual test user. Reverse migration waits for no executing MDS
tasks, allowing an unreaped zombie while still rejecting live tasks or failed
process inspection. Fresh complete hosted validation must still pass every
phase and the unchanged 90% floor.

### Earlier diagnostic checkpoints

Build eleven passes **1,517 focused native cases**, with three skips. The seven
changed AIO/DNS source records were dropped completely before merging this
fresh passing execution. All **47 selected native guards** pass; the example
configuration guard requires unsandboxed macOS network sysctl reads. The
**12 exact regressions** covering the prior CLI profiler collision and static
checksum audit failure pass on the canonical Linux build. Sweep seven is running.

Build ten includes the dependency refresh, retry/error normalization, HTTP
Range handling, recursive-copy confinement, staging cleanup, TPC descriptor
fixes, broker identity refusal, and FUSE publication fixes. The Linux build has
nginx http_auth_request and the real Ceph striper SDK enabled. Both native
macOS and Linux server/client incremental builds pass.

The third complete sweep finished all ordinary phases but exited 1:

| Phase | Result |
|---|---|
| Parallel, four workers | 44,482 passed; 450 skipped; 48 xfailed; 8 non-strict xpassed; 4 failed |
| Serial | 6,096 passed; 309 skipped; 4 xfailed |
| Destructive | 183 passed; 3 skipped |
| Client conformance | 1,034 passed |

Its four failures were corrected and passed focused rechecks. The fourth
sweep's parallel phase then reported **45,376 passed, 442 skipped, 48 xfailed,
8 non-strict xpassed and four failures**: two intermittent AIO deferred replies,
a fixture address guard, and intermittent FUSE reopen reads. Its serial phase
was stopped after forward Ceph migration timed out with the private MDS
quiesced. Forward migration needs the MDS online; reverse recovery needs a
separate quiesced phase. The task MDS is back online, and only the interrupted
test's known striper objects were removed from its disposable pool.

The AIO failures exposed a concurrent heartbeat-policy update: the loop could
check a nonzero interval, then reread zero and send an immediate extra ping.
Atomic field handoffs and one interval snapshot fix the race. A deterministic
interleaving failed against the previous objects and now passes all seven
cases; **200 parallel deferred-reply repetitions** pass. The native macOS
AIO/snapshot selection passes **14 cases**. Executable snapshots now take the
existing build writer's lock, preventing copies of a paused linker's nonempty
but incomplete output; the snapshot/build/run helper selection passes 22 cases.

FUSE reads exposed a second publication race: an updated file's persisted
checksum record remained stale until asynchronous RELEASE closed the writer.
Writable FLUSH now drains writes and sends remote SYNC. The server's VFS sync
publishes CSI tags behind the carried mutation policy and checks the live fd
against the pathname before publication. Successful flush clears folded CRCs
so later partial writes recompute their edges. Tag persistence retains the
existing close-time best-effort behavior. This adds a remote durability barrier
per writable FUSE flush while keeping handles valid across dup/unlink.
Four native cases failed against the old server; all **seven** now pass,
including corruption, policy refusal, bad descriptors and replaced names.
The combined FUSE/AIO selection passes **83 cases**, including **2,000 immediate
close/reopen cycles**. The earlier failed traces are retained separately.

Additional focused contracts include:

| Family | Passing cases |
|---|---:|
| Recursive web transfer / root tree-copy policy | 35 / 42 |
| FTP data / control framing / GSI delegation | 62 / 38 / 40 |
| HTTP Range reads / persistent file retry / WebDAV metadata | 56 / 32 / 48 |
| Remote tier factory / stack composition | 45 / 66 |
| Retry/replay policy / page-write repair | 90 / 45 |
| Upload commit / HTTP staged commit | 29 / 51 |
| S3 staged/multipart commit / batch deletion | 67 / 38 |
| DNS bridge / authorization endpoints | 37 / 37 |
| Ceph errors / rename / striper SDK adapter | 84 / 53 / 48 |
| HTTP body handling and decompression | 96 |
| Broker lifecycle / proxy connect / page-read completion / directory AIO | 25 / 48 / 31 / 16 |
| Packet-marking registry, mapping, DNS callbacks and allocation failures | 40 |
| CMS forwarded namespace / frame correlation and manager retargeting | 72 / 39 |
| Storage scanner HTTP / benchmark worker ownership | 57 / 33 |
| Checksum manifests and cache metadata records | 65 |
| SSS keytab administration / encrypted password exchange | 35 / 31 |
| OCI HTTP copy and eStargz conversion integrity | 37 |
| Tape REST batch authorization and lifecycle | 57 |
| Native read/write compression and vector framing | 62 |
| TLS framing, cancellation and whole-read deadlines | 45 |
| ZIP copy/extraction ownership and output integrity | 43 |
| Fault-proxy parsers, mutation bounds and PROXY wire headers | 114 |
| HTTP/WebDAV/S3 diagnosis, signing failures and redaction | 51 |
| Storage-report summaries and tape stage/poll requests | 31 |
| VFS writer publication, integrity and spill ownership | 37 |
| FUSE metadata retry, identity and read-only namespace policy | 23 |
| AIO reconnect worker deadlines and completion handoff | 23 |
| CSI geometry, checksum coverage and publication errors | 19 |
| Cache digest policy, content-addressed verification and quarantine | 95 |
| Staging writeback, namespace delegation and spool ownership | 34 |
| Block deduplication and copy-on-write ownership under failure | 33 |
| Async transport framing and accumulation failure | 37 |
| Async manager ownership and lazy-stream fallback | 30 |
| DNS prefetch ownership and hash-collision identity | 22 |
| Persisted and binary checksum records | 49 |
| HTTP peer-name wait completion and cancellation | 16 |
| Durable stage-request journal and lock ownership | 25 |

Build seven passed 584 native checks and the 47 unique CI/complexity guards.
The latest native test files also pass their individual Python quality and C
complexity limits. The new broker startup refusal was rebuilt and validated on
both hosts. It rejects an unresolved worker account before idmap/socket/fork
rather than disabling the peer-UID check.

The scanner/keytab selection also passes **92 native macOS cases**, and the OCI
HTTP transfer selection passes **37** there. The new Python families pass every
repository complexity metric. Build nine passed the 47 unique native guards.

The following production fixes are included in canonical Linux build ten.
CMS numeric arguments now require a complete, representable integer: malformed
truncate sizes previously became zero. Its parser unit and 72 forwarded-request
cases pass against a private corrected parser. Automount shutdown now closes
the self-pipe reader after joining the controller; nine lifecycle cases exposed
the old descriptor leak, and all **18** pass with the private corrected object.
The ZIP writer now fails when its input shrinks after the checksum pass,
instead of completing a corrupt archive (**21** private writer cases pass).
Worker I/O clears the reused job's checksum-mismatch output, and blocking
page reads retry EINTR (**55** private worker cases pass).

A deterministic live Ceph regression reproduces a source-version race in the
forward migration tool: `get_last_version()` belongs to the I/O context, so a
different worker's read can replace the version obtained by `stat`. Mapping
now deep-copies that context before stat/copy/redirect. Copy, redirect and
stale-version refusal all pass (**3** cases) in a separate disposable pool.
The API's context ownership is documented in
[Ceph's librados reference](https://docs.ceph.com/en/latest/rados/api/librados/#c.rados_get_last_version).
Those private replacement objects were excluded from the production coverage
union. The six changed production source records were removed completely
before merging fresh build-ten execution.

Sweep five finished against the frozen build-nine tree with the private Ceph
MDS online. Its parallel phase finished with **45,917 passed, 442 skipped,
48 xfailed, 8 non-strict xpassed and 1 failed**: the host-literal guard flagged
four IPv6 parser literals. The vectors now use a documentation address; the
guard and all 40 packet-marking cases pass. The serial phase exposed the Ceph
version race described above: **6,095 passed, 309 skipped, 4 xfailed and
1 failed**. The destructive phase passed **183 cases**, with three skips;
client conformance passed **1,034 cases**. The run exited 1, and none of its
counters were added to the passing union. The scanner and OCI HTTP tests
now use the central host settings; all **94** pass on macOS. The 114 parser
cases pass on both hosts, and the macOS incremental rebuild and configuration
check pass with both project modules loaded. All **47 unique native CI
guards** pass on the current source tree (`native-guards10.log`). New contracts and
the later fixes are included in the next complete validation.

The 82 new diagnostic HTTP cases also pass together on macOS. Their finite
peer distinguishes an empty response from a TCP reset, and assertions cover
wire methods, range fallback, signing scope, capacity totals, stage request
bodies, refusal before network access, and response-body/credential redaction.
Both new files pass all Python complexity metrics.

The canonical Linux build-ten server/client rebuild and nginx configuration
check pass. Its 24-file regression selection passes **967 cases**, including
the original concurrent Ceph migration failure. The additional **25 VFS writer
cases** pass against the same server objects: actual bytes, corruption removal,
policy isolation, atomic abort, fd ownership, spill holes/overlaps/capacity and
temporary-file cleanup are asserted. The native complexity guard passes.

The writer selection now passes **37 cases**, adding allocation cleanup,
interrupted source reads, fragment-array growth and the spill-fragment ceiling.
Another **23 FUSE metadata cases** pass, checking retry deadlines, identity
refusal, staged-file fallback and read-only WebDAV namespace operations.

A new reconnect regression exposes lost callbacks when the first replayed
request immediately loses its new transport: the remaining parked requests
were detached from connection ownership. The correction retains the unissued
tail on the connection and stops replay when its state changes. All **18**
private corrected-object cases pass, including worker-start refusal, repeated
disconnect and unsafe-request refusal. The native macOS client rebuild passes.
The private replacement source is excluded from the production coverage union.
Sweep six has finished, allowing the canonical Linux rebuild to proceed.

Sweep six exited 1. Its parallel phase finished with **46,806 passed,
442 skipped, 48 xfailed, 8 non-strict xpassed and 3 failed**. Two CLI golden
failures come from incompatible profiler timestamps in an old optional smoke
binary: each command produces exactly its expected hash with fresh private
counters. The next build will relink the optional binaries. Golden expectations
remain unchanged. The serial phase passed **6,100 cases**, with 308 skips and
four expected failures. The destructive phase passed **183 cases**, with three
skips. Client conformance passed **1,034 cases**. Report capture completed;
none of this failed run's counters enter the passing coverage union.
Its static checksum audit misclassifies a new
`csi_mismatch = 0` reset as a read; the scanner now distinguishes literal set/reset
assignments from actual reads, with **10 focused checks passing**. Runtime
corruption assertions are unchanged. Current native complexity, duplication
and Python quality guards pass (`complexity11.log`, `duplication11.log` and
`python-quality11-current.log`).

Further AIO regressions reproduce two errors: loop creation reported stale
`errno` instead of the code returned by `pthread_create`, and a distant request
deadline overflowed an `int` into a 1 ms polling interval. The corrected private
objects pass **20 lifecycle cases** and **12 deadline cases**; the lifecycle
cases include successful attachment, shutdown and allocation refusal. The
native macOS client rebuild passes (`macos-client-rebuild11b.log`), and the
current production complexity and duplication guards pass. These two source
files, like the reconnect correction, await the next canonical Linux rebuild.
No coverage from a private replacement implementation is counted.

The **23 worker cases** run the real reconnect worker in a thread with finite
clock/transport seams and check retry cadence, deadline clipping and one
completion wakeup. The **19 CSI cases** use actual files and metadata records
to check growth/shrink preservation, exact CRCs, read-after-write, allocation
failures and bounded readback. All **95 cache verification cases** pass with
real digest computation and staged files, including policy refusal, malformed
or mutable content keys, corruption, missing files, symlinks and quarantine
fallback. Their final Python and C complexity scores pass. Logs include
`aio-worker11.log`, `aio-lifecycle-fixed11-v2.log`, `aio-deadline-fixed11.log`,
`csi-record11.log` and `cache-verify11-v4.log`.

Four new async dispatch regressions showed that failed reply accumulation could
report a truncated reply as successful. Dispatch now removes and fails the
request exactly once; late frames are ignored. All **37 transport cases** pass
with the private corrected object, and **30 manager cases** pass against the
canonical library. Their logs are `aio-accumulation-before11.log`,
`aio-transport-fixed11.log` and `aio-manager11-v2.log`.

DNS cache tests exposed equal-hash entries becoming unreachable after tree
rotations. Both forward and reverse lookup now start at the first matching
hash and inspect its successors, checking the full name/family or address.
All **22 cases** pass with the private corrected objects, including every family
insertion order and actual hostname/IPv6 CRC collisions. Evidence includes
`dns-prefetch11-v2.log`, `dns-reverse-collision-before11.log` and
`dns-prefetch-fixed11-v3.log`. Production complexity and duplication guards
pass (`complexity11d.log`, `duplication11d.log`). These fixes await canonical
build eleven; private replacement counters remain excluded.

The native macOS build-eleven client/server rebuilds and `nginx -t` pass with
both project modules loaded. The optional S3 metadata driver now declares the
protocol archive dependency and its runner always relinks it before use;
a failed build returns failure instead of accepting an old binary. The native
build-graph/harness selection passes **58 cases** (`macos-build-graph11.log`).
The next Linux preflight will relink every existing optional driver before
resetting counters and running golden-output checks.

The **49 integrity-record cases** pass using real xattrs, sidecars and locks;
checks include stale timestamps/sizes, malformed binary lengths and failed
persistence. The **16 HTTP peer-name cases** check inline/deferred completion,
once-only resumption and cancellation before request-pool destruction. The
**25 stage-registry cases** check real journal records, expiry, slot reuse,
owner refusal and lock release through I/O faults. Their logs are
`integrity-record11-v2.log`, `http-peer-name11.log` and `stage-registry11.log`.
All three families pass the C and Python complexity limits.

The **34 staging cases** verify real bytes, partial writes, flush retries,
credential forwarding, namespace refusal and spool cleanup. The **33 block
reference cases** verify that checksum collisions, failed repoints, hash-read
errors and copy-on-write failures preserve object bytes and reference ownership.
Their successful logs are `stage-writeback11-v7.log` and `pblock-refs11.log`.

Evidence under `build/coverage90/` includes `linux-rebuild9.log`,
`macos-rebuild9.log`, `aio-policy-before.log`, `aio-policy-after8.log`,
`waitresp-after8.log`, `macos-aio-after8-retry.log`, `csi-sync-before.log`,
`csi-sync-after9.log`, `rebuild9-fleet.log` and `pmark-runtime9.log`.
Additional evidence is in `zip-transfer9-v2.log`, `zip-writer9.log`,
`zip-writer-fixed9.log`, `ceph-version-before2.log`, `ceph-version-after.log`,
`vfs-worker9-v2.log`, `vfs-worker-fixed9.log` and `macos-host-contract10.log`.
`full-sweep3.log` and `full-sweep4.log` retain failed complete-run evidence.
The fixed build-ten production inventory and its passing focused report are
in `build/dependency-update/lima-share/coverage90-dev-report/rebuild10-focused/`.
`build/coverage90/diagnostic-green.info` is the passing union quoted above.

### Build nineteen checkpoint, 2026-11-09 18:24 UTC

The production build remains unchanged during parallel sweep twelve. Sweep
eleven's parallel lane failed after documented device sleep; none of its
counters were merged. Its remaining lanes passed: **6,099 serial tests**
(309 skipped, four expected failures), **183 destructive tests** (three
skipped), and **1,034 client conformance tests**. The complete parallel lane
is being repeated with the original selection and deadlines, followed by the
privileged group. These are separate phase results, not a claim that sweep
eleven passed.

The current GCC analyzer passed all 1,232 translation units. The four changed
server translation units also passed Clang analysis. Native macOS normal and
ASan builds, configuration validation, physical-block catalog/driver units,
and the five selected strict ASan runtime cases passed. Darwin LeakSanitizer
is unavailable. Evidence includes `fanalyzer19.log`, `codechecker19.log`,
`asan-write19.log`, `rebuild19-focused.log` (1,451 passing tests),
`full-sweep11.log` and the ongoing `parallel12.log`.

Additional passing native families cover origin bootstrap (57), cache-store
dispatch and sparse reads (12), TPC source-open negotiation (27), proxy
directives (56), cache eviction (13), and multi-block truncation (16).
They preserve the production object graph and use finite fault injection at
provider boundaries. The complete existing object-linked C contracts also
pass (`object-units19.log`). The coverage inventory remains exactly 183,151
production lines; unexecuted production lines remain in the denominator.

The v2.0.0 test package matrix contains **24 platform/architecture sets**:
ARM64 and x86_64 for AlmaLinux 8–10, CentOS Stream 9–10, Fedora 43/44/Rawhide,
Ubuntu 24.04/26.04, NixOS 26.05, and macOS. AlmaLinux 8 and macOS provide
client tools. At this checkpoint, **17 sets** have validated current binaries;
seven Intel server sets remain pending. Linux validation includes package
installation, module loading, exact local/remote reads, missing-file errors,
and read-only refusal. This is not a full-suite run on each distribution.
Artifacts and per-target evidence are under `dist/test-v2.0.0/` and
`build/test-packages-v2.0.0/`. No release or tag has been published.

The dedicated Intel package VM was temporarily suspended at critically low
battery to preserve its running builds; the coverage VM remains active.
Remaining work is completion of the ordinary and privileged suite, the
separate quiesced Ceph reverse recovery phase, final coverage enforcement,
the seven Intel package rebuilds, and final artifact manifests/checksums.

### Validation recovery checkpoint, 2026-11-09 23:12 UTC

The device rebooted after its battery was exhausted. Both task VMs were
restarted, the existing XFS test volume was remounted, and the Ceph MDS was
restarted. Power is now stable at 100% on AC. Sweep twelve was interrupted;
its counters are excluded. Sweep thirteen exposed insufficient temporary
disk capacity, so the coverage VM root filesystem was enlarged to 160 GiB
and its existing XFS test volume to 96 GiB. Completed raw counter archives
were compressed and hash-verified before reclaiming their original copies.
The unchanged 200 MB transfer test, parser cases, and address-literal guard
then passed together (65 tests).

Sweep fifteen stopped with 23 failures, 43,560 passes, 411 skips, 43 expected
failures and eight non-strict unexpected passes. All failures came from the
new packed-block transform fixture. AddressSanitizer proved that gcov's
shutdown allocator read a pointer to the fixture's expired main-stack state.
The fixture now clears that pointer before returning; wrappers tolerate its
absence. Seven related fixtures received the same lifetime cleanup. A fresh
preflight using the full coverage compiler launchers passed **5,498 tests
across all 126 server-object fixture families**. Production sources remain
identical to the v6 package snapshot (2,843 files verified). Sweep fifteen's
counters are excluded; sweep sixteen is running with the original selection.
Evidence is `parallel15.log` and `fixture-preflight19.log`, with JUnit output
under `coverage90-dev-report/fixture-preflight19/`.

Current packages are validated for 21 of the 24 target sets. The remaining
Intel builds are CentOS Stream 10, Fedora Rawhide and Fedora 43. RPM build
helpers batch ELF candidate discovery while retaining the original distro
RPATH policy worker. Equivalence checks cover valid and invalid ELF RPATHs,
archives, text, truncated binaries and symlinks. Their exact helper manifest
and validation logs are retained with the package build evidence.

### UTC-boundary fixture correction, 2026-11-10 00:17 UTC

macOS entered lid-triggered sleep after 23:27 UTC despite the task's wake
assertion; the device returned to sustained AC operation after 00:05 UTC.
The coverage sampler records gaps of 603, 1,063 and 595 seconds. Sweep
sixteen was stopped with two failed proxy-positive cases, 19,716 passes,
84 skips and 39 expected failures. Its counters are excluded.

The failures exposed a fixture issue independent of production validation:
the X.509 epoch was rounded down to the startup day's midnight, so one-day
positive proxies expired precisely at the next midnight. The retained failed
proxy's `notAfter` is `2026-11-10T00:00:00Z`. The same boundary also advanced
future-dated controls into their validity window. The fixture now anchors
day offsets to the actual run-start instant. Three deterministic cases cross
midnight with valid, expired and future-dated proxies; the old implementation
fails the valid and future cases. All three pass after the correction.
The live WebDAV proxy acceptance/rejection checks and X.509 compatibility
checks pass together (**18 tests**); the Python quality guard also passes.
Evidence is `x509-epoch-before19.log`, `x509-epoch-after19.log`,
`x509-epoch-native19.log` and `python-quality68.log`.

Sweep seventeen repeats the complete parallel selection and privileged group
with unchanged production sources. The complete remaining ordinary phases
are queued after successful capture, followed by standalone namespace tests
with a private subordinate-ID range. The package matrix now has **23 current
validated sets**; Fedora 43 x86_64 is the remaining build. The source-only test
supplement contains 69 verified updates relative to the frozen v6 snapshot.

At 00:40 UTC, all **24 v2.0.0 package sets** have passed installation/runtime
validation, including the final Fedora 43 x86_64 build. All 20 server sets use
the current v6 snapshot; the four client-only sets retain identical sources
(790 client/shared entries verified). The package output now contains 24
bundles and an index that explicitly marks full-suite validation as pending.
Independent verification passes for all bundle members, 917 global checksums,
352 current server DEB/RPM artifacts and 69 source-only test updates. Evidence
is `build/test-packages-v2.0.0/logs/artifact-verification24-pending.log`.
The completed Intel package VM was shut down gracefully; the coverage VM
continues the fresh suite.
