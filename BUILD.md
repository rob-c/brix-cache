# BUILD.md — Local RPM build of BriX-Cache

Log of building the `nginx-mod-brix-cache` RPM (and its sibling packages) locally
on this host, against the host's distribution nginx via `nginx-mod-devel`.

- **Host:** AlmaLinux 9.8 (`platform:el9`), x86_64
- **Target nginx:** `nginx-1.20.1-28.el9_8.4.alma.1` (distro), built against the
  matching `nginx-mod-devel` of the same version — the module is ABI-locked to it.
- **Spec:** `packaging/rpm/nginx-mod-brix-cache.spec` (Version 0.1.0, Release 8)
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
  libcurl-devel krb5-devel libcom_err-devel sqlite-devel fuse3-devel \
  librados-devel libradospp-devel libradosstriper-devel libcephfs-devel
```

Notes:
- `jansson-devel` comes from **CRB**; the Ceph `-devel` stack from **centos-ceph-reef**.
- These match `BuildRequires:` in the spec and the tested `Dockerfile.alma9`.

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

**VOMS name caveat (EL9) — FIXED in the spec, see §2d.** The C VOMS library ships as
`voms-libs` on EL8 but as **`voms`** on EL9+; both Provide `libvomsapi.so.1()(64bit)`,
the `.so` the module `dlopen`s at runtime (`config` line 4). The `voms` package is
already installed here. The spec originally hardcoded `Requires: voms-libs`, which does
not resolve on EL9; it now requires the soname directly.

---

## 2. Building the RPM

Driver: `packaging/rpm/build-rpm.sh <version>`. It tars the current checkout
(VCS/build artifacts excluded) into `.rpmbuild/SOURCES/nginx-xrootd-<version>.tar.gz`,
copies the spec, and runs `rpmbuild -ba` with `_topdir=.rpmbuild`. **The tarball is
built from the working tree**, so uncommitted source fixes are picked up on rebuild.

```bash
packaging/rpm/build-rpm.sh 0.1.0
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

Second run: **exit 0**, ~4m35s wall (`-j$(nproc)`). Nine RPMs produced in
`.rpmbuild/RPMS/` and `.rpmbuild/SRPMS/`:

| RPM | Size | Notes |
|---|---|---|
| `nginx-mod-brix-cache-0.1.0-8.el9.x86_64.rpm` | 3.4 MB | the two module `.so`s + loader + docs |
| `brix-cache-client-0.1.0-8.el9.x86_64.rpm` | 0.8 MB | native CLI tools + FUSE mounts |
| `brix-cache-tests-0.1.0-8.el9.noarch.rpm` | 1.9 MB | pytest suite |
| `brix-tools-0.1.0-8.el9.x86_64.rpm` | 0.2 MB | Ceph migration/rescue tools |
| `nginx-mod-brix-cache-0.1.0-8.el9.src.rpm` | — | source RPM |
| `*-debuginfo` / `*-debugsource` | — | 4 debug packages |

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

**Before the fix**, `dnf install` of the module RPM failed:

```
Error: nothing provides voms-libs(x86-64) needed by nginx-mod-brix-cache-0.1.0-8.el9
```

Cause: same EL8-vs-EL9 naming as §1c — nothing on EL9 *Provides* `voms-libs` (the C
library ships as `voms`, which is installed and provides `libvomsapi.so.1`).

**Fix (applied to `packaging/rpm/nginx-mod-brix-cache.spec`):** require the soname the
module actually `dlopen`s instead of a package name that changed between EL releases —
`voms-libs` on EL8 and `voms` on EL9+ both Provide it, so one line works everywhere:

```diff
-Requires:       voms-libs%{?_isa}
+Requires:       libvomsapi.so.1()(64bit)
```

After rebuild, the module RPM's VOMS require reads `libvomsapi.so.1()(64bit)`, provided
here by `voms-2.1.3-1.el9`, and `dnf install` resolves cleanly (no unmet deps):

```
$ sudo dnf install --assumeno .rpmbuild/RPMS/x86_64/nginx-mod-brix-cache-0.1.0-8.el9.x86_64.rpm
Dependencies resolved.
...
Total size: 3.4 M
```

> **Not installed on this host.** A newer `nginx-mod-brix-cache-1.1.1-20.el9` is already
> installed (the running dev/test fleet, installed 2026-07-09), so dnf classifies our
> `0.1.0-8` build as a *downgrade*. We deliberately did **not** install it to avoid
> clobbering that environment — the clean dependency resolution above plus the `nginx -t`
> load test in §2c are sufficient proof. To install our build anyway on a clean host:
> `sudo dnf install <rpm>` (deps now resolve); over the newer install it would need
> `--allow-downgrade`, which is not recommended here.

### 2e. Rebuilding

```bash
# incremental re-run (regenerates tarball from working tree each time)
packaging/rpm/build-rpm.sh 0.1.0

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

> These edits are uncommitted. `packaging/rpm/README.md` still describes the old
> `voms-libs` dependency in prose and may deserve a follow-up doc pass, but the
> build-governing spec is now correct.

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
| `BRIX_BUILD_CLIENT` | `ON` | build/install the client tools |
| `BRIX_BUILD_CEPH_TOOLS` | `ON` | build the Ceph migration/rescue tools |
| `NGINX_SRC_DIR` | auto | nginx source tree (auto-read from `macros.nginxmods`, else newest `/usr/src/nginx-*`) |
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

> On this host we did **not** run `sudo cmake --install` — the newer
> `nginx-mod-brix-cache-1.1.1-20.el9` dev-fleet install is live (§2d). All CMake
> verification used a `DESTDIR` staging dir. `build/` is git-ignored.
