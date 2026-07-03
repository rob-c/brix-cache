# RADOS / cephfsro builds — how they are made, and how Docker is used

**Date:** 2026-07-02 · **Scope:** the Ceph-enabled builds of the nginx-xrootd
module — the **`ceph`** (block-only librados) and **`cephfsro`** (read-only
CephFS-via-RADOS) storage drivers plus the stock-XrdCeph **striper** layer —
and the Docker machinery (`tests/ceph_harness.sh`, `tests/ceph/Dockerfile.build`,
`tests/ceph/build_in_container.sh`) every one of those builds runs through.

> **Naming note:** this covers **cephfsro** (the read-only CephFS-from-RADOS
> driver, `src/fs/backend/rados/sd_cephfs_ro.c`). It is unrelated to the
> repo's CVMFS work (`src/protocols/cvmfs/`, `tests/cvmfs/`), which is a
> Stratum-1 caching/classification effort with a pure-Python harness and **no
> Docker or special build** at all.

**Companion docs:** `tests/ceph/README.md` (command quick-start),
[`python-migration-tools.md`](python-migration-tools.md) (migration tools),
`docs/superpowers/specs/2026-06-30-cephfs-rados-program-design.md`
(driver-lineup design), `src/fs/backend/README.md` (driver seam).

---

## 1. Why Docker at all (the three constraints)

The whole Ceph test/build story is shaped by the development host being
**Docker Desktop on WSL2** with a RHEL-family distro:

1. **The Ceph MON lives inside the Docker Desktop VM.** A single-node Ceph
   ("demo") container on `--network host` binds the *VM's* network, not the
   WSL2 distro's — so librados clients can only reach the MON from **other
   `--network host` containers**. Nothing Ceph-facing can run directly on the
   host.
2. **`librados-devel` is not installable on the host.** The Ceph Storage WG
   ships dev packages for CentOS Stream, not RHEL. So the module must be
   *compiled* somewhere with the headers — a CentOS Stream 9 container.
3. **Bind mounts from the WSL2 distro don't surface in the DD VM.** Source
   cannot be volume-mounted into the build container; it is delivered as a
   **tar stream over `docker cp`** instead (works regardless of file-sharing
   configuration).

Everything below is a consequence of these three facts. On a native-Linux
host with `librados-devel` installable, the same scripts still work (the
harness IP-probing handles both cases), Docker just stops being mandatory
for the build half.

## 2. The two containers

| Container | Image | Role |
|---|---|---|
| `xrd-ceph-demo` | `quay.io/ceph/demo:latest-reef` | the single-node Ceph cluster (MON+MGR+OSD) |
| `xrd-ceph-work` | `xrd-ceph-build` (built from `tests/ceph/Dockerfile.build`) | build **and** run environment: compiles the module/tests/tools, runs nginx, hosts every in-container test |

Both run `--network host` so they share the DD VM's network namespace — the
work container reaches the MON at the VM's IP.

## 3. The cluster harness — `tests/ceph_harness.sh`

```bash
tests/ceph_harness.sh start|stop|status|env|pool-reset
```

`start` does, in order:

1. **IP autodetection.** The demo image requires explicit `MON_IP` +
   `CEPH_PUBLIC_NETWORK`. The harness probes the container-visible primary
   IPv4 CIDR **from inside a throwaway `--network host` alpine container**
   (`ip -4 -o addr show`, skipping `lo`, `/32`s, and docker bridges) — this
   is what makes it correct on both native Docker (real host net) and Docker
   Desktop (VM net). `MON_IP=…` overrides.
2. **Cluster start:**
   `docker run -d --name xrd-ceph-demo --network host -e MON_IP=… -e
   CEPH_PUBLIC_NETWORK=… -e CEPH_DAEMON=demo -e DEMO_DAEMONS="mon,mgr,osd" …`
   then polls `ceph -s` for `HEALTH_OK|HEALTH_WARN` (up to 3 min).
3. **Credential extraction.** `ceph.conf` + `ceph.client.admin.keyring` are
   `docker cp`'d out to `/tmp/ceph-harness/` — these are what get wired into
   the work container (§4) and what host-side scripts point `CEPH_CONF` at.
4. **Test pool.** Creates pool `xrdtest` (32 PGs) idempotently, application
   `rados`, and — because the demo cluster has a single OSD — `size 1` /
   `min_size 1` so the pool's PGs go fully active.
5. Prints `env` exports for test consumption:
   `TEST_CEPH=1 CEPH_CONF=… CEPH_KEYRING=… CEPH_POOL=xrdtest CEPH_MON_HOST=…`
   (use as `eval "$(tests/ceph_harness.sh env)"`).

`pool-reset` drops and recreates `xrdtest`; `stop` removes the container
(cluster state is disposable by design).

**The CephFS on top.** The harness itself manages only MON/MGR/OSD + the
flat pool. The CephFS that `cephfsro` and the migration tests read was added
on top of the demo cluster (an MDS + a filesystem); on the current dev
cluster it is fs **`cephfs`** with pools **`cephfs.cephfs.meta`** /
**`cephfs.cephfs.data`** (stock `fs volume` naming — the spike-era docs say
`cephfs_metadata`/`cephfs_data`, so **never hardcode**: every recent runner
discovers the names via `ceph fs ls --format json`, e.g.
`run_py_migrate.sh`). Seeding for tests is done through **libcephfs**
(`tests/ceph/cephfs_seed.c`, `cephfs_seed2.c`, or python3-cephfs one-liners),
always followed by `ceph tell mds.<id> flush journal` — dentries live in the
MDS journal until flushed and a pure-RADOS reader cannot see them before
that.

## 4. The build image and the work container

### 4.1 `tests/ceph/Dockerfile.build` → image `xrd-ceph-build`

Layered like this — each choice is deliberate:

- **`FROM quay.io/ceph/demo:latest-reef`** — not for the daemons, for the
  **dnf repos**: the image is CentOS Stream with the Ceph repos pre-wired,
  so `librados-devel` (and `libradosstriper-devel`, `libradospp-devel`,
  `python3-rados`, `python3-cephfs`) install cleanly.
- Enables **CRB** and **EPEL**, then installs the toolchain + the module's
  full optional-dependency set (`openssl/pcre2/zlib` core; `libxml2/xslt`,
  `jansson`, `krb5`, `libcurl`, `sqlite`, `uuid`, `zstd/xz/bzip2/lz4`,
  `brotli`, `liburing`) **plus `librados-devel`**.
- Unpacks the **stock nginx source** (currently 1.28.3) at `/opt/nginx-src`
  — the module is attached at `./configure` time, never baked in.
- **Sanity gate:** compiles and links a 3-line `rados_create()` program so a
  broken librados install fails the image build, not a later module build.
- The repo source is **not** in the image (see §1's bind-mount constraint) —
  the image is a stable toolbox; source arrives per-build.

Build once: `docker build -f tests/ceph/Dockerfile.build -t xrd-ceph-build tests/ceph`.

### 4.2 `tests/ceph/build_in_container.sh` → container `xrd-ceph-work`

Every module build with Ceph enabled goes through this script:

1. Requires the cluster to be up (`/tmp/ceph-harness/ceph.conf` present).
2. **(Re)creates `xrd-ceph-work`** from the image on `--network host`
   (`sleep infinity` — it stays around as the standing build/run box).
3. **Delivers the source**: `tar czf` of the whole repo — excluding `.git`,
   object files, pycache, the volatile test tree — written to a temp file
   first (so "file changed as we read it" is a tolerated exit 1, not a
   broken pipe), then streamed in with `docker exec -i … tar xzf -` to
   `/work/repo`. Edits on the host mean re-running the script (or a targeted
   `docker cp` of the changed file, which is what the per-test runners do).
4. **Wires the cluster credentials**: copies the harness's `ceph.conf` +
   admin keyring to `/etc/ceph/` inside the container — this is what both
   the compiled driver and every CLI (`rados`, `ceph`, `xrdcp` …) use.
5. **Configures + builds** inside the container:
   ```
   cd /opt/nginx-src
   ./configure --with-stream --with-stream_ssl_module --with-http_ssl_module \
               --with-http_dav_module --with-threads --add-module=/work/repo
   make -j$(nproc)
   ```
   and greps `objs/ngx_auto_config.h` for **`BRIX_HAVE_CEPH`** — printing a
   loud warning if Ceph was *not* detected (the build still succeeds, just
   without the drivers; see §5).
6. Result: `/opt/nginx-src/objs/nginx` inside `xrd-ceph-work`.

## 5. How `./config` gates the Ceph code (feature-probe, no flags)

The module's repo-root `./config` decides Ceph support by **compiling a
probe**, exactly like nginx's own autotests — there is no `--with-ceph`
flag:

1. Writes `#include <rados/librados.h> … rados_create(…)` to the autotest
   file and tries `$CC … -lrados`.
2. On success: `CFLAGS += -DBRIX_HAVE_CEPH=1`, `BRIX_CEPH_LIBS=-lrados`,
   and prints `+ xrootd storage backend: ceph/rados enabled`.
3. **Nested probe** for `<radosstriper/libradosstriper.h>`: on success adds
   `-DBRIX_HAVE_RADOSSTRIPER=1` and switches the libs to
   `-lradosstriper -lrados` — this is what enables the stock-XrdCeph
   (RAL/Glasgow) on-RADOS layout compatibility in `sd_ceph_striper.c`.
4. `BRIX_WITHOUT_CEPH=1` in the environment force-disables even when the
   headers are present.

Key properties:

- **A no-Ceph build is byte-for-byte unchanged.** `sd_ceph.c` /
  `sd_cephfs_ro.c` are always in the source list (`config` lines
  `$ngx_addon_dir/src/fs/backend/rados/…`), but without the define they
  contribute only their pure libc-only helpers (LFN→object-key naming,
  stripe naming, N2N), and the driver rows in `sd_registry.c` are
  `#if BRIX_HAVE_CEPH`-compiled out.
- `cephfs_denc.c` / `cephfs_layout.c` (the CephFS on-disk decoders) are
  **pure C with no RADOS dependency** and always compile — which is what
  lets them unit-test host-side with a plain `cc` (§7.1).
- The link flags go into **`ngx_module_libs`** (not only `CORE_LIBS`) —
  required so a *dynamic* module `.so` can dlopen with its librados
  dependency recorded (learned the hard way in the RPM packaging work).

## 6. The RADOS driver family (what actually gets built)

All under `src/fs/backend/rados/`:

| File | Role | Gate |
|---|---|---|
| `sd_ceph.c/.h` | the `ceph:` block-only backend (flat objects keyed by export-relative path; data + xattr + staged writes) + the shared `sd_ceph_conn_t`/`sd_ceph_oid_*` low-level layer | `BRIX_HAVE_CEPH` |
| `sd_ceph_striper.c/.h` | stock-XrdCeph (libradosstriper) data-plane layout | `BRIX_HAVE_RADOSSTRIPER` |
| `sd_cephfs_ro.c` | **cephfsro** — read-only CephFS served straight from RADOS (path walk via metadata-pool omaps, data via `<ino>.<objno>` objects; every mutating vtable slot returns `EROFS`) | `BRIX_HAVE_CEPH` |
| `cephfs_denc.c/.h` | Ceph encoding primitives (LE ints, strings, `ENCODE_START` framing) | none (pure C) |
| `cephfs_layout.c/.h` | typed decoders: dentry / `inode_t` v2→19 / fragtree / `file_layout_t` / xattrs | none (pure C) |
| `sd_ceph_compat.c/.h` | shared naming/N2N helpers | none |

nginx config forms (stream face; WebDAV shares the binding via the global
registry):

```nginx
brix_storage_backend ceph:xrdtest;                        # block-only, ceph:<pool>[@<conf>]
brix_storage_backend cephfsro:META+DATA?assume_quiesced=1; # RO CephFS (frozen fs)
brix_storage_backend cephfsro:META+DATA?live=1;            # RO CephFS (best-effort live)
```

## 7. The cephfsro build/test ladder (fast → full)

Four rungs, each building strictly more than the last:

### 7.1 Decoder unit tests — host-side, **no Docker, no cluster**

The decode core is dependency-free, so it compiles anywhere:

```bash
cc -I src/fs/backend/rados tests/ceph/cephfs_denc_unittest.c \
   src/fs/backend/rados/cephfs_denc.c -o /tmp/t && /tmp/t
cc -I src/fs/backend/rados tests/ceph/cephfs_layout_unittest.c \
   src/fs/backend/rados/cephfs_layout.c src/fs/backend/rados/cephfs_denc.c \
   -o /tmp/t && /tmp/t tests/ceph/fixtures/reef-18.2.4
```

Ground truth is **captured bytes**: `tests/ceph/fixtures/reef-18.2.4/*.bin`
are raw omap dentry values pulled from the live cluster
(`rados -p <meta_pool> getomapval <dir_oid> '<name>_head' out.bin`), with
`ceph-dencoder` as the decode oracle where it can parse. The Python port's
tests (`tests/ceph/test_cephfs_meta.py`, also cluster-free) assert against
the **same fixtures**, so C and Python decoders validate each other.

### 7.2 Live driver test — `tests/ceph/run_cephfs_ro_live.sh`

Compiles the *driver itself* against a real cluster, without nginx: the
runner `docker cp`'s just the needed sources (`sd.h`, `sd_ceph.*`,
`sd_ceph_compat.*`, `cephfs_denc/layout.*`, `sd_cephfs_ro.c`) plus
`tests/ceph/ngx_shim.h` — a small header that **stubs the nginx types** the
driver signature needs — and the test main
(`sd_cephfs_ro_live_test.c`) into `xrd-ceph-work`, builds with plain
`gcc … -lrados`, and drives the vtable against the **seeded** CephFS:
stat / 5 MiB byte-exact read / ls / getxattr / symlink / `EROFS` on writes.
(Same pattern as `run_sd_ceph_live.sh` for the block driver.)

### 7.3 Full module e2e — `build_in_container.sh` + smoke scripts

The §4.2 build, then nginx runs **inside `xrd-ceph-work`** with a `ceph:` or
`cephfsro:` export and the smokes assert wire behaviour:

```bash
docker cp tests/ceph/ceph_export_smoke.sh xrd-ceph-work:/work/ &&
  docker exec -e CEPH_POOL=xrdtest xrd-ceph-work bash /work/ceph_export_smoke.sh
docker cp tests/ceph/cephfs_ro_smoke.sh xrd-ceph-work:/work/ &&
  docker exec xrd-ceph-work bash /work/cephfs_ro_smoke.sh
```

`ceph_export_smoke.sh`: root:// `xrdcp` PUT/GET + stat + xattr AND WebDAV
PUT/GET, objects landing in the pool. `cephfs_ro_smoke.sh`: byte-exact GET,
listings, and write-refusal (root:// error, HTTP 403) against the seeded fs
on both faces. The in-container client side uses **stock** `xrdcp`/`xrdfs` +
`curl`.

### 7.4 Recovery & migration tools — same containers, per-tool runners

`run_rescue_tools.sh` (the three C rescue/migrate CLIs),
`run_striper_migrate.sh` (C++ striper→CephFS migrator) and
`run_py_migrate.sh` (both Python tools) all follow one pattern: **host-side
runner → `docker cp` the sources → compile (if C/C++) and execute inside
`xrd-ceph-work` → assert against the demo cluster**. Compile rules worth
knowing: the C++ tools build with one `g++` line
(`g++ -std=c++17 … -lrados -lcephfs/-lradosstriper`); when a `.cpp` links
the C decoders, compile those with **`gcc -c` first** and link the `.o`s —
`g++` treats `.c` as C++ and breaks the `extern "C"` contract. The Python
tools need no build at all (distro `python3-rados`/`python3-cephfs`; their
redirect bridge is ctypes — see
[`python-migration-tools.md`](python-migration-tools.md) §4; its optional
compiled shim needs `libradospp-devel`, which is a separate package from
`librados-devel` on el9 and provides `librados.hpp`).

## 8. Gotchas (all learned empirically)

- **`docker exec` heredocs need `-i`** — without it `bash -s` reads EOF,
  runs nothing, and exits 0 "successfully".
- **Never hardcode the CephFS pool names** — `cephfs_metadata/cephfs_data`
  vs `cephfs.cephfs.meta/.data` depends on how the fs was created; discover
  with `ceph fs ls --format json`.
- **Always `flush journal` after seeding** through libcephfs, or the
  pure-RADOS readers (cephfsro, reverse migration walk) see a stale/empty
  namespace.
- **In-container nginx debugging:** run as `user root`, `worker_processes 1`;
  kill with `pkill -9 nginx` (matching `-f objs/nginx` misses workers).
- The demo cluster is **single-OSD** — custom pools need `size 1` or their
  PGs never activate (the harness does this for `xrdtest`; do the same for
  any pool you add).
- The work container's nginx build tree lives at `/opt/nginx-src` and the
  module at `/work/repo`; a fresh `build_in_container.sh` run replaces the
  container, so long-lived state (test files, built tools in `/tmp`) does
  not survive it.
- `--network host` + Docker Desktop means ports/addresses are the **VM's**:
  reach services from other host-net containers, not from the WSL2 shell.
