# `tests/ceph/` — Ceph/RADOS backend test harness

End-to-end harness for the librados storage backend (`src/fs/backend/rados/`),
built for **Docker Desktop on WSL2** (where the MON only lives in the DD VM, so
everything that talks to RADOS runs in a `--network host` container).

## One-time

```bash
tests/ceph_harness.sh start                                   # single-node Ceph (pool xrdtest)
docker build -f tests/ceph/Dockerfile.build -t xrd-ceph-build tests/ceph   # build env (librados-devel)
tests/ceph/build_in_container.sh                              # build the module WITH ceph (in xrd-ceph-work)
```

## Tests

```bash
# (1) standalone LIVE driver test — drives the sd_ceph vtable against the pool:
#     open/pwrite/pread/fstat/stat/setxattr/getxattr/listxattr/removexattr/
#     staged_open/write/commit/unlink.
tests/ceph/run_sd_ceph_live.sh

# (2) end-to-end export test — nginx with a ceph export (auth off), verifies
#     root:// xrdcp PUT/GET + stat + xattr AND http:// (WebDAV) PUT/GET, with the
#     objects landing in pool xrdtest. Runs inside the build container:
docker cp tests/ceph/ceph_export_smoke.sh xrd-ceph-work:/work/ &&
  docker exec -e CEPH_POOL=xrdtest xrd-ceph-work bash /work/ceph_export_smoke.sh
```

> **Note:** the experimental `cephns` directory-over-omap driver was removed
> (2026-06-30). The flat `ceph` driver above is the block-only reference; a real
> directory namespace is provided by reading a CephFS via the read-only
> `cephfsro` backend (below) or by migrating into a real CephFS. See
> [`docs/superpowers/specs/2026-06-30-cephfs-rados-program-design.md`](../../docs/superpowers/specs/2026-06-30-cephfs-rados-program-design.md).

## CephFS-interop research spike (read-only, throwaway)

Empirical investigation of whether we can read a real **CephFS** filesystem's data
via **pure RADOS** (no kernel/FUSE mount). Findings + go/no-go in
[`docs/superpowers/specs/2026-06-30-cephfs-rados-interop-spike.md`](../../docs/superpowers/specs/2026-06-30-cephfs-rados-interop-spike.md).

Requires a CephFS on this cluster: add an MDS + `cephfs` fs (pools
`cephfs_metadata`/`cephfs_data`), then seed + dissect from the build container:

```bash
# seed a known tree via libcephfs (no mount; needs -D_FILE_OFFSET_BITS=64):
gcc -D_FILE_OFFSET_BITS=64 tests/ceph/cephfs_seed.c -lcephfs -o /tmp/seed && /tmp/seed
ceph tell mds.<id> flush journal          # REQUIRED — dentries live in the MDS journal until flushed

# prove path -> inode -> bytes via PURE RADOS (omap dentry walk + data object reads):
gcc -D_FILE_OFFSET_BITS=64 tests/ceph/cephfs_rados_poc.c -lrados -o /tmp/poc
/tmp/poc cephfs_metadata cephfs_data /dir1/sub/big.bin     # -> 5 MiB reconstructed byte-exact
```

**Result:** read path PROVEN (path resolved through dir omaps, 5 MiB file
reconstructed across 2 data objects). Spike conclusion: a **read-only** rescue
backend (`cephfsro`) is feasible for a quiesced fs; an in-place "upgrade" of
flat/cephns data to CephFS is NO-GO (must copy-through-mount). See the spec.

## cephfsro — read-only CephFS-via-RADOS driver

The spike's read path is now a real driver: **`cephfsro`**
(`src/fs/backend/rados/sd_cephfs_ro.c`) serves a CephFS by reading its metadata
omaps + data objects directly, with **no mount/MDS/libcephfs**. Read-only (every
mutating slot is absent); the fs MUST be quiesced (operator asserts via the URI).

```nginx
# stream (root://): two pools (metadata + data); a consistency assertion is REQUIRED.
#   ?assume_quiesced=1  fs is frozen (MDS down/failed, journal flushed)
#   ?live=1             fs still mounted — best-effort eventually-consistent
xrootd_storage_backend cephfsro:cephfs_metadata+cephfs_data?assume_quiesced=1;
```

**Consistency modes.** `cephfsro` re-resolves from the root on every request, so it
naturally picks up *flushed* changes. The mode picks the safety posture:
- **`assume_quiesced=1`** — trusts a frozen fs; retries only genuinely transient
  cluster errors (EAGAIN/ETIMEDOUT/EBUSY/EIO…) with bounded backoff.
- **`live=1`** — for a still-mounted fs with infrequent MDS syncs. Adds
  **optimistic walk-version revalidation**: each dir object a resolve depends on is
  recorded with its RADOS version and re-checked after the walk; if an MDS write
  landed mid-walk the resolve is retried (so you get the new state, not a torn or
  stale one) rather than served silently inconsistent. A genuine, stable not-found
  still fast-fails. Reads are eventually-consistent, not a coherent point-in-time
  snapshot — for that, read a CephFS snapshot (a future extension).

- **Decoders** (`cephfs_denc.{c,h}` + `cephfs_layout.{c,h}`): pure-C, versioned
  Ceph encoding reader + typed decoders (`inode_t` struct_v 2→19, `file_layout_t`,
  dentry primary/remote, fragtree leaves, xattr map). Unit tests (no cluster):
  ```bash
  cc -I src/fs/backend/rados tests/ceph/cephfs_denc_unittest.c   src/fs/backend/rados/cephfs_denc.c -o /tmp/t && /tmp/t
  cc -I src/fs/backend/rados tests/ceph/cephfs_layout_unittest.c src/fs/backend/rados/cephfs_layout.c src/fs/backend/rados/cephfs_denc.c -o /tmp/t && /tmp/t tests/ceph/fixtures/reef-18.2.4
  ```
  Byte fixtures live in `tests/ceph/fixtures/reef-18.2.4/` (see its README).
- **Live driver test** (against the seeded fs, in the build container):
  ```bash
  tests/ceph/run_cephfs_ro_live.sh   # stat/read(5MiB)/ls/getxattr/symlink + EROFS
  ```
  Seed with `cephfs_seed.c` + `cephfs_seed2.c`, then `ceph tell mds.<id> flush
  journal` before reading via RADOS.
- **End-to-end through nginx** (a read-only `cephfsro:` export on both faces):
  ```bash
  docker cp tests/ceph/cephfs_ro_smoke.sh xrd-ceph-work:/work/ &&
    docker exec xrd-ceph-work bash /work/cephfs_ro_smoke.sh
  ```
  Verifies root:// (stat/ls/`xrdcp` GET byte-exact, writes refused) and http://
  WebDAV (GET byte-exact, PUT refused 403) against the seeded CephFS. Needs the
  in-container nginx built with `XROOTD_HAVE_CEPH` and `xrootd-client` installed.

## Recovery & migration tools (operator utilities)

Offline tools (no nginx) that reuse the same RADOS layers. Build + smoke all three
in the container with `tests/ceph/run_rescue_tools.sh` (host-side runner).

- **`xrdcephfs_rescue`** (`tests/ceph/xrdcephfs_rescue.c`) — recover from an
  unmountable **CephFS** via pure RADOS, driving the `cephfsro` core:
  ```bash
  xrdcephfs_rescue <meta_pool> <data_pool> ls|stat|cat|get|cp -r <path> [local]
  ```
- **`xrdrados_rescue`** (`tests/ceph/xrdrados_rescue.c`) — recover from a **flat
  RADOS pool** (the block-only `ceph` backend, or any object pool):
  ```bash
  xrdrados_rescue <pool> ls [prefix] | stat <key> | get <key> <file> | cp <prefix> <dir>
  ```
- **`xrdceph_migrate`** (`tests/ceph/xrdceph_migrate.c`) — **copy-through-mount**
  migration of a flat pool into a real filesystem tree (point `<dest_dir>` at a
  mounted CephFS so its MDS builds the namespace — the only sound migration, since
  CephFS keys data by MDS-allocated inode). Recreates the key→path layout and
  carries `user.*` xattrs (incl. `user.XrdCks.*` checksums):
  ```bash
  xrdceph_migrate <pool> <dest_dir>
  ```
  All three assume a quiesced source and only read from RADOS.

## Python migration tools (XrdCeph ⇄ CephFS, pure Python 3)

Pure-Python re-implementations of the two bidirectional migration tools, with
identical semantics and CLI grammar plus operator quality-of-life additions
(`--json` JSONL output, resumable `--state` manifest, `--prefix`/`--match`
worklist filters, progress, O(N) source indexing). The C++ originals stay the
proven reference; spec:
`docs/superpowers/specs/2026-07-02-python-xrdceph-cephfs-migration-design.md`,
deep reference:
[`docs/10-reference/xrdceph-cephfs-bidirectional-migration.md`](../../docs/10-reference/xrdceph-cephfs-bidirectional-migration.md).

- **`xrdceph_striper_migrate.py`** — striper pool → CephFS (zero-move
  redirects by default; `--mode copy`, `--rollback`, `--finalize`,
  `--verify`, `--delete-source` guard as in C++):
  ```bash
  xrdceph_striper_migrate.py <striper_pool> <cephfs_data_pool> <dest_prefix> \
      [--mode redirect|copy] [--rollback] [--finalize] [--verify] [--list F] \
      [--json] [--state F] [--prefix P] [--match GLOB] ...
  ```
- **`xrdceph_cephfs_to_striper.py`** — quiesced CephFS → striper (namespace
  walked from pure RADOS via the `pymigrate.cephfs_meta` decoders; mandatory
  `--assume-quiesced`; `--report-only` classification; verify via a real
  libradosstriper read):
  ```bash
  xrdceph_cephfs_to_striper.py <meta_pool> <cephfs_data_pool> <striper_pool> \
      --assume-quiesced [--report-only] [--finalize] [--rollback] [--verify] ...
  ```

> **READ-ONLY until finalize** (both directions): a write to a
> redirect-migrated file writes THROUGH to the source object — serve the
> migrated estate read-only, or the source is silently modified and rollback
> can no longer restore it.

**Dependencies:** distro `python3-rados` + `python3-cephfs` only. The
C++-only redirect ops (`set_redirect`/`copy_from`/`tier_promote`/
`unset_manifest`) are reached by `pymigrate/radosbridge.py` via ctypes against
librados's exported (ABI-versioned) C++ symbols, gated by a pre-write
self-test round-trip; if that path is unusable it falls back to compiling the
tiny C-ABI shim `pymigrate/shim/rados_manifest_shim.cpp` (needs g++ +
`librados.hpp`, package `libradospp-devel` on el9). `PYMIGRATE_FORCE_SHIM=1`
forces the shim path; `PYMIGRATE_SHIM=/path/to.so` points at a prebuilt one.

**Tests:**
```bash
# decoder + plumbing unit tests (no cluster):
python3 -m pytest tests/ceph/test_cephfs_meta.py --noconftest -v
# full e2e against the demo cluster (both directions, all modes, shim leg):
tests/ceph/run_py_migrate.sh
```

## What works (verified)

- **Driver data + metadata plane:** range read/write, fstat/stat, truncate, and
  **xattr** (get/set/list/remove) — all against a live RADOS pool.
- **root:// (XRootD wire):** `xrdcp` in/out byte-exact, `xrdfs stat`, `xrdfs
  xattr` set/get/list.
- **http:// (WebDAV):** `curl`/client PUT + GET byte-exact (via the driver's
  `staged_*` write path).
- Objects land as RADOS objects in the configured pool.

## Config

```nginx
# stream (root://) — storage_backend is stream-only; the WebDAV face shares the
# binding via the global registry keyed on the same export root.
stream { server { listen 1094;
    xrootd on; xrootd_root /export; xrootd_auth none; xrootd_allow_write on;
    xrootd_upload_resume off;
    xrootd_storage_backend ceph:xrdtest;          # ceph:<pool>[@<conf>][?<key_prefix>]
} }
http { server { listen 8080;
    location / { xrootd_webdav on; xrootd_webdav_root /export;
                 xrootd_webdav_auth none; xrootd_webdav_allow_write on; } } }
```

`conf` defaults to `/etc/ceph/ceph.conf`. The export root (`/export`) is just a
logical mount point — namespace + data live in RADOS, not on local disk.

## Notes / limitations (basic backend)

- The **flat `ceph`** backend is block-only — it has no directories; `xrdfs
  ls`/`mkdir`/`mv` are unsupported (data movement + stat + xattr work). A real
  directory namespace comes from a CephFS, read via `cephfsro` or migrated into.
- `staged_commit` is a no-op (writes go straight to the final object, like
  root://); true atomic-publish (temp object + copy-on-commit) is a follow-on.
- For production, ceph's synchronous `rados_*` should run on a `thread_pool` so it
  never blocks the event loop (functionally correct without one; perf follow-on).
- The container build uses **stock** `xrdcp`/`xrdfs` + `curl` because the in-tree
  native client currently can't link (unrelated WIP break in `shared/xrdproto`).
