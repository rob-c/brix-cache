# Migrating a CephFS to stock XrdCeph (libradosstriper) — runbook

Operator runbook for `xrdceph_cephfs_to_striper`
(`client/apps/ceph/xrdceph_cephfs_to_striper.cpp`) — the **reverse** of the Glasgow/RAL
tool: it exposes an existing **CephFS** as stock-XrdCeph (libradosstriper) storage,
zero-move via RADOS redirects, then finalizes to a self-owned XrdCeph layout so
CephFS can be torn down. For sites (e.g. Lancaster/Manchester) moving from CephFS
back to XrdCeph.

## Hard requirement: CephFS must be UNMOUNTED / quiesced

The tool walks the CephFS namespace **directly from RADOS** (no mount), using the
same versioned decoder as the read-only `cephfsro` backend. The MDS must **not** be
mutating objects underneath it. So: **stop all clients, fail/stop the fs (`ceph fs
fail <fs>` or stop the MDS), and flush the journal** first. The tool refuses to run
without `--assume-quiesced` (your assertion that this is done).

This is the opposite of the forward direction, and it is unavoidable: the forward
source (striper) was passive data; here the source is CephFS, whose MDS actively
owns the objects — a live MDS would purge/scrub/relocate them under the redirects.

## Why redirect-then-finalize (and why no live zero-move)

CephFS data is `<ino>.<objno8>`; XrdCeph wants `<soid>.<stripe16>` with striper
xattrs. RADOS has no rename, so the names can only be bridged by **redirect** (zero
data movement) or **copy**. Both are in-cluster (no external uplink). This tool uses:

1. **Redirect (default, zero-move):** per file, create striper-named redirect stubs
   `<soid>.<stripe16>` in the target pool pointing at the CephFS data objects, and
   stamp `striper.layout.*` + `striper.size` so libradosstriper reads `<soid>` (=
   the file's path). No bytes copied; CephFS data is the single copy. **Validated:**
   XrdCeph reads whole files byte-exact through the redirects.
2. **`--finalize`:** materialize each stub into an OWNED striper object
   (`tier_promote`, in-cluster), decoupling from CephFS. **Validated:** after
   finalize, deleting the CephFS data objects leaves the file fully readable by
   XrdCeph. CephFS (metadata + data pools) can then be dropped.

## Prerequisites

- CephFS **quiesced/unmounted** (MDS stopped or `fs fail`, journal flushed).
- The CephFS **metadata** and **data** pools + the **target striper pool**
  reachable from an in-cluster node.
- Build deps: `librados` C++ + `libradosstriper` + the in-tree decoder
  (`cephfs_layout.c` + `cephfs_denc.c`).

## Build

```bash
make -C client ceph-tools        # dep-gated; binary lands in client/bin/
# or by hand (the decoders MUST compile as C — g++ would break their extern "C" boundary):
gcc -c -D_FILE_OFFSET_BITS=64 -I src/fs/backend/rados \
    src/fs/backend/rados/cephfs_layout.c -o cephfs_layout.o
gcc -c -D_FILE_OFFSET_BITS=64 -I src/fs/backend/rados \
    src/fs/backend/rados/cephfs_denc.c  -o cephfs_denc.o
g++ -std=c++17 -D_FILE_OFFSET_BITS=64 -I src/fs/backend/rados \
    client/apps/ceph/xrdceph_cephfs_to_striper.cpp cephfs_layout.o cephfs_denc.o \
    -lrados -lradosstriper -o xrdceph_cephfs_to_striper
```

## Pre-flight: identify what will NOT migrate

The walk classifies every namespace entry and prints a summary; `--report-only`
does this as a pure inventory (no changes). **Run it first.**

```bash
xrdceph_cephfs_to_striper <meta_pool> <cephfs_data_pool> <striper_pool> \
    --assume-quiesced --report-only
```

What it identifies and how each is treated:

| Component | Detection | Treatment |
|---|---|---|
| **Hardlinked file** (`nlink>1`) | inode nlink | **migrated but UNVERIFIED** — only the primary path; alias names are dropped |
| **Hardlink alias** (remote dentry) | dentry kind | **skipped** (XrdCeph has no hardlinks) |
| **Symlink** | inode mode | **skipped** (no data objects) |
| **Special file** (fifo/socket/device) | inode mode | **skipped** (no data objects) |
| **File in another data pool** | `file_layout_t.pool_id` ≠ target | **skipped** (data not in the migrated pool) |
| **Snapshots (CoW-diverged)** | non-`_head` dentry keys | counted; **snapshot data NOT migrated** |
| **Snapshots (any)** | `mds_snaptable` `last_snap` ≥ 2 | reported; **`.snap` data NOT migrated** |
| **RADOS pool snapshots** | `rados snap_list` | warned; **not migrated** |
| Out of scope entirely | — | RBD/RGW pools, other CephFS file systems |

Hardlinks are explicitly flagged **UNVERIFIED** (the per-file data migrates fine,
but the multiple-names semantics has no XrdCeph equivalent and was not validated).
If the inventory lists anything you cannot accept losing/changing, resolve it (e.g.
delete snapshots, flatten hardlinks, relocate other-pool files) **before** migrating.

## Procedure

1. **Quiesce** CephFS (stop clients, `ceph fs fail <fs>`, flush journal).
2. **Inventory** with `--report-only` (above); resolve anything unacceptable.

2. **Dry-run** to preview the namespace walk + actions:
   ```bash
   xrdceph_cephfs_to_striper <meta_pool> <cephfs_data_pool> <striper_pool> \
       --assume-quiesced --dry-run
   ```
   `--strip PFX` trims a leading path prefix when forming the soid (the XrdCeph
   object id = the file's path).

3. **Redirect (zero-move) with verify:**
   ```bash
   xrdceph_cephfs_to_striper <meta_pool> <cephfs_data_pool> <striper_pool> \
       --assume-quiesced --verify --threads 8
   ```
   `--verify` reads each soid back through `libradosstriper` and checks the carried
   `user.XrdCks.adler32`. Re-runnable: already-stamped soids are skipped.

4. **Validate + cut over** XrdCeph to serve from the striper pool. At this point the
   data still physically lives in the CephFS data pool (behind redirects) and is
   read-only — do not write through XrdCeph yet.

5. **Finalize** to decouple, once you are happy:
   ```bash
   xrdceph_cephfs_to_striper <meta_pool> <cephfs_data_pool> <striper_pool> \
       --assume-quiesced --finalize --threads 8
   # optionally drop the CephFS data objects as you go:
   #   ... --finalize --delete-source
   ```
   After finalize the striper objects are owned and writable; XrdCeph is fully
   independent of CephFS.

6. **Decommission CephFS** — delete its metadata + data pools.

### Rollback (before finalize)

```bash
xrdceph_cephfs_to_striper <meta_pool> <cephfs_data_pool> <striper_pool> \
    --assume-quiesced --rollback
```
Removes the striper overlay; **detaches each stub (`unset_manifest`) before
deleting** so the delete cannot propagate to the CephFS data objects (a redirect
stub delete-throughs otherwise). The CephFS data is left intact — bring the MDS
back up to resume CephFS. (Rollback is only meaningful **before** `--finalize`; once
finalized and the CephFS source is dropped, there is nothing to roll back to.)

## Options

| Option | Effect |
|---|---|
| `--assume-quiesced` | REQUIRED — assert CephFS is unmounted/failed + journal flushed |
| `--report-only` | walk + classify + print the unhandled-component inventory; migrate nothing |
| `--finalize` | materialize redirects into owned striper objects (decouple) |
| `--rollback` | remove the striper overlay (detaches stubs; CephFS intact) |
| `--strip PFX` | strip a leading path prefix when forming the soid |
| `--threads N` | parallel workers (default 4) |
| `--verify` | libradosstriper-read each soid + check `user.XrdCks.adler32` |
| `--delete-source` | (finalize only) delete the CephFS data objects after verify |
| `--dry-run` | report actions, write nothing |
| `--conf PATH` | ceph.conf (default `/etc/ceph/ceph.conf` / `$CEPH_CONF`) |

## Safety summary

- **Redirect phase is read-only and reversible**: CephFS data is untouched (the
  redirects only read it); `--rollback` removes the overlay without harming it.
  Serve XrdCeph read-only until finalized — a write through a redirect would
  propagate to the CephFS data object.
- **Finalize is the point of no return** for `--delete-source`: once the CephFS
  data is dropped, the striper objects are the only copy.
- Idempotent/resumable; the walk + per-file work re-run safely.
- All data movement (finalize's `tier_promote`) is **in-cluster** — never the
  external uplink.

## Caveats / scope

- Single shared geometry per file is taken from the CephFS inode layout
  (`object_size`/`stripe_unit`/`stripe_count`); striper objects are stamped to
  match, so libradosstriper reads them with identical striping.
- Hardlinks (remote dentries) and snapshots are skipped by the walk (head, primary
  inodes only) — handle those out of band if present.
- Validated on reef 18.2.4 against a seeded CephFS file (redirect read byte-exact +
  checksum, finalize + source-delete still readable). Recovery/scrub of redirect
  objects and cross-version behaviour carry the same "validate first" caveats as
  the forward tool.
