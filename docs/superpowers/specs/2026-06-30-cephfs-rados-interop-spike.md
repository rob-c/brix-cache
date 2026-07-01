# CephFS ↔ RADOS interop — research spike findings

**Status:** spike COMPLETE 2026-06-30 — empirical, with a working read-path PoC.
**Owner:** Rob Currie
**Question:** can we (1) *upgrade* existing flat/cephns RADOS data to be readable
by a real CephFS, and (2) build a `cephfs-rados` backend that serves
CephFS-stored data via pure RADOS when CephFS can't be mounted? In what envelope?

**Method:** stood up a real single-node CephFS in the Docker harness (MDS added
to `xrd-ceph-demo`; pools `cephfs_metadata`/`cephfs_data`), seeded a known tree
via **libcephfs** (`tests/ceph/cephfs_seed.c` — no kernel mount / no `/dev/fuse`),
then dissected the on-RADOS layout with the `rados` CLI and **proved a pure-RADOS
read path** (`tests/ceph/cephfs_rados_poc.c`).

---

## 1. Confirmed on-RADOS layout (Ceph reef, empirical)

Seed tree → inodes: `/`=0x1, `/top.txt`=0x10000000002 (15 B), `/dir1`=0x10000000000,
`/dir1/hello.txt`=0x100000001f7 (27 B), `/dir1/sub`=0x10000000001,
`/dir1/sub/big.bin`=0x100000001f8 (5 MiB).

### Data pool (`cephfs_data`)
- File bytes live in objects named **`<ino_hex>.<stripe_index_hex8>`**, striped at
  the file's `object_size` (default **4 MiB**). Verified: `big.bin` (5 MiB) →
  `100000001f8.00000000` (4 MiB) + `100000001f8.00000001` (1 MiB); `hello.txt` →
  `100000001f7.00000000`.
- The **first** object (`.00000000`) carries xattrs **`layout`** (the
  `file_layout_t`: object_size/stripe_unit/stripe_count/pool) and **`parent`**
  (the *backtrace*: inode ancestry, used by `cephfs-data-scan` recovery). **These
  appear only after the MDS flushes** (see §2).

### Metadata pool (`cephfs_metadata`)
- A directory is an object **`<dirino_hex>.00000000`** whose **OMAP** maps one key
  per child: **`"<name>_head"`** → a Ceph-encoded **primary dentry** (`'i'`=0x69)
  embedding the full `InodeStore`/`inode_t` (~500 B). The child **inode number** is
  a little-endian u64 at a **version-specific offset** (offset 31 in reef).
- Also present: `<ino>.00000000.inode` (per-inode), the **MDS journal** objects
  (`200.0000000x`), `mds0_inotable` (inode allocator), `mds0_sessionmap`,
  `mds_snaptable`, `mds0_openfiles.0`, and assorted `4xx/5xx/6xx` system objects.

---

## 2. The decisive constraint: the MDS owns the metadata

Immediately after creating the tree, the dir-object omaps were **empty** and the
data backtraces absent — the dentries lived only in the **MDS journal + in-memory
cache**. Only after `ceph tell mds.demo flush journal` did the dir omaps populate
(`dir1_head`, `top.txt_head`, …) and the data `parent`/`layout` xattrs appear.

Consequences:
- **A pure-RADOS reader sees consistent namespace only on flushed metadata.** It
  must run against a **quiesced** fs (ideally MDS down / fs `failed`), or it will
  miss/stale recently-changed entries still in the journal.
- **Out-of-band writes cannot coexist with a live MDS.** Inode allocation
  (`mds0_inotable`), dir omaps, the journal and backtraces are MDS-owned;
  modifying them under a running MDS corrupts the filesystem.

---

## 3. PoC: pure-RADOS read path (PROVEN)

`tests/ceph/cephfs_rados_poc.c` — no mount, no libcephfs, only `librados` omap +
object reads:
1. start at root inode `0x1`;
2. per path component, read omap key `"<name>_head"` from `<dirino_hex>.00000000`
   in the metadata pool; extract the child inode (LE u64 @ reef offset 31);
3. read `<ino_hex>.<idx_hex8>` from the data pool, idx = 0,1,… until `-ENOENT`.

Result (against the live fs): `/dir1/sub/big.bin` → ino `0x100000001f8` → **5242880
bytes reconstructed byte-exact** (head `BIGSTART`, tail `BIGENDED`) from 2 objects;
`hello.txt` and `top.txt` likewise. **The read path is feasible.**

---

## 4. Go/no-go + recommendations

### #1 — "upgrade existing librados data → CephFS-compatible"
- **Zero-copy / in-place upgrade: NO-GO.** CephFS keys data by **MDS-allocated
  inode**; our objects are keyed by LFN/uuid. Adoption-in-place is impossible —
  objects must be re-keyed (a copy; RADOS has no rename) **and** inodes must be
  minted by the MDS (can't be safely allocated offline without collision).
- **Recommended (GO): copy-through-mount.** Mount the target CephFS and copy from
  the cephns export into it; the MDS lays down correct inodes, layout, dentries
  and backtraces. It is a **migrate-copy, not an in-place upgrade** — bytes are
  rewritten. Tooling: a thin copier (cephns reader → CephFS-mount writer), or
  simply `xrdcp -r` from the cephns export to a CephFS-backed export.
- The offline `cephfs-data-scan`/`cephfs-table-tool` route exists but is the
  disaster-recovery path (fragile, MDS-down, version-sensitive) and still can't
  avoid the re-key copy — **not recommended** as a product feature.

### #4 — "cephfs-rados" backend (serve CephFS data via pure RADOS)
- **Read-only: GO**, scoped as a **rescue/last-resort reader** for when the fs
  can't be mounted but the pools are intact and the fs is **quiesced/MDS-down**.
  The PoC proves the mechanism. Real work beyond the PoC:
  - a **version-pinned dentry/`inode_t` decoder** (`sd_cephfs_decode.{c,h}`,
    unit-tested against captured byte fixtures; start at reef, gate by encode
    version) — this is the main cost + ongoing maintenance risk;
  - per-inode **layout decode** (`object_size`/stripe params) for non-default /
    striped files (the PoC assumed consecutive default-4 MiB objects);
  - **fragmented directories** (large dirs split into `<ino>.<frag>` objects) and
    **remote dentries** (`'L'/'l'` hardlinks);
  - a hard **"fs must be quiesced"** guard + clear operator docs.
  - Implementation reuses the existing `sd_ceph_conn_t` + `sd_ceph_oid_*` layer; a
    `cephfsro` driver implements stat/open/pread/opendir/readdir over the omap
    walk + data reads.
- **Read-write: NO-GO.** Cannot coexist with a live MDS without corruption;
  out of scope.

### Reference alignment (relates to the deferred block-only sub-project)
- For *block-only* storage, **stock XrdCeph (libradosstriper)** remains the
  reference; the `cephfs-rados` work is orthogonal (it reads a *foreign* CephFS
  layout, it is not our native storage format).

---

## 5. Spike artifacts (throwaway, under `tests/ceph/`)
- `cephfs_seed.c` — libcephfs seeder (creates the known tree).
- `cephfs_rados_poc.c` — the pure-RADOS path→ino→bytes reader (PoC).
- Harness: the existing `xrd-ceph-demo` cluster gained an MDS + a `cephfs` fs
  (additive; `xrdtest` pool untouched).

## 6. Proposed follow-on sub-projects (each its own spec, if pursued)
1. **`cephfs-rados` read-only rescue driver** — the versioned decoder + `cephfsro`
   backend + quiesce guard + Ceph-version test matrix.
2. **CephFS migrate-copy tool** — cephns → CephFS-mount copier (documented as a
   copy), or just document the `xrdcp -r` recipe.
3. **Block-only mode + XrdCeph alignment** (the originally-deferred sub-project).
