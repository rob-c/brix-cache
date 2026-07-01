# CephFS / RADOS storage program — design

**Status:** design (umbrella program spec), 2026-06-30
**Owner:** Rob Currie
**Predecessor:** [`2026-06-30-cephfs-rados-interop-spike.md`](2026-06-30-cephfs-rados-interop-spike.md)
(the empirical spike that proved the pure-RADOS read path and set the go/no-go
constraints this design builds on).

This is the umbrella design for the RADOS/CephFS storage program. It defines the
final driver lineup, retires the experimental `cephns` driver, and specifies in
detail the first implementable unit — the read-only `cephfsro` driver and its
shared decode core — plus the recovery and migration tooling that share it.

---

## 1. Goals

1. **Two, clearly-scoped RADOS drivers**, no overlap:
   - `ceph` — a **pure librados block-only** backend; the reference for block-only
     storage (the role XrdCeph plays upstream).
   - `cephfsro` — a **read-only** backend that serves a real CephFS by reading its
     RADOS objects directly, for when CephFS cannot be mounted.
2. **Retire `cephns`** (the directory-over-omap experiment) — its niche is better
   served by `ceph` (block-only) below and a real CephFS above.
3. **Recovery tooling** to extract data from a damaged/unmountable cluster via
   librados — for both a pure-RADOS pool and a CephFS layout.
4. **Migration** from RADOS/legacy data into a real CephFS.

### Non-goals
- No writes to a CephFS via RADOS (the MDS owns inode allocation / journal /
  dir omaps / backtraces; out-of-band writes corrupt a live fs — see spike §2).
  `cephfsro` is read-only, full stop.
- No in-place / zero-copy "upgrade" of flat data to CephFS (spike §4 #1: data must
  be re-keyed to MDS-allocated inodes — that is a copy). Migration is copy-based.
- No live-coexistence with an active MDS. Serving/recovery target a **quiesced**
  filesystem (operator-asserted, see §7).

---

## 2. Program map (final lineup)

| Unit | Kind | Role | State |
|---|---|---|---|
| `ceph` | SD driver | Pure librados **block-only** storage; block-only reference | exists (`sd_ceph.c`), keep + refocus |
| `cephfsro` | SD driver | **Read-only** CephFS-via-RADOS | **new** (this spec) |
| `cephfs_denc` / `cephfs_layout` | shared core | Versioned Ceph encoding + typed struct decoders | **new** (this spec) |
| CephFS recovery CLI | tool | Offline extraction of a CephFS via RADOS (the `cephfsro` core, no nginx) | **new** (this spec) |
| pure-RADOS recovery CLI | tool | Offline listing/extraction of a flat pool (the `ceph` layer) | **new** (this spec) |
| rados→cephfs migration | tool | Copy legacy/flat data into a real CephFS (copy-through-mount) | **new** (this spec) |
| `cephns` | SD driver | directory-over-omap experiment | **REMOVE** (§3) |

Implementation order (each later phase depends only on the shared core):
**P0** retire cephns → **P1** decode core (`cephfs_denc`+`cephfs_layout`) →
**P2** `cephfsro` driver + nginx wiring → **P3** CephFS recovery CLI →
**P4** pure-RADOS recovery CLI → **P5** rados→cephfs migration.
The `ceph` driver's refocus (§4) is documentation/scoping only and rides along.

---

## 3. Retiring `cephns` (P0, destructive — explicit go required)

`cephns` (`sd_ceph_ns.c`, the omap-record directory model) is removed. This is a
**destructive cleanup** and will only be executed on an explicit, separate
go-ahead; it is recorded here so the program is internally consistent.

Removal touches (no git operations will be run by the agent):
- `src/fs/backend/rados/sd_ceph_ns.c` — delete.
- `src/fs/backend/rados/sd_ceph_omap.{c,h}` — delete (the cephns record codec;
  **not** reused by `cephfsro`, which decodes CephFS's own omap dentry format via
  the new `cephfs_denc`/`cephfs_layout`, a different on-disk encoding).
- `src/fs/backend/sd_registry.c` — drop the `xrootd_sd_ceph_ns_driver` row.
- `src/fs/vfs_backend_registry.c` — drop the `cephns:` route; the backend-name
  param on `config_ceph` collapses back to the single `ceph` form.
- `config` — drop `sd_ceph_ns.c` + `sd_ceph_omap.c` from the source list.
- tests: `tests/ceph/sd_ceph_ns_live_test.c`, `sd_ceph_omap_unittest.c`,
  `sd_ceph_migrate.c`, `sd_ceph_migrate_test.c`, `ceph_ns_smoke.sh` — delete.
- docs: `docs/superpowers/specs/2026-06-30-cephns-directory-rados-driver-design.md`,
  the cephns sections of `tests/ceph/README.md`, and the memory note.

**Reusable salvage:** the `sd_ceph_conn_t` + `sd_ceph_oid_*` low-level layer that
cephns introduced into `sd_ceph.c` **stays** — `cephfsro` and the recovery tools
build on it. Only the namespace/omap-record layer is removed.

---

## 4. Driver `ceph` — pure librados block-only reference (P-doc)

No behavioural change; this fixes its *role* so the program is coherent:

- `ceph` is the **block-only** backend: flat object store keyed by export-relative
  path, data + xattr + staged write, no directory namespace. It is the reference
  for block-only storage and the substrate the recovery/CephFS layers read through
  (via `sd_ceph_oid_*`).
- The `ceph` driver advertises *no* directory capability; the VFS seam above it
  already handles "backend has no namespace" by returning the right errors. This
  is the natural home for the block-only-metadata question from the original asks
  (#2/#3): block-only means "no namespace ops," expressed as **driver
  capabilities**, not a runtime API flag — the seam consults caps and never issues
  `opendir`/`mkdir`/`rename` to a block-only driver. (A separate API-level
  "metadata-off" switch, if still wanted, is its own spec and is **deferred**.)

---

## 5. Driver `cephfsro` — read-only CephFS via RADOS (P2)

### 5.1 Layering

```
proto handler ─▶ VFS seam ─▶ sd_cephfs_ro  (read-only SD driver)
                                  │  path walk, file read, dir enum
                                  ├─▶ cephfs_layout   (typed struct decoders)
                                  │      └─▶ cephfs_denc (Ceph encoding framing)
                                  └─▶ sd_ceph_oid_*  (raw RADOS object+omap I/O)
```

- **`cephfs_denc.{c,h}`** — pure bytes-in/struct-out. Implements Ceph's encoding
  primitives: fixed LE ints, `ceph_le*`, strings/`bufferlist`s, `std::map`/set
  iteration counts, and the **`ENCODE_START(v, compat, bl)`** framing (struct_v
  byte, compat_v byte, u32 byte-length → bounded sub-cursor) with matching
  `DECODE_FINISH` length-skip. No RADOS, no nginx → unit-testable with plain gcc.
- **`cephfs_layout.{c,h}`** — typed decoders over `cephfs_denc`, each a
  **version-dispatch table** keyed on the `struct_v` read from its frame:
  - `decode_dentry` → primary (`'I'/'i'`) yields embedded inode; remote
    (`'L'/'l'`) yields `(ino, d_type)` to resolve via the anchor.
  - `decode_inode` (`InodeStore`/`inode_t`) → mode, size, mtime/ctime, `nlink`,
    `file_layout_t`, symlink target, and the **xattr map**.
  - `decode_fragtree` (`fragtree_t`) → the set of dir fragments for an inode.
  - `decode_file_layout` → object_size / stripe_unit / stripe_count / pool_id.
  Unknown/too-new `struct_v` → clean `XRDC`/`errno` failure, never a wild read.
- **`sd_cephfs_ro.c`** — the SD driver. Read-side vtable only:
  `open`/`pread`/`preadv`/`fstat`/`stat`/`opendir`/`readdir`/`getxattr`/
  `listxattr` + symlink read. Every mutating slot (`pwrite`, `staged_*`, `unlink`,
  `mkdir`, `rename`, `setxattr`, `truncate`) returns **`EROFS`**.

### 5.2 Path resolution

Walk from the CephFS root inode `0x1`. For each path component `name` under dir
inode `D`:
1. enumerate `D`'s fragments via `decode_fragtree` (default: single frag `.00000000`);
2. read omap key `"<name>_head"` from the fragment object(s)
   `<D_hex>.<frag_hex8>` in the **metadata** pool;
3. `decode_dentry`; if remote, resolve the target inode (anchor/backtrace) to get
   its `inode_t`.

A small per-connection inode cache (LRU) avoids re-decoding hot dirs.

### 5.3 File read

From the file inode's `file_layout_t`, compute object names and offsets:
`object_size`, `stripe_unit`, `stripe_count`, data pool. For the common default
(stripe_count 1, object_size = stripe_unit = 4 MiB) this is the spike's simple
`<ino>.<idx>` sequence; for striped/custom layouts the read maps each
`(file_offset,len)` to the correct `<ino>.<object_index>` in the data pool. Reads
stop at the inode's recorded size (don't trust object presence alone).

### 5.4 Directory listing, hardlinks, symlinks, xattr (v1, all in scope)

- **Fragmented dirs:** `readdir` iterates every fragment object from
  `decode_fragtree`, paging omap keys; entries ending `_head` are current names.
- **Hardlinks:** remote dentries resolve to the primary inode via the anchor; a
  file with `nlink>1` opens identically from any of its names.
- **Symlinks:** target string lives in the inode (`decode_inode`); the driver
  exposes it for the proto layer's symlink semantics.
- **xattr (read-only):** `getxattr`/`listxattr` served from the decoded inode
  xattr map (includes `user.*`; the internal `ceph.*` are filtered/optional).
- **Snapshots (`.snap`):** out of scope for v1 (head only).

### 5.5 Capabilities

A new **read-only** capability profile: `CAP_DIRS | CAP_XATTR` read, **no**
`CAP_WRITE` / rename / mkdir / setxattr. The VFS seam consults caps and never
routes a mutation to `cephfsro`.

### 5.6 Config & registry

CephFS uses **two** pools, so a new config form. The quiesce assertion (§7) is
carried in the backend URI as a required `?assume_quiesced=1` suffix — fail-closed
(a standalone `cephfsro_assume_quiesced` directive is a possible future nicety,
but the URI assertion avoids new directive plumbing and keeps the safety gate in
one place):

```nginx
xrootd_storage_backend cephfsro:<metadata_pool>+<data_pool>[@<conf>]?assume_quiesced=1;
```

`vfs_backend_registry.c` parses the `meta+data` pair and the quiesce assertion;
`sd_registry.c` registers `xrootd_sd_cephfs_ro_driver` (guarded
`#if XROOTD_HAVE_CEPH`). Served read-only through root:// / WebDAV / S3 GET + ls +
stat like the other drivers.

---

## 6. Version dispatch & fixtures (the multi-version requirement)

`cephfs_layout` is **multi-version from day one** by construction: each typed
decoder dispatches on the `struct_v` in its frame, so a single binary handles a
range of Ceph releases and refuses cleanly on an unknown one.

Coverage is proven by **byte-fixtures + ground truth**, not by hardcoded offsets:
- capture real encoded dentries/inodes from a live cluster
  (`rados getomapval … --omap-key '<name>_head' out.bin`);
- dump the authoritative decode with Ceph's own
  `ceph-dencoder type InodeStore import out.bin decode dump_json`;
- a unit test asserts `cephfs_layout`'s C decode matches that JSON.

`ceph-dencoder` is a **build/test-time** tool only — never a runtime dependency.
The table ships seeded with **reef** (the spike cluster); other releases
(pacific…squid) are added as their fixtures are captured from the matching demo
image. The dispatch table makes "add a version" = "add a row + a fixture."

---

## 7. Safety & consistency model

Per the spike, a pure-RADOS reader only sees a consistent namespace when the fs is
**quiesced** (MDS journal flushed, no live writers); un-flushed dentries live in
the MDS journal, and a running MDS mutates omaps/inotable underneath a reader.

Enforcement = **operator assertion** (the chosen model): `cephfsro` refuses to
bind unless the backend URI carries a consistency assertion — `?assume_quiesced=1`
(fs frozen) **or** `?live=1`; there is **no active MDS-state probing**.

**Live mode (still-mounted, best-effort).** `?live=1` serves a fs that is still
mounted and occasionally written, accepting *eventual* consistency. Because the
driver re-resolves per request it already reflects flushed changes; live mode adds
**optimistic walk-version revalidation** — every dir object a resolve depends on is
captured with its RADOS object version and re-checked after the walk, and a
mismatch (an MDS write landed mid-walk) triggers a bounded re-resolve. Both modes
also retry genuinely transient cluster errors with exponential backoff; permanent
errors (a stable not-found, EACCES, unknown encoding) fast-fail. Live mode is *not*
a coherent point-in-time snapshot (cross-object atomicity still belongs to the
MDS); for that, read a CephFS snapshot — a natural follow-on to the deferred
snapshot-decoding work. The operator is responsible for quiescing (e.g. `ceph fs fail <fs>` or
stopping the MDS and `ceph tell mds.<id> flush journal` beforehand). Docs state
this prominently. The recovery CLIs carry the same assertion as a required flag.

---

## 8. Recovery tools (P3, P4)

Both are thin CLIs over already-built layers — no nginx, for when the cluster
can't or shouldn't run the proxy.

- **CephFS recovery CLI** (`xrdcephfs_rescue`): drives the `cephfsro` core to
  `ls` / `stat` / `cat` / recursively **copy out** a subtree of an unmountable
  CephFS to a local dir or another backend. 100% shared decode + walk code.
- **pure-RADOS recovery CLI** (`xrdrados_rescue`): over the `ceph` flat-object
  layer (`sd_ceph_oid_*` + `rados_nobjects_list`) — enumerate, stat, get xattrs,
  and extract objects from a flat pool by key/prefix. For block-only pools with no
  CephFS metadata at all.

Both reuse `client/` credential/temp-file hardening and the VFS↔local copy
primitives where applicable.

---

## 9. rados→cephfs migration tool (P5)

Copy-based, per the spike's NO-GO on in-place upgrade. The tool mounts (or is
pointed at a mount of) the **target CephFS** and copies from a source —
either a flat `ceph` pool (via `xrdrados_rescue`/`sd_ceph_oid_*`) or any export —
into the mount, letting the **MDS** build correct inodes, layout, dentries and
backtraces. It is explicitly a **migrate-copy**, not an in-place conversion; the
simplest form is documented as `xrdcp -r <source-export> <cephfs-mount>`, with the
tool adding resumability, xattr/checksum carry-over (`user.XrdCks.*`), and
progress/verification.

---

## 10. Testing strategy

- **Decoder unit tests** (gcc, no cluster): fixture bytes + `ceph-dencoder` JSON
  ground truth for dentry/inode/fragtree/layout, per supported `struct_v`;
  plus malformed/short/too-new-version inputs → clean failure.
- **Live end-to-end** (`tests/ceph/cephfs_ro_smoke.sh`, in `xrd-ceph-work`):
  seed a known tree (extend the spike's `cephfs_seed.c` to include a **fragmented
  directory**, a **hardlink**, a **symlink**, a **striped-layout file**, and
  **xattrs**), `flush journal`, then assert via root:// / WebDAV:
  byte-exact reads, correct full listings, hardlink open-from-either-name, symlink
  target, xattr read, and **`EROFS` on every write attempt**.
- **Recovery CLIs:** copy-out a subtree, diff against the seeded tree.
- **Migration:** flat pool → mounted CephFS → read back via a normal mount,
  byte-exact + xattr/checksum preserved.
- **Non-ceph host build** stays green (everything Ceph-specific under
  `#if XROOTD_HAVE_CEPH`; `cephfs_denc`/`cephfs_layout` pure-C compile always).

---

## 11. Build / wiring notes

- New sources registered in top-level `./config` (`$ngx_addon_dir/src/...`):
  `cephfs_denc.c`, `cephfs_layout.c`, `sd_cephfs_ro.c`; then `./configure`.
- New `.c` ⇒ `rm -rf objs && ./configure && make` in the container (configure over
  stale objs ⇒ mixed-ABI garbage — known harness gotcha).
- All RADOS work runs inline today; ceph's synchronous `rados_*` on a
  `thread_pool` is a perf follow-on (functionally correct without one), same as the
  existing `ceph` driver.

---

## 12. Open risks

1. **Encoding drift across versions** — mitigated by framed decode + fixtures +
   clean refusal on unknown `struct_v`; still the main maintenance cost.
2. **Anchor/backtrace decode for hardlinks** — the most involved struct; if a
   release proves too costly, hardlinks can degrade to "primary-name only" with a
   logged warning (documented limitation) rather than blocking the release.
3. **Fixture capture needs a demo cluster per version** — only reef available now;
   other versions land incrementally.
4. **Operator-assertion safety** — relies on the operator actually quiescing; the
   docs and the required flag are the only guardrails (by explicit choice).

---

## 13. Decommissioned / deferred

- `cephns` — removed (§3).
- API-level "metadata-off" runtime switch (original ask #2) — superseded by
  driver capabilities (§4); a standalone runtime flag is **deferred** to its own
  spec if still wanted.
