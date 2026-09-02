# Storage Driver Slot Matrix — every backend, every verb, one verdict per cell

> **Audience:** anyone extending a storage backend, or deciding whether a feature
> can be offered over a given export type.
> **Scope:** the 58 function-pointer slots of `struct brix_sd_driver_s`
> (`src/fs/backend/sd.h`) against all 12 registered drivers.
> **Companions:** [`storage-backend-drivers-deep-dive.md`](storage-backend-drivers-deep-dive.md)
> (how each driver works), [`src/fs/backend/README.md`](../../src/fs/backend/README.md)
> (file-by-file map), [`multi-user-backend-credentials-through-the-vfs.md`](multi-user-backend-credentials-through-the-vfs.md)
> (the `_cred` plane).

---

## 0. What this document is for

The SD vtable is the whole contract between the protocol layer and storage. A
NULL slot is not a bug by itself — for most backends it is the honest answer, and
the VFS has a generic fallback that is frequently *exact*. But a NULL slot is also
where a feature quietly stops working on one export type and nobody notices,
because nothing above the seam is red.

So this document takes a position on **every empty cell**: either the backend's
protocol cannot express the verb, or something above the driver already answers
it correctly, or it is a real gap — and a real gap gets closed, not catalogued.
§6 is the record of the last eleven.

**Current state: 421 of 756 cells implemented, zero open gaps.** Every empty
cell now carries a verdict, and the verdicts are machine-checked against the
source. §6 records what each of the eleven former gaps landed as, and — where the
protocol stops short of the whole verb — exactly where the ceiling is.

### Regenerating the table

```bash
python3 tools/diag/sd_slot_matrix.py docs/09-developer-guide/_slot-matrix-table.md
```

The implemented half is read out of `src/fs/backend/**/*.c`; only the verdicts for
the empty cells are editorial, and they live in that script. It exits non-zero on
either of two drifts:

* **an empty cell with no verdict** — a new slot was added to the vtable, or a
  driver lost one, and nobody said what that means;
* **a verdict for a cell that is now implemented** — the excuse outlived the gap.

The second check is the one that matters over time. A stale "this protocol cannot
do that" is how a table like this becomes a fiction.

---

## 1. The matrix

| op | posix | pblock | block | mir | ceph | cfs-ro | frm | http | remote | xroot | cache | stage |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `init` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | nil | nil | nil | nil | nil | nil |
| `cleanup` | ✅ | ✅ | nil | nil | ✅ | ✅ | nil | nil | nil | nil | nil | nil |
| `open` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `close` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `pread` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `pwrite` | ✅ | ✅ | ✅ | syn | ✅ | ro | tier | np | np | ✅ | dec | ✅ |
| `preadv` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | tier | ✅ | ✅ | ✅ | dec | dec |
| `preadv2` | ✅ | ✅ | ✅ | syn | ✅ | seam | tier | np | np | np | dec | dec |
| `copy_range` | ✅ | ✅ | seam | syn | seam | ro | tier | sup | sup | sup | dec | dec |
| `read_sendfile_fd` | ✅ | ✅ | ✅ | syn | ✅ | np | tier | np | np | np | ✅ | dec |
| `ftruncate` | ✅ | ✅ | flat | syn | ✅ | ro | tier | np | np | ✅ | dec | ✅ |
| `fsync` | ✅ | ✅ | ✅ | syn | ✅ | ro | tier | np | np | ✅ | dec | ✅ |
| `fstat` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `read_advise` | ✅ | ✅ | ✅ | syn | np | np | tier | np | np | np | ✅ | dec |
| `reserve` | ✅ | ✅ | ✅ | syn | np | ro | sup | np | sup | sup | ✅ | ✅ |
| `stat` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `unlink` | ✅ | ✅ | flat | syn | ✅ | ro | tier | ✅ | ✅ | ✅ | ✅ | ✅ |
| `unlink_many` | np | ✅ | flat | syn | ✅ | ro | tier | np | ✅ | np | ✅ | ✅ |
| `mkdir` | ✅ | ✅ | flat | syn | ✅ | ro | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `rename` | ✅ | ✅ | flat | syn | ✅ | ro | tier | ✅ | ✅ | ✅ | ✅ | ✅ |
| `server_copy` | ✅ | ✅ | flat | syn | np | ro | tier | ✅ | ✅ | ✅ | ✅ | ✅ |
| `setattr` | ✅ | ✅ | flat | syn | ✅ | ro | tier | ✅ | ✅ | ✅ | ✅ | ✅ |
| `truncate_path` | seam | seam | flat | syn | ✅ | ro | tier | np | np | ✅ | ✅ | ✅ |
| `sync_publish` | ✅ | ✅ | flat | syn | np | ro | ✅ | np | np | np | ✅ | ✅ |
| `exchange` | ✅ | ✅ | flat | syn | np | ro | ✅ | np | np | np | ✅ | ✅ |
| `opendir` | ✅ | ✅ | ✅ | syn | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `readdir` | ✅ | ✅ | ✅ | syn | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `closedir` | ✅ | ✅ | ✅ | syn | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `getxattr` | ✅ | ✅ | flat | syn | ✅ | ✅ | tier | ✅ | ✅ | ✅ | ✅ | ✅ |
| `listxattr` | ✅ | ✅ | flat | syn | ✅ | ✅ | tier | ✅ | ✅ | ✅ | ✅ | ✅ |
| `setxattr` | ✅ | ✅ | flat | syn | ✅ | ro | tier | ✅ | ✅ | ✅ | ✅ | ✅ |
| `removexattr` | ✅ | ✅ | flat | syn | ✅ | ro | tier | ✅ | ✅ | ✅ | ✅ | ✅ |
| `staged_open` | ✅ | ✅ | flat | syn | ✅ | ro | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `staged_write` | ✅ | ✅ | flat | syn | ✅ | ro | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `staged_commit` | ✅ | ✅ | flat | syn | ✅ | ro | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `staged_abort` | ✅ | ✅ | flat | syn | ✅ | ro | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `staged_path` | ✅ | ✅ | flat | syn | path | ro | path | path | path | path | path | path |
| `dedup_publish` | ✅ | ✅ | cas | cas | cas | cas | cas | cas | cas | cas | cas | cas |
| `dedup_gc` | ✅ | refc | cas | cas | cas | cas | cas | cas | cas | cas | cas | cas |
| `recall` | np | ✅ | np | syn | np | np | ✅ | ✅ | ✅ | ✅ | walk | walk |
| `residency` | np | ✅ | np | syn | np | np | ✅ | ✅ | ✅ | ✅ | walk | walk |
| `recall_cred` | id | ✅ | id | syn | np | ro | ✅ | ✅ | ✅ | ✅ | walk | walk |
| `evict` | nil | ✅ | flat | syn | nil | ro | ✅ | np | np | ✅ | ✅ | ✅ |
| `evict_cred` | id | ✅ | id | syn | nil | ro | id | np | np | ✅ | ✅ | ✅ |
| `space` | seam | ✅ | ✅ | syn | ✅ | ✅ | tier | ✅ | np | ✅ | ✅ | ✅ |
| `query_checksum` | seam | seam | seam | syn | ✅ | seam | tier | ✅ | ✅ | ✅ | walk | walk |
| `enumerate` | ns | ✅ | ns | syn | ✅ | ns | np | ns | ✅ | ns | walk | walk |
| `open_cred` | id | ✅ | id | syn | ✅ | ro | id | ✅ | ✅ | ✅ | ✅ | ✅ |
| `staged_open_cred` | id | ✅ | id | syn | scope | ro | id | ✅ | ✅ | ✅ | ✅ | ✅ |
| `stat_cred` | id | ✅ | id | syn | ✅ | ro | id | ✅ | ✅ | ✅ | ✅ | ✅ |
| `unlink_cred` | id | ✅ | id | syn | ✅ | ro | id | ✅ | ✅ | ✅ | ✅ | ✅ |
| `unlink_many_cred` | id | ✅ | id | syn | ✅ | ro | id | np | ✅ | np | ✅ | ✅ |
| `mkdir_cred` | id | ✅ | id | syn | scope | ro | id | ✅ | ✅ | ✅ | ✅ | ✅ |
| `rename_cred` | id | ✅ | id | syn | scope | ro | id | ✅ | ✅ | ✅ | ✅ | ✅ |
| `exchange_cred` | id | ✅ | id | syn | np | ro | id | np | np | np | ✅ | ✅ |
| `setattr_cred` | id | ✅ | id | syn | ✅ | ro | id | ✅ | ✅ | ✅ | ✅ | ✅ |
| `truncate_path_cred` | id | seam | id | syn | ✅ | ro | id | np | np | ✅ | ✅ | ✅ |
| `getxattr_cred` | id | ✅ | id | syn | ✅ | ro | id | ✅ | ✅ | ✅ | ✅ | ✅ |
| `listxattr_cred` | id | ✅ | id | syn | ✅ | ro | id | ✅ | ✅ | ✅ | ✅ | ✅ |
| `setxattr_cred` | id | ✅ | id | syn | ✅ | ro | id | ✅ | ✅ | ✅ | ✅ | ✅ |
| `removexattr_cred` | id | ✅ | id | syn | ✅ | ro | id | ✅ | ✅ | ✅ | ✅ | ✅ |
| `server_copy_cred` | id | ✅ | id | syn | np | ro | id | ✅ | ✅ | ✅ | ✅ | ✅ |
| `opendir_cred` | id | ✅ | id | syn | ✅ | ro | id | ✅ | ✅ | ✅ | ✅ | ✅ |
| **implemented** | **37** | **59** | **17** | **7** | **44** | **14** | **19** | **40** | **42** | **47** | **47** | **48** |

_63 slots x 12 drivers = 756 cells: 421 implemented, 0 open gaps (marked ⚠)._

## 2. Legend

| code | meaning |
|---|---|
| ✅ | implemented |
| **⚠** | **real remaining gap** — the protocol can express it and we do not. None remain; the generator still emits this marker so the next one is visible the day it appears. See §6. |
| `seam` | the generic path above the driver is **exact**, not degraded. A slot here would save a syscall or a round trip, nothing more. |
| `np` | **the protocol/API has no such operation.** There is no wire verb or library call to route to. |
| `sup` | **superseded** by another slot on the same driver, which the VFS already prefers. |
| `ns` | **the namespace IS the catalog.** `enumerate` exists to reconcile a driver's *own* object store against the namespace; a driver with only one of those has nothing to reconcile, and a walk is the inventory. |
| `flat` | **flat fixed-extent device** (`block`): the export is N equal-size extents named `/0`…`/N-1`. No namespace to mutate, no xattrs to carry, no shrink, no staged commit. |
| `ro` | **read-only driver by design** (`cephfs_ro`) — see §4. |
| `tier` | **the composing registry requires a tier in front, and that tier owns the slot** (`frm`) — see §4. |
| `id` | **no assumable per-user identity at this backend**, so no `_cred` twin. Deny mode refuses rather than silently running as the export — see §5. |
| `scope` | the op **cannot be honestly scoped to the caller** with the state it threads; documented per-slot in the driver — see §4 (`ceph`). |
| `dec` | **decorator byte plane**, deliberately outside the parity contract — see §3. |
| `walk` | **the seam descends the decorator chain** (or the object carries its own driver), so a decorator slot here would shadow the real answer — see §3. |
| `nil` | the driver holds nothing that needs the slot: no registry lifecycle (`init`/`cleanup` on a cache-constructed or composed driver), or no state to release. |
| `syn` | **synthetic zero-storage backend** (`mirage`): it holds no bytes and no namespace — every read is computed from the offset — so there is nothing to mutate, list, stage, scope or account for. |
| `cas` | **commit-time content dedup is a cache-STORE verb.** `src/fs/cache/gcas.c` calls `dedup_publish`/`dedup_gc` on `cs->store->driver` directly, never down a decorator chain, so only a driver configurable as `brix_cache_store` is ever asked. |
| `refc` | **the alias has no separate lifetime to collect** (`pblock`): F10 refs fold byte-identical blobs and the refcount reaps the canonical, so a NULL `dedup_gc` is the contract in `sd.h`, not an omission. |
| `path` | **no real local filesystem path exists to hand out.** `staged_path` is what lets the cache manifest hand a protocol handler an on-disk path for a staged object; only a true local filesystem has one. `sd_cache_manifest` enforces this at config time, so a non-POSIX staging tier is rejected at `nginx -t`, not at runtime. |

### The two counts that do not match

`tools/ci/check_sd_driver_conformance.py` reports 38 ops for `posix` where this
table says 36. Both are right: the conformance checker counts every field of the
struct initialiser, and `name`, `caps` and `cred_accept` are **data**, not
function pointers. This table censuses the 61 *slots*. `posix` has 36 slots plus
`name` and `caps`; `remote` has 42 plus all three.

---

## 3. The decorator contract (`cache`, `stage`)

`cache` and `stage` are not backends — they wrap one. That makes two whole
classes of empty cell correct by construction, and the parity gate in
`check_sd_driver_conformance.py` encodes exactly where the line is.

**`dec` — the byte plane is excluded on purpose.** The parity base covers the
namespace, xattr and space verbs plus their `_cred` twins, and stops there,
because *the cache serves reads from its store and the stage tier owns writes*.
Their data slots differ by design and always will. Two consequences worth
knowing before filing a bug against one:

* A whole-file cache **hit** never reaches `sd_cache`'s byte slots at all — it
  returns the store object, which carries the store's own driver. The cache's
  `pread` is reached only for a **partial/slice** object. That is why the missing
  `preadv` costs nothing: `brix_sd_obj_preadv`'s per-iovec `pread` loop runs
  against block-granular fills, so there is no round-trip amplification to avoid.
* `stage` is the mirror image: its `pwrite`/`ftruncate`/`fsync` are the write-back
  path and its read-side extras are absent for the same reason.

**`walk` — the seam already descends.** `recall`, `residency`, `enumerate` and
`query_checksum` are questions about the **backing store**, so the VFS walks
`brix_vfs_decorator_source()` to the first implementer rather than asking the top
of the chain. A decorator slot here would answer *about the cache* a question
that was asked *about the origin* — a cache-fronted tape export would report
ONLINE for everything. The descent is unit-tested in
`tests/c/test_vfs_enumerate_decorator.c`, including that the first implementer
wins and that the walk only ever descends.

**Where parity IS enforced.** The gate exists because it caught a real defect:
`truncate_path` was relayed by `stage` and not by `cache`, so a cache-fronted
`root://` export silently lost path-native truncate. Note the fix's shape — the
capability gate moved to the **leaf** while dispatch stays on the leaf too;
adding the slot to `cache` alone would have converted the working
open + `ftruncate` fallback into `ENOSYS` over http/s3/posix.

---

## 4. Per-driver reading

**`posix` (36).** The reference implementation, and the only driver with
`staged_path`. Its six non-`_cred` blanks are all `seam` or `np`: `statvfs(2)` *is*
the exact answer for `space` (the slot exists for backends whose logical space
differs from the filesystem underneath — pblock quota, an origin's `oss.space`);
`query_checksum` is answered from `user.XrdCks.*` by the layer above; a plain
filesystem is never nearline.

**`pblock` (57).** The most complete driver — POSIX parity over a SQLite catalog,
including the nearline pair and its own `enumerate` (catalog rows vs. block
files is precisely the reconciliation `enumerate` was added for). Its four blanks
are `staged_path` (the staged object is block-chain, not a file) and the
`truncate_path`/`query_checksum` seams.

**`block` (17).** A raw device presented as fixed-size extents. Almost every blank
is the `flat` verdict: there is no namespace, so nothing to rename or list
xattrs on, and the extents are fixed, so there is nothing to truncate. It carries
`space` because the device capacity is a real number. Its two zero-copy/advisory
slots are implemented **inside the extent window** — §6.6.

**`ceph` (44).** Flat RADOS with a synthetic directory model (ADR-1). `server_copy`
is `np` on a verified reading of the headers, not the documentation: librados'
`copy_from` is **C++-only**, and the C API has no equivalent — the C header is the
authority here. The three `scope` cells are documented at the top of
`sd_ceph_ns_cred.c` and are worth repeating, because they are the interesting
kind of "no":

* `rename_cred` — `sd_ceph_rename` copies bytes through `st->striper`, which is
  bound to the **export's** connection. A cred-shaped wrapper would assert the
  wrong identity for the copy while looking correct at the call site.
* `staged_open_cred` — a cred-scoped stage would have to hold the ioctx and pin
  the connection across both commit *and* abort.
* `mkdir_cred` — directories are synthetic and `mkdir` touches no object, so
  there is no cluster-side authority to scope.

That file exists because **in RADOS the ioctx IS the identity at the OSDs**: with
only `open_cred` published, every metadata op still ran as the service account
while the data plane was checked as the user. Classic confused deputy, visible
only in allow mode — deny mode was always safe (§5).

**`cephfs_ro` (14).** A rescue driver: it reads a CephFS's on-RADOS structures
directly, with no MDS and no mount, and `init()` refuses to bind unless the
operator asserts the filesystem is quiesced. Every mutating slot is absent by
design. The `_cred` column is `ro` for a reason that is *not* just "read-only":
this driver reads the **metadata pool's omaps** directly, and raw metadata-pool
access is an admin-level CephX capability that no per-user keyring should hold.
Per-user scoping here would be worse than the export account, not better.

**`frm` (18).** The nearline (tape/MSS) driver is a thin residency layer, and the
composing registry **requires a cache tier in front** — so the byte and namespace
verbs are the tier's, not the tape's. `enumerate` is `np` rather than `tier`: the
MSS adapter vtable is `exists`/`recall`/`migrate`/`purge`, per key. HSMs answer
about a key you name; they do not hand you the tape's inventory.

**`http` (40) and `remote` (42).** The two object/HTTP origins share a shape: no
partial write (`PUT`/`COPY` are whole-object, which is exactly what the
`staged_*` slots do), no local fd, no per-read flags. `remote`'s `space` is `np`
because the S3 API has no capacity endpoint at all — no bucket usage, no quota;
`http` has one because RFC 4331 `quota-available-bytes` is a real WebDAV property.
Both now carry the nearline pair — over the WLCG Tape REST API and over S3
GLACIER respectively — and both arm `CAP_NEARLINE` only from an explicit operator
field, never by inference (§6.1–6.3).

**`xroot` (47).** The most complete remote driver, with a native spelling for
nearly everything: `kXR_Qspace`/`kXR_QFSinfo` for `space`, `kXR_Qcksum` for
`query_checksum`, `kXR_chmod` for `setattr`, TPC for `server_copy`, and the
nearline pair over `kXR_prepare`. Its blanks are the vectored/advisory reads that
the root:// wire has no verb for, plus `enumerate` (`ns`).

---

## 5. The `_cred` plane, and why `id` is safe

`sd_cred_forward.h` routes to the `_cred` slot when a per-user credential is
present *and* the driver implements it, otherwise to the plain slot — **unless**
the caller is in deny mode (`cred->fallback_deny`) and the plain slot would
actually run. That combination means a per-user op would silently execute on the
shared service credential in a mode that explicitly forbids the fallback, so it
is refused with `EACCES` before any I/O.

That rule was written as defensive hardening when nothing had the shape. It is
**live now**: `posix`, `block`, `frm` and `cephfs_ro` all carry plain slots with
no `_cred` twin, which is what the `id` verdict means — a local or read-only
backend has no per-user identity to assume. So an `id` cell is not an unguarded
hole; it is a slot that deny mode refuses and allow mode runs as the export,
which is the documented allow-mode contract.

Two lessons from closing the `_cred` asymmetries are worth carrying into any new
driver:

* **A LAZY slot must COPY the borrowed credential.** `sd_remote`'s `opendir_cred`
  keeps fetching pages after the slot returns; `sd_ceph`'s is eager and can
  release. Getting this backwards is a use-after-free that only fires under
  pagination.
* **Assert on the signing key, never on the bytes.** The `sd_remote` confused
  deputy was invisible in a body-diff test and obvious the moment the test looked
  at which credential signed the request.

---

## 6. The 11 gaps, and what closed them

All eleven are implemented. What follows is the record of each: the spelling that
was chosen, and — where the protocol cannot express the whole verb — the exact
line the implementation stops at, because that line is now the honest ceiling
rather than an absence.

### 6.1 `http` · `recall` + `residency` — the WLCG Tape REST API

`http/sd_http_nearline.c`. `residency` is one `POST {tape_api}/archiveinfo` with
`{"paths":["/key"]}`, and the reply's per-file `locality` maps onto the four
residency states: `DISK`/`DISK_AND_TAPE` → ONLINE, `TAPE` → NEARLINE,
`UNAVAILABLE` → OFFLINE, `LOST` → LOST, `NONE` → `ENOENT`. `recall` asks
residency first, returns `NGX_OK` when the object is already online, and
otherwise `POST {tape_api}/stage` with `{"files":[{"path":"/key"}]}`, keeping the
reply's `requestId` and parking the open with `NGX_AGAIN`.

Two decisions are load-bearing:

* **An unknown locality is `EIO`, not ONLINE.** The Tape REST API's vocabulary is
  closed, so a token this build has not seen means we are not talking to that API
  — reading it as ONLINE would serve a stub for an object still on tape.
* **The cap is declared, never inferred.** `cfg->tape_api` — and nothing else —
  arms `BRIX_SD_CAP_NEARLINE`, because the composing registry *requires* a cache
  tier behind a nearline driver (§9.4 of the tier contract). Inferring the cap
  from, say, a 202 on a GET would turn working configurations into `nginx -t`
  failures.

The object key travels through `sd_http_json_quote`, which escapes `"`, `\` and
control bytes and **refuses** an overflow rather than truncating: a truncated path
names a different object. That is an injection defence before it is an encoding —
the same reasoning as the hex-encoded dead-property names in 6.3.

### 6.2 `remote` · `recall` + `residency` — S3 GLACIER + RestoreObject

`remote/sd_remote_nearline.c` over two new S3 primitives in `s3/sd_s3_archive.c`:
`sd_s3_archive_state` (one HEAD, three headers) and `sd_s3_restore`
(`POST ?restore` with a `<RestoreRequest>` body, signed through `sd_s3_sign_ext`).
`x-amz-storage-class` in `GLACIER`/`DEEP_ARCHIVE` is nearline; a non-empty
`x-amz-archive-status` catches the INTELLIGENT_TIERING demotion, which keeps its
storage class and reports the demotion only there; `ongoing-request="false"` in
`x-amz-restore` means a restored copy is readable **now**, so that reads ONLINE.

Three details worth carrying:

* **The unknown class maps the opposite way to 6.1** — an unrecognised S3 storage
  class reads as ONLINE. AWS adds classes routinely and every non-archival one
  serves reads directly; guessing "archived" would park every open on a restore
  that was never needed, whereas guessing "online" degrades to exactly the
  behaviour this driver had before the slot existed. The asymmetry with the
  http mapping is deliberate and documented in both files.
* **`Tier: Standard`, not Expedited.** Expedited is a paid capacity reservation
  AWS can refuse outright; a recall that fails because the reservation was
  unavailable is worse than a slower one that succeeds.
* **409 `RestoreAlreadyInProgress` is the same outcome as 202.** Treating it as an
  error would fail every concurrent reader of one archived object but the first.

`recall` leaves `reqid_out` empty: RestoreObject issues no request id, and the
poll is the next HEAD. Neither slot ever reports OFFLINE or LOST — S3 has no
spelling for either, and inventing one would be a verdict the API never gave.
`CAP_NEARLINE` is armed from `cfg->nearline`, the operator's declaration that the
bucket is archive-backed, for the same reason as 6.1.

To take three headers off **one** round trip, the static HEAD leg in
`sd_s3_meta.c` was split into a shared `sd_s3_head_send` that hands back the live
response. Three HEADs would have been three signed round trips per residency
query; a second copy of the wire leg would have been a duplication-gate failure.

### 6.3 `http` · `setattr` + `setattr_cred` — advisory attrs as dead properties

`http/sd_http_setattr.c`, and it adds no wire spelling at all. `setattr` is
`brix_meta_advisory_from_setattr` → read the current blob through
`sd_http_getxattr_common` → `brix_meta_advisory_patch` → write it back through
`sd_http_setxattr_cred`, so the RFC 4918 dead-property encoding and the credential
gate each exist exactly once and the `_cred` twin is the same body with the cred
threaded. A request with nothing the advisory model can represent (an atime-only
`utimensat`, say) returns success **without a round trip**.

No existence probe is needed: `PROPPATCH` on a missing resource is 404, which
`sd_http_status_to_errno` already maps to `ENOENT`.

### 6.4 `ceph` · `setattr` + `setattr_cred` — advisory attrs in a RADOS xattr

`rados/sd_ceph_meta.c`, as an ioctx-explicit `sd_ceph_setattr_io` core shared by
the plain slot and the tagged acquire/run/release runner in `sd_ceph_ns_cred.c` —
the shape every namespace slot on this driver has, and the reason is §4's: in
RADOS **the ioctx IS the identity at the OSDs**, so a body that reached
`st->ioctx` would write the caller's metadata under the export's authority.

The one non-obvious guard: a missing xattr and a missing object can both come
back as `-ENODATA`/`-ENOENT` depending on the OSD, so an absent blob is
disambiguated with a `rados_stat` before it is treated as empty. Without that,
`setattr` on a path that does not exist would **create** an object carrying
nothing but a mode, and `stat` would thereafter report a file that was never
written.

### 6.5 `ceph` · `query_checksum` — OSD-side, crc32c, unstriped

`rados/sd_ceph_meta.c` over `rados_read_op_checksum` with
`LIBRADOS_CHECKSUM_TYPE_CRC32C`. The slot is deliberately narrow, and both
narrowings are the protocol ceiling rather than unfinished work:

* **crc32c only.** The OSD also computes xxhash32/xxhash64; neither is in this
  project's canonical algorithm set. Every other algorithm keeps falling back to
  the byte-reading compute in `core/compat/integrity_info.c` — which is what the
  seam did before, so nothing regressed.
* **A striped object declines.** Its bytes live in sibling stripe objects, and a
  checksum of the head object alone would be the digest of a fraction of the file
  presented as the digest of the whole. `NGX_DECLINED` returns it to the seam.

The conditioning is the part to get right: the OSD's op is a table-driven CRC32C
*update* seeded with the caller's init value and **not** post-conditioned, so the
slot seeds `0xFFFFFFFF` and XORs the reply — otherwise the value would be
plausible, stable, and not the crc32c anyone else computes. (`crc64` ≠
`crc64nvme` is the same class of mistake, one algorithm over.) A `rados_stat`
precedes the op because the length has to be fixed when the op is **built**, and
the size cached at open may be stale; it also makes a missing object `ENOENT`
rather than a checksum of nothing.

### 6.6 `block` · `read_sendfile_fd` + `read_advise` — the extent window is the gate

`block/sd_block.c`. This was flagged as a *security-shaped* gap, and the
implementation is shaped by that: the fd a sendfile caller receives is addressed
with **logical** offsets the driver never sees, so it cannot clamp the range after
the fact. `read_sendfile_fd` therefore hands back the device fd only when the
object's extent is based at device offset 0 — the one condition under which
logical and physical offsets coincide — and additionally refuses a request that
already leaves the extent. Every base-shifted extent returns `NGX_INVALID_FILE`
and falls back to the clamped `pread` path.

That gate keeps the case where zero-copy actually pays: the common single-extent
export, where `extent_size == 0` makes the whole device one object `/0`.
`read_advise` maps onto `posix_fadvise(2)` inside the same shifted, clamped
window.

---

## 7. Where the new slots are tested

The wave added **76 `(driver, slot)` pairs** — the working-tree driver tables
minus their `git show HEAD:` versions. Every one of them is exercised by a test
that links *that driver*, not merely by a test that happens to call a slot of the
same name on another one. The distribution, and the file that carries it:

| driver | new slots | where they are driven |
|---|---|---|
| `http` | 17 | `tests/c/test_sd_http_*.c` (object-linked) and `tests/unit/test_sd_http_nearline.c` (unity build, via `tests/cmdscripts/sd_slot_unit.py`) |
| `cache` | 14 | `tests/c/test_decorator_cred_forward.c` — the real `sd_cache_forward.o` over a fake source driver |
| `ceph` | 13 | `tests/ceph/sd_ceph_live_test.c` + `tests/ceph/sd_ceph_cred_live_test.c` — **a live RADOS pool is required** |
| `stage` | 13 | `tests/c/test_decorator_cred_forward.c` — the real `sd_stage.o`, same fake source |
| `remote` | 8 | `tests/c/test_sd_remote_*.c` |
| `xroot` | 6 | `tests/c/test_sd_xroot_setattr.c` + `tests/c/test_sd_xroot_query.c` |
| `block` | 3 | `tests/unit/test_sd_block_zerocopy.c` (ngx-free unity) + `tests/c/test_sd_block_space.c` |
| `pblock` | 1 | `src/fs/backend/pblock/sd_pblock_unittest_block.c` |
| `cephfs_ro` | 1 | `tests/ceph/sd_cephfs_ro_live_test.c` — live pool |

Three things about that table are worth stating, because each of them decided
where a test could live:

**A file-static slot is still reachable — through the real vtable.**
`sd_xroot_query_checksum` has no external linkage and no other entry point, so
`test_sd_xroot_query.c` takes the driver from `brix_sd_xroot_create()` and
dispatches through `->query_checksum`. That is the shipping dispatch path, not a
back door, and it is why the unit links the *whole* xroot closure (io, staged,
ns, ns_cred, ns_dir, nearline): the driver table names every slot, so the
object's `.rodata` carries a relocation for each one whether or not the test
calls it.

**The namespace plane of a driver often cannot join that driver's unity build.**
`sd_block_space` lives in `sd_block_ns.c`, which needs an nginx pool and a log
and so compiles only in the module build — the ngx-free unity unit that
`#include`s `sd_block.c` cannot see it. `test_sd_block_space.c` links the two
objects instead and drives a real `sd_block_init` over a stand-in device file,
which costs three nginx core objects and two stubs.

**The Ceph arms need a cluster, and are not faked.** `setattr`,
`query_checksum` and `setattr_cred` on the RADOS driver run against a real pool
through `tests/cmdscripts/ceph_operator.py`; there is no mock librados in this
tree and inventing one would test the mock. `query_checksum` is pinned to the
published CRC32C check vector — the object is seeded with `123456789` and the
digest must read `e3069283`, which is the only assertion that catches a dropped
seed or a dropped final XOR (either one yields a confident `1cf96d7c`).

## 8. What the wave before this one closed

For the record, so §6 reads as the end of a programme rather than the whole of
it. The wave that produced this table closed, among others: `query_checksum` on
`xroot`/`http`/`remote` (kXR_Qcksum · RFC 3230 Want-Digest · the S3
additional-checksum headers); `space` on `xroot`/`http`/both Ceph drivers;
`server_copy` on `http` (with a CR/LF `Destination` guard); `setattr` on `xroot`
over `kXR_chmod`; xattrs on `http` as dead properties; the `_cred` twins across
`sd_remote` and `sd_ceph` (two confused deputies, both allow-mode-only); the
decorator `_cred` twins and the four VFS sites that bypassed the decorator to
reach the leaf and lost its cache invalidation; `truncate_path` decorator parity;
and `enumerate` on `remote` over an undelimited ListObjectsV2 — which turned an
S3 inventory from one signed LIST per pseudo-directory plus a HEAD per entry into
`ceil(n/1000)` requests with the stats carried in the same response.

The narrative for each lives in
[`development-history.md`](development-history.md) and the per-phase docs under
`docs/refactor/`.
