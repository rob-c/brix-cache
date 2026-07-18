# Phase-83 — pblock as a *laboratory* filesystem (fault-capable, semantics-rich test backend)

**Goal:** evolve the pblock storage driver (`src/fs/backend/pblock/`) from a
faithful POSIX drop-in into the project's **reference test filesystem**: a
backend that can *misbehave on demand* (faults, corruption, latency, crashes,
anomalies) and *exceed POSIX* (quotas, snapshots, versioning, dedup, nearline
simulation, native catalog enumeration) — so every VFS/protocol branch that
POSIX either trivially satisfies or can never reach becomes natively testable
with `pytest`, no MinIO/Ceph/tape hardware required.

**Provenance:** anchors below read from the tree at working state on
**2026-07-17** (post-`8e15882c` + uncommitted P82 work). Re-verify anchors at
the start of each wave and mark drift `DRIFT:` inline (phase-80 convention).

**Prime directive (unchanged from the pblock charter):** the driver stays
**ngx-free** (libc + sqlite3 only, `malloc`-owned state —
`docs/09-developer-guide/pblock-storage-backend.md` §14), **build-gated** on
`BRIX_HAVE_SQLITE`, and the **hot byte path stays database-free**. Every
feature here must preserve those three properties or state explicitly where it
bends them. All new `.c` files go in the repo-root `./config` source list
(BUILD GOVERNANCE), and each feature lands with the standard 3-test set
(success + error + security-negative).

**Fail-closed lab gate:** every behavior-altering feature in this phase sits
behind one master directive, `brix_sd_pblock_lab on` (default **off**). With
the gate off, pblock is byte-for-byte the production driver — the fault
tables, shapers, and anomaly engines are not consulted (a single cached flag
test on the metadata path, zero cost on the byte path). Production semantics
features (quota, snapshots, GC, enumeration, locks) are individually gated by
their own directives and do NOT require the lab gate.

---

## STATUS — ALL 17 FEATURES LANDED (Waves A–D complete, 2026-07-18, UNCOMMITTED)

Waves A + B + C + D complete: F0–F17 (F14 test-triad completed 2026-07-18, closing Wave D). Full per-feature detail below.

**Landed:** F0 (control plane), F1 (fault injection: `fault.pread`/`fault.pwrite`
= `errno=NAME [after_bytes=N] [short=N]`), F2 (capability masking), F8
(latency/bandwidth shaping: `shape.read_bps`/`shape.write_bps`/`shape.open_ms`),
F16 (in-memory catalog mode), F14 (native catalog enumeration + `CAP_CATALOG`),
**F7** (crash-point harness + `pblock-fsck` consistency oracle),
**F17** (op audit log — `--replay` deferred, see below), **F3** (per-block
CRC32c integrity / CSI — driver-owned `csi` catalog table + `pblock-fsck
--verify-csi` oracle, see below), **F5** (quotas + space accounting — trigger
rollup + three-tier EDQUOT enforcement + the `space` seam slot + `pblock-fsck
--verify-usage`, see below), **F4** (nearline/tape simulation — `nearline`
residency table + bounded synchronous recall + `residency`/`recall` vtable
slots + `CAP_NEARLINE`, see below), **F9** (eventual-consistency anomaly
emulation — `recent` event table + visibility/stale-stat/list-lag ctl rules,
lab-gated, see below), **F15** (byte-range locks / mandatory lease
enforcement — `locks` lease table, open-time + snapshot-range + namespace
gates, EBUSY→kXR_FileLocked edge wiring, see below), **F10** (content-addressed
dedup + refcounted blobs — `blobs` refcount table, publish-time fold with
mandatory byte-verify, CoW share-break at open, O(metadata) server_copy +
`pblock-fsck --verify-refs`, see below). **Waves B and C are complete; Wave D
has begun (F10).**

**Design realized — the F0 two-tier control plane:**
- **STATIC opts** ride a **`?tail` query on the backend root**
  (`brix_storage_backend pblock:///srv/x?lab=1&caps=-sendfile&mem=1`), NOT the
  planned standalone `brix_sd_pblock_lab on` directive. Rationale: the tail is
  stripped in `brix_storage_backend_posix_root` (`src/core/config/runtime_server_backend.c`)
  **before** mkdir/root-canonicalization would create a literal `?` dir or
  canonicalize it away, and persisted as a one-line sidecar `<root>/pblock.opts`
  that the sqlite-gated driver reads at init. This keeps the ngx config side
  free of any sqlite dependency. **No tail ⇒ no sidecar ⇒ lab OFF** (byte-for-byte
  production driver — the fail-closed master gate).
- **RUNTIME rules** are rows in a `ctl(key TEXT PRIMARY KEY, value TEXT, epoch
  INTEGER)` table in `catalog.db`, driven by tests via the sqlite3 CLI. The
  driver re-reads rules only when `MAX(epoch)` changes and only at a metadata
  boundary (open) → **snapshot-at-open**: a fault set after a handle opens does
  not affect that handle. Hot byte path is a pure function over the per-handle
  snapshot + byte counters — zero SQLite, zero locks; `pblock_state_t.lab==NULL`
  when the gate is off, `pblock_obj_t.lab==NULL` when no rule applies.

**F2 structural change:** added `uint32_t caps` to `brix_sd_instance_s` (seeded
`= driver->caps` in `brix_sd_instance_create`, narrowed by pblock init via
`pblock_caps_apply`); `brix_sd_caps()`/`brix_sd_fd()` now read *instance* caps;
the 2 direct `driver->caps` consumers (vfs_sync.c, s3/put_inner.c) converted to
`brix_sd_caps()`.

**New files:** `src/fs/backend/pblock/pblock_ctl.{c,h}` (opts/sidecar/ctl table),
`pblock_fault.{c,h}` (fault grammar + hot-path gate). **F14:**
`pblock_catalog_enumerate` (flat catalog `SELECT`) + `sd_pblock_enumerate` slot +
`BRIX_SD_CAP_CATALOG`. **F7:** `tools/pblock-fsck/{pblock-fsck.c,Makefile}`
(standalone libc+sqlite3 oracle) + `pblock_lab_crash()` in `pblock_fault.{c,h}`.

**F7 realized — crash points + fsck oracle:**
- **Crash points** are compiled-in `pblock_lab_crash(st->lab, "<point>")` calls at
  named durability boundaries; when lab is on and the `ctl` key `crash.at` equals
  the point, the worker dies `_exit(86)` (nginx master respawns). Points wired:
  `after_block_write` (`sd_pblock_io.c` post-`write_blocks`),
  `before_catalog_update`/`after_catalog_update` (`sd_pblock.c` around the close
  catalog touch), `mid_staged_commit` (`sd_pblock_staged.c` pre-`pblock_catalog_put`),
  `before_unlink_row` (`sd_pblock_namespace.c` post-`pblock_remove_blocks`). Gated
  on `ls != NULL` → **inert when the master gate is off** (security-negative proven).
- **`pblock-fsck`** is a self-contained oracle (libc + sqlite3, re-derives the blob
  fan-out path math, no module link) that cross-checks `catalog.db` against the block
  store and classifies residue: `ORPHAN <blob>` (blob dir, no row), `DANGLING <path>`
  (row, no blocks), `SIZE <path> cat=N disk=M` (catalog size ≠ block extent). Exit =
  finding class (0 clean / 1 findings / 2 error / 3 refused). `--gc` removes orphan
  blob dirs + dangling rows; `--repair` rewrites size to block truth; mutating modes
  **fail closed** on an unknown catalog `PRAGMA user_version` (exit 3).

**F17 realized — op audit log (`--replay` deferred):**
- **`audit=1`** rides the same `?tail` static-opts channel (parsed in
  `pblock_opts_parse`, `pblock_ctl.c`; the sidecar writer has no key allowlist so
  it passes through verbatim). It is its **own gate** — independent of the `lab=1`
  master gate — so audit can run over an otherwise byte-for-byte production driver.
- **Schema + write:** `pblock_audit_init` creates
  `oplog(seq INTEGER PRIMARY KEY AUTOINCREMENT, ts, op, path, aux, uid, gid,
  result, errno)` at init; `pblock_audit_log` (both in `pblock_ctl.c`, so **no new
  `.c` ⇒ no `./configure`**) INSERTs one row per metadata boundary. Wired at:
  `open` (`sd_pblock.c` open wrapper), `close` (folds the per-handle `r=/w=/mb=`
  totals), `staged_open`/`commit` (`sd_pblock_staged.c`), and
  `unlink`/`rmdir`/`mkdir`/`rename`/`copy` (`sd_pblock_namespace.c`).
- **Best-effort, hot-path-pure:** `pblock_audit_log` returns void, saves/restores
  `errno`, and swallows every sqlite error — audit can never change an op's
  outcome. Byte-I/O accounting (`a_rbytes`/`a_wbytes`/`a_maxblock` on
  `pblock_obj_t`) is guarded `if (os->st->audit)` in `sd_pblock_io.c`, so the
  audit-off byte path is untouched.
- **Deferred:** `pblock-fsck --replay` (re-execute an oplog against a fresh
  export). Fragile cross-schema coupling into a clean catalog, no F17 test leg
  needs it, and it is orthogonal to the audit-write contract this slice proves.

**F3 realized — per-block CRC32c integrity (CSI):**
- **`csi=1`** rides the same `?tail` static-opts channel (its own gate, not the
  `lab=1` master gate — integrity is not a lab toy). Parsed in `pblock_opts_parse`
  (`pblock_ctl.c`); when on, `pblock_csi_init` creates
  `csi(blob_id TEXT, block_no INTEGER, crc INTEGER, PRIMARY KEY(blob_id, block_no))`
  and the instance advertises `BRIX_SD_CAP_FSCS` (honest per-instance capability).
- **Design choice (resolved the plan's UNVERIFIED unknown): driver-owned catalog
  table, NOT the posix `csi_tagstore`.** The posix tagstore attaches CRCs to a
  real POSIX path (`resolved`, via xmeta xattr / `.cinfo` sidecar) — meaningless
  for pblock's sharded blobs where nothing lives at the logical path. And
  `CAP_FSCS` is consumed *nowhere* (pure capability-matrix bit; `job->csi` is only
  populated on the POSIX-fd path), so **no VFS seam is needed** — the driver's own
  `pread` returns `-1/EIO` on a mismatch and that propagates through the normal
  sd read path. The block granule IS the CSI granule (one CRC per block file);
  the table is keyed by the **rename-stable blob_id** (rename is a pure catalog
  row-move → CRCs survive it for free), 0 is the "unset" sentinel (same as the
  xmeta tagstore; a genuine CRC of 0 is skipped, ~1/2³² benign miss).
- **Hot-path DB-free (`pblock_csi.c`):** at open, `pblock_csi_load` snapshots the
  at-rest CRCs into a handle-local `uint32_t*` (one DB read). `pblock_csi_verify`
  is a **pure function** over that snapshot — no DB, no locks — invoked in
  `sd_pblock_pread` on the bytes just read; it only checks blocks fully covered by
  the buffer and not written by this handle (an integer `[csi_dlo, csi_dhi)` extent
  widened on `pwrite`, so a just-written block's stale snapshot is skipped). At
  close, `pblock_csi_flush` recomputes exactly the written extent from disk and
  `INSERT OR REPLACE`s in one transaction (a metadata boundary). Because PUTs
  travel the **staged** path, flush is also wired at `sd_pblock_staged_commit` and
  after `server_copy`; `pblock_csi_drop` clears rows at unlink/rename-overwrite.
- **`pblock-fsck --verify-csi`** is the offline oracle: for every file row with
  `csi` rows it re-CRCs each recorded block file on disk (local bitwise CRC32c
  matching `brix_crc32c_value`) and reports `CSI <path> block=K` on a mismatch or a
  missing block, exit = finding class. The `csi` table's absence is not a finding
  (a non-csi export has nothing to verify).

**Tests (all green):** `sd_pblock_unittest.c` +4 (fault-inject, gate-closed,
caps-mask, enumerate); live scenario `pblock-lab` in `tests/cmdscripts/pblock_live.py`
(registered in `tests/test_cmd_pblock_live.py`) — 9 checks: sidecar written +
carries `lab=1`, clean transfer, `fault.pread=EIO` fails a fresh GET
(snapshot-at-open), and the **security-negative** gate-off proof that the
identical ctl rule is inert. Regression: `pblock-root` live + pblock C unit
still fully green (caps/instance change non-regressive). **F7:**
`tests/test_pblock_lab_crash.py` — 4 tests: live crash `after_block_write` →
xrdcp fails → fsck flags SIZE residue → `--gc --repair` converges → I/O recovers
(success/oracle); gate-off armed crash is inert (security-neg); standalone
orphan-detect + `--gc` (oracle); mutating fsck refuses unknown schema, exit 3
(error/refusal). pblock C-unit regression re-run green (crash calls are no-ops
when `lab==NULL`). **F17:** `tests/test_pblock_lab_audit.py` — 3 tests:
op-sequence recorded with a gap-free `seq` across 2 workers + `close` folds
`r=/w=/mb=` (success); `DROP TABLE oplog` mid-run → user op still succeeds and
bytes round-trip (error / best-effort); recorded `uid/gid` matches the catalog
`objects` owner row (security / attribution). F7 crash + pblock C-unit
regression re-run green after the io.c/open/close audit edits (5 passed).
**F3:** `tests/test_pblock_lab_csi.py` — 3 tests: a multi-block PUT lands one CRC
row per block, reads back byte-exact, the oracle is quiet, and the CRCs survive a
rename (success); a byte flipped in a block file on disk → GET fails with I/O
error (never serves the corruption), the oracle pinpoints `CSI /bad.bin block=1`
while the clean sibling stays green (error); corrupting the `csi` *tag* row with
the data untouched also fails closed — the driver trusts the at-rest CRC, not the
bytes (security-neg). pblock C-unit (now compiling `pblock_csi.c` + `crc32c.c`) +
audit + F7 crash suites re-run green (csi-off path non-regressive).
**F5:** `tests/test_pblock_lab_quota.py` — 3 tests: mixed workload (2 PUTs +
mkdir + rm) keeps the trigger rollup exact, statvfs reports against the 100m
quota (free=96 MB) not the backing disk, oracle quiet (success); 3m quota —
second PUT refused on the wire, existing file byte-exact, usage ≤ quota, rm →
in-quota PUT works again (error); `quota.uid.0` ctl row refuses uid 0's PUT
while `quota.uid.12345` does not — one tenant's quota row cannot starve another
(security-neg). Regression sweep green: pblock C-unit (now compiling
`pblock_quota.c`), csi 3, audit 3, crash 4, seam guard SEAM-OK.
**F4:** `tests/test_pblock_lab_nearline.py` — 3 tests: a demoted file's GET
blocks ≥ the simulated `nearline.recall_ms`, serves byte-exact, and lands the
file online (next GET immediate) (success); `nearline.fail.<path>` → the GET
errors on the wire — not a hang — and classifies the object LOST so later
opens fail fast (error); `xrdfs stat` of an offline file answers fast and
leaves the demotion untouched (residency is a pure read), and on a no-tail
export the identical demotion + ctl rows are inert (security-neg). Regression
re-run green: pblock C-unit (now compiling `pblock_nearline.c`) + quota 3 +
csi 3 + audit 3 + crash 4 + seam guard.

**F9:** `tests/test_pblock_lab_anomaly.py` — 3 tests: with visibility + list
lag armed, a fresh PUT is ENOENT to other GETs and missing from `xrdfs ls`
for the window, then both converge byte-exact (success); after an overwrite,
stat serves the pre-update size for the stale window, then converges to the
new row (error); the writer lane is exempt — an overwrite PUT of its own
still-invisible file succeeds while a reader GET still lags — and a no-tail
export treats identical ctl rules + a hand-planted fresh event row as inert
(security-neg). Convergence asserts are deadline polls, not fixed sleeps: the
windows are anchored to server-side event stamps (a slow PUT shifts them).
The planned cache-tier/TPC tolerance tests remain follow-on consumers of the
simulator, not part of the driver contract. Regression re-run green: 17
(quota + nearline + csi + audit + crash + cache-pblock) + seam guard.

**F15:** `tests/test_pblock_lab_locks.py` — 3 tests (rows planted with a
foreign synthetic owner 12345 vs the wire identity 0): a whole-file `'W'`
lease refuses a second writer's PUT at open (kXR_FileLocked) while a plain
GET passes, released it lands, and a range `'W'` lease admits the open but
kills the overlapping write through the snapshot (success); an
already-expired row is inert and a live 3 s-TTL lease refuses exactly until
expiry — deadline-polled against the row's server-side `expires_at`, per the
F9 lesson (error); an `'X'` lease excludes readers AND the bypass routes
(`xrdfs rm`/`mv` refused) until released, while a no-tail export treats
identical hand-planted rows as inert (security-neg). The planned "B cannot
release A's lock" leg is subsumed: acquire/release ride the sqlite ctl
channel (no wire release op exists to abuse), so the meaningful negatives
are the data-plane bypasses and gate-off inertness. Regression re-run green:
20 (quota + nearline + csi + audit + crash + anomaly + cache-pblock) + seam
guard + error-mapping/simple C units 12.

**F5 realized — quotas + real space accounting:**
- **Gate:** `quota=`/`quota_inodes=` in the `?tail` static opts (size suffixes
  k/m/g/t via the now-exported `pblock_parse_size`, `pblock_ctl.c`). Armed only
  when an opt is present AND `pblock_quota_init` succeeds — otherwise no table,
  no triggers, byte-for-byte production writes (fail-safe). Per-uid runtime
  limits are `ctl` rows `quota.uid.<n>` (bytes, suffixes allowed).
- **Rollup by SQLite triggers, not call sites:** `pblock_quota.c` creates
  `usage(scope, id, bytes, inodes)` (scopes `total`/`uid`/`gid`) maintained by
  `usage_ai`/`usage_ad`/`usage_au` AFTER-triggers on `objects` — transactional
  by construction; no driver path can forget the accounting. Dirs count inodes,
  zero bytes. Init rebuilds the rollup from `objects` so arming on a populated
  export starts honest.
- **Three enforcement tiers** (the design discovery of the slice — the two
  write paths differ):
  1. *Metadata-boundary admission* (`pblock_quota_admit`, errno=EDQUOT →
     kXR_NoSpace / HTTP 507): open-create + mkdir (+1 inode), staged_open,
     staged_commit (byte delta vs the existing dst row, checked BEFORE the
     destructive drop), server_copy (overwrite-aware delta).
  2. *DB-free hot-path cap:* `pblock_obj_t.quota_max` — the largest size this
     handle may grow the file to — snapshotted at open by
     `pblock_quota_max_size` (min of export-quota room and uid-ctl room;
     INT64_MAX when off) and enforced in `sd_pblock_pwrite`/`copy_range`.
     **This is what actually stops a wire PUT**: kXR uploads ride the plain
     open-create+pwrite path, NOT staged — the close-time check alone let the
     client stream every byte and report success. Same snapshot-at-open
     pattern as lab/CSI; zero SQLite on the byte path.
  3. *Close/fsync backstop:* `pblock_quota_touch_admit` (growth vs the stored
     row) before `pblock_catalog_touch` — catches racy concurrent growth.
- **The one seam extension:** optional `space` SD vtable slot
  (`brix_sd_space_t {total,used,free}`) + `brix_vfs_space()`; kXR_statvfs
  (`brix_make_vfs_body`, `src/protocols/root/read/stat.c`) prefers the slot.
  `sd_pblock_space` answers only when a byte quota is armed (total=quota,
  used=rollup) else ENOTSUP → statvfs(2) fallback; POSIX behavior unchanged.
  EDQUOT→kXR_NoSpace mappings added (`error_mapping.c`, namespace_ops.c,
  webdav/copy.c, root/write/mv.c; `#ifdef EDQUOT` guarded).
- **`pblock-fsck --verify-usage`** recomputes the rollup from `objects` (CTE +
  both-direction LEFT JOIN — portable, no FULL OUTER JOIN) and reports
  `USAGE <scope> id=N stored=B/I actual=B/I`; with the trigger rollup and the
  live recompute that is a triple oracle. Runs only when `usage` exists.
- **Gotchas recorded:** `pblock_ctl_get` returns **1=found / 0=absent /
  -1=error** — a `!= 0` test read every found ctl row as "no limit"; xrdfs
  statvfs prints the **raw kXR_vfs body** (`"<nrw> <free_mb> <util> ..."` e.g.
  `1 96 4 0 0 0`) — parse by field index; quota-refused PUTs have
  real-ENOSPC semantics (a partial dest may remain; accounted usage never
  exceeds the quota).

**F4 realized — nearline/tape simulation:**
- **Gate:** `nearline=1` in the `?tail` static opts (its own opt). Armed only
  when `pblock_nearline_init` succeeds; then — and only then — the instance
  advertises `BRIX_SD_CAP_NEARLINE` (honest per-instance capability; the VFS
  residency seam and the cache tier's recall-at-fill both key off it). New
  `src/fs/backend/pblock/pblock_nearline.{c,h}`.
- **State:** driver-owned `nearline(path TEXT PRIMARY KEY, res INTEGER)` table
  — NOT the plan's `objects.residency` column (no ALTER on the shared schema,
  no interplay with the F5 usage triggers). **Absence = ONLINE**: a
  production-shaped export stores nothing and pays one indexed miss per gated
  open. Tests demote files by inserting rows via sqlite3 (the standard ctl
  channel) instead of the planned `nearline.set` ctl verb — same transport,
  one less parser. Residency follows the logical path: rename moves the row,
  unlink/overwrite drops it (new content is ONLINE by absence).
- **Recall is bounded SYNCHRONOUS, sd_frm parity — the design deviation from
  the plan's `recall_queue`/NGX_AGAIN sketch.** Nothing in-tree consumes
  NGX_AGAIN parking yet (`cache_open_recall_parked` treats it as
  EAGAIN-and-fail; the stage-engine RECALL integration is the deferred async
  half — same deferral as the frm `kind=tape` ledger). sd_frm, the reference
  nearline driver, blocks bounded at open. So: `pblock_nearline_recall` sleeps
  `ctl:nearline.recall_ms` (capped 30s, EINTR-resumed), then flips the row
  ONLINE (deletes it) — or, when `ctl:nearline.fail.<path>` is set, marks it
  LOST and errors (EIO; a LOST row is terminal, later opens fail fast ENOENT).
- **Two entry points, one lane:** (a) the `recall` vtable slot for the cache
  tier's recall-at-fill (returns NGX_OK once online, like sd_frm); (b) an
  open-time self-recall in `pblock_open_as_inner` (existing-file branch, TRUNC
  exempt — replacement content needs no recall) so a **plain export exercises
  the lane with stock xrdcp, no cache tier needed**. The `residency` slot is a
  pure read (never advances a recall) feeding kXR stat's offline flag / tape
  REST / S3 storage-class.
- **Fail-open bookkeeping:** an unreadable simulation table never takes the
  export down (recall admits); row maintenance at namespace boundaries is
  best-effort void.

**F9 realized — eventual-consistency anomaly emulation:**
- **Gate:** the `lab=1` master gate (an anomaly simulator is a lab toy by
  definition — unlike F3/F4/F5 there is no own opt). All hooks guard on
  `st->lab != NULL`, so a production-shaped export never reaches the module.
  New `src/fs/backend/pblock/pblock_anomaly.{c,h}`.
- **State:** driver-owned `recent(path PK, created_ms, updated_ms, old_size,
  old_mtime)` event table — NOT the plan's `visible_at` column on `objects`
  (same no-ALTER rationale as F4). **Two independent event columns** are the
  key wrinkle: a PUT records its create at open AND an update at close-touch;
  a single event slot would let the close clobber the create and kill the
  visibility lag mid-upload. Events are recorded only while the matching ctl
  rule is armed; rows expire logically (the read side is pure — never
  deletes), so table growth is bounded by namespace size via PK upsert.
- **Rules** (ctl keys, ms, clamped to 60 s so a fat-fingered row can't wedge
  an export for hours): `anomaly.visibility_ms` — a fresh creation answers
  ENOENT to reader opens *and stats* for the window (S3 GET/HEAD-after-PUT);
  `anomaly.stale_stat_ms` — after an update, stat serves the captured
  pre-update size/mtime (S3 HEAD-after-overwrite; the pre-touch row is
  captured at the close/commit/copy boundary); `anomaly.list_lag_ms` —
  readdir omits entries created within the window (S3 LIST-after-PUT; the
  dir path now rides `pblock_dir_t` so entries hide by full path).
- **Writer exemption = the S3 session monotonic-read guarantee,
  structurally:** write-intent opens (`WRITE|CREATE|TRUNC`) skip the
  visibility gate, and a handle that wrote reads through its own open
  snapshot (`os->meta`) without a catalog lookup — the writing session can
  never see its own phantom ENOENT.
- **Event recording boundaries:** create → `pblock_open_create` success and
  `staged_commit` (fresh path) and `server_copy` (fresh dst); update →
  close-touch, `staged_commit` over an existing row, `server_copy` overwrite
  (each with the pre-update row). Rename moves the event row, unlink/drop_dst
  delete it. All catalog-side at metadata boundaries — the byte path is
  untouched, and all bookkeeping is best-effort (a missing `recent` table
  makes the writers no-op and consultation find nothing).

**F15 realized — byte-range locks / mandatory lease enforcement:**
- **Gate:** own `locks=1` opt (like F4/F5 — a lease backend is a capability,
  not a lab toy); armed only when `pblock_locks_init` actually installs the
  table, so an init failure leaves the byte-for-byte production path. New
  `src/fs/backend/pblock/pblock_locks.{c,h}`.
- **State:** driver-owned `locks(path, off, len, mode, owner, expires_at)`
  table. `len=0` ⇒ whole-file lease; modes `'W'` (excludes other writers) /
  `'X'` (excludes everyone), unknown modes read as `'X'` (strictest). Live =
  `expires_at > now` (unix seconds) — expired rows are ignored everywhere and
  never deleted on the read side, so a crashed client can never wedge the
  export. Foreign = `owner != uid` (owner is the synthetic catalog uid; tests
  plant/release rows via sqlite3, the standard ctl channel).
- **Enforcement (all refusals errno EBUSY):** (1) open-time in
  `pblock_open_as_inner` before both the existing and create branches (a
  whole-file lease guards the *name* — create under a foreign lease is as
  much a conflicting write as an overwrite): live foreign `'X'` refuses
  everyone, live foreign whole-file `'W'` refuses write-intent
  (`WRITE|CREATE|TRUNC|APPEND`); (2) range rows (`len>0`) admit the open but
  are snapshotted per-handle (`os->lock_rng/lock_n`, freed at close) by the
  `sd_pblock_open_as` wrapper — pwrite/copy_range deny overlap via a pure
  scan, no per-I/O DB hits (per the design, a conflicting later open is
  refused at *its* open; a later-acquired lease does not affect already-open
  handles — the documented snapshot model); (3) namespace bypass routes —
  unlink, rename (src AND dst), staged publish over a leased name — refuse
  while ANY live foreign lease exists. Rename moves lease rows, unlink /
  drop_dst delete them.
- **KEY EDGE GOTCHA — the refusal errno must be EBUSY, NOT EAGAIN:** on a
  read open the kXR edge answers EAGAIN with kXR_wait ("nearline recall in
  flight, retry") — a stock client then retries a lock that only clears on
  the HOLDER's schedule, i.e. hangs for the whole lease lifetime (same
  failure family as the F9/negcache wait-vs-pace lesson). Landed edge wiring:
  `brix_kxr_from_errno` EBUSY→kXR_FileLocked (error_mapping.c) +
  an explicit EBUSY→kXR_FileLocked branch in `brix_open_map_open_error`
  (open_resolved_file_open.c — the shared mapper for POSIX and driver opens,
  whose ladder is hand-rolled and previously fell to kXR_IOError). WebDAV
  namespace ops surface EBUSY as 409 via the existing BRIX_NS_CONFLICT
  mapping; RFC 4918 423 stays with the DAV LOCK layer.

**F10 realized — content-addressed dedup + refcounted blobs:**
- **Gate:** own `dedup=1` opt (a capability, like csi/locks — not a lab toy);
  armed only when `pblock_refs_init` installs the `blobs` table, so an init
  failure leaves the byte-for-byte production path (no refcount reads anywhere).
  New `src/fs/backend/pblock/pblock_refs.{c,h}`.
- **State:** driver-owned `blobs(blob_id PK, refcount, size, block_size,
  content_hash)` + a `content_hash` index. **A row's ABSENCE means refcount 1**
  — legacy blobs (created before the gate) and gate-off exports read identically
  to a single reference, so enabling dedup on a populated export is safe.
- **Content hash = the whole-object CRC-32 from the wverify accumulator**
  (`src/core/compat/wverify.{c,h}`, out-of-order-safe, fails closed on any
  gap/overlap) fed on the write path. A `void *wv` on `pblock_obj_t` /
  `pblock_staged_t` is armed ONLY on create + O_TRUNC opens (content written
  whole ⇒ an honest hash); a non-trunc overwrite gets none (stale hash is
  fail-safe: the byte-verify below rejects it). Recorded as `crc32:%08x`;
  `''` (empty) takes a blob out of the candidate pool.
- **Publish-time dedup** at BOTH publish boundaries via one shared helper
  `pblock_refs_dedup_publish` — kXR PUTs (plain open-create+pwrite) fold at
  `sd_pblock_close`, WebDAV PUTs (staged) fold at `sd_pblock_staged_commit`.
  Candidates = same `content_hash` + `size` + `block_size`, refcount ≥ 1,
  different blob; a **hash match is only a NOMINATION — every candidate is
  byte-verified** (chunked compare through `pblock_read_blocks`, transient block
  fds) before linking, so a CRC collision OR a forged `blobs` row can never
  alias content. Match ⇒ bump survivor + repoint the `objects` row
  (+`nscache_inval`) + release our now-redundant blob; no match ⇒ track our own
  (upsert PRESERVING refcount — never resets it). Own-blob guarded to
  refcount == 1 before folding (never strands a sibling); empty files skip.
- **Copy-on-write share-break at OPEN** (`pblock_refs_break_share`, a metadata
  boundary — the hot byte path stays refcount-free): a write-intent open of a
  shared blob (`refcount > 1`) first copies its blocks to a fresh private blob
  (or, on O_TRUNC, starts from an empty block 0 — the bytes are doomed),
  repoints the row (+`nscache_inval`), carries the csi rows over
  (`INSERT..SELECT`, non-trunc only), releases the old reference, and rewrites
  `meta->blob_id` in place. A DB error that can't prove privacy REFUSES the
  open (never writes through a possibly-shared blob).
- **server_copy = O(metadata) refcount bump** (early branch in
  `sd_pblock_server_copy_as`): dst row shares the src blob, `refcount++`; on
  catalog-put failure the bump is rolled back with `pblock_refs_release`
  (race-safe — if a concurrent src unlink already dropped to 1, the rollback
  correctly removes the now-unreferenced blocks); an overwritten dst releases
  its old blob; no csi flush (the shared rows already exist). The first write
  to either sharer breaks the share at open.
- **Release** (`pblock_refs_release`) replaces `remove_blocks + csi_drop` at
  unlink and drop_dst: gate off (or the last reference) removes blocks + csi
  rows exactly like the pre-F10 code; a still-shared blob decrements only. **A
  DB error KEEPS the blocks** (an fsck-collectable orphan beats removing bytes
  a sibling may still reference — fail-safe direction).
- **fsck:** `pblock-fsck --verify-refs` — `blobs.refcount` vs
  `COUNT(objects WHERE blob_id=… AND is_dir=0)` via LEFT JOIN → REFS finding
  class (a blobs-table-absent export is not a finding).
- **Legacy/hardlink notes:** the plan's `link` ns-op is a doc-level no-op (no
  wire verb exists — the catalog-level share is exercised by server_copy).
  Dedup'd copies still count logical size per `objects` row in the F5 usage
  rollup (documented logical accounting).

**Wave B complete. Wave C COMPLETE (trajectory gate in §6 resolved: proceed) —
F5 ✅ F4 ✅ F9 ✅ F15 ✅. Wave D COMPLETE — F10 ✅ F6 ✅ F11 ✅ F12/F13 ✅ F14 ✅. All 17 features landed.**

**F11 realized — versioning + trash/undelete:**
- **Gate:** own `versions=N` / `trash=1` opts that **auto-arm F10 refs** (both
  history rows pin a blob, so a delete/overwrite must *transfer* a reference,
  never physically free). Armed only when `pblock_refs_init` **and**
  `pblock_hist_init` both install their tables; an init failure leaves the plain
  path. New `src/fs/backend/pblock/pblock_hist.{c,h}`; `versions`/`trash` fields
  on `pblock_state_t`, `pblock_ctl.c` parses the two opts.
- **Capture = copy-on-write reference transfer:** `version_push` (on
  `staged_commit` overwrite, BEFORE `drop_dst`) and `trash_push` (in
  `sd_pblock_unlink`, BEFORE `pblock_refs_release`) each `pblock_refs_bump` the
  live blob **first**, so the caller's subsequent release only decrements — the
  reference moves from the live object to the history row and the refcount never
  hits 0. A failed push is **fail-open** (plain overwrite/delete, no history).
  Versions are trimmed to the newest N generations (oldest `gen` released first).
- **State:** `versions(path, gen, blob_id, …, PRIMARY KEY(path,gen))` + a
  `blob_id` index; `trash(trash_id INTEGER PK AUTOINCREMENT, path, blob_id, …,
  deleted_at)` + `path`/`blob_id` indexes. Path is **only ever a bound column —
  never interpolated** — so a hostile name can neither inject nor traverse.
- **Undelete = symmetric transfer:** `pblock_hist_undelete` pops the
  most-recent trash instance (`ORDER BY deleted_at DESC, trash_id DESC`) back
  into the namespace — EEXIST if the name is live, ENOENT if not trashed — with a
  bump-for-the-new-row / release-for-the-removed-trash-row net-zero transfer.
- **Control plane = reserved namespace, service-only:** `mkdir
  /.pblock/undelete/<path>` recovers — intercepted at the TOP of the inner
  (service) `sd_pblock_mkdir_as`, before resolve, exactly like F6. An
  identity-carrying wire request hits the ordinary parent-exist gate instead
  (the reserved parent doesn't exist), so recovery is service-only at zero wire
  cost.
- **fsck:** offline `pblock-fsck --list-versions <path>` / `--list-trash` /
  `--undelete <path>` (undelete is transactional + schema-fail-closed like
  `--gc`; a live name ⇒ EEXIST exit 1, not-trashed ⇒ exit 1) and `--gc
  --trash-ttl <secs>` purges trash older than `<secs>` (0 = all) then reclaims
  the now-unreferenced blocks via the standard orphan pass. **`--verify-refs`
  and `snap_recount` are now history-aware** — referrers = live objects **+
  snapshot copies + versions + trash rows**, each term added only for a table
  the export actually has, so a versioned/trashed export shows no false REFS
  drift. `check_rows` folds every history-referrer blob into the referenced set
  so `check_orphans`/`--gc` never mistake a version- or trash-pinned blob for an
  orphan.

**Tests (F11):** `sd_pblock_unittest.c` — `test_versioning` drives the driver
vtable (staged-publish overwrites retain exactly N=2 generations with the oldest
blob freed on trim; unlink → trash → `mkdir /.pblock/undelete/<p>` recovers
byte-identical; undelete of a never-trashed name ⇒ ENOENT, over a live name ⇒
EEXIST; a hostile `x';DROP TABLE trash;--` path only ever misses and a legit
recover still works). `tests/test_pblock_lab_versioning.py` — 3 optin legs over
WebDAV (success: three atomic PUT overwrites → offline `--list-versions` shows
`n=2`, delete two files → `--list-trash` → `--undelete` → byte-identical GET →
TTL `--gc` purge, `--verify-refs` clean at every checkpoint; security-neg:
hostile/`../` undelete paths are bound-column misses at exit 1 with the trash
table unharmed + undelete over a live name is EEXIST + a legit recover still
round-trips; inertness: a no-tail export never grows the versions/trash tables).
All green (C-unit ALL PASS incl. `test_versioning`, versioning pytest 3/3, VFS
seam clean).

**F6 realized — snapshots / instant fixture reset:**
- **Gate:** own `snap=1` opt that **auto-arms F10 refs** — a snapshot pins the
  blobs its copied rows reference, so a delete between take and restore must
  *decrement* a shared blob (F10 release), never physically remove blocks the
  restore still needs. Armed only when `pblock_refs_init` **and**
  `pblock_snap_init` both install their tables; an init failure leaves the plain
  path. New `src/fs/backend/pblock/pblock_snap.{c,h}`.
- **State:** single-table design — `snapshots(name PK, created_at)`,
  `snap_objects(snap, path, …, PRIMARY KEY(snap,path))` + a `blob_id` index,
  `snap_xattrs(snap, path, name, value)`. The snapshot name is **only ever a
  bound column value — never interpolated into SQL** — so injection is
  structurally impossible; a strict charset validator (`[A-Za-z0-9_.-]`, 1..64,
  not `.`/`..`) is defence-in-depth on top.
- **Take/restore/drop** each run inside one `BEGIN IMMEDIATE` and finish with
  `snap_recount` — materialise any missing legacy blob row (seed 0) then
  `UPDATE blobs SET refcount = live-object-count + all-snapshot-copy-count`, the
  exact ledger the F10 release path reads, so a blob no longer referenced
  anywhere falls to 0 (an fsck `--gc`-collectable orphan; never removed
  mid-txn — fail-safe). Take = INSERT snapshot + copy `objects`/`xattrs`
  (duplicate name ⇒ `EEXIST` via the PK). Restore = `DELETE objects/xattrs` +
  re-INSERT from `snap_*` + recount + `nscache_clear` (the whole namespace was
  replaced). Drop = delete the three tables' rows + recount.
- **EBUSY, not corruption:** restore refuses (`errno=EBUSY`) while any
  regular-file handle is open — an atomic `open_files` counter bumped in
  `pblock_make_obj`/`staged_open` and released in `close`/`commit`/`abort`
  (snap-gated) — so the namespace is never swapped out from under a live fd.
- **Control plane = reserved namespace, service-only:** `mkdir /.pblock/snap/<n>`
  takes, `mkdir /.pblock/restore/<n>` restores, `rmdir /.pblock/snap/<n>` drops
  — intercepted at the TOP of the inner (service) `sd_pblock_mkdir_as` /
  `sd_pblock_unlink`, before resolve. An identity-carrying wire request reaches
  the `_cred` slots and hits the ordinary resolve/parent-exist gate instead (the
  reserved parents don't exist), so snapshot control is service-only at zero
  extra cost — no wire-protocol change.
- **fsck:** offline `pblock-fsck --snapshot <name>` / `--restore <name>` — same
  bound-name SQL + charset gate as the driver (self-contained libc+sqlite3),
  schema-fail-closed like `--gc`/`--repair`; invalid name ⇒ exit 3. **`--verify-refs`
  is now snapshot-aware** — referrers = live objects **+ snapshot copies**
  (matches `snap_recount`), so a snapshotted export no longer shows false REFS
  drift; a non-F6 export keeps the original plain-`objects` query.

**Tests (F6):** `sd_pblock_unittest.c` — `test_snapshot` drives the real driver
control path through the vtable (mkdir `/.pblock/snap/fix` take → delete both
files → mkdir `/.pblock/restore/fix` restore → byte-identical reads; **restore
refused EBUSY while a handle is open**, namespace intact; a hostile name
`x';DROP TABLE snapshots;--` rejected `EINVAL`, a legit snapshot still works,
`rmdir` drops it). `tests/test_pblock_lab_snapshot.py` — 3 optin legs (success:
data over a live server, offline `--snapshot fix` → delete both over the wire →
`--restore fix` → byte-identical GETs, `--verify-refs`/consistency clean
throughout; security-neg: `--snapshot`/`--restore` refuse `x';DROP…`, `..`,
`.`, `a/b`, names with spaces at exit 3 and the catalog is unharmed — a
following legit snapshot/restore round-trips; inertness: gate-off export never
grows the `snapshots` table). All green (C-unit ALL PASS incl. `test_snapshot`,
snapshot 3/3, F10 dedup 3/3 regression clean, VFS seam clean).

**Tests (F10):** `sd_pblock_unittest.c` — `test_dedup_refs` (dedup lifecycle:
identical writes share → unlink decrements → survivor intact; server_copy CoW
bump; O_TRUNC break-share diverges blob_ids; **2-thread concurrent share-break**
— the plan's critical-correctness item), `test_dedup_forged_hash` (a forged
`content_hash` cannot alias differing content — byte-verify rejects), and
`test_dedup_gate_closed` (no opt ⇒ identical PUTs stay physically distinct).
`tests/test_pblock_lab_dedup.py` — 3 optin legs (success: identical PUTs share
`blobs.refcount=2`, GETs byte-exact, unlink → 1 → survivor intact,
`--verify-refs` clean throughout; error/CoW: overwrite breaks the share,
sibling unchanged, blob_ids diverge, refcounts 1/1; security-neg: forged
`content_hash` cannot alias + a hand-corrupted refcount is caught by
`--verify-refs` + gate-off identical PUTs stay distinct). All green
(C-unit ALL PASS, dedup 3/3, pblock lab regression locks/csi/quota/crash/cache
14 + anomaly/audit/nearline 9 all pass, VFS seam clean).

---

## 0. Scope, non-goals, and the feature roster

**In scope — 17 features in 4 waves:**

| # | Feature | Wave | Gate |
|---|---|---|---|
| F0 | Control plane (`ctl` catalog table + directives) | A | — (infrastructure) |
| F1 | Deterministic fault injection | A | lab |
| F2 | Capability masking (backend impersonation) | A | lab |
| F8 | Latency / bandwidth shaping | A | lab |
| F16 | In-memory mode (tmpfs blocks + `:memory:`-style catalog) | A | own directive |
| F3 | CSI page checksums (`CAP_FSCS`) + corruption injection | B | CSI: own; corrupt: lab |
| F7 | Crash-point harness + `pblock-fsck` scrub/orphan-GC tool | B | crash: lab; fsck: standalone tool |
| F17 | Op audit log + deterministic trace replay | B | own directive |
| F5 | Quotas + real space accounting (statvfs seam) | C | own directive |
| F4 | Nearline/tape simulation (`CAP_NEARLINE`) | C | own directive |
| F9 | Eventual-consistency / anomaly emulation | C | lab |
| F15 | Byte-range locks / mandatory lease enforcement | C | own directive |
| F10 | Content-addressed dedup + refcounted blobs (⇒ hardlinks) | D | own directive |
| F6 | Snapshots / instant fixture reset + CoW clones | D | own directive |
| F11 | Versioning + trash/undelete | D | own directive |
| F12 | Encryption-at-rest (cap-interplay exercise) | D | own directive |
| F13 | Compression-at-rest (logical≠physical size exercise) | D | own directive |
| F14 | Native catalog enumeration (`CAP_CATALOG`) + query surface | D | none (pure addition) |

**Non-goals:** distributed/replicated pblock; production crypto review of F12
(it is a *semantics* exercise — XChaCha/AES via a vendored single-file
implementation or a trivial keyed transform, documented as NOT a security
boundary); persistence-format compatibility guarantees across this phase
(pblock is pre-1.0 — a `schema_version` bump per wave with **no** migration
code is acceptable; document "recreate the export"); porting any of this to
posix/s3/ceph drivers (the seam stays untouched except where a feature
implements an *existing* optional slot).

---

## 1. Architecture — the control plane (F0, prerequisite for everything)

### 1.1 Where knobs live

Two tiers, matching how tests actually work:

1. **Static config — directives.** One new directive family parsed where the
   backend string is parsed today. The backend entry builder
   (`src/fs/vfs/vfs_backend_config.c:30-58` — bare `"pblock"` names;
   `src/core/config/runtime_server_backend.c:59-102` — the `pblock://<path>`
   scheme) gains an options tail:
   `brix_storage_backend "pblock:///srv/x?lab=1&caps=-sendfile,-hard_rename&quota=10G"`.
   Query-string options keep the plumbing in ONE place (the existing string
   already flows to `pblock_state_t` construction) instead of threading a new
   conf struct through `shared_conf.h`. Parsed into a new
   `pblock_opts_t` member of `pblock_state_t` (`pblock_store.h:24-30`).

2. **Runtime control — the `ctl` table.** A new catalog table:

   ```sql
   CREATE TABLE IF NOT EXISTS ctl(
     key TEXT PRIMARY KEY,    -- e.g. 'fault.pwrite', 'shape.read_bps'
     value TEXT NOT NULL,     -- JSON-ish or scalar, feature-defined
     epoch INTEGER NOT NULL   -- bumped on every write
   );
   ```

   plus a single-row `ctl_epoch` accessor (`MAX(epoch)`). **Tests drive it
   with the `sqlite3` CLI directly against `<root>/catalog.db`** — no
   protocol round-trip, no admin endpoint, works from pytest with two lines.
   The driver caches the parsed control set in `pblock_state_t` and re-reads
   it **only when the epoch changed, checked only at metadata boundaries**
   (open/close/fsync/ns-ops) — the byte path sees a pre-resolved per-object
   snapshot taken at `open` (stored in `pblock_obj_t`,
   `sd_pblock_internal.h:52-60`). WAL mode (catalog already runs
   `journal_mode=WAL` + busy-timeout, doc §13) makes concurrent test-writer /
   server-reader access safe.

   Consequence to document loudly in tests: **a fault set while a file is
   open does not affect already-open handles** (their snapshot is taken at
   open). This is a feature — deterministic — not a bug; tests that need
   mid-transfer faults set them *before* open with an offset trigger (F1).

### 1.2 New files

```
src/fs/backend/pblock/
  pblock_ctl.{c,h}       F0: ctl table CRUD + epoch cache + opts parser
  pblock_fault.{c,h}     F1/F8/F9: fault/shape/anomaly evaluation (pure functions)
  pblock_csi.c           F3: CSI tagstore adapter
  pblock_quota.c         F5: quota accounting + statvfs
  pblock_nearline.c      F4: residency model + fake recall
  pblock_locks.c         F15: range-lock table + enforcement
  pblock_refs.c          F10/F6/F11: blob refcounts, snapshots, versions, trash
  pblock_xform.{c,h}     F12/F13: per-block transform seam (identity/crypt/compress)
  pblock_audit.c         F17: op log + replay reader
tools/pblock-fsck/       F7: standalone fsck/scrub/GC binary (pure libc+sqlite)
tests/c/test_pblock_lab.c        new CUnitSpec suite (ctl/fault/xform/refs units)
tests/test_pblock_lab*.py        pytest suites per wave (see per-feature sections)
```

All under `#if BRIX_HAVE_SQLITE` like their includers. Unit-test compile
lists live in `tests/cmdscripts/*.py` (bash runners are gone — memory:
`c_tests_bash_to_python_port`); extend the list that builds
`sd_pblock_unittest.c` / `sd_pblock_catalog_unittest.c`.

---

## 2. Wave A — misbehavior on demand

### F1 — Deterministic fault injection

**What:** a fault rule set evaluated inside the pblock I/O and namespace
entry points (`sd_pblock_io.c` — `sd_pblock_pread/pwrite/preadv/preadv2/
ftruncate/fsync`; `sd_pblock_namespace.c` — ns ops;
`sd_pblock_staged.c` — staged writes; `sd_pblock.c` — open/close). Rule
shape (stored per-op in `ctl`):

```
fault.<op> = errno=EIO        [after_bytes=N] [after_calls=N] [at_block=K]
           | short=BYTES      (return a short read/write once)
           | errno=ENOSPC     mode=persistent|once
           | busy             (force SQLITE_BUSY exhaustion on the catalog op)
           | torn             (write only the first M bytes, then errno)
```

`after_bytes`/`after_calls`/`at_block` make faults *deterministic and
positional* — "EIO at block 3 of a 5-block read" — which is exactly what real
hardware never gives you reproducibly. The evaluation is a pure function in
`pblock_fault.c` over the per-object snapshot + a per-object running counter
in `pblock_obj_t` (no locks, no DB).

**Why it pays:** tests-from-below for the whole errno→kXR→HTTP mapping table,
the VFS short-I/O loops (which the seam contract says live ABOVE the driver —
`src/fs/backend/README.md` "single verbatim syscalls"), wverify's
unlink-on-mismatch (`src/fs/vfs/vfs_wverify.c`), cache write-through flush
failure legs, MODE E mid-stream failure (P82), and staged-commit abort paths.

**Tests:** `tests/test_pblock_lab_faults.py` — (s) EIO at block K surfaces as
kXR_IOError / HTTP 500 with no partial state; (e) ENOSPC mid-STOR →
wverify/staged abort leaves no catalog row and no orphan blocks (assert via
F7 fsck); (sec) fault rules are inert when `lab` is off even if the `ctl`
table is pre-seeded (fail-closed gate test). Plus C units for the rule
parser/evaluator.

### F2 — Capability masking

**What:** `caps=-sendfile,-fd,-hard_rename,…` (opts tail or `ctl` key,
applied at instance build) ANDs a mask over the advertised bitmap
(descriptor caps at `src/fs/backend/pblock/sd_pblock.c:373`; bit definitions
`src/fs/backend/sd.h:83-110`). Additive masks (`+nearline`) are how F4
switches on. Dropping `CAP_FD` also forces `read_sendfile_fd` to return
`NGX_INVALID_FILE` and (with `+memfile`) advertises `BRIX_SD_CAP_MEMFILE`
(`sd.h:110`) so pblock impersonates the S3/remote shape.

**Why:** one backend exercises every "if backend lacks X" branch in the VFS —
memory-backed serving and the TLS `b->memory=1` vs cleartext sendfile split
(INVARIANT 2), copy+delete rename fallback (no `CAP_HARD_RENAME`), no
`CAP_SERVER_COPY` → VFS byte-copy lane, no `CAP_XATTR_WRITE` → ENOTSUP
mapping — without standing up MinIO or Ceph.

**Caveat to verify in A:** audit that the VFS truly consults caps on every
such branch (phase-71 "vfs-capability-uniformity" claimed closure —
re-verify; any place that assumes POSIX shape despite the caps word is a
pre-existing bug this feature will flush out. Expect to file fixes ABOVE the
seam as part of this wave).

**Tests:** parametrized backend matrix in the existing suites — extend
`tests/cmdscripts/storage_backend_schemes.py` /
`tests/cmdscripts/tier_matrix_drivers.py` with `pblock-degraded` rows;
(s) full transfer suite green with `-fd-sendfile+memfile`; (e) rename works
via copy+delete with `-hard_rename` and is still atomic-or-absent; (sec) a
masked-off cap cannot be re-enabled from the `ctl` table when `lab` is off.

### F8 — Latency / bandwidth shaping

**What:** `shape.read_bps`, `shape.write_bps`, `shape.open_ms`,
`shape.jitter_ms`, `shape.stall_at=OFF:MS` (one long stall at byte offset
OFF). Implemented as computed `nanosleep`s inside `sd_pblock_io.c` — legal
because pblock byte I/O already runs on the **AIO thread pool**, never the
event loop (doc §13); an assertion documents that shaping must never run on
an event-loop-entered path (open shaping uses the thread-pool open lane
only, else it is skipped and logged once).

**Why:** deterministic reproduction of timeout/slow-peer behavior: proxy
splice stalls (memory: `proxy_splice_writable_eagain_stall` took days to
reproduce organically), kXR_wait tuning, MODE E marker cadence, client
retry/timeout logic, dashboard in-flight visibility.

**Tests:** (s) `read_bps=1M` on a 4 MiB file takes ≥3 s and completes; (e)
`stall_at` beyond client timeout → clean server-side teardown, no fd leak
(reuse the 200×-PASV leak-check pattern from `tests/test_gridftp_evil.py`);
(sec) shaping keys inert without the lab gate.

### F16 — In-memory mode

**What:** `pblock://mem:<name>` (or `?mem=1`): block root on a
per-instance `memfd`/tmpfs directory (`/dev/shm/pblock-<name>-<pid>`), and
the catalog opened with `PRAGMA journal_mode=MEMORY; synchronous=OFF` (NOT
literal `:memory:` — multi-worker access still needs a shared file; document
that mem-mode is **single-worker or accepts lost-on-crash**, which is the
point). Teardown removes the tree.

**Why:** the fast tier (memory: `test_suite_fast_tier`) spends real time on
fixture setup/teardown fsyncs. Mem-mode pblock gives RAM-speed populate +
instant delete, and pairs with F6 snapshots for millisecond fixture reset.
Also removes disk-full flake from CI boxes.

**Tests:** (s) full posix-parity smoke (`tests/cmdscripts/pblock_live.py`
lanes) green in mem-mode; (e) worker restart → export empty, server serves
clean ENOENT (no stale catalog); (sec) mem root refuses a non-tmpfs
absolute-path escape in the name (`mem:../x` rejected).

---

## 3. Wave B — integrity and truth

### F3 — CSI page checksums (`CAP_FSCS`) + corruption injection  ✅ LANDED

> **LANDED 2026-07-18** (see the F3-realized block in STATUS for the as-built
> record). The in-wave decision resolved to a **driver-owned `csi` catalog table**
> (NOT the posix `csi_tagstore`, whose xmeta/`.cinfo` layout is anchored to a real
> POSIX path that pblock's sharded blobs do not have) and — because `CAP_FSCS` has
> no consumers and `job->csi` is POSIX-fd-only — **no VFS seam**: the driver's own
> `pread` returns EIO on a mismatch. Corruption injection is done by the test
> directly against the block file (`_flip_byte`); the driver's contribution is the
> serving-time verify + the `pblock-fsck --verify-csi` oracle. The plan sketch
> below is superseded on the storage-layout and seam questions.

**What (two halves, one wave because they verify each other):**

1. *CSI integration* — pblock is the only full-parity driver missing
   `BRIX_SD_CAP_FSCS` (doc §12). Adapt the existing tagstore
   (`src/fs/backend/csi_tagstore.h` — `brix_csi_open/verify_read/
   write_update/flush`, lines 69-91) in `pblock_csi.c`: tags keyed by
   `blob_id` (not logical path — rename must not re-tag), stored either in
   the tagstore's native xmeta location under `<root>/data/…/<blob>/` or a
   `csi` catalog table (decide in-wave: the tagstore API takes an
   `abs_path`, so the per-blob object dir is the least-code answer —
   UNVERIFIED until `csi_tagstore.c` storage layout is read). Wire
   `verify_read`/`write_update` at the pblock read/write boundaries,
   `flush` at close — mirroring how the posix driver integrates
   (read `csi_verify.c` call sites first).

2. *Corruption injection* — `ctl`: `corrupt.<path> = block=K off=O xor=B`
   applied ONCE directly to the block file by… nothing in the server: the
   **test** does it, because blocks are plain files. What the driver adds is
   the *oracle*: `pblock-fsck --verify-csi` (F7) and the serving-time CSI
   mismatch path. A tiny pytest helper
   (`tests/_pblock_lab_helpers.py: corrupt_block(root, path, block, off)`)
   resolves logical path → blob via the catalog and flips the byte.

**Why:** end-to-end tests of the integrity stack with *known-bad* data:
pgread per-page CRC32c (INVARIANT 1) actually detecting, CKSM/checksum_core
readers erroring not serving garbage, wverify vs a backend that corrupted
after write, cache-fill digest quarantine (`staged_path` verify lane,
`sd.h:410-416`).

**Tests:** (s) clean file round-trips with CSI on, `CAP_FSCS` advertised,
tags survive rename; (e) flipped byte → pgread returns CRC-failed page /
HTTP integrity error, NOT silent data; (sec) corrupting the *tag* (not the
data) also fails closed. C unit: tag lifecycle across write/truncate.

### F7 — Crash-point harness + `pblock-fsck`

**What:**

1. *Crash points* — `ctl`: `crash.at = <named-point>` where the named points
   are compiled-in markers: `after_block_write`, `before_catalog_update`,
   `after_catalog_update_before_blocks_sync`, `mid_staged_commit`,
   `after_unlink_row_before_block_rm`. Hitting one calls `_exit(86)`
   (worker dies; nginx master respawns). Gated on lab, obviously.

2. *`pblock-fsck`* — standalone binary (`tools/pblock-fsck/`, pure
   libc+sqlite like the driver, reusing `pblock_store.c` path math +
   `sd_pblock_catalog.c` — both already ngx-free by design): cross-checks
   catalog rows ↔ block files. Reports: orphan blob dirs (no row), dangling
   rows (missing blocks within `size`), size mismatches (catalog size vs
   last block extent), refcount drift (after F10), CSI mismatches
   (`--verify-csi`, after F3). `--gc` deletes orphans older than a grace
   age; `--repair` truncates size to block truth. Exit code = finding count
   class, machine-parsable line output for pytest.

**Why:** the doc's own "known limits" flags catalog/blocks divergence as THE
pblock hazard. Crash points + fsck turn durability from an assumption into a
test: kill between block write and catalog commit, restart, fsck must show
exactly one orphan and `--gc` must converge to zero findings. fsck is also
the assertion oracle every other feature's error-leg tests use ("and the
store is still consistent").

**Tests:** `tests/test_pblock_lab_crash.py` — (s) each crash point ×
{plain write, staged commit, unlink, rename}: restart, fsck classifies the
expected residue, `--gc`/`--repair` converge, subsequent I/O correct; (e)
fsck on a live export under load reports no false positives (WAL snapshot
read); (sec) fsck refuses to run `--gc` on a catalog whose `schema_version`
it doesn't know.

### F17 — Op audit log + deterministic replay  ✅ LANDED (audit); replay deferred

**What:** `audit=1` → append-only `oplog` catalog table
`(seq, ts, op, path, aux, uid, gid, result, errno)` written at metadata
boundaries only (open/close/ns/staged-commit — NOT per-I/O; per-I/O totals
are folded into the close record: bytes_read, bytes_written, max_block).
Plus `tools/pblock-fsck --replay <oplog.sql>`: re-executes the namespace op
sequence against a fresh export to reproduce a reported end-state.

**Why:** three test superpowers: (1) *assertion surface* — pytest asserts
"this WebDAV COPY performed exactly: open src, staged_open dst, N writes,
commit" instead of inferring from side effects; (2) *flake forensics* — a
failing concurrent test dumps the interleaving that actually happened; (3)
*replay* — a CI failure's oplog re-run locally reproduces the catalog
end-state deterministically.

**Tests:** (s) known op sequence appears verbatim, seq gap-free across two
workers; (e) oplog write failure (fault-injected via F1 `busy`) never fails
the user op (audit is best-effort, documented); (sec) oplog records the
*synthetic* uid/gid identity (P80 `ids` table, `sd_pblock_catalog.c:358`)
so multiuser tests can assert attribution.

---

## 4. Wave C — semantics POSIX can't give you

### F5 — Quotas + real space accounting ✅ LANDED (2026-07-18 — see STATUS "F5 realized")

**What:** the catalog already knows every size and owner
(`objects.size/uid/gid` — schema at `sd_pblock_catalog.c:332-344`).
Maintain a `usage(scope, id, bytes, inodes)` rollup table updated
transactionally inside the SAME statement window as size-changing ops
(write-back at close/fsync, truncate, unlink, staged-commit — all already
catalog boundaries, so the hot path is untouched). Directives/opts:
`quota=10G`, `quota_inodes=100k`, per-uid/per-gid rows via `ctl`
(`quota.uid.<n>=BYTES`). Exceeding → `ENOSPC`/`EDQUOT` at the *catalog
write-back*, and pre-checked at open/staged_open (admission) so the common
case fails early. Second half: implement a **driver space report** —
`kXR_statvfs` today calls raw `statvfs(2)` on the export root
(`src/protocols/root/read/stat.c:31-40`, marked with a vfs-seam-allow
question — UNVERIFIED whether it routes through the seam); add an optional
`space` slot to the SD vtable (`sd.h`, next to `residency`) returning
{total, used, free} so pblock reports *quota-aware logical* space and the
SRR endpoint (memory: `srr_wlcg_endpoint`) gets honest numbers. POSIX slot
= existing statvfs behavior; NULL ⇒ current fallback. **This is the one
deliberate seam extension in the phase.**

**Why:** deterministic `ENOSPC`/`507 Insufficient Storage`/`kXR_NoSpace`
tests (today only reachable by actually filling a disk), per-user quota
tests for the P80 multiuser model, and SRR reporting tests with exact
expected numbers.

**Tests:** (s) usage rollup matches `SUM(size)` after a mixed workload
(fsck cross-checks it too); (e) quota hit mid-upload → EDQUOT, staged abort,
usage unchanged; (sec) user A's writes can't consume user B's per-uid quota
(attribution via cred slots, `sd_pblock_cred.c`).

### F4 — Nearline/tape simulation ✅ LANDED (2026-07-18 — see STATUS "F4 realized")

**What:** the seam already defines the whole contract — `recall` slot
(`sd.h:418-426`, returns NGX_AGAIN to park the open), `residency` slot
(`sd.h:428-434`), `BRIX_SD_CAP_NEARLINE` (`sd.h:104`) — with **no
in-tree driver implementing it** (phase-64 §9.3 design). pblock implements
it as pure simulation: an `objects.residency` column
(online/nearline/offline/lost) + `recall_queue(path, reqid, ready_at)`
table; `recall` inserts with `ready_at = now + ctl:nearline.recall_ms`,
returns NGX_AGAIN; a check at metadata boundaries (or the cache tier's
existing waiter poll — read `brix_stage` waiter machinery first, anchor
UNVERIFIED) flips it online. `ctl` verbs: `nearline.set=<path>:offline`,
`nearline.fail=<path>` (recall → lost).

**Why:** exercises the *entire* dormant nearline lane — kXR_stall/kXR_wait,
HTTP tape-REST/202-style handling, FRM staging (`sd_frm.c` interplay),
cache-tier parked opens — natively, no MSS. This is the difference between
"the seam has slots" and "the slots have ever run".

**Tests:** (s) offline file: open parks, recall completes after N ms, bytes
serve; (e) `nearline.fail` → open resumes with the lost-classification
error, not a hang; (sec) residency read (`xrdfs stat`) never triggers a
recall (pure-read contract, `sd.h:428-430`).

### F9 — Eventual-consistency / anomaly emulation ✅ LANDED (2026-07-18 — see STATUS "F9 realized")

**What:** object-store read-after-write anomalies, on demand:
`anomaly.visibility_ms=N` (a created path is ENOENT to *other* opens for
N ms — implemented as a `visible_at` column consulted in lookup),
`anomaly.stale_stat_ms=N` (stat may serve the pre-update row),
`anomaly.list_lag_ms=N` (readdir omits recent rows). All catalog-side;
byte path untouched.

**Why:** the cache tier, the HTTP/S3 backends, and TPC flows all contain
logic that *claims* to tolerate S3-style eventual consistency (remote-origin
drivers, sd_remote/sd_xroot fills). Today that logic is tested against
nothing. pblock-with-anomalies is a deterministic S3-consistency simulator
under the full protocol stack.

**Tests:** (s) with visibility lag, PUT-then-GET through the *cache* tier
still serves correctness (fill retries/waits); (e) TPC pull of a
just-created source with lag → retry-then-succeed, not 404-fail; (sec)
anomalies never apply to the *same* handle that wrote (session
monotonic-read guarantee, matching real S3).

### F15 — Byte-range locks / mandatory lease enforcement ✅ LANDED (2026-07-18 — see STATUS "F15 realized")

**What:** a `locks(path, off, len, mode, owner, expires_at)` catalog table +
enforcement at open (whole-file leases: `O_EXCL`-style write lease) and at
the pwrite boundary via the open-time snapshot (range locks are
lease-scoped: acquired at open via opts/xattr-style intent, re-validated at
catalog boundaries — NOT per-I/O DB hits; a conflicting later open is
refused at *its* open, which is what makes per-I/O checks unnecessary).
Expiry via `expires_at` so a crashed client can't wedge the export.

**Why:** backs WebDAV LOCK/UNLOCK with real enforcement (today
advisory-at-best — verify current webdav lock handling first, anchor
UNVERIFIED), gives concurrent-writer exclusion tests (two STORs to one
path), and models the "single-writer" guarantee TPC destinations want.

**Tests:** (s) writer A holds lease, writer B's open → 423/kXR_locked;
(e) lease expiry frees it, B proceeds; (sec) B cannot release A's lock
(owner = synthetic uid).

---

## 5. Wave D — storage transforms and time travel

### F10 — Content-addressed dedup + refcounted blobs (⇒ hardlinks) ✅ LANDED

**What:** foundation for the rest of wave D. New `blobs(blob_id, refcount,
size, block_size, content_hash)` table; `objects.blob_id` becomes a
foreign reference. `unlink` decrements; blocks are removed at refcount 0
(the current direct-remove in `pblock_remove_blocks`,
`pblock_store.h:48-49`, moves behind `pblock_refs.c`). Optional
`dedup=1`: staged-commit computes a content hash (reuse wverify's ngx-free
CRC accumulator `src/core/compat/wverify.{c,h}` for the cheap tier, or
SHA-256 via the checksum helpers — decide in-wave) and links to an existing
blob on match instead of publishing new blocks. Hardlinks fall out: a
`link` ns-op inserts a second `objects` row on the same blob (surface via
WebDAV COPY fast-path and a root:// extension only if a protocol verb
exists — otherwise catalog+fsck-level feature only, exercised by
server_copy).

**Why:** makes `server_copy` O(metadata) (a refcount bump) — which then
*tests* every caller of `CAP_SERVER_COPY` (kXR_clone, WebDAV COPY) against
copy-on-write semantics; `nlink>1` stat results exercise protocol stat
paths that have never seen them.

**CoW invariant:** any pwrite/truncate on a blob with refcount>1 must first
break the share (copy touched blocks to a fresh blob — block granularity
makes this cheap). This is the critical-correctness item of wave D; the C
unit suite gets a dedicated multi-thread share-break test.

### F6 — Snapshots / instant fixture reset + CoW clones ✅ LANDED

**What:** `pblock-fsck --snapshot <name>` (offline) and a `ctl`-triggered
online variant: `BEGIN IMMEDIATE`, copy the `objects`/`xattrs` rows into
`snap_<name>_*` tables (or a single `snapshots` + row-versioned design —
decide in-wave; separate tables are dumber and fine at test scale),
increment every referenced blob's refcount, commit. Restore = swap tables
back + refcount fixup. Blob refcounts (F10) make both O(metadata).

**Why:** *millisecond fixture reset*. The conftest teardown today wipes the
fleet (memory: `conftest_teardown_wipes_fleet`); populated-export tests
re-upload fixtures constantly. `snapshot → test mutates → restore` turns
every destructive test cheap, and clone-from-snapshot gives per-test
isolated exports sharing one populated block store.

**Tests:** (s) snapshot, delete everything, restore, byte-identical reads,
fsck clean; (e) restore while handles are open → refused (EBUSY) not
corrupted; (sec) snapshot names sanitized (SQL identifier injection).

### F11 — Versioning + trash/undelete — ✅ LANDED

**What:** `versions=N` keeps the previous blob on overwrite-publish
(staged-commit over an existing path moves the old `objects` row into
`versions(path, gen, blob_id, size, mtime, …)`, refcount held) — trimmed to
N generations. `trash=1` turns unlink into a move into `trash(path,
deleted_at, blob_id, …)` with `trash_ttl` GC via fsck `--gc`. Exposed
read-only through a reserved namespace `/.pblock/versions/<path>/<gen>` and
`/.pblock/trash/…` (catalog-synthesized directories — pblock already fully
owns its namespace so no real-fs reserved-name hazard; the VFS confinement
re-check must be verified to pass these paths through, anchor UNVERIFIED).

**Why:** tests for lifecycle tooling (undelete flows, version listing via
plain WebDAV PROPFIND), and a safety net that makes destructive-op tests
self-auditing ("the old content is exactly in gen-1").

### F12 / F13 — Encryption / compression at rest (per-block transform seam) ✅ LANDED (2026-07-18)

> **LANDED 2026-07-18 (UNCOMMITTED).** One seam `pblock_xform.{c,h}` (ngx-free,
> under the sqlite build gate), two transforms selected by the export `?tail`:
> `xform=crypt:<keyfile>` (per-block keyed XOR keystream — length-preserving,
> explicitly NOT a reviewed security boundary per non-goals) and `xform=zstd`
> (level-3, gated on the pre-existing `BRIX_HAVE_ZSTD` + `-lzstd` already in the
> module build). Every block — **including block 0** — is stored as a
> self-describing block file `[u32 logical_len LE][u32 phys_len LE][phys bytes]`
> (`PBLOCK_XFORM_HDR = 8`). Because the block engine still issues arbitrary
> sub-block writes, a transformed write is **read-modify-write**: load the whole
> logical block, overlay the new bytes, re-encode; `block_store` writes **in
> place** (`O_WRONLY|O_CREAT` + `ftruncate` to exact size, not temp+rename) so
> the persistent block-0 fd the caller holds stays valid (single-writer-per-block
> assumption). `pblock_write_blocks`/`pblock_read_blocks` early-branch to the
> xform path when `pblock_xform_active`; the raw hot path is untouched with no
> transform. `sd_pblock_ftruncate` re-stores the boundary block at the trimmed
> logical length.
>
> **Cap interplay (the F12 point):** a transformed export drops
> `CAP_SENDFILE|CAP_IOURING` at instance build (per-export mask — the doc-blessed
> "simpler and sufficient" choice) **and** `read_sendfile_fd` returns
> `NGX_INVALID_FILE` (belt-and-braces) — block 0 holds transformed bytes.
>
> **Per-file record + config-mismatch guard:** the transform kind is recorded per
> file at create in a new `objects.xform TEXT` column (schema + forward-compat
> `ALTER TABLE`; `pblock_meta.xform[16]`, threaded through the objects
> SELECT/INSERT and the staged-commit meta). `sd_pblock_stat` refuses (EIO) any
> object whose recorded kind ≠ the export's configured kind, so no read fast-path
> (sendfile/pread) can ever serve one transform's bytes decoded as another — the
> universal metadata boundary was the correct enforcement point (the block-0
> sendfile fast path bypasses the driver `open`, so an `open_existing`-only guard
> was insufficient). `pblock_open_existing` keeps the same guard for the open
> lane. Directories carry no transform (`xform` stays `""`).
>
> **Fail-closed config:** unlike the lab toys, a bad spec (unknown transform,
> unreadable crypt keyfile, `zstd` without libzstd) fails `sd_pblock_init` — the
> pblock store is never built for the export (logged "pblock backend init
> failed"), rather than silently serving unreadable bytes. (Note: instance init
> is lazy per-worker, so this manifests as a request-time init failure, not an
> `nginx -t` refusal.)
>
> **Opts sidecar is sticky:** the `<root>/pblock.opts` sidecar is (re)written only
> when the `?tail` is present; reconfiguring the same root with an *empty* tail
> leaves the prior sidecar in place. To actually change/clear a transform, supply
> a new tail.
>
> **Files:** `src/fs/backend/pblock/pblock_xform.{c,h}` (new); wired in
> `pblock_store.{c,h}` (RMW read/write + `pblock_state_t.xform`), `sd_pblock_io.c`
> (sendfile-fd + ftruncate), `sd_pblock.c` (init config/cap-mask + create/existing
> guards), `sd_pblock_namespace.c` (stat guard), `sd_pblock_catalog{.h,.c}` +
> `sd_pblock_catalog_objects.c` (`xform` column), `pblock_ctl.{h,c}` (opts parse),
> `sd_pblock_staged.c` (staged-commit meta), repo-root `./config` (source/header
> lists). **Tests:** `tests/test_pblock_lab_xform.py` — 3 (crypt roundtrip +
> plaintext-never-on-disk + headered block = success; zstd byte-identical +
> physical ≪ logical + catalog keeps logical size = F13 success; bad-spec/missing
> keyfile init-fail + zstd-object-under-crypt-export EIO⇒500 = error +
> security-neg), all green vs the private-tree binary. `pblock_xform.c` added to
> the `sd_pblock_unittest` compile list (`c_regression_units.py`); pblock C-unit
> ALL PASS; F11/F6/F10/F5 lab suites unchanged (12 green).

**What:** one seam, two transforms. `pblock_xform.{c,h}` defines
`xform_encode/decode(block_buf)` applied in `pblock_write_blocks` /
`pblock_read_blocks` (`pblock_store.h:44-47`). `xform=crypt:<keyfile>` or
`xform=zstd` recorded **per file at create** (like `block_size` — doc §14
"per-file block size" principle) in a new `objects.xform` column.
Cap interplay is the point: a transformed file **must not** offer its
block-0 fd — `read_sendfile_fd` returns INVALID and the instance drops
`CAP_SENDFILE`/`CAP_IOURING` for transformed opens (per-open cap word, or
simplest: an export with xform configured masks the caps at instance
build — decide in-wave; per-export is simpler and sufficient).
Compression additionally makes **logical size ≠ physical bytes**: catalog
size stays logical; block files are compressed units with a per-block
length header — which forces the read path to stop assuming
`block_file_size == extent` and gives fsck a new class of checks.

**Why:** F12 exercises the "backend cannot sendfile" lane *with* CAP_FD
absent for a reason tests can toggle per-file; F13 exercises every place
that conflates logical and physical size (quota vs du, statvfs, cache
sizing, Content-Length). Both are semantics exercises — F12 is explicitly
NOT a reviewed security boundary (see non-goals).

**Build note:** zstd adds a `./configure` probe (`BRIX_HAVE_ZSTD`) mirroring
the sqlite gate; absent ⇒ `xform=zstd` is a config error, everything else
compiles unchanged.

### F14 — Native catalog enumeration (`CAP_CATALOG`) ✅ LANDED (2026-07-18)

> **LANDED 2026-07-18 (UNCOMMITTED).** The driver `enumerate` slot is a single
> flat `SELECT` over `objects` (`pblock_catalog_enumerate`, sd_pblock_catalog_objects.c)
> adapted to the `brix_sd_catalog_ent_t` callback by `pblock_enum_thunk`
> (sd_pblock.c) — directories are skipped (enumeration reports stored objects,
> not the namespace), `want_stat` carries each object's size/mtime. Advertised
> via `BRIX_SD_CAP_CATALOG` in `.caps`; the driver-agnostic VFS wrapper
> `brix_vfs_enumerate_catalog` (vfs_dir.c) dispatches to it and returns
> `NGX_DECLINED`/ENOTSUP for a backend with no native catalog (POSIX — the
> namespace IS the catalog), so the engine falls back to a walk. **The scan is
> unconfined — a nested object comes back by full path with no subtree gate —
> which is exactly why enumeration is a SERVICE-PLANE inventory verb: there is
> no `enumerate_cred` slot in the driver vtable (sd.h), so no user/identity
> protocol path can reach the whole-catalog scan.** Tests: `sd_pblock_unittest.c`
> `test_lab_enumerate` — three independent oracles agree (enumerate count = 3,
> enumerate `want_stat` size-sum = 9 bytes, and a recursive opendir/readdir/stat
> namespace walk = the same count+bytes), the nested `/d/c` is present (proves
> the scan is unconfined) and the `/d` directory is excluded (success);
> early-callback abort stops the walk yet the slot still returns `NGX_OK`
> (error); and the verb is advertised with no cred variant (security-neg). Note:
> F14 has zero deps (§6: "may land in A") and its source shipped with Wave A;
> this entry records the completed test triad + LANDED marker.

**What:** implement the existing optional `enumerate` slot
(`sd.h:436-444` — fires a callback per stored object, NOT a namespace
walk) as a single `SELECT` over `objects` (+`blobs` after F10), advertise
`BRIX_SD_CAP_CATALOG` (`sd.h:105`). The VFS wrapper already exists and
reports ENOTSUP today. Follow-on inside the feature: point the dashboard
VFS browser (`src/observability/dashboard/vfs_browse.c` — pblock-aware
already, verify how) and any inventory/drift tooling at it.

**Why:** cheap (the catalog IS a database), completes the last unimplemented
optional slot besides nearline, and gives tests + fsck + SRR a fast
"everything stored" oracle that doesn't recurse the namespace. Also the
natural place to expose snapshot/version/trash object counts.

**Tests:** (s) enumeration count/size totals match a namespace walk and the
F5 usage rollup — three independent oracles agreeing is itself a standing
consistency test; (e) early callback abort honored; (sec) enumeration is
service-plane only (no cred slot — not reachable from user protocols).

---

## 6. Wave ordering, dependencies, sizing

```
A: F0 → {F1, F2, F8, F16}                 (F0 blocks all; rest independent)
B: F7-fsck early (it is every wave's test oracle) → F3 → F7-crash → F17
C: F5 → F4 (recall queue reuses ctl/quota patterns) → F9 → F15
D: F10 → {F6, F11} → F12/F13 (xform) → F14 (anytime; zero deps — may land in A if a
   quick win is wanted)
```

Sizing calibration (pblock today ≈ 5.7k LOC across 16 files): wave A ≈
1.5–2k, B ≈ 2–2.5k (fsck tool is the bulk), C ≈ 2–2.5k, D ≈ 3–4k
(CoW share-break + xform dominate). Total ≈ 9–11k LOC + ~15 pytest files +
2 CUnitSpec suites. Each wave lands independently green
(`PYTHONPATH=tests pytest`, fleet via `tests/manage_test_servers.sh`);
schema bumps per wave, no migrations (non-goals).

**Strategic gate (decide before wave C):** waves A+B are pure test-leverage
and justify themselves. C and D add *production-shaped* semantics — before
starting C, confirm pblock's trajectory (test lab only vs. candidate
primary backend, README's stated ambition). If test-lab-only, F15/F11/F12
may be parked; if primary-backend-track, they graduate from "interesting"
to "required" and deserve design review beyond this doc.

## 7. Risks and standing rules

- **Hot-path purity** is the review bar for every wave: fault/shape/anomaly
  evaluation must be per-object-snapshot + counters, never a DB read per
  I/O. A flame-graph check against `pblock-metadata-performance.md`
  baselines closes each wave.
- **Seam discipline:** F5's `space` slot is the only vtable change. Every
  other feature is inside the pblock directory. If a feature seems to need
  a second slot, that is a design smell — bring it back to this doc first.
- **Cap-uniformity fallout (F2):** expect to find VFS branches that ignore
  the caps word; fix them above the seam as separate commits with their own
  tests, not folded into pblock changes.
- **INVARIANT 12** (VFS sole storage truth) is untouched: everything here is
  *below* the seam or in the standalone fsck tool (which owns the store by
  definition, like the driver).
- Standard blocks apply: no `goto`, no new globals, 3 tests per change,
  no git writes without OP approval, stop after 2 identical failures.

## 8. Companion docs to update as waves land

`docs/09-developer-guide/pblock-storage-backend.md` (§12 caps table, §14
limits list shrink), `src/fs/backend/README.md` driver table row,
`docs/10-reference/` new page for the `ctl` key reference +
`pblock-fsck` man-style page, `TESTING.md` lab-backend how-to.
