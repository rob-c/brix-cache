# Phase-97 — CMS/CNS coverage closure (manager parity + the missing namespace events)

**Goal:** close every CMS/CNS item the testsuite combinatorial-coverage audit
left open, and finish the CNS work the tree itself recorded as deferred. Two
distinct deliverables, one subsystem:

1. **Cross-implementation manager parity** — the audit's *only* open CMS item.
2. **The missing CNS mutation events** — rename and path-based truncate, which
   the emit plane never covered, leaving a manager's inventory permanently wrong
   after either operation.

**Provenance:** anchors read from the tree at working state on **2026-08-05**
(post-phase-96, several waves uncommitted). Re-verify anchors at the start of
each wave and mark drift `DRIFT:` inline (phase-80 convention).

---

## 1 — What the audit actually left open

`docs/refactor/testsuite-combinatorial-coverage-audit-2026-08-04.md` names CMS
in exactly two places (L1274, L1302) — both the same bullet, the per-subsystem
cross-implementation parity list:

> Still open from this bullet: the per-subsystem parity list (S3, WebDAV
> TPC/COPY, tokens, GSI/VOMS/CRL, krb5/sss/pwd, **CMS**, cache tiers,
> checksums, IPv6, proxy mode, metrics exposition) — the parity probe covers the
> root:// read/stat/absent/traversal contract, not those.

Every other CMS-adjacent item in that audit is already marked CLOSED: the
`cachemx_cmsd` metric rows, the `stub-upstream-redirect` / `stub-upstream-error`
manager-plane fleet specs, and `test_a_upstream_redirect.py`. So the audit's CMS
debt is one item, and it is a **testing** gap, not a product gap:
`test_cross_backend_parity.py` proved the *data-server* contract matches stock
XRootD, and `test_cms_mesh_interop.py` proved BriX and stock nodes/managers
**interoperate** — but nothing ever asked whether a BriX manager and a stock
`cmsd` manager give a client the *same answers* for the same namespace.

### 1.1 What was NOT in scope, and why it is recorded here anyway

Applying the audit's own methodology (find declared-but-never-driven cells) to
the CNS subsystem surfaced real **product** gaps that the audit does not mention
because no test ever drove those cells. They are in scope for this phase under
the standing "complete any deferred work" rule — §2.

`docs/refactor/xrootd-feature-parity-audit-2026-08-04.md` §2 (Clustering) holds a
separate 19-row gap table (multi-manager, `cms.delay`/`sched`/`space`/`fxhold`/
`dfs`, dynamic supervisor, `cms.perf pgm`, `cms.altds`, `cms.allow` netgroup,
request coalescing, peer/proxy roles, `cms.fsxeq`). That is a different
document's backlog and stays **out of scope** here — recorded so a reader does
not mistake this phase for a clustering-feature phase.

---

## 2 — The deferred work: CNS never learned about rename or truncate

### 2.1 The bug

`brix_cns_emit()` covered four operations: `ADD`, `DEL`, `MKDIR`, `RMDIR`. Two
mutation paths changed the namespace and emitted **nothing**:

| Path | Anchor (pre-phase-97) | Consequence at the manager |
|---|---|---|
| `kXR_mv` (inline) | `src/protocols/root/write/mv.c` — no emit after `mv_execute()` | Old path served forever; new path invisible |
| `kXR_mv` (durable queue) | `src/protocols/root/write/backend_async_root.c` — *"RENAME/MV is outside the CNS v1 op set (ADD/DEL/MKDIR/RMDIR only), so it emits nothing."* | Same, plus the comment recorded it as known-deferred |
| `kXR_truncate` (path form) | `src/protocols/root/write/truncate.c` — no emit | Pre-truncate size served for the life of the entry |

The truncate case is subtle: a *handle*-based truncate is followed by
`kXR_close`, which already emits the authoritative `ADD` with the final size. The
**path**-based form is the only size change in the protocol with no close behind
it, so it is the only one that needs its own emit.

### 2.2 Why a rename is one event, not a `DEL` + `ADD` pair

A pair is wrong twice over:

- **Directories strand their children.** The manager holds an entry per
  *recorded path*, not a tree. `DEL /a` + `ADD /b` leaves every recorded
  `/a/child` pointing at a path that no longer exists — permanently, because
  nothing will ever emit for those children again.
- **A pair is not order-safe.** Two frames can be applied in either order; the
  `ADD`-then-`DEL` interleaving deletes the destination that was just created.

So phase-97 adds a **single, subtree-aware `BRIX_CNS_MV`** event carrying both
paths. `CMS_RR_CNS` (40) is a private frame code outside the stock `kYR_*` range
— only BriX peers parse it — which is what makes extending its payload safe in
both directions:

- a **new** data server talking to a **pre-MV** manager: the old decoder reads
  the header, ignores the trailing bytes, and then rejects the unknown op in
  `brix_cns_inv_apply` — a no-op, not a corrupt entry;
- a **pre-MV** data server talking to a **new** manager: it simply never sends
  the op.

### 2.3 Wire format

Unchanged 22-byte header, new optional tail:

```
op[1] rsvd[3] size[8] mtime[8] name_len[2] | path[name_len]
                                           | name2_len[2] path2[name2_len]   (MV only)
```

`rsvd[0]` carries the destination's `is_dir`. `BRIX_CNS_HDR_LEN` stays 22, so
every existing codec path is byte-for-byte unchanged.

### 2.4 Inventory semantics (`brix_cns_inv_rename`)

The table is a flat, fixed-capacity, pointer-free POD block (it lives either in a
per-worker heap allocation or an nginx SHM slab), so "rename a subtree" is a
linear pass with an explicit contract:

| Case | Behaviour | Rationale |
|---|---|---|
| Child under the source | Re-prefixed in place | Carries the subtree with the parent |
| `/run/abc` vs source `/run/a` | **Untouched** | Match is on the `/` component boundary, not `strncmp` alone |
| Destination already recorded | Overwritten; source slot freed | A rename over an existing entry collapses to one |
| Source never recorded | Inserted at the destination | A DS may rename a file the manager never saw |
| Re-prefixed child exceeds `BRIX_CNS_PATH_MAX` | **Dropped**, never truncated | A truncated path is a *wrong* answer; an absent one falls through to locate |
| Table full, source unknown | `-1` | Fixed capacity is the design; failure is visible |

### 2.5 Observing the destination — and why not `stat()`

The emit must report the destination's real size/mtime. INVARIANT 12 confines
raw data syscalls to `src/fs/backend/` (guard: `tools/ci/check_vfs_seam.py`,
whose tier-3 regex flags a bare `stat(`), and a bare `stat()` would in any case
be **wrong** on a non-POSIX backend. So both wrappers observe through
`brix_vfs_probe()` inside one shared `root_cns_probe()` helper, bound with the
requesting user's identity, backend credential and delegation — the same binding
the surrounding op already uses.

The mode gate runs **before** the probe (`conf->cns_mode != BRIX_CNS_EMIT` →
return), so a node that is not a federation data server never pays for the
syscall.

If the destination cannot be observed, `brix_root_cns_emit_moved()` degrades to a
`DEL` of the source rather than emitting an invented size — a wrong size in the
inventory is worse than an absent entry, which falls through to a normal locate.

### 2.6 Where the emit hangs

- **inline** — `mv.c`, after `mv_execute()` succeeds, before the OK reply.
- **durable queue** — `backend_async_root.c` `baq_root_done()`, the waker: the
  inline handler returned *before* the rename ran, so the late path is the only
  place the event can come from. `park->resolved` is the source and
  `park->detail` the destination for `BRIX_BAQ_RENAME`.
- **truncate** — `truncate.c`, path branch only, after `brix_log_access`.

A **failed** rename emits nothing (the call sites are on the success path), so a
client cannot conjure a manager-visible namespace entry by asking for a rename it
cannot perform.

---

## 3 — Files touched

| File | Change |
|---|---|
| `src/net/cms/cns_inventory.h` | `BRIX_CNS_MV`; `brix_cns_inv_rename()` decl |
| `src/net/cms/cns_inventory.c` | `inv_is_under()`, `inv_reprefix()`, `brix_cns_inv_rename()` |
| `src/net/cms/cns.h` / `cns.c` | MV codec (`_encode_mv` / `_decode_mv`), `brix_cns_rename()` locked wrapper |
| `src/net/cms/server_recv_frame_handlers.c` | MV branch in `cms_srv_frame_cns` (malformed tail → drop whole frame) |
| `src/net/cms/cns_emit.{c,h}` | `cns_emit_ready()` / `cns_logical()` extracted; `brix_cns_emit_rename()` |
| `src/protocols/root/write/common.c` | `root_cns_probe()`, `brix_root_cns_emit_moved()`, `brix_root_cns_emit_resized()` |
| `src/protocols/root/write/write.h` | Both wrapper decls |
| `src/protocols/root/write/mv.c` | Inline emit |
| `src/protocols/root/write/truncate.c` | Path-branch emit |
| `src/protocols/root/write/backend_async_root.c` | `BRIX_BAQ_RENAME` waker emit (replaces the deferred-work comment) |

No new `.c` files: the root-plane helpers went into the existing
`write/common.c`, so `./config` is untouched and `check_config_coverage.py`
cannot regress.

---

## 4 — Tests

**Unit** (`src/net/cms/cns_inventory_unittest.c`, pure, nginx-free, built under
`-Wall -Wextra -Werror`): file rename · directory subtree carry **with the
`/run/abc` component-boundary control** · rename over an existing entry ·
unknown-source insert · overlong-child drop · bad inputs (NULL/empty/oversize,
both sides) · full table.

**End-to-end** (`tests/test_cns.py`, real 2-node cluster):

| Test | Covers |
|---|---|
| `test_manager_reflects_mv_file` | MV converges: destination appears with the **observed** size, source disappears |
| `test_manager_reflects_mv_directory_subtree` | Recorded child moves with its parent, size intact; neither old path survives |
| `test_manager_reflects_path_truncate_size` | Manager stops serving the pre-truncate size |
| `test_mv_of_missing_source_creates_no_manager_entry` | **Negative** — a failed rename seeds no phantom entry |
| `test_manager_reflects_async_backend_mv` | The `brix_backend_async` waker emits (the inline path could not have) |

**Cross-implementation parity** (`tests/test_cms_cross_impl_parity.py`) — §1's
open item. Topology `b` (BriX manager + real data node) vs topology `bl` (real
`cmsd` manager + real data node): one variable differs, the manager
implementation. Byte-identical content is seeded into **both** export roots (not
pushed through a manager — a write-path difference would contaminate the read
comparison), then both front doors are driven with the same `xrdfs`/`xrdcp`:
locate succeeds on both · stat reports the identical size · the read is
byte-exact and identical across managers · `ls` surfaces the file on both · an
absent path errors on both · a traversal path escapes neither (asserted on
content, not just exit code). Skips cleanly when the mesh is not up.

### 4.1 Running them

```
PYTHONPATH=tests python3 -m pytest tests/test_cns_inventory.py -q          # pure unit
PYTHONPATH=tests python3 -m pytest tests/test_cns.py -q                    # 2-node cluster
cd tests && python3 cms_mesh_servers.py start                              # then:
PYTHONPATH=tests python3 -m pytest tests/test_cms_cross_impl_parity.py -q
```

**Run these one at a time.** `TEST_ROOT` defaults to `/tmp/xrd-test` and the
session teardown in `tests/conftest.py` does `shutil.rmtree(TEST_ROOT)`, so a
*second* concurrent `pytest` session deletes the first one's export roots and
`tmp_path` tree mid-run. The symptom is misleading: `kXR_open` on a freshly
created path answers `kXR_NotFound` (its data root vanished under a live server)
and later tests die on `bind() … Address already in use` from the servers that
teardown could no longer find. This is the pre-existing
`conftest_teardown_wipes_fleet` behaviour, not a CNS defect — a serial run of
`tests/test_cns.py` on an idle box is green.

---

## 5 — CNS emit from the non-root:// planes — DELIVERED

This section was originally written as *out of scope*, on the reasoning that
`brix_cns` is a `stream{}`-only directive
(`src/protocols/root/stream/directives_tpc.h`), that `brix_cns_emit()` needs an
`ngx_stream_brix_srv_conf_t`, and that bridging it to `http{}` would take a new
directive **plus** a per-worker CMS-context accessor — a global, which CLAUDE.md
forbids.

Neither turned out to be needed, so the gap is closed rather than documented.

### 5.1 Why no new directive and no global

The emitting server block is a pure function of the cycle. `cns_emit_conf()`
(`src/net/cms/cns_emit.c`) walks `cmcf->servers` and returns the first block that
is in `brix_cns emit` mode with a live, logged-in manager link — the same walk
`src/core/config/process.c` already performs at worker init. It caches nothing,
so there is no global and nothing that can go stale across a reload, and the walk
(a handful of server blocks) accompanies a syscall plus a network frame, so it is
noise against the work it rides on.

The consequence is that an operator configures **nothing extra**. A node that
already declares `brix_cns emit` on its `stream{}` root:// server automatically
reports its WebDAV, S3 and gridftp mutations to the same manager, against the
same logical paths.

### 5.2 The seam

Three functions in `src/net/cms/cns_emit.{c,h}`:

| function | purpose |
| --- | --- |
| `brix_cns_emit_active()` | is this node reporting at all — lets a caller skip a probe it would otherwise pay for on every mutation |
| `brix_cns_emit_at(root_canon, op, path, size, mtime)` | ADD / DEL / MKDIR / RMDIR |
| `brix_cns_emit_rename_at(root_canon, src, dst, size, mtime, is_dir)` | MV, as one event (§2) |

`root_canon` is the **caller's** export root, not the stream server's: an
`http{}` location resolves against its own `brix_export`, and that is the prefix
that has to come off to produce the logical path. Size and mtime come from the
caller's own VFS probe, because only the caller holds the identity, backend
credential and delegation that make the object observable.

Redundant managers each keep their own inventory, so `cns_emit_send()` fans one
encoded event out to **every** logged-in link. Deliberately not
`ngx_brix_cms_pick_ctx()`: rotation is right for a locate (any manager can
answer) and wrong for a mutation, where a round-robined ADD would leave every
other manager's catalogue permanently missing that object.

### 5.3 Call sites

Every one is on a **success path** — a refused mutation may neither seed a
phantom entry nor evict a live one — and on the **event loop**, because the CMS
connection belongs to it. Where the work is offloaded, the report is made from
the offload's event-loop completion, never from the pool thread.

| plane | file | events |
| --- | --- | --- |
| WebDAV | `protocols/webdav/put.c`, `put_body.c` | ADD on commit (sync + threaded completion) |
| WebDAV | `protocols/webdav/namespace.c` | MKDIR on MKCOL; DEL/RMDIR on DELETE (sync + `brix_baq` queue waker) |
| WebDAV | `protocols/webdav/move.c` | MV (sync + collection-offload completion) |
| WebDAV | `protocols/webdav/copy.c`, `copy_collection.c` | ADD of the destination |
| S3 | `protocols/s3/put_finalize.c` | ADD on PutObject commit, reusing the ledger's probe |
| S3 | `protocols/s3/post_object.c` | ADD on browser POST upload, reusing the ETag probe |
| S3 | `protocols/s3/multipart_complete_body.c` | ADD on CompleteMultipartUpload, from `s3_mpu_send_result` |
| S3 | `protocols/s3/copy.c` | ADD of the CopyObject destination |
| S3 | `protocols/s3/object_meta.c`, `delete_objects.c` | DEL on DeleteObject / DeleteObjects |
| gridftp | `protocols/gridftp/ev/ftp_ev_cmd.c` | ADD on a committed STOR/APPE via `brix_ftp_ev_cns_note_stored()`; MKDIR/DEL/RMDIR on MKD/DELE/RMD via `ftp_ev_ns_mutate()`; MV on RNFR+RNTO |

All of the gridftp plane's reporting lives in `ftp_ev_cmd.c`, including the STOR
report, which `ftp_ev_data.c` calls from `brix_ftp_ev_data_finish()` — the single
event-loop completion for every transfer shape (stream + MODE E, active +
passive). Keeping it there rather than inline at the call site is what holds
`ftp_ev_data.c` under the 600-line cap and puts one file in charge of the
plane's namespace story.

MKD/DELE/RMD are one table-driven transaction (`ftp_ev_ns_verb_t`): read-only
gate → resolve → one VFS op → CNS report → reply. They were three copies of that
sequence before, which is why the CNS line tripped `check_duplication` at the
copy-paste threshold; extracting it removed two grandfathered blocks from
`tools/ci/duplication_backlog.txt` rather than adding a third.

Staging temporaries deliberately emit nothing: `s3/checksum.c`, the
`brix_vfs_unlink_path` cleanups in `s3/multipart_complete_body.c` and
`s3/multipart_complete_upload_part_copy.c` are internal, not namespace events.

### 5.4 Tests

`tests/test_cns_http.py` against `tests/configs/nginx_cns_http_data.conf` — one
export published over all four planes at once, one manager. Per plane: a success
case (the mutation converges at the same logical path with the observed size), an
error case (a refused mutation moves nothing — notably a failed DELETE must not
evict a live entry), and a security-negative (a traversal attempt is refused by
path confinement and reports nothing, so the manager cannot be taught a path
outside the export). A final cross-plane test writes the same payload over all
four and asserts one consistent inventory, which catches a per-plane naming or
gating divergence that the individual tests would each pass.

```
PYTHONPATH=tests python3 -m pytest tests/test_cns_http.py -q
```

Same serial-run caveat as §4.1 — it reuses the `lc-cns-manager` fixed ports.

### 5.5 Still out of scope

**Worker-0 gating.** `ngx_brix_cms_start` runs only on worker 0, so
`conf->cms.ctxs` is populated there and nowhere else. A mutation handled by any
other worker reports nothing. This is pre-existing (it bounds root:// emit
identically) and the manager falls through to locate for anything it does not
hold, so it is a coverage gap in the inventory, not a correctness one. Closing it
needs a cross-worker path to the link — a separate design change.

**The clustering feature backlog** in
`docs/refactor/xrootd-feature-parity-audit-2026-08-04.md` §2 — see §1.1.
