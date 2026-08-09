# Phase 94 — Bound-write substream data-path (parallel upload)

**Date:** 2026-08-04
**Author:** multi-client conformance track (follows the data-substream read work)
**Status:** **✅ PHASE 1 & PHASE 2 IMPLEMENTED & TESTED (2026-08-04); Phase 3 resolved.**
Server serves bound **writes** for fd-backed exports; the BriX client fans **both uploads and
downloads** across substreams by default (read fan-out added as the symmetric completion), and an
opt-in **`--parallel`** flag runs a true concurrent (thread-per-connection) striped download.
**Phase 2 (gateway → remote root:// origin) WORKS and is PROVEN** — a writable gateway with the
default `brix_upload_resume on` (and always-on POSC) stages the upload to a **local, export-rooted
`.part` file** (a real fd + real local path), which is exactly the fd-backed shape Phase-1
publishes and fans out; the existing resume/POSC commit then flushes the complete `.part` (incl.
cross-worker bound writes) onto the remote origin at close. Verified end-to-end by
`tests/test_data_substreams_gateway.py` (8 MiB `--streams 4` upload, `chunks-on-secondaries>0`,
byte-exact **on the origin's own storage**). The doc's earlier "gated" verdict was wrong: it
assumed gateway writes take the driver-backed whole-object staged writer (`file->writer != NULL`),
but that path is entered ONLY by a whole-object PUT backend (S3/WebDAV, `needs_staged`) with no
local temp — that residual case still degrades to the resilient primary safely (§5). **Phase 3**:
`brix-xrdcp` default-on is proven in-repo; the 5-client `brixbench` matrix is an external rig not
in this repo (§6 status box). See §0.1 for what landed and the design refinements.

## 0.1 What landed in Phase 1 (2026-08-04)

**Server (bound-write datapath for fd-backed exports):**
- `handles.c` — publish handles that are readable **or writable** (fd-gated, so
  staged writers / driver objects are still never published).
- `fd_table.c` — factored a shared `brix_bound_confined_open()` (used by both read
  and write reopen), added `brix_reopen_bound_write_handle` (O_WRONLY, no
  O_CREAT/O_TRUNC) + `brix_ensure_write_handle` (mirror of the read ensure), and
  wired the bound reopen into `brix_validate_write_handle`.
- `policy.c` — a bound connection may issue `kXR_write` (only) against a
  primary-published writable handle; every other write-family op stays primary-only.
- `recv_process.c` — a bound `kXR_write` reopens the writable handle in this worker
  *before* the streaming/buffered paths inspect `file->fd`; the primary-side
  non-zero-pathid refusal now exempts bound connections.

**Client (`brix-xrdcp`):**
- `copy_pump.c` / `copy_upload.c` / `copy_internal.h` — the upload sink spreads write
  chunks round-robin across primary + bound secondaries; a chunk a secondary won't
  take falls back to the resilient primary write (idempotent pwrite).
- `xrdcp.c` — data substreams **ON by default** (`streams=4`), `-S N` overrides.
- `copy_pump.c` / `copy_local.c` — the download source (`pump_src_secondary`) reads chunks
  round-robin over primary+secondaries; a read a secondary won't serve falls back to the primary
  read (`kXR_read` has no pathid → routed by connection, served against the published handle).
- `copy_local.c` `copy_download_parallel` — opt-in `--parallel` thread-per-connection striped
  download for true concurrent throughput (see §5 status box); `xrdcp_parse_transport.c` parses `--parallel`.
- `BRIX_STREAMS_DEBUG` prints `upload substreams=<n> chunks-on-secondaries=<m>` and
  `download substreams=<n> chunks-on-secondaries=<m>`.

**Design refinements discovered while implementing (deviations from the plan):**
1. **Protocol = whole write on the secondary** (header+payload, pathid 0), exactly
   mirroring bound reads (routed by connection, self-addressed by offset). This
   avoids the cross-connection header-on-primary rendezvous entirely — no S-side
   correlation machinery needed.
2. **No heavyweight close barrier (S4) is required for correctness.** Each bound
   write is applied+acked **synchronously**, and a well-behaved client issues close
   only after all write acks — same contract single-stream writes already rely on.
   For a direct-to-final fd write the bytes are in the shared page cache before the
   ack, so the primary's close reads a complete file with no new durability gap. A
   malicious early-close yields a short file exactly as single-stream does. S4 is
   therefore dropped as unnecessary (documented, not skipped).
3. **The capability handshake (X1–X3) is unnecessary for correctness** — the
   client's per-chunk safe-fallback means a NEW client against an OLD/gateway server
   that refuses bound writes simply re-writes each refused chunk on the primary.
   **Verified** against `:21096` (substreams off → 0 secondaries) and `:21097`
   (old module, binds accepted but bound-write refused → `substreams=3
   chunks-on-secondaries=0`, byte-exact). An advertisement remains a *future
   optimization* to avoid the wasted secondary attempts, not a correctness need.

**Tests (`tests/test_data_substreams_parallel.py`, all green on a `worker_processes 2`
fd-export server):** single bound write; striped 4-way parallel write; concurrent
threaded writes; security-neg (bound conn cannot open; bound write to an unpublished
handle refused); client default-upload fan-out (asserts `chunks-on-secondaries>0`
and byte-exact); client default-download read fan-out and opt-in `--parallel` striped
download; and **checksum parity** — a sub-written file's server checksum equals a
single-stream write's (`test_subwritten_file_checksum_matches_single_stream`, S5). Plus
the pre-existing read tests and the `test_session_bind.py` tests still pass (no
regression); VFS-seam + complexity + client-build guards clean.

---

**Related docs**
- Scoping summary: [`../09-developer-guide/bound-write-substream-scoping.md`](../09-developer-guide/bound-write-substream-scoping.md)
- Current feature matrix: [`../09-developer-guide/data-substreams-conformance.md`](../09-developer-guide/data-substreams-conformance.md)
- Multi-client findings index: [`../09-developer-guide/multiclient-conformance-findings.md`](../09-developer-guide/multiclient-conformance-findings.md)
- Streaming-write engine (the reusable apply core): `src/protocols/root/write/write_stream.c`
- Read-substream mechanics (the template): `src/protocols/root/session/handles.c`, `src/protocols/root/session/bind.c`

---

## 0. Goal & non-goals

**Goal.** Let `kXR_write` payloads arrive on **bound secondary connections** so an
upload can be driven in parallel across N TCP streams, matching the parallel-read
capability BriX already has, and matching what go-hep (`WithSubStreams`) and
`xrdcp --streams N` expect on the write path.

**Non-goals (this phase series).**
- No change to the read-substream path (already shipped + tested).
- No change to `brix_data_substreams` gating semantics — `off` still refuses bind.
- Phase 1 does **not** attempt staged/gateway parallel writes (that is Phase 2).
- No new transport; sub-streams stay plain `kXR_bind` TCP connections.

**Definition of done (whole series).** All five benchmark clients upload byte-exact
with sub-streams ON by default; a fd-export BriX genuinely fans writes across
connections; a gateway/staged BriX degrades to inline safely; every path has
success + error + security-negative tests (CLAUDE.md "3 tests per change").

---

## 1. Background — exactly where we are

### 1.1 Wire facts
```
kXR_read   ClientReadRequest    : fhandle[4] offset[8] rlen[4]              -- NO pathid
kXR_write  ClientWriteRequest   : fhandle[4] offset[8] pathid[1] pad[3]     -- pathid + self-addressing offset
kXR_bind   ClientBindRequest    : sessid[16]                                 -- server replies pathid[1]
```
The write header **carries its own absolute `offset`** — a substream write names its
byte range, so disjoint parallel writes are well-defined on the wire. The routing
asymmetry: a read is routed only by *which connection it arrived on*; a write is
self-identifying via `pathid` + `offset`.

### 1.2 What is built (anchors)
| piece | state | anchor |
|---|---|---|
| Accept bind, assign pathid 1–253 | ✅ | `bind.c` `brix_handle_bind` |
| Refuse bind when `brix_data_substreams off` | ✅ | `bind.c:48` |
| Publish **readable** handle metadata to SHM (cross-worker) | ✅ | `handles.c:197` `brix_session_handle_publish` |
| Refuse to publish **write-only** handles ("attractive misuse path") | ✅ (by design) | `handles.c:167` |
| Bound conn may **only read** primary handles | ✅ | `policy.c:117` |
| Serve bound read via independent reopen-O_RDONLY + dev/inode validate | ✅ | `open_resolved_file.c:130` |
| **Refuse non-zero-pathid write, no desync** ("the exact hook a future data-path uses") | ✅ | `recv_process.c:255` |
| Streaming-write engine: bounded-chunk apply, one ack, both backends | ✅ | `write_stream.c` |
| Client opens+binds N-1 secondaries on upload | ✅ | `copy_upload.c:194`, `streams.c` |
| Client write pump runs on **primary only** | ✅ (limitation) | `copy_pump.c:113` `pump_sink_remote` |

### 1.3 The decisive constraint — two write backends
`write_stream.c:96,108` branches the apply on backend:

| backend | detect | apply | reopen-independently safe? |
|---|---|---|---|
| **plain fd / driver** | `file->fd >= 0` \|\| `file->sd_obj.driver` | `apply_direct` → **pwrite @offset** via VFS job | **YES** — disjoint-range pwrites from independent fds to one file is POSIX-safe |
| **staged whole-object** | `file->writer != NULL` | `brix_staged_append_raw` → **append-only, sequential, per-connection**, hydrated at close | **NO** — append has no foreign-offset concept; stage+hydrate+commit is single-owner |

Reads generalise across workers because reopen-O_RDONLY is stateless. Writes only
generalise for the fd backend. **This splits the work into two phases of very
different cost.**

---

## 2. Guiding constraints & invariants to honor

- **INV-4** `resolve_path()` before every `open()` — the secondary's reopen-O_WRONLY
  MUST run the same path resolution as the read reopen, not trust the published path
  blindly beyond dev/inode.
- **INV-10** SHM: the new durable-bytes accounting MUST use `brix_shm_table_*`
  (never bare `ngx_shmtx_create`), spin+yield mutex only.
- **INV-12** VFS: all pwrites go through `brix_vfs_*` / the `src/fs/backend/` seam —
  no raw `pwrite()` outside the backend. The apply already respects this; the bound
  apply must too.
- **INV-2** TLS `b->memory=1` vs cleartext file-backed sendfile — the bound-write
  ingest path must not mix buffer modes (writes are memory-buffered payloads; fine,
  but keep the read sendfile path untouched).
- **HARD BLOCK** no `goto`, functional/early-return, reuse HELPERS, 3 tests/change.
- **Behavior-preserving & incremental** (house refactor rule): each task builds green
  and passes the suite; the refusal path stays the safe default until a task flips it.
- **Capability negotiation is mandatory** — a client MUST NOT blind-fire substream
  writes at a server that will refuse them mid-transfer. See §3.

---

## 3. Cross-cutting: capability negotiation (prerequisite for Phase 1 client work)

The client learns whether the server will accept substream writes **before** it
starts striping, and for **this specific handle** (backend differs per open).

- **Server advertises** support on the **open reply** for a *write* open: a new bit in
  the `ServerOpenBody` response flags (or an appended TLV) = `BRIX_OPEN_F_SUBWRITE`,
  set only when the opened handle is fd/driver-backed AND `brix_data_substreams on`.
  Staged/gateway write-opens leave it clear.
- **Client gate**: only stripe writes across secondaries when the open reply set
  `BRIX_OPEN_F_SUBWRITE` *and* it successfully bound ≥1 secondary; otherwise inline
  (today's behaviour). Never fail a copy because sub-writes are unavailable.
- **Backward/forward safe**: an old server never sets the bit → new client inlines.
  A new server + old client → old client never sends pathid writes → unaffected.

Tasks: `X1` server sets the flag on eligible write-opens (`open_resolved_file.c` build
response, `open_build_response`); `X2` client reads + stores it on `brix_file`
(`client/lib/…` open parse); `X3` wire-doc the flag in `docs/09-developer-guide/agent-guide-extended.md`.

---

## 4. Phase 1 — fd-export bound writes (Option A)

**Scope:** parallel writes to a **fd/driver-backed export** (`brix_export …`),
cross-worker via publish-writable + reopen-O_WRONLY + pwrite@offset, with a close
barrier. Staged/gateway write-opens keep returning `kXR_Unsupported` on a pathid
write → inline fallback. This is a bounded, testable slice.

### 4.1 New data structures

**Writable handle publication** (extend the SHM entry, `handles.c` struct):
```c
/* additions to brix_shared_handle_entry_t */
unsigned  writable   : 1;   /* fd/driver-backed, eligible for bound writes   */
uint64_t  expected_sz;      /* client-declared total (0 = unknown/stream)    */
```
Publish writable entries ONLY for fd/driver handles; staged writers stay unpublished
(keep the `handles.c:167` guard, but branch: readable→as today; writable-fd→publish
with `writable=1`; writable-staged→still skip).

**Durable-range accounting for the close barrier** (new SHM sidecar keyed by
`(sessid, handle_index)`), created via `brix_shm_table_*`:
```c
typedef struct {
    ngx_shmtx_sh_t lock;        /* INV-10: spin+yield                      */
    uint64_t  bytes_durable;    /* sum of acked, fsync-or-writeback bytes   */
    uint64_t  high_water;       /* max(offset+len) seen                     */
    uint32_t  streams_active;   /* primary + bound writers still open       */
    uint8_t   sealed;           /* primary requested close; barrier armed   */
    /* optional: compact range set for hole detection (see 4.4 R-note)      */
} brix_write_barrier_t;
```

### 4.2 Server tasks

- [x] **S1 — publish writable fd handles.** ✅ done (`handles.c` publish now `readable || writable`, fd-gated). In `brix_session_handle_publish` /
  its eligibility helper (`handles.c:167`), add a writable-fd branch that publishes
  `writable=1`, dev/inode, and `expected_sz` (from the write-open opaque if the client
  declared a size). MUST NOT publish staged writers. *Accept:* a fd write-open appears
  in the SHM table with `writable=1`; a staged write-open does not.
  *Security-neg test:* a bound conn cannot use a writable entry to `open`/`stat` — only
  write (S2).

- [x] **S2 — widen bound-conn policy for writes.** ✅ done (`policy.c` bound conn may only `kXR_write`). `policy.c:117`: a bound connection
  may issue `kXR_write` against a **writable published** handle it did not open; still
  no `open`/`close`/`stat`/`mv`/`rm`. Keep dev/inode + sessid scoping identical to the
  read path. *Accept:* bound `kXR_write` to a published writable handle is authorised;
  bound `open`/`close` still refused; wrong-sessid refused.

- [x] **S3 — bound-write apply datapath (core).** ✅ done, **refined**: rather than parsing a
  non-zero pathid on the primary, the client sends the *whole* `kXR_write` (pathid 0) on the
  secondary; `recv_process.c` calls `brix_ensure_write_handle` to reopen O_WRONLY (dev/inode-
  validated) in that worker before the streaming/buffered path pwrites at `offset`. Staged/non-
  eligible handles stay refused. Original wording below. — Replace the refusal at
  `recv_process.c:255` for the **fd-eligible** case: instead of `kXR_Unsupported`,
  route into a bound-write apply that (a) resolves+reopens the path O_WRONLY
  (INV-4, dev/inode-validated like the read reopen), (b) pwrites the payload at
  `offset` through the VFS seam (INV-12), reusing `write_stream.c` chunking for large
  frames, (c) updates the barrier counters (S4), (d) acks. Keep the refusal for
  staged/non-eligible handles (fallback preserved, no desync).
  *Accept:* a bound `kXR_write` lands the exact bytes at `offset` on disk.
  *Error test:* pwrite failure → `kXR_error` on the secondary, barrier not advanced.
  *Security-neg:* pathid write to a **staged** handle still refused cleanly.
  **Risk: HIGH (core datapath).**

- [~] **S4 — close barrier — DROPPED as non-load-bearing (see §0.1 finding 2).** Each bound
  write is applied+acked *synchronously* and the client issues close only after all write acks
  (same contract single-stream writes rely on); for fd-exports the bytes are in the shared page
  cache before the ack, so close reads a complete file with no new durability gap, and a
  malicious early-close yields a short file exactly as single-stream does. Re-open this for Phase
  2 (staged hydration). Original wording below. — On the primary's `close`, if the
  handle was published writable and any secondary wrote, **do not commit/ack until**
  `bytes_durable == expected_sz` (or all `streams_active` writers have closed AND no
  holes below `high_water`), subject to a timeout → `kXR_error` and no commit. Counter
  lives in `brix_write_barrier_t` (INV-10 SHM). *Accept:* close blocks until all
  secondary ranges are durable; a killed secondary → close times out → file NOT
  committed. **Risk: HIGH (partial-commit is the worst bug class).**

- [x] **S5 — checksum parity proven; streaming-digest guard not needed.** ✅ The server
  computes checksums by **re-reading the completed file** on `query checksum`
  (`query/checksum_qcksum_async.c`), not via a rolling/streaming digest — so out-of-order
  disjoint substream pwrites cannot corrupt it, and a sub-written file hashes identically to a
  single-stream write. **Verified** end-to-end: `test_subwritten_file_checksum_matches_single_stream`
  uploads the same bytes sub-written (default `streams=4`, asserting `chunks-on-secondaries>0` so
  the check isn't vacuous) and single-stream (`-S 1`), then asserts the SERVER's checksum of both
  is equal and matches an independent `adler32` of the source. No on-open `BRIX_OPEN_F_SUBWRITE`
  clear is required because there is no streaming digest to break; if a future streaming digest is
  added, this test fails and forces the clear. *Accept:* ✅ checksum on a sub-written file matches
  a single-stream write of the same bytes.

- [ ] **S6 — metrics/log + gate.** *Partial/deferred.* `brix_data_substreams off` still refuses
  bind unchanged (verified); a dedicated `substream_writes_total` metric is a follow-up. Access-log `WRITE` entries carry pathid; a
  `substream_writes_total` low-cardinality metric (INV-8); `brix_data_substreams off`
  still refuses bind unchanged. *Accept:* log/metric reflect substream writes; off-mode
  unaffected.

### 4.3 Client tasks

- [x] **C1 — multi-stream upload pump.** ✅ done, **refined**: `pump_sink_remote` spreads write
  chunks round-robin across primary + secondaries (self-addressing, no server reassembly), each
  secondary write best-effort with fallback to the resilient primary. Original wording below. — Generalise `upload_stream_body`
  (`copy_upload.c`) + `transfer_pump` so the byte range is split into per-stream
  strides and each secondary issues `brix_file_write` on its own connection. Track
  per-stream absolute offset. Sink writes are self-addressing so no reassembly needed
  server-side. *Accept:* `--streams 4` upload issues writes on 4 connections (server
  access-log delta) and round-trips byte-exact. **Risk: HIGH.**

- [~] **C2 — pathid tagging — N/A under the refined protocol.** The write goes whole on the
  secondary connection with pathid 0; the server routes by *which connection* it arrives on
  (mirroring reads), so no client-side pathid tagging on the write header is needed. — Set the `pathid` byte in the `kXR_write` header to the
  secondary's assigned pathid (primary stays 0). Anchor: write framing in
  `client/lib/net`. *Accept:* server sees the correct pathid per connection.

- [~] **C3 — per-stream resilient reopen — obviated by safe-fallback.** A severed secondary
  isn't individually reconnected; the chunk it would carry falls back to the resilient *primary*
  write at the same offset (idempotent pwrite), which keeps its full reopen/retry semantics. Net:
  a killed secondary never fails the copy. Per-stream reconnect is a throughput optimization for
  Phase 3. — The current resilient reopen
  (`copy_pump.c` `pump_sink_reopen`) assumes one connection; make it per-stream so a
  single severed secondary reconnects+rebinds and re-issues its own ranges without
  disturbing the others. *Accept:* kill one secondary mid-upload → it recovers, upload
  still byte-exact.

- [~] **C4 — capability gate — obviated by safe-fallback (see §0.1 finding 3).** No
  `BRIX_OPEN_F_SUBWRITE` advertisement is needed for correctness: a secondary that refuses the
  write (old server / gateway) simply routes that chunk to the primary. Verified against `:21097`
  (old module) → `chunks-on-secondaries=0`, byte-exact. An advertisement stays a *future*
  optimization to skip the wasted secondary attempt. — Stripe writes across secondaries ONLY when
  the open reply set `BRIX_OPEN_F_SUBWRITE` and ≥1 secondary bound; else inline. Never
  fail the copy. *Accept:* upload to a gateway/staged BriX silently inlines; to a
  fd-export BriX fans out.

- [x] **C5 — default streams for upload + guards.** ✅ done (`xrdcp.c` `opts.streams = 4`;
  write-compression / paged-write uploads set `sink.ss = NULL` so they stay single-stream). — Choose the upload default stream
  count; keep write-compression disabling streams (`copy_upload.c:190`); small files
  below a stride threshold stay single-stream. *Accept:* default-on upload works; tiny
  files and `--compress` uploads stay single-stream.

### 4.4 Phase-1 test matrix (extends `tests/test_data_substreams_parallel.py`) — ✅ green
- [x] fd-export, N disjoint bound writes reassemble byte-exact on disk (raw-socket).
  (`test_single_bound_write_lands`, `test_striped_parallel_write_reassembles` 4×60KiB.)
- [~] close barrier: **N/A** — barrier dropped (S4). Covered instead by synchronous-ack
  correctness: a bound write is durable before its ack, close reads a complete file.
- [x] cross-worker (`worker_processes 2`): secondaries land on another worker, correctness holds
  (test server runs `worker_processes 2`; `test_concurrent_bound_writes_threaded`).
- [x] `brix_data_substreams off`: bind refused (existing `tests/test_bind_substreams.py`).
- [x] checksum parity: sub-written vs single-stream file → identical **server** digest, and equal
  to an independent `adler32(source)` (`test_subwritten_file_checksum_matches_single_stream`; the
  server checksums by re-reading the finished file, so out-of-order disjoint pwrites can't skew it).
- [x] client `brix-xrdcp` default upload to fd-export round-trips byte-exact with real secondary
  fan-out (`TestClientUploadFanout`, asserts `chunks-on-secondaries>0`); mixed-version to an old
  module inlines without failing (`:21097` → `chunks-on-secondaries=0`, byte-exact).
- [x] security-neg: bound conn cannot `open` (`test_bound_conn_cannot_open`); bound write to an
  unpublished handle refused (`test_bound_write_unpublished_handle_refused`).

> **R-note (hole detection):** a plain `bytes_durable == expected_sz` counter can be
> fooled by an overwrite that hides a gap. If `expected_sz` is unknown (streamed
> stdin), the barrier needs a compact range set (or a "no gaps below high_water"
> proof) rather than a scalar. Decide during S4; the scalar is fine only when the
> client declares `expected_sz` and never overlaps ranges (which the C1 strider
> guarantees). Document the assumption where S4 lands.

### 4.5 Phase-1 rollout / flags
- Reuse the existing `brix_data_substreams on|off` gate; no new server directive for
  Phase 1 (fd-export eligibility is automatic via the open backend).
- Ship server first (S1–S6) behind the capability flag OFF-by-advertisement until the
  client lands; a server that advertises but has a bug is caught by the raw-socket
  tests before any client depends on it.
- Client default-on (C5) flips only after the server matrix is green.

---

## 5. Phase 2 — staged/gateway bound writes (Option B)

> **STATUS (2026-08-04): ✅ IMPLEMENTED & PROVEN for the root:// gateway — no new server code
> needed; Phase-1 already fans it out. Only the whole-object PUT case falls back.** Standing up a
> real rig (a BriX `brix_storage_backend root://origin` gateway with a `brix_stage` write tier,
> `worker_processes 2`) and running a default `--streams 4` upload settled this empirically:
>
> 1. **A writable root:// gateway stages the upload to a LOCAL, export-rooted `.part` file, NOT
>    the driver-backed whole-object staged writer.** With `brix_upload_resume on` (default) — and
>    POSC, which is *always* implemented — the open path (`open_resolved_file_staging.c`) builds a
>    deterministic/`.posc.*` **local `.part`** under the export root and opens it as a real kernel
>    fd (`file->fd >= 0`, real local path). The bytes are flushed to the remote origin by the
>    existing resume/POSC commit at close. This is the *exact* fd-backed shape Phase-1 publishes
>    to the SHM handle table and fans bound writes across — so **gateway bound writes already work,
>    cross-worker, end-to-end**. The earlier "staged write ALWAYS means an unpublishable
>    `file->writer`" premise was wrong: `file->writer != NULL` is entered ONLY by
>    `brix_open_write_needs_staged` — a backend advertising NO random write AND no `.pwrite`
>    (whole-object S3/WebDAV PUT). A root:// origin gateway never hits it.
> 2. **The flush includes the cross-worker bound writes.** The resume/POSC commit (and, for the
>    `brix_stage` write-back tier, `stage_move_copy_loop`) reads the completed local `.part` **to
>    EOF** — it does not trust any primary-only in-memory cursor/high-water — so bytes a bound
>    secondary pwrote on another worker (same inode, shared page cache) are flushed to the origin.
>    The client issues `close` only after every write ack, so the `.part` is complete at commit
>    (same synchronous contract as §0.1 finding 2; no close barrier needed).
> 3. **PROVEN:** `tests/test_data_substreams_gateway.py::TestGatewayBoundWriteFanout` — 8 MiB
>    `--streams 4` upload through the gateway: `chunks-on-secondaries>0` (real fan-out, not a
>    silent single-stream fallback) AND byte-exact **on the origin's own storage**.
>
> **Residual fallback case (correct, tested):** a whole-object PUT backend (S3/WebDAV,
> `needs_staged` → `file->writer != NULL`, sequential, `fd < 0`, never published) still refuses a
> bound write cleanly and the client re-writes that chunk on the resilient primary — byte-exact.
> Covered by `test_bound_write_unpublished_handle_refused` + the `:21097` mixed-version test
> (`chunks-on-secondaries=0`, byte-exact). Genuine parallel throughput *straight into* such a
> sequential whole-object store (B-i/B-ii below) remains the only deferred item; it is a
> throughput optimisation, not a correctness gap, and is gated on a proven need.
>
> **Symmetric completion shipped (2026-08-04):** the client now also fans **downloads**
> across bound secondaries (`pump_src_secondary` — reads self-address by offset, route by
> connection, and fall back to the primary read on any miss), so data sub-streams are used by
> default in *both* directions for fd-exports. Tested by `TestClientDownloadFanout`.
>
> **True concurrent throughput shipped (2026-08-04, opt-in `--parallel`):** the serial round-robin
> fan-out distributes chunks across sockets but keeps one in-flight op at a time, so it hides no
> RTT. `copy_download_parallel` (`copy_local.c`) adds a **thread-per-connection striped
> download**: a known-size local-file download is split into one contiguous disjoint stripe per
> bound connection, each thread `pwrite`s its range into the destination. The read handle is a POD
> `brix_file` shared read-only (the read path never mutates it; streamid comes from each
> connection's own `brix_send`), so no lock is needed; writes go through `brix_vfs_pwrite` with
> io_uring OFF (plain thread-safe `pwrite(2)`, INV-12), reusing the atomic temp+rename+commit.
> **Fail-closed** (any stripe error drops the temp — no single-link ride-out), hence opt-in with
> the resilient serial fan-out as the default. Tested by
> `TestClientDownloadFanout::test_parallel_striped_download_byte_exact` (+ small-file / stdout
> eligibility fallbacks verified).

**Scope:** parallel writes when BriX is a **gateway** staging to a remote origin
(`file->writer != NULL`). This is the common production shape and the expensive path.

### 5.1 Why Phase 1 doesn't cover it
`brix_staged_append_raw` is **append-only, sequential, single-owner**. A foreign
offset from another worker/connection has nowhere to go. Two ways out:

- **B-i — same-worker rendezvous.** Forward each secondary's `{offset, payload}` to
  the **primary connection's worker** (SHM ring or fd handoff), where the single owner
  applies them in offset order into the staged writer. Cost: a **bulk cross-worker
  datapath** (MiB/s copied through SHM or fds) — exactly what the read side avoided —
  plus backpressure, lifetime, and failure handling for the ring.
- **B-ii — random-access staging.** Replace append staging with a **pwrite@offset
  staging file** that hydrates at close. Then bound writes are just Phase-1 pwrites
  into the staging file, and cross-worker independent reopen works again. Cost: touches
  the hydrate/commit/`brix_upload_resume`/POSC pipeline (`copy_upload.c` + staging
  backend); needs the close barrier (S4) to gate hydration.

### 5.2 Recommendation for Phase 2
Prefer **B-ii (random-access staging)** over **B-i (rendezvous)**: it reuses the
Phase-1 apply + barrier and avoids a brand-new bulk cross-worker transport. B-i only
wins if random-access staging is infeasible for the target backend (e.g. a backend
that can only be written sequentially).

### 5.3 Phase 2 tasks — resolved by the empirical finding above
The whole B-ii "build a random-access staging file" programme turned out to be **already
present** for the `root://` gateway: the resume/POSC `.part` under the export root IS a
random-access local pwrite@offset staging file, and its commit already reads it whole. So:
- [x] **P1** random-access staging file (pwrite@offset) + flush-at-close — **already exists** as
  the resume/POSC `.part` (`open_resolved_file_staging.c`); Phase-1 fans bound writes into it.
- [x] **P2** publish writable staged handles — the `.part` handle is `fd >= 0`, so Phase-1's
  existing publish gate already publishes it; no staged-skip to lift for the `.part` path.
- [x] **P3** hydration/commit gating — the flush reads the `.part` to EOF and the client closes
  only after all acks, so no barrier is needed (§0.1 finding 2 argument, re-verified).
- [x] **P4** POSC/`brix_upload_resume` semantics under parallel writes — resume stays ON; the
  disjoint self-addressed pwrites into the shared `.part` are order-independent (verified
  byte-exact on origin). Documented here.
- [~] **P5** advertise `BRIX_OPEN_F_SUBWRITE` — still just a *future optimisation* (obviated by
  the client safe-fallback, §0.1 finding 3); not required for correctness.
- [x] **P6** origin-side commit correctness under parallel writes — proven byte-exact on the
  origin by `test_data_substreams_gateway.py`.
- [x] tests: gateway parallel upload byte-exact at origin (`test_data_substreams_gateway.py`);
  whole-object-PUT fallback covered by `test_bound_write_unpublished_handle_refused`.

**Only genuinely-deferred item:** parallel throughput *straight into* a sequential whole-object
store (B-i rendezvous / B-ii new-temp for the `needs_staged` PUT path). A throughput-only
optimisation with no correctness gap; gated on a proven need, behind an opt-in directive.

---

## 6. Phase 3 — cross-client validation & default-on (closeout)

> **STATUS (2026-08-04): brix-xrdcp default-on PROVEN in-repo; the 5-client matrix +
> `brixbench parallel_write` are EXTERNAL-RIG items.** The `brixbench` rig
> (`run_matrix.sh` + `compare.py` + the five `bench_*/` client drivers) is **not in this
> repository** — it is the external matrix described in
> `multiclient-conformance-findings.md`. So the `parallel_write` op and the live 5-client
> sweep cannot be added here; they are follow-ups for the rig checkout. `brix-xrdcp`
> default-on (upload *and* download fan-out) is proven by `TestClientUploadFanout` /
> `TestClientDownloadFanout`. Expected behaviour of the other four with the server default
> ON is already documented in §"Cross-client behaviour" of the conformance doc (all
> byte-correct: they either don't fan writes and hit the safe-fallback, or use their own
> substream logic which the server serves/refuses without desync).

- [x] `brix-xrdcp` upload + download fan-out ON by default, byte-exact (in-repo tests).
- [ ] *(external rig)* Verify PyXRootD, go-hep (`WithSubStreams`), XrdRust, stock
  `xrdcp --streams` upload correctly with sub-streams ON by default.
- [ ] *(external rig)* `brixbench` matrix: add a `parallel_write` op mirroring the readv
  closure; verify byte-exact against fd-export BriX (fan-out) and gateway BriX (safe inline).
- [x] Update `docs/09-developer-guide/data-substreams-conformance.md` — bound-write moved to
  ✅ (fd) / ⚠️ (gateway); client-state table shows default `streams=4` with real upload fan-out.
- [x] Update `docs/09-developer-guide/multiclient-conformance-findings.md` verdict.

---

## 7. Sequencing & dependency graph

```
X1 (server advertise) ──┐
                        ├─> C4 (client gate) ─> C1/C2/C3/C5 (client fan-out)
X2 (client read flag) ──┘
S1 (publish writable) ─> S2 (policy) ─> S3 (apply) ─> S4 (close barrier) ─> S5 (cksum) ─> S6 (metrics)
                                                     └─ raw-socket tests gate before any client dep
Phase 1 green  ─────────────────────────────────────> Phase 2 (B-ii staging) ─> Phase 3 (default-on + matrix)
```
Critical path is **S3 → S4** (the two HIGH-risk hunks). Everything else is plumbing
that can proceed in parallel once S1/S2 land.

## 8. Exit criteria

- **Phase 1:** ✅ fd-export parallel upload byte-exact cross-worker; close barrier
  dropped as non-load-bearing (synchronous apply+ack — §0.1 finding 2); staged path
  still safe-inline; full test matrix (§4.4) green incl. checksum parity (S5);
  `brix-xrdcp --streams N` upload fans out to fd-export, inlines to gateway.
- **Phase 2:** ✅ gateway (`root://` origin) parallel upload byte-exact at origin — achieved by
  Phase-1's fan-out into the local resume/POSC `.part`, flushed whole to the origin at close; no
  barrier needed (flush reads the `.part` to EOF; client closes after all acks). Proven by
  `test_data_substreams_gateway.py`. Residual whole-object-PUT (`needs_staged`) case falls back
  safely (tested). Parallel throughput straight into a sequential whole-object store (B-i/B-ii)
  stays deferred as a throughput-only optimisation.
- **Phase 3:** all five clients default-on and byte-exact; `brixbench parallel_write`
  PASS on both server types; conformance docs updated.

## 9. Open questions (decide at implementation time)

1. **Advertisement carrier** for `BRIX_OPEN_F_SUBWRITE`: reuse a `ServerOpenBody` flag
   bit vs an appended TLV (the open reply already grows for retstat/codec — follow that
   pattern).
2. **Barrier shape** (§4.4 R-note): scalar `bytes_durable` (needs declared
   `expected_sz`, non-overlapping strides) vs a range set (handles unknown size /
   overlap). Prefer scalar if C1 guarantees disjoint strides + declared size.
3. **Upload default stream count** and the small-file stride threshold below which the
   client stays single-stream.
4. **Phase 2 backend reality:** which production origins can accept random-access
   staging hydration vs sequential-only (drives B-ii vs B-i).
