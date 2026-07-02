# Phase 46 — S3 write concurrency & per-request syscall cost

**Status:** IMPLEMENTED 2026-06-21 — W1 (a/b/c offloads) + W2 (a/b syscall cuts) landed
and strace-verified; W3 deliberately deferred (§2 W3). Built clean (`-Werror`); 336 S3 +
WebDAV + integrity tests pass, 5 FRM-staging tests pass (W2b with FRM enabled). **Two
latent bugs found and fixed while implementing W1a** — see the status table below.
**Scope:** `src/protocols/s3/` write path + two shared seams (`src/frm/residency.c`,
`src/core/config/postconfiguration.c`). **No wire/format changes** — responses, XML, ETags,
headers, and continuation tokens are byte-identical, so xrootd / XrdHttp / xrootd-S3
(XrdClS3) compatibility holds by construction.
**Next free number** (45 is `phase-45-s3-data-plane-performance.md`, implemented).

---

## Implementation status (what landed)

| WS | Status | Proof |
|---|---|---|
| **W1a** spooled PUT offload | DONE | spooled `copy_file_range` runs on a thread-pool TID, not the event thread (strace) |
| **W1b** aws-chunked decode offload | DONE | decoded-payload `pwrite`s on a thread-pool TID (strace); 8 streaming tests byte-exact |
| **W1c** multipart Complete offload | DONE | part-concat `copy_file_range` on a thread-pool TID (strace); 13 multipart tests byte-exact |
| **W2a** PUT parent-dir fast-path | DONE | PUT into an existing prefix → **0** `mkdirat` (was depth-many) (strace) |
| **W2b** FRM residency probe guard | DONE | GET/HEAD on a no-tape export → **0** residency `stat`/`getxattr` (strace); FRM-enabled staging still correct (5 tests) |
| **W3** listing walk-cursor cache | DEFERRED | marginal payoff vs cross-request cache complexity (see §2 W3) |

**Two latent bugs W1a uncovered and fixed:**
1. **The S3 async offload never engaged for the normal config.** The S3 postconfiguration
   resolved `common.thread_pool` only on *server-level* loc-confs, but `xrootd_s3` lives in
   a `location {}` block whose conf never received the pointer — so *every* PUT (in-memory
   and spooled) silently ran synchronously on the event loop. Fixed with a lazy resolver
   `s3_thread_pool()` (caches into the loc-conf at request time), mirroring the WebDAV
   COPY/MOVE pattern (`src/protocols/webdav/copy.c`, `move.c`); now used by all three offloads.
2. **The async PUT completion never set the `ETag` header** (the sync path did) — latent
   because the async path never ran. Exposed once the offload engaged; fixed in
   `s3_put_aio_done`.

---

## 0. Context (why)

Phase-45 fixed the S3 **read + listing + multipart** hot paths (listing O(page), the
redundant GET `fstat`, zero-copy multipart concatenation). What remains, confirmed by
code audit, is on the **write path and per-request fixed cost**:

1. **The event loop blocks on large writes.** Only *in-memory, identity-encoded* PUT
   bodies use the thread pool today (`put.c:764` gate `!body_summary.has_spooled && …`).
   Everything else runs **synchronously on the nginx worker's event loop**, stalling it
   (and every other connection that worker serves) for the whole transfer:
   - **spooled** PUT bodies (large uploads nginx writes to a temp file) —
     `xrootd_http_body_write_to_fd` inline (`put.c:816`);
   - **aws-chunked** decode — the `pread`/`pwrite` state machine inline
     (`aws_chunked.c:307` via `s3_put_streaming`, `put.c:742`);
   - **CompleteMultipartUpload** — the up-to-10 000-part `copy_file_range` loop inline
     (`multipart_complete_body.c:155-218`).
   This is the dominant remaining S3 throughput-under-concurrency gap (phase-45 deferred
   it as "W4"); it is invisible to single-stream benchmarks but caps how many
   simultaneous large transfers a worker can serve without head-of-line blocking.

2. **Per-request fixed syscall cost** the audit surfaced:
   - **Every PUT** issues a `mkdirat` per key path component even when the prefix
     already exists — `xrootd_mkdir_recursive_confined_canon` (`mkdir.c:131-147`) has no
     EEXIST fast-path. Uploading N objects into one prefix pays this N times.
   - **Every S3 GET/HEAD** issues an extra `stat` + `getxattr` for the FRM tape-residency
     probe (`object.c:112,247` → `residency.c:69,46`), **ungated** — even on a plain S3
     export with no tape staging. Native XRootD already gates this on `conf->frm.enable`
     (`read/stat.c:135`); S3 (and WebDAV PROPFIND) do not.

**Compatibility invariant (every workstream):** identical bytes on the wire. The
offload moves *where* the I/O runs, not *what* is returned; the syscall cuts change
*how many* syscalls happen, not the result. The FRM gate is behavior-identical: when
FRM was never configured no object carries a residency xattr, so the probe already
returns ONLINE — skipping it yields the same answer (exactly the native-XRootD gate's
semantics).

**Validation reality:** WSL2 throughput is untrustworthy (phase-33 P0), so success is
**deterministic**: byte-identical responses; the offload provably *happens* (thread-pool
task posted / `strace` shows the write I/O on a worker thread, not the event thread); and
`strace` syscall-count deltas (fewer `mkdirat` per PUT into an existing prefix; no
residency `stat`+`getxattr` on GET/HEAD when FRM is off). The concurrency win is
architectural — a large transfer no longer stalls the worker — and is shown by a slow
large PUT not blocking a concurrent GET, not by a Gbps number.

---

## 1. Keystone — take blocking writes off the event loop

Extend the **already-proven** `s3_put_aio_*` thread-pool pattern (`put.c:122-209`:
task struct → worker fn → completion event that commits/checksums/finalizes on the event
loop, holding the request open with `r->main->count++`). The worker thread only does the
blocking I/O against fds + paths captured into the task struct; **all request-touching
work (commit, checksum, dashboard, metrics, response/XML) stays in the completion
callback on the event loop** — exactly how the in-memory PUT path already works, so no
new UAF/impersonation surface beyond the existing template.

---

## 2. Workstreams

### W1 — Offload the blocking write paths (keystone)
**Files:** `src/protocols/s3/put.c`, `src/protocols/s3/aws_chunked.{c,h}`, `src/protocols/s3/multipart_complete_body.c`

- **W1a — spooled PUT bodies (smallest, safest, do first).** Widen the thread-pool gate
  (`put.c:764`) to also admit `body_summary.has_spooled` bodies: the existing worker fn
  `s3_put_aio_thread` already calls `xrootd_http_body_write_to_fd`, which handles spooled
  bufs (kernel `copy_file_range` from the nginx spool temp fd). No new task type — just
  stop excluding spooled. Large uploads (exactly the ones nginx spools) stop blocking the
  worker. **Risk:** low — same worker fn, same completion, fds only.
- **W1b — aws-chunked decode.** Add an aio task that captures the staged fd + decoded
  length + root_canon and runs `s3_aws_chunked_decode_to_fd` on the worker; the completion
  does commit + trailer/checksum verify + finalize (mirror `s3_put_aio_done`). **Risk:**
  medium — must move the trailer-checksum + error mapping into the completion.
- **W1c — CompleteMultipartUpload concatenation.** Offload the part loop
  (`multipart_complete_body.c:155-218`) into a task (capture `mpu_dir`, `final_tmp`,
  `fs_path`, `root_canon`); the completion does the atomic rename + full-object checksum +
  `CompleteMultipartUploadResult` XML. **Risk:** medium — the XML/response build moves to
  the completion callback; keep the impersonation principal re-established as the existing
  handler does.
- **Validation:** byte-exact round-trips (existing `test_s3*.py` / `test_s3_multipart.py`);
  a new test asserts the offload occurred (thread-pool task / `strace` shows the write on a
  non-event thread) and that a slow large PUT does not block a concurrent GET on the same
  worker. Falls back to the synchronous path when no thread pool is configured (unchanged).

### W2 — Per-request syscall cuts (cheap, safe)
**Files:** `src/protocols/s3/put.c` (or `src/fs/path/mkdir.c`), `src/frm/residency.c`

- **W2a — PUT parent-dir fast-path.** Before `xrootd_mkdir_recursive_confined_canon`
  (`put.c:692`), confined-`stat` the parent dir; if it exists and is a directory, skip the
  recursive mkdir entirely. Cuts the per-PUT `mkdirat` storm for the common "many objects
  into one prefix" pattern. **Risk:** low (benign TOCTOU — the recursive mkdir remains the
  fallback when the stat says "absent"). **Validation:** `strace` a PUT into an existing
  deep prefix → assert ~0 `mkdirat`, vs depth-many before.
- **W2b — FRM residency probe cheap when FRM is off.** Add a process-global "FRM ever
  configured" guard set at FRM config/init time and consulted at the top of
  `frm_residency_probe` (`residency.c`) to return ONLINE immediately when FRM was never
  configured — eliminating the `stat`+`getxattr` per S3 GET/HEAD (and WebDAV PROPFIND) on a
  plain export. Matches the native-XRootD `conf->frm.enable` gate's semantics from a single
  shared chokepoint (no per-module config plumbing). **Risk:** low — same behavior native
  already has; when FRM *is* configured nothing changes. **Validation:** `strace` a GET/HEAD
  with FRM unconfigured → assert no residency `stat`/`getxattr`; the FRM tape tests
  (`test_frm*.py`) still pass with FRM enabled.

### W3 — *(Optional / deferred)* listing pagination walk-cursor cache
**File:** `src/protocols/s3/list_objects_v2.c`

- Each paginated page still re-runs the **full** recursive `s3_walk` + `qsort` + linear
  continuation scan over the whole prefix subtree (`list_objects_v2.c:135-159`) — phase-45
  made the *stat* O(page) but the *readdir* walk is still O(subtree) per page. A short-TTL,
  per-worker cached sorted-key cursor keyed by the (opaque) continuation token would make
  page 2..N O(page) for the walk too. **Deferred:** it introduces cross-request mutable
  cache state (coherency, eviction, memory, TLS-unsafe), and `readdir` is far cheaper than
  the `lstat` phase-45 already eliminated — so the payoff is marginal versus the complexity.
  Listed for completeness; correctness must fall back to a full walk on miss/staleness.

---

## 3. Non-goals (already done or owned elsewhere — do not re-propose)

- Listing O(page) lazy-stat + growable store, GET `stat_current` cache, zero-copy multipart
  concatenation — **phase-45**.
- `sendfile`/zero-copy GET, kTLS, config bundle, `-O3 -march=v2` build flags — phase-32/33.
- Stream-plane pipelining / windowed TLS reads / concurrent-AIO — phase-29/31/32/33.
- io-uring backend — phase-44.
- Spooled-PUT double-disk-write elimination (rename nginx's spool temp into the object) —
  nginx owns the spool temp lifecycle and it isn't confined; out of scope.
- HEAD checksum-open avoidance / multi-slot SigV4 cache / repeat-GET fd cache — judged
  not worth it in phase-45.

---

## 4. Sequencing

1. **W2a + W2b** first — tiny, deterministic, immediate per-request wins; de-risk the
   shared-seam touches (mkdir, residency) before the bigger offload.
2. **W1a** — widen the spooled gate (small, high value, reuses the proven path).
3. **W1b**, then **W1c** — the fuller offload (more completion-callback restructuring).
4. **W3** — only if profiling on a real perf host shows the per-page re-walk dominates.

Each workstream is one PR with the mandatory 3 tests (success + error + a deterministic
characterization assertion) and a full `test_s3*.py` regression (the phase-45 baseline),
plus `test_webdav.py` + `test_frm*.py` for the shared-seam changes (W2b).

## 5. Files to modify

| Workstream | Files |
|---|---|
| W1a / W1b / W2a | `src/protocols/s3/put.c` (gate widen; chunked task; parent fast-path) |
| W1b | `src/protocols/s3/aws_chunked.{c,h}` (offload task) |
| W1c | `src/protocols/s3/multipart_complete_body.c` (offload task) |
| W2a (shared option) | `src/fs/path/mkdir.c` (stat fast-path if shared) |
| W2b | `src/frm/residency.c` + the FRM config/init hook (process-global guard) |
| W3 (optional) | `src/protocols/s3/list_objects_v2.c` |
| Tests | new `tests/test_s3_perf_characterization.py` additions (offload-occurs + syscall-delta); existing `test_s3*.py` / `test_s3_multipart.py` / `test_webdav.py` / `test_frm*.py` for regression |

## 6. Expected outcome

- Large spooled / aws-chunked PUTs and many-part CompleteMultipartUpload no longer stall
  the event loop — a worker keeps serving other connections during big transfers.
- PUT into an existing prefix: `mkdirat` storm → ~0 syscalls.
- GET/HEAD on a no-tape export: residency `stat`+`getxattr` → 0.
- Zero wire/format change; the phase-43/45 S3 test baseline stays green.
