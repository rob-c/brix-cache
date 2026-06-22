# Phase 45 — S3 data-plane performance (scale-out without breaking the wire)

**Status:** IMPLEMENTED 2026-06-21 — W1 (keystone), W2/R1, and W3 landed; W2/R2 and
W4 deliberately deferred (see §2). Built clean (`-Werror`); 181 S3 tests + 155 WebDAV
+ integrity-matrix green; the strace syscall-count proof confirms list stats track the
page, not the bucket.
**Scope:** `src/s3/` data path + the read VFS seam it shares (`src/fs/vfs_open.c`,
`src/fs/vfs_write.c`, `src/fs/vfs_internal.h`). **No wire/format changes** —
ListObjects XML, ETags, response headers, and continuation tokens are byte-identical
before/after, so xrootd / XrdHttp / xrootd-S3 (XrdClS3) compatibility holds by
construction. **Next free number** (44 is `phase-44-io-uring-backend.md`).

---

## 0. Context (why)

Phase-43 made the S3 surface *correct/complete*. The general throughput levers are
already done elsewhere and must NOT be re-proposed: cleartext GET already uses
`sendfile` zero-copy (~5 Gbps), kTLS is config-gated (phase-32 §1A), the config bundle
(`sendfile/tcp_nopush/output_buffers/thread_pool/directio`) and build flags
(`-O3 -march=x86-64-v2`, phase-33 D1) ship, PUT already streams without a full-body copy
(phase-31 W2.2), the SigV4 signing-key is cached per worker/day, and an io-uring backend
is its own plan (phase-44).

What remains is **S3-specific data-plane work the general levers never touched**, dominated
by one thing: **the ListObjects path does not scale.** Every list request

1. allocates a *fixed* `s3_entry_t[65536]` = **~273 MB** (`key[4096]` × 65536 — `s3.h:97`
   `S3_MAX_KEY 4096`, `s3.h:103` `S3_LIST_MAX_ENTRIES 65536`, `s3.h:107` `char key[S3_MAX_KEY]`;
   allocated at `list_objects_v2.c:126`) **regardless of bucket size**, and
2. issues an `lstat` for **every object in the whole prefix subtree** (`list_walk.c:138`,
   `xrootd_lstat_confined_canon` per entry), re-walked from scratch on **every** paginated
   page (`list_objects_v2.c:126-156` — full walk + `qsort` + linear continuation scan per page).

On a 1 M-object bucket, a single `max-keys=1000` page does ~1 M `lstat`s and a 273 MB malloc;
deep pagination multiplies it. This is a latent OOM / CPU cliff under concurrent listing —
and it is **invisible to the existing throughput benchmarks**, which test single-object GET,
not listing.

The plan also folds in two small, high-certainty hot-path cuts the audit confirmed (W2) and a
zero-copy multipart assembly win (W3).

### Compatibility invariant (applies to every workstream)

The response bytes a client sees — ListObjects V1/V2 XML (keys, lexicographic sort order,
`KeyCount`, `IsTruncated`, `CommonPrefixes`, synthetic `"mtime-size"` ETags), GET/HEAD
headers, and multipart results — are **identical** before and after. Verified by the existing
`test_s3*.py` suites (byte-for-byte) plus new *characterization* tests asserting
syscall/allocation counts.

### Validation reality

WSL2 throughput is untrustworthy (phase-33 P0). Success is therefore measured by
**deterministic** metrics that hold on any host — `strace -c` syscall counts, peak RSS /
allocation size, and unchanged XML — **not** Gbps. A real perf host remains a prerequisite
only for the optional offload work (W4).

---

## 1. Keystone — make ListObjects O(page), not O(bucket)

Two coupled changes to `list_walk.c` + `list_objects_v2.c` (and the shared V1 emitter):

- **Collect names cheaply, stat lazily.** The walk only needs *names* + a file/dir/symlink
  discriminator to build the sorted candidate set; `size` / `mtime` / `ETag` are only needed
  for the ≤`max-keys` objects actually **emitted**. Use `readdir`'s `d_type`
  (`DT_DIR` / `DT_REG` / `DT_LNK`) to classify with **zero** stats; `lstat` only on
  `DT_UNKNOWN`. Sort by key (already stat-independent — `entry_cmp` is a `strcmp` on the key,
  `list_walk.c:54-59`), then `lstat` **only the emitted page slice** to fill size/mtime/ETag.
  CommonPrefixes need no stat at all. → `lstat` count drops from *O(objects in subtree)* to
  *O(page)*.
- **Right-size the entry store.** Replace the flat `s3_entry_t[65536]` (273 MB) with a
  growable, pool-backed vector of compact records holding a **pooled key pointer** (+
  `is_prefix`, and the page-only stat fields), starting small and growing to the same logical
  cap. → allocation scales with *actual* key count × avg key length, not a fixed 273 MB.

Net: a `max-keys=1000` page over a million-object bucket goes from ~273 MB + ~1 M `lstat` to a
few MB + ~1 K `lstat`, with **byte-identical XML**.

---

## 2. Workstreams

### W1 — Listing scalability (the keystone)
**Files:** `src/s3/list_walk.c`, `src/s3/list_objects_v2.c`, `src/s3/list_objects_v1.c`, `src/s3/s3.h`

- **L1 lazy-stat:** thread `d_type` out of the `readdir` loop; classify via `d_type`, with an
  `lstat` fallback only on `DT_UNKNOWN`; **defer** size/mtime/ETag to the post-sort page slice.
  Preserve the symlink-skip security property exactly (`DT_LNK` → skip; `DT_UNKNOWN` → `lstat`
  then `S_ISLNK` skip — same outcome as `list_walk.c:130-140` today, which exists to stop a
  symlink leaking another tenant / the host FS).
- **L2 growable store:** replace the fixed `s3_entry_t[65536]` with a pool-backed growable
  vector of `{ char *key; uint8_t is_prefix; off_t size; time_t mtime; char etag[…]; }` (key
  strings pooled at their true length). Keep the same effective entry cap so the
  truncation point / `IsTruncated` semantics are unchanged.
- Both the V2 (`list_objects_v2.c`) and V1 (`list_objects_v1.c`) emitters consume the same
  walker + page-slice, so they stay in lockstep.
- **Risk:** medium — must preserve exact sort / pagination / ETag. Mitigation: the change is
  *where/when* we stat, not *what* we emit; the existing list tests assert byte-identical XML.
- **Validation:** `strace -c -f` a `max-keys=1000` list over an N-object bucket → assert
  `lstat`/`newfstatat` count ≈ (dirs + page), not N; assert the entries allocation is ≪ 273 MB
  (a `/metrics` gauge or a debug-build malloc-size probe); diff the XML against the pre-change
  response for several prefix/delimiter/pagination cases.

### W2 — GET/HEAD hot-path syscall cuts
**Files (actual):** `src/fs/vfs_internal.h` (the `stat_current` bit),
`src/fs/vfs_open.c` (`adopt_fd` set + `xrootd_vfs_file_stat` cached answer),
`src/fs/vfs_write.c` (invalidate on write). R2 would have touched `src/s3/object.c`.

- **R1 — kill the redundant GET `fstat` (DONE).** `xrootd_vfs_adopt_fd` already `fstat`s and
  caches `fh->size`/`fh->mtime`/etc. (`vfs_open.c:122,141-142`), but `xrootd_vfs_file_stat`
  `fstat`'d the fd **again** (`vfs_open.c:377`) on every GET (`object.c:91`). Implemented as a
  `stat_current` bit on the handle (`vfs_internal.h`): set in `adopt_fd`, cleared in
  `xrootd_vfs_write` (so a write-then-stat still gets a live `fstat` — preserving the
  documented contract), and consulted by `xrootd_vfs_file_stat` to answer from the cached
  fields. Saves one `fstat` per GET; shared with the WebDAV GET path.
- **R2 — HEAD checksum open avoidance: DEFERRED (not implemented).** Investigated and dropped:
  the second open is NOT wasted on the common path, because HEAD echoes a cached
  `x-amz-checksum-crc64nvme` *by default* (the phase-43 behavior), so the fd is needed to read
  that xattr. Skipping it would drop the default checksum echo — a visible header change that
  violates the compatibility invariant. The only ways to avoid the open (a path-based
  integrity-xattr read, or gating the unrelated FRM residency probe) fall outside this plan's
  `src/s3/` + VFS scope and carry correctness risk. Left for a future FRM/integrity-layer pass.
- **Risk:** low. **Validation (R1):** GET/HEAD content/size/ETag unchanged (31 S3 + 155 WebDAV +
  byte-exact integrity-matrix tests); the `xrootd_vfs_write` invalidation keeps the live-fstat-
  after-write contract.

### W3 — Zero-copy multipart assembly
**File:** `src/s3/multipart_complete_body.c`

- CompleteMultipartUpload concatenates parts with a **read/write loop** in 64 KiB chunks on the
  event loop (`multipart_complete_body.c:178-206`). Switch part→final concatenation to the
  existing zero-copy helper `xrootd_copy_range` / `copy_file_range` (the same one PUT uses,
  `src/compat/copy_range.c`), falling back to the read/write loop on `EXDEV` / `ENOSYS`. Large
  multipart objects (multi-GiB) stop round-tripping every byte through userspace.
- **Risk:** low-medium — must keep the atomic temp+rename and the full-object checksum compute
  intact. **Validation:** `test_s3_multipart.py` (byte-exact reassembly + checksum) stays
  green; `strace` shows `copy_file_range` replacing the read/write loop.

### W4 — *(Optional / deferred)* offload blocking writes off the event loop
**Files:** `src/s3/put.c`, `src/s3/aws_chunked.c`

- Today only **in-memory, non-codec** PUT bodies use the thread pool (`put.c:764-765`);
  **spooled** bodies, the **aws-chunked** decode (`aws_chunked.c`, inline `pread`/`pwrite`),
  and **multipart complete** run synchronously on the event loop, stalling the worker during
  large transfers. Extending the `s3_put_aio_*` offload to these is real
  throughput-under-concurrency work, but it changes async control flow (UAF discipline,
  `r->main->count` refcounts) and is **only meaningfully measurable on a real perf host**.
  Listed as a deferred follow-up, not in the committed core. **Risk:** high (event-loop
  lifetime). Gate behind the existing thread pool; no behavior change when unset.

---

## 3. Non-goals (already done or owned elsewhere — do not re-propose)

- `sendfile` / zero-copy GET, kTLS, `ssl_buffer_size`, the config bundle, build flags —
  phase-32 / phase-33.
- Stream-plane read pipelining / windowed TLS reads / concurrent-AIO — phase-29 / 31 / 32 / 33.
- PUT full-body-copy elimination — phase-31 W2.2.
- io-uring backend — phase-44.
- SigV4 multi-slot signing-key cache — single-region HEP makes it ~zero value; note and skip.
- A repeat-GET open-fd cache — object stores have low GET-repeat locality and the invalidation
  cost is high; the slice / open cache (phase-26) already covers the read-through case. Skip.

---

## 4. Sequencing

1. **W2** first — smallest, lowest risk, immediate per-request win, and the shared VFS seam it
   touches de-risks the later work.
2. **W1** (the keystone) — land L1 + L2 together; gate the whole thing on the
   byte-identical-XML diff before merging anything else.
3. **W3** — independent, zero-copy multipart.
4. **W4** — only if/when a trustworthy perf host is available.

Each workstream is one PR with the mandatory 3 tests (success + error + a characterization
assertion) and a regression run of the full `test_s3*.py` suite (the 230-pass phase-43
baseline).

## 5. Files to modify

| Workstream | Files (actual) |
|---|---|
| W1 (done) | `src/s3/list_walk.c`, `src/s3/list_objects_v2.c`, `src/s3/list_objects_v1.c`, `src/s3/s3.h` |
| W2/R1 (done) | `src/fs/vfs_internal.h`, `src/fs/vfs_open.c`, `src/fs/vfs_write.c` |
| W2/R2 (deferred) | — (would be `src/s3/object.c`) |
| W3 (done) | `src/s3/multipart_complete_body.c` |
| W4 (deferred) | `src/s3/put.c`, `src/s3/aws_chunked.c` |
| Tests | new `tests/test_s3_perf_characterization.py` (scale correctness + strace syscall-count proof); existing `test_s3.py` / `test_s3_multipart.py` / `test_webdav.py` / `test_integrity_matrix.py` for the byte-identical regression |

## 6. Expected outcome

- ListObjects memory per request: **273 MB fixed → O(actual keys)** (a few MB for typical pages).
- ListObjects `lstat` syscalls per page: **O(objects in subtree) → O(page)** (≤ `max-keys`).
- GET: **one fewer `fstat`**; HEAD: **no spurious `open` when no checksum** present.
- Multipart Complete: **userspace byte-copy → kernel `copy_file_range`** for part assembly.
- Zero wire/format change; the phase-43 S3 test baseline stays green.
