# Bulk storage scan / verify / fill — admin namespace+checksum auditing

**Status:** design / spec — approved 2026-06-29
**Owner:** Rob Currie
**Date:** 2026-06-29
**Scope:** A server-side, throttled, parallel, streaming bulk-scan engine
(`src/fs/scan/`) that enumerates a confined export subtree and, per object, either
dumps metadata + stored checksum, verifies stored vs recomputed, backfills
missing checksums, or feeds a client-side compare against an external manifest.
Streamed to an admin over an HTTP chunked NDJSON endpoint, driven by a thin
clean-room client (`xrdstorascan`). **No new `root://` wire opcode** in this
phase (the engine is protocol-agnostic so one can be added later); **no RADOS
symbol above `src/fs/backend/`** — every byte and every namespace touch flows
`proto → VFS → SD driver`, so CEPH works for free.

**Hard constraint (operator):** every read this tool performs MUST be
**byte-compatible with stock XrdCeph** (`/tmp/xrootd-src/src/XrdCeph`) — it reads
the exact bytes stock would serve and decodes the exact stored-checksum blob
stock writes, introducing no new Ceph access path. See **§7** for how this is
satisfied and the single driver dependency it lands on.

---

## 0. Motivation

Site admins — especially CEPH sites — currently have no efficient way to (a)
produce a manifest of object paths + recorded checksums on the backend, or (b)
verify that the bytes on disk still match those recorded checksums, without
either dragging every object back over the wire or hand-rolling a recursive
`dirlist` + per-file `Qcksum` loop that hammers the backend.

The pieces already exist but don't compose into an admin tool:

| Existing | What it gives | Why it's not enough |
|---|---|---|
| `kXR_Qckscan` (`src/query/`) | server-side recursive checksum of a subtree | **recomputes** every file (no verify-against-stored), **buffers the whole result** in memory, walks **single-threaded**, **no throttle** |
| `xrootd_vfs_walk()` (`src/fs/vfs_walk.c`) | thread-safe, confined, non-metered recursive walk firing a per-file callback | it's an enabler, not a product — no parallelism, throttle, or streaming around it |
| `xrootd_integrity_get_fd()` (`src/core/compat/integrity_info.h`) | checksum lookup (xattr cache) or compute, with cache-update opt | per-file primitive; nothing orchestrates it in bulk |
| xattr `user.XrdCks.<alg>` + CSI tagstore | checksums-at-rest already on disk | nothing exposes a bulk read of them |
| dashboard / SRR (`src/dashboard/`, `src/srr/`) | admin-auth HTTP/JSON endpoints, `openat2 RESOLVE_BENEATH` confinement | precedent to reuse for transport + auth |

This phase composes them into one throttled, streaming engine + a thin client.

---

## 1. Module layout — `src/fs/scan/`

```
src/fs/scan/
  scan_engine.c / scan_engine.h    walk → bounded queue → worker pool → emit; mode dispatch
  scan_throttle.c / scan_throttle.h shared token bucket: concurrency + byte-rate + adaptive
  scan_record.c / scan_record.h     NDJSON record formatting (file / cursor / summary)
  scan_http.c                       HTTP endpoint binding: auth, param parse, chunked stream
  README.md
```

**Layering rule:** `scan_engine.c`, `scan_throttle.c`, `scan_record.c` are
**ngx-free and protocol-agnostic** — they take a `rootfd`, a parsed
`xrootd_scan_opts_t`, and an emit callback. `scan_http.c` is the *only*
nginx-coupled file; it owns the `ngx_http_request_t`, auth, and chunked output.
This boundary is what lets a future `root://` scan opcode reuse the engine
unchanged (drive it from a thread task, emit over `kXR_status` frames).

New source files register in the top-level `./config` (`$ngx_addon_dir/src/fs/scan/...`),
then `rm -rf objs && ./configure && make` (new-source build rule — never
`./configure` over a stale `objs/`).

---

## 2. The engine (`scan_engine.c`) — one walk, four actions

### 2.1 Data flow

```
xrootd_vfs_walk(rootfd, subtree, enqueue_cb)   ── producer (1 walk task)
        │  {logical_path, struct stat}
        ▼
   bounded ring buffer  (capacity = 2 × parallel; full ⇒ walk blocks = backpressure)
        │
        ├──► worker[0] ─┐
        ├──► worker[1] ─┤  N = parallel thread-pool tasks
        ├──► ...        ├─►  per-object ACTION (mode-dispatched)
        └──► worker[N-1]┘        │
                                 ▼
                    emit_cb(record)  ── serialized by emit_mutex,
                                        preserves deterministic walk order
```

The walk callback is deliberately cheap: it only stats (the walk already did the
`fstatat`) and enqueues. All expensive work happens in the workers so it is
bounded by the throttle.

**Ordering guarantee.** Records are emitted in walk order even though workers
finish out of order: each queue entry carries a monotonic sequence number; the
emit side releases record `k` only after `k-1` has been emitted (a small
reorder window bounded by `parallel`). This keeps the `after=<cursor>` resume
contract sound — a cursor `P` means "every path ≤ P in walk order is done."

### 2.2 Modes (per-object action)

| Mode | Reads bytes? | Action | Record `status` values |
|---|---|---|---|
| `dump` | **no** | read stored checksum from `XrdCks.<alg>` xattr (POSIX `user.XrdCks.<alg>` via `xrootd_vfs_fgetxattr`; Ceph via the striper xattr namespace) — decode the stock binary `XrdCksData` blob | `ok` (always) — `stored:null` when absent, `stale:true` when the blob's `fmTime` ≠ current mtime |
| `verify` | yes | `xrootd_integrity_get_fd(fd,{allow_xattr_cache:0,no_compute:0})` recompute, compare to stored | `ok` \| `mismatch` \| `stale` (stored present but `fmTime`≠mtime — known-outdated, recompute differs *expectedly*) \| `missing` (no stored to compare) \| `unreadable` |
| `fill` | yes (only if missing/stale) | if no stored checksum **or** stored is stale: compute + persist as a stock `XrdCksData` blob (`update_xattr_cache:1`, `fmTime`=current mtime); else skip | `filled` \| `already` \| `unreadable` |
| `compare` | **no** (server side) | identical to `dump`; the diff happens in the client | `ok` |

`dump` and `compare` never enter the byte path, so they do **not** engage the
byte-rate throttle and run at near-`stat` speed. Only `verify`/`fill` read object
data and are gated by the full throttle.

**`fmTime` staleness (stock parity).** Stock XRootD (`XrdCksManager`) stamps the
checksum blob with the file mtime at calc-time (`fmTime`) and treats the stored
value as stale — to be recomputed — whenever `fmTime ≠ current mtime`. The scan
mirrors this exactly: `verify` reports a `fmTime`-mismatch as `stale`, **not**
`mismatch`, so an admin is not alarmed by an expected post-write divergence;
`fill` refreshes a stale blob; `dump` flags it. The `XrdCksData` binary
encode/decode reuses the existing stock-compatible codec (phase-58 §8.1) — no new
on-disk format is introduced.

### 2.3 Confinement & seam

Every filesystem touch goes through the VFS seam — `xrootd_vfs_walk` for
enumerate, `xrootd_vfs_open_fd_at` for the per-object fd, `xrootd_vfs_fgetxattr`
for the stored value, `xrootd_integrity_get_fd` for compute/persist. No raw
libc FS call in `src/fs/scan/`. This is what makes the engine backend-neutral
(POSIX, pblock, S3, **RADOS**) with no scan-specific backend code.

---

## 3. Throttle — `scan_throttle.c`

One `xrootd_scan_throttle_t`, guarded by a single mutex, consulted by every
worker **before** it reads bytes. Four independent controls compose:

- **Concurrency cap.** Counting gate; at most `parallel` workers in the
  read/checksum action simultaneously. Excess workers park on a condvar.
- **Byte-rate cap.** Leaky bucket over bytes read from the backend. A worker
  about to read a file of `size` bytes waits until the bucket has accrued
  enough tokens (`max_rate` bytes/s refill). This is the primary CEPH
  protection — it bounds RADOS read throughput, not request count.
- **Adaptive multiplier** `m ∈ [0.1, 1.0]` applied to both caps, recomputed each
  tick from two sampled signals:
  1. **Foreground pressure** — count of active non-scan requests (existing
     per-worker request gauge). Rising → shrink `m`.
  2. **Backend read-latency EWMA** — measured per-read inside the worker.
     Rising → shrink `m`.
  Effect: the sweep auto-yields to real client traffic ("background mode").
  *Fallback (scope note):* if the foreground-pressure gauge proves too noisy,
  drop to latency-EWMA only — the design does not depend on both.
- **Budget.** `max_bytes` / `max_seconds`. On hit: stop enqueuing, drain
  in-flight workers, emit a final `cursor` record, end the stream cleanly. The
  run is resumable from that cursor.

The token-bucket math (`bytes_available(now)`, refill, wait-quantum) is pure and
unit-testable in isolation.

---

## 4. Transport + wire schema — `scan_http.c`

### 4.1 Endpoint

`GET /xrootd/api/v1/scan` — in the existing dashboard/SRR API namespace, same
admin-token auth and audit-log line. Response: `200 OK`, `Transfer-Encoding:
chunked`, `Content-Type: application/x-ndjson`; one JSON object per line,
flushed (`ngx_http_output_filter` + flush buf) as produced.

### 4.2 Query parameters

| Param | Meaning | Default / clamp |
|---|---|---|
| `mode` | `dump` \| `verify` \| `fill` \| `compare` | required |
| `path` | export-relative subtree, confined under `xrootd_scan_root` | `/` |
| `alg` | `adler32` \| `crc32c` \| `crc64` \| `crc64nvme` | `adler32` |
| `parallel` | worker count | clamp ≤ `xrootd_scan_parallel` |
| `max_rate` | bytes/s read cap (`200M` etc.) | clamp ≤ `xrootd_scan_max_rate` (0 = unlimited) |
| `adaptive` | `0` \| `1` | `xrootd_scan_adaptive` |
| `max_bytes` / `max_seconds` | budget | 0 = none |
| `after` | resume cursor (walk-order path) | none |

Per-request params may **lower** but never exceed configured ceilings —
operator caps always win.

### 4.3 Record types (NDJSON)

```json
{"t":"file","path":"/atlas/x.root","size":12345,"mtime":1719600000,"alg":"adler32","stored":"a1b2c3d4","cks_mtime":1719600000,"computed":"a1b2c3d4","status":"ok"}
{"t":"cursor","after":"/atlas/x.root"}
{"t":"summary","files":120345,"bytes":98765432,"ok":120300,"mismatch":2,"stale":11,"missing":40,"unreadable":3,"filled":0,"elapsed_s":812.4}
```

- `file` — one per object. `computed` present only for `verify`/`fill`;
  `cks_mtime` is the stored blob's `fmTime` (null when no stored value), so a
  consumer can see staleness without re-deriving it.
- `cursor` — emitted on checkpoint interval and on budget-stop; carries the
  last fully-emitted walk-order path for `--resume`.
- `summary` — final record with run totals.

### 4.4 Backpressure & confinement

Backpressure is inherent: a slow admin socket stalls the chunked write, which
stalls the emit callback (under `emit_mutex`), which stalls workers — no
unbounded buffering anywhere. Path confinement reuses the dashboard's `openat2
RESOLVE_BENEATH` against `xrootd_scan_root`; a traversal attempt (`path=../x`)
resolves outside and returns 403. Auth is admin-token only (same gate as the
dashboard file browser).

---

## 5. Config directives (`src/core/config`)

```nginx
xrootd_scan            on | off;     # default off — opt-in admin feature
xrootd_scan_root       <path>;       # confinement root (default: export root)
xrootd_scan_parallel   <n>;          # ceiling on parallel workers (default 4)
xrootd_scan_max_rate   <bytes/s>;    # ceiling on read rate (default 0 = unlimited)
xrootd_scan_adaptive   on | off;     # default on
```

Field in `src/core/config/config.h` (`NGX_CONF_UNSET`), `ngx_command_t` in
`src/core/config/directives.c`, merged in `merge_*_conf()`. No new top-level block, so
no `./configure` needed for the directives themselves (only for the new source
files).

---

## 6. Client — `xrdstorascan` (clean-room C, atop `libxrdc`/HTTP)

Follows the phase-37 native-tool pattern (no libXrdCl). Subcommands map to
`mode`:

```
xrdstorascan dump    davs://host//atlas/        -o manifest.tsv
xrdstorascan verify  davs://host//atlas/ --parallel 8 --max-rate 200M --resume
xrdstorascan fill    davs://host//atlas/ --alg crc32c
xrdstorascan compare davs://host//atlas/ --manifest rucio_dump.tsv
```

- Wraps the HTTP endpoint; maps `--parallel/--max-rate/--adaptive/--max-bytes/
  --max-seconds` to query params.
- Renders streamed NDJSON → TSV (default), `--json` (passthrough), or `--summary`
  (totals only).
- `--resume` persists the last `cursor` to a sidecar `<output>.scanstate` and
  re-issues with `after=` on restart.
- **compare** streams the server `dump`, diffs locally against the catalog file
  (`path \t checksum` lines), classifying `missing` (in manifest, not on
  storage), `extra` (on storage, not in manifest), `mismatch` (both, differ);
  optionally issues a targeted `verify` for entries where the stored value is
  absent so a definitive recompute decides.

Auth via the existing client credential machinery (token / GSI), same as the
other native tools.

---

## 7. CEPH path + byte-compatibility with stock XrdCeph

### 7.1 What stock XrdCeph does (the compatibility target)

From `/tmp/xrootd-src/src/XrdCeph` (`XrdCephPosix.cc`, `XrdCephXAttr.cc`):

- **Bytes are striped via `libradosstriper`.** A file's logical name `fr.name`
  is read/written with `striper->read/write(fr.name, …)` under a layout
  `[user@]pool[,nbStripes[,stripeUnit[,objectSize]]]`. The on-the-wire file is the
  *reassembly* of many RADOS objects by the striper — **not** a single flat
  RADOS object. The striper persists its layout in `striper.layout.stripe_unit`
  / `striper.layout.object_size` xattrs.
- **Checksums are the stock `XrdCksData` blob.** `XrdCks` stores the checksum in
  xattr `XrdCks.<alg>` (e.g. `XrdCks.adler32`) as a *binary* `XrdCksData` struct
  (name, length, `fmTime`, `csTime`, value) — not a hex string. On Ceph that
  xattr lives in the striper/RADOS xattr namespace (via `XrdCephXAttr` →
  `ceph_posix_*xattr`); on POSIX it is `user.XrdCks.<alg>`.

### 7.2 How the scan stays byte-compatible

The scan engine adds **no** Ceph access path of its own — it only calls
`xrootd_vfs_* → obj->driver->*` and the existing stock-compatible `XrdCksData`
codec. Therefore byte-compatibility is satisfied by two existing/owed pieces, not
by anything in `src/fs/scan/`:

1. **Byte reads** (`verify`/`fill`) go through `obj->driver->pread`. For the
   result to equal what stock serves, the **`sd_ceph` driver must read via
   `libradosstriper` with the matching layout/pool** — i.e. reassemble the same
   bytes stock would. This is the phase-60 **"libradosstriper interop with stock
   XrdCeph"** open item. **Dependency, stated plainly:** `verify` and `fill` on a
   Ceph export are correct **only once `sd_ceph` is striper-backed**; until then
   the scan engine must refuse `verify`/`fill` on a Ceph-backed export (clean
   `501`/error record, never a wrong-bytes answer). `dump`/`compare` (xattr-only)
   are safe earlier, as soon as the driver exposes the `XrdCks.<alg>` xattr from
   the striper namespace.
2. **Stored-checksum read/write** uses the existing `XrdCksData` binary codec
   (phase-58 §8.1) against the `XrdCks.<alg>` xattr — the exact name, blob layout,
   and `fmTime` semantics stock uses. `fill` writes a blob stock reads back
   unchanged (round-trip verified in tests, §8).

No object data leaves the storage host — only NDJSON result lines do. This is
the core CEPH win: the expensive striper-read + checksum runs next to the OSDs,
throttled, producing results stock XrdCeph would agree with byte-for-byte.

> **Guard:** a test asserts that for a fixture file written by *stock* XrdCeph,
> the scan's `dump`/`verify` reproduce stock's stored checksum and a recompute
> over the striper-reassembled bytes — the regression that protects the
> compatibility constraint.

---

## 8. Testing (3-per-change: success + error + security-neg)

**Engine unit** (standalone, like `csi_unittest.c`):
- walk → queue → emit ordering (out-of-order worker completion still emits in
  walk order; cursor monotonic);
- each mode's per-object action against a fixture tree;
- throttle token-bucket math (`bytes_available`/refill/wait), concurrency gate,
  adaptive multiplier response to synthetic pressure/latency.

**HTTP integration** (`tests/test_scan.py`):
- `dump` manifest matches a known fixture tree (paths, sizes, stored checksums);
- `verify` flags a deliberately byte-corrupted file as `mismatch`, an
  xattr-stripped file as `missing`, and a file whose mtime was bumped after its
  checksum was recorded as `stale` (not `mismatch`); clean tree → all `ok`;
- `fill` backfills a checksum-less file and refreshes a `stale` one, second
  `dump` shows both populated with current `fmTime` (`already` on re-run);
- the `XrdCksData` blob `fill` writes is decoded back by the stock-compatible
  codec to the same name/length/value/`fmTime` (round-trip);
- `compare` flags injected missing / extra / mismatch against a manifest;
- `--resume` after an interrupted run completes the remainder exactly once
  (no dupes, no gaps).

**Security-neg:**
- non-admin token → 403;
- `path=../escape` → confined / 403;
- `parallel`/`max_rate` above operator ceiling are clamped (observed worker
  count / measured rate stays ≤ ceiling), not honored;
- `xrootd_scan off` → 404/disabled.

**CEPH (stock-parity guard):** against the single-node Ceph harness from
phase-60, a fixture file is written **by stock XrdCeph** (striper layout +
`XrdCks.adler32` blob); the scan's `dump` must reproduce stock's stored checksum
and `verify` must recompute it over the striper-reassembled bytes and report
`ok`. Same logical tree must yield NDJSON identical to the POSIX backend. Until
`sd_ceph` is striper-backed, a `verify`/`fill` request on a Ceph export must
return a clean "unsupported on this backend" error (asserted) — **never** a
wrong-bytes answer.

---

## 9. Scope boundaries (YAGNI)

- **No new `root://` opcode** this phase — engine is opcode-ready, but HTTP is
  the only transport shipped.
- **`compare` diff is client-side** — the server only streams `dump`; the
  catalog never goes to the server.
- **No scheduler / cron** inside the module — admins drive cadence with their
  own scheduler against the endpoint (or a later wrapper).
- **No mutation beyond `fill`** — the tool never deletes/quarantines a corrupt
  object; it reports. Remediation is a separate, deliberate admin action.
- **No striper work in this phase** — making `sd_ceph` libradosstriper-backed is
  phase-60's job. This spec *depends on* it for Ceph `verify`/`fill` and gates
  those modes off a non-striper Ceph driver; it does not implement it.
- **No new on-disk checksum format** — `fill` writes the stock `XrdCksData` blob
  via the existing codec; the tool stays read-compatible with stock XRootD/XrdCeph.

---

## 10. Open questions resolved during design

1. *Client tool vs server expansion?* → **Server engine + thin client** (CEPH:
   checksum next to storage).
2. *Which modes?* → **all four** (dump / verify / fill / compare).
3. *Throttle model?* → **all of** concurrency + byte-rate + adaptive + budget.
4. *Transport?* → **HTTP chunked NDJSON** (streaming + backpressure + resume +
   `curl`-debuggable; reuses dashboard auth/confinement) over a new `root://`
   opcode.
5. *Byte-compatibility with stock XrdCeph?* → **mandatory and structural** (§7):
   bytes via `obj->driver->pread` (must be `libradosstriper`-backed = phase-60
   dependency; `verify`/`fill` gated off until then), checksum via the stock
   `XrdCksData` blob in `XrdCks.<alg>` using the existing codec, with `fmTime`
   staleness honored. The scan engine adds no Ceph-specific path of its own.
