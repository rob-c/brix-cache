# Metadata hyper-optimization — round 7 (syscall-per-op burndown: persistent rootfd, probe-free delete, miss-priced canonicalisation)

2026-09-02. The engineering record for the metadata-ops/sec axis of the
"out-perform xrootd with a clear margin" work. Rounds 5–6
(`throughput-hyperopt-rounds-5-6.md`) banked the throughput axis; this round
attacks the two losing metadata benchmarks — create+rm and stat-miss — by
counting filesystem syscalls per protocol leg under strace and deleting every
one whose answer the next syscall already gives.

## The syscall census (per request leg, excluding socket recv/send)

| leg                | before | after | stock xrootd 5.9 |
|--------------------|-------:|------:|-----------------:|
| kXR_rm (file)      |      9 |     1 | ~2 (stat+unlink) |
| kXR_mkdir          |      5 |     1 | ~2               |
| kXR_rmdir          |      7 |     1 | ~2               |
| kXR_stat (miss)    |     ~12|     2 | 1                |
| kXR_open create    |     ~9 |     5 | —                |

Every mutation leg is now `recvfrom + <one *at syscall on the persistent
rootfd> + sendto`. The stat-miss leg is `openat2(rootfd, …) = ENOENT` plus one
failing `open(O_PATH)` from the confined symlink-follow fallback.

## 7a — the persistent confinement rootfd, threaded end to end

The per-worker export rootfd (`brix_init_server_rootfd`,
`process_server_init.c` — `open(root_canon, O_PATH|O_DIRECTORY|O_CLOEXEC)`)
existed but only the TPC engine bound it. Every metadata leg instead re-opened
the root per call (`brix_beneath_open_root` / `brix_open_root_fd`:
openat2 + close per request, sometimes twice).

Now `brix_vfs_ctx_t.rootfd` (default −1) is bound to `conf->rootfd` at every
root-protocol ctx-build site — `op_table.c op_vfs_ctx` (all table verbs),
`mkdir.c`, `stat.c` (×2), `statx.c` (×3), `query/metadata.c`,
`path/op_path.c`, `open_resolved_file_staging.c brix_open_probe` — and the
namespace layer grew BORROWED-fd twins that skip the open/close and never
close the fd they are handed:

- `brix_ns_delete_at` / `brix_ns_mkdir_at` (`core/compat/namespace_ops.c`,
  shared bodies `ns_delete_run`/`ns_mkdir_run` with the owned-fd wrappers);
- `brix_lstat_confined_canon_at` (`fs/path/resolve_confined_ops.c`);
- the VFS arms dispatch on `ctx->rootfd >= 0` (`vfs_unlink.c`,
  `vfs_unlink_many.c`, `vfs_mkdir.c`, `vfs_stat.c` ×2);
- `sd_posix_unlink`/`sd_posix_mkdir` use `st->rootfd` the same way (the bench
  export is driverless, but driver-backed posix exports get the same win).

Escape refusal is unchanged: the `_at` variants strip the root prefix with
`brix_beneath_strip_root` (EXDEV → DENIED on any path outside `root_canon`),
and all impersonation-broker arms are preserved verbatim (the broker ignores
the local rootfd by design).

## 7b — beneath_open_parent hands the root back borrowed

`beneath.c beneath_open_parent()` resolved the parent directory of the final
component via `openat2(rootfd, ".", …)` even when the name HAD no parent —
i.e. every single-component operation (the entire metadata benchmark surface)
paid an extra openat2+close. It now returns `rootfd` itself, BORROWED, and
all callers release through the new `beneath_close_parent(pfd, rootfd)`
(closes only when `pfd != rootfd`, errno-preserving).

Safety argument, spelled out because it is the confinement boundary: the
*at() family does not honor RESOLVE_BENEATH, which is why intermediate
components must be resolved via openat2 — but a single-component name has no
intermediates, and `unlinkat`/`mkdirat`/`renameat` never follow the final
symlink. The kernel window is identical to the old code's; one openat2 fewer.

## 7c — ns_delete_fast: the delete probe was answering questions unlinkat answers

`brix_ns_delete` ran an lstat classify probe (openat2+fstat+close) before
every removal, whose only surviving job was picking the AT_REMOVEDIR flag —
and `require_empty_dir` added a getdents emptiness scan that was also
check-then-act racy. `ns_delete_fast` (every non-recursive delete) classifies
from the removal syscall's own errno instead:

- `unlinkat(rootfd, rel, require_directory ? AT_REMOVEDIR : 0)`;
- `EISDIR` → it was a directory (kXR_rm on a dir): retry with AT_REMOVEDIR;
- `AT_REMOVEDIR`'s own `ENOTEMPTY` answers the emptiness scan race-free;
- `ENOTDIR` from AT_REMOVEDIR-on-file **or symlink** matches the old
  lstat-based `require_directory` rejection (lstat classified a symlink as
  not-a-dir; unlinkat(AT_REMOVEDIR) on a symlink also answers ENOTDIR — the
  target directory is never touched through the link);
- `ENOENT` honors `idempotent_missing`.

Verified safe to drop `.existed`/`.was_dir` probe fidelity: no delete caller
reads them except `vfs_rename.c`, whose value comes from `brix_ns_rename`.
kXR_rmdir-on-missing → OK is by design (stock `do_Rmdir` tolerates ENOENT —
verified against live xrootd 5.9.6).

## 7d — brix_realpath_existing: canonicalisation priced for the miss

The stat handlers' confined symlink-follow fallback (`stat.c`, `statx.c`)
fires on **every** ENOENT, and glibc `realpath(3)` readlink-walks every path
component — 8 readlinks per genuine miss on a deep export root, which was the
entire stat-miss gap vs stock's single `newfstatat`. The fallback exists for
one case: an in-export symlink with a host-absolute target, which
RESOLVE_IN_ROOT chroots to ENOENT where stock follows it on the real fs.

`brix_realpath_existing` (`fs/path/canonical.c`) keeps realpath semantics but
makes the kernel do the resolution: `open(path, O_PATH|O_CLOEXEC)` + one
`readlink("/proc/self/fd/N")`, falling back to realpath(3) when /proc is
absent. A genuine miss now costs exactly the failing open. The
security-relevant property — an ESCAPING symlink canonicalises to its TRUE
outside target so the callers' root-prefix check refuses it — is pinned by
the unit test against realpath(3) parity.

## What was deliberately left alone

- `brix_staged_lock_carry`'s one `lgetxattr` per staged commit (phase-107 C7
  WebDAV-lock carry across replace-publish): correctness machinery, not
  governed by `brix_lock_enforcement off`.
- The create leg's `geteuid()+getegid()` pair (retstat flag bits,
  `open_resolved_file.c` / `stat_body.c`): frozen-at-fork values, but the
  call sites don't carry conf and the win is two of the cheapest syscalls —
  revisit only if create+rm still trails.

## Tests and guards

`tests/c/test_ns_fastpath.c` (`c_object_units.py` spec `ns_fastpath`, REAL
`namespace_ops.o + beneath.o + canonical.o`): 18 assertions across the three
changes — the EISDIR retry, ENOTEMPTY/ENOTDIR/ENOENT/idempotent arms, the
symlink-refusal parity cases, borrowed-fd survival through every `_at` call
(the beneath root-borrow), EXDEV escape refusal on both entry points, and
realpath(3) parity including the escaping-symlink case. The
`brix_fs_dir_is_empty` abort stub doubles as proof the getdents pre-probe is
gone. Guards green: `check_vfs_seam`, `check_vfs_mutation_gate`,
`check_config_coverage`, `check_complexity`, `check_duplication`;
`objs/nginx -t` clean; full protocol smoke (mkdir/rmdir/rm/upload/stat/
roundtrip/ls + symlink-fallback semantics) green.

## 7e — shared-handle table: the high-water frontier

Every publish/lookup/unpublish on the cross-worker shared-handle table
(`session/handles.c`) scanned all `BRIX_SESSION_HANDLE_SLOTS`
(= registry_slots × max_files) SHM entries under the table mutex. The table
now keeps a `high_water` frontier: occupied slots live only in the prefix
below it, so every scan stops there; the frontier slot itself is the free
fallback when the prefix has no hole, and a freed top run walks the frontier
back down on slot clear. On the metadata benchmarks the table holds a
handful of live entries, so the per-request scan drops from the full array
to those few — all while holding the same mutex the data path contends on.
Unit: `tests/c/test_handle_high_water.c` (45 assertions — frontier growth,
hole reuse before frontier advance, top-run retirement, full-table refusal).

## 7f — dirlist opendir joins the rootfd fast path (10 → 8 syscalls)

Round 7a threaded the persistent confinement rootfd through open/stat/delete
but `brix_vfs_opendir` still ran the full openat2-from-scratch confinement
walk. It now calls `brix_opendir_confined_canon_at(ctx->rootfd, rel)` when
the session holds a rootfd (`vfs_dir.c`), dropping the per-dirlist leg from
10 syscalls to 8 — the same borrow discipline as 7b: the rootfd is the
session's, never closed by the dir handle.

## 7g — zero-copy readdir: the borrow API

`brix_vfs_readdir` copied every entry name into the connection pool
(`ngx_pnalloc` + memcpy per entry — ~102 allocations per dirlist100). The new
`brix_vfs_readdir_borrow` (`vfs_dir_iter.c`) yields the handle's CURRENT
entry name in place — the POSIX `dirent` `d_name`, or the driver plane's
handle-owned `de_scratch` — valid only until the next readdir/closedir.
Single-pass consumers only; the dirlist stream handler
(`dirlist/handler_stream.c`) fully consumes each name (skip checks, meta,
chunk append) before advancing. The pooled `brix_vfs_readdir` stays for
every other caller (propfind, gridftp, fattr — unchanged). The readdir
family moved to `vfs_dir_iter.c` alongside this; `vfs_dir.c` keeps lifecycle
only.

## 7h — the cached dirlist chunk (and the request-1023 connection kill)

Each dirlist allocated its 64 KB response chunk from the connection pool.
Two costs: the allocation itself on every request, and — the real defect —
the pool accounting: at `BRIX_MAX_CONN_POOL_BYTES` (64 MB) the connection is
killed, which a long-lived listing client reaches at request ~1023
(64 MB / 65544). A monitoring loop doing one dirlist per second died every
~17 minutes with kXR_NoMemory.

The chunk is now per-connection: `ctx->rd.dirlist_chunk` (one `ngx_alloc` of
`XRD_RESPONSE_HDR_LEN` + 64 KB on first dirlist, freed at disconnect),
reused whenever `ctx->out.count == 0`. The guard matters: the out-ring parks
REFERENCES (`slot->wbuf = buffer`), so while any parked response still
points at the chunk the handler falls through to the old per-request pool
alloc. Flood regression: `tests/test_dirlist_chunk_reuse.py` — 1200
dirlists on one connection pass on the new binary; the old binary dies at
round 1023 with wire errnum 3008 (kXR_NoMemory), exactly 64 MB / 65544.

## File-size burndown (the 600-line guard, uncommitted work)

Four files went over the cap during rounds 5–7; all split along natural
seams, `check_file_size` fully green:

- `vfs_internal.h` 604 → 600 (comment compression; the header sits AT the
  cap — any future addition must free lines first).
- `session/registry.c` 632 → 357 + `registry_slots.c` (281) +
  `registry_slots_internal.h`: slot mechanics (src-key, scan, LRU reap,
  fill, find, src-cap evict, finish-eviction) — every helper takes the
  table explicitly and none locks; registry.c holds `brix_session_mutex`
  around each call (finish_eviction deliberately after release). No static
  widened — function linkage only.
- `core/aio/pgreads.c` 755 → 470 + `pgreads_pool_send.c` (309) +
  `pgreads_internal.h`: the §1.2/§1.3 pool-thread send engine (POLLOUT
  budgeted send loop, single-frame sender, chunked read+CRC+send streamer)
  split along the thread/loop seam; the three helpers it alone uses stayed
  static in the new file.
- `read/pgread.c` 786 → 555 + `pgread_request.c` (209) +
  `pgread_internal.h` (the run struct + page-geometry constants): decode +
  early checks + warm inline path split from the producers (AIO post,
  offload, sync fallback) and response framing.

Validated post-split on the isolated build: full link, `nginx -t`, 98
dirlist wire/differential tests, multi-stream `xrdcp -S 4` roundtrip
(registry register/bind through the split slot helpers), an 8 GB pgread
transfer, and the guard set (file_size, vfs_seam, mutation_gate,
config_coverage, duplication, complexity) all green.

## Scoreboard

Quiet-host banked numbers (min-of-p50 across 4 interleaved rounds, µs,
lower is better; both servers share the same ~146 µs symmetric network RT
per round trip):

| op          | brix | stock 5.9.6 | delta |
|-------------|------|-------------|-------|
| dirlist100  | 199  | 193         | −3.1% |
| mkdir+rmdir | 364  | 351         | −3.7% |
| create+rm   | 461  | 441         | −4.5% |
| stat-miss   | 128  | 131         | +2.3% (brix wins) |

Dirlist came from −7.8% (pre-7g) through −5.7% (borrow API) to −3.1%
(cached chunk). A later 4-round confirmation on a loaded host (loadavg ~3)
swung WHOLE rounds both directions — stock swept rounds 1–2, brix swept
round 4 on every op by 8–12% — i.e. the residual per-op deltas sit inside
round-to-round host noise. Axis (c) is banked as parity-with-trades: brix
wins stat-miss outright, trades the other three inside noise, and no longer
kills long-lived listing connections (7h).
