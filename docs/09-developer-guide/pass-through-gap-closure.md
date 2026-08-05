# Pass-Through Gap Closure: BriX-vs-raw-XRootD parity over a remote backend

This document is the durable decision record for the operations that failed **only
because BriX fronts a remote (`root://`) backend** — surfaced by the pure-python
`xrd` benchmark burn-down (BriX :21094 vs official xrootd :21095, 100-repeat p50).
Every gap below is now closed. Agent memory entries about this work must point
here rather than restate it, so the rationale cannot drift from the code.

## Context

BriX is an nginx stream module speaking the XRootD wire protocol. The storage
plane is `proto handler → VFS (brix_vfs_*) → storage driver`. For a `root://`
origin the driver is `sd_xroot`, and BriX **auto-composes a posix write-stage
tier** (`sd_stage`) over it: writes stage to a local temp and commit-on-close.

A benchmark comparing BriX pass-through against the same origin, accessed
directly, isolated six operations that BriX broke or could not serve. They fell
into two root-cause classes plus one backend-config gap.

## Root-cause classes

**Class A — the handler stat'd the empty LOCAL export.** `statx` and `locate`
called `brix_stat_beneath(conf->rootfd, …)` against the local export directory
(empty, since data lives on the origin) instead of routing to the backend. They
answered `kXR_NotFound` for files that exist on the origin.

**Class B — stat-by-open cannot describe a directory.** `sd_xroot_stat`
described a path by *opening* it; a directory open returns `kXR_isDirectory`
(→ `EISDIR`), so directories were undescribable. This broke `isdir` directly, and
broke `rename` (its destination-parent probe opened the parent dir → `EISDIR` →
"invalid destination path"), and would have broken `statx`/`locate` once routed.

## Fixes

### Keystone — a real origin `kXR_stat` (closes isdir, rename; enables statx, locate)

A by-name `kXR_stat` that can describe a directory, replacing stat-by-open.

- `brix_cache_origin_stat` (`src/fs/cache/origin_ns.c`) — sends the wire
  `kXR_stat` (16 zeroed option/fhandle bytes + path), parses the ASCII
  `"id size flags mtime"` reply, sets `is_dir` from the `kXR_isDir` flag bit.
- `sd_xroot_stat` / `sd_xroot_stat_cred` (`src/fs/backend/xroot/sd_xroot_io.c`)
  rewritten to use it via `sd_xroot_session()`, filling `S_IFDIR|0755` for a
  directory and `S_IFREG|0444` for a file.

### statx / locate — route through the VFS backend seam (Class A)

- `statx.c` — new `brix_statx_vfs_stat()` helper builds a `brix_vfs_ctx_t` and
  calls `brix_vfs_statf()` instead of `brix_stat_beneath()` (symlink fallback
  kept as secondary).
- `locate.c` — `locate_check_data_server` probes existence via
  `brix_vfs_ctx_init` + `brix_vfs_statf` instead of `brix_stat_beneath`.

### truncate — a path-native truncate seam that bypasses the write-stage tier

**Root cause.** The old path-based `kXR_truncate` handler opened a *write handle*
to resize. Over a remote backend that write-open is interposed by the stage tier:
it RECALLs the whole origin object to a local temp, truncates the temp, then on
close the staged commit re-opens the origin **while the write handle still holds
it** — stock xrootd refuses the concurrent write-open. The client saw
`kXR_Unsupported: Operation not supported`.

**Key insight.** The XRootD wire `kXR_truncate` has a **path form** (request
`dlen > 0` carries the path payload, `fhandle` zeroed). The origin resizes a named
object with no open handle at all — so no RECALL, no staged write-open, no
self-collision.

**Design.** A path-native `truncate_path` seam, dispatched exactly like
`rename`/`unlink` (check the bound driver advertises the slot; execute on the
namespace *leaf* so per-user `*_cred` slots are reached; the stage decorator
advertises a forwarder that passes straight to its source):

| Layer | Addition |
|:---|:---|
| Driver vtable (`src/fs/backend/sd.h`) | `truncate_path` + `truncate_path_cred` slots |
| Cred forwarder (`src/fs/backend/sd_cred_forward.h`) | `brix_sd_truncate_path_maybe_cred` |
| Origin verb (`src/fs/cache/origin_write.c`) | `brix_cache_origin_truncate_path` — wire `kXR_truncate` **path form** |
| xroot driver (`sd_xroot_ns.c`, `sd_xroot_ns_cred.c`) | `sd_xroot_truncate_path` (+ `_cred`); errno via `sd_xroot_errno` (kXR_NotFound→ENOENT) |
| Stage decorator (`src/fs/backend/stage/sd_stage.c`) | `sd_stage_truncate_path` forwards to source (mirrors `.setattr`) |
| VFS seam (`src/fs/vfs/vfs_sync.c`) | `brix_vfs_truncate_path` — leaf-dispatch with cred; **POSIX falls back** to open(O_WRITE)+ftruncate+close (prior behavior) |
| Handler (`src/protocols/root/write/truncate.c`) | path branch calls the seam instead of open+truncate+close |

This seam is the template for any future "resize / mutate-by-name over a staged
remote backend" need: use the wire op's path form, forward through the stage
decorator to the source, dispatch on the leaf for credentials.

### checksum — enable server-side checksum on the origin (backend-config gap)

Not a BriX defect: BriX edge-computes checksums (returns `adler32`), but the
benchmark's origin had no `xrootd.chksum` directive and answered
`kXR_Unsupported`, so only BriX could serve one. Enabling it on the origin makes
the *official* side work too:

```
xrootd.chksum max 4 crc32c adler32 md5
ofs.cksrdsz 64k
```

If the shipped example origin configs should default to this, that is a separate
edit to the config templates under `docs/03-configuration` / the example rig.

## Testing

Raw-socket regressions in `tests/cmdscripts/xroot_gateway_regress.py` (asserted
in `tests/test_cmd_xroot_gateway_regress.py`):

- stat of a directory reports `isDir`; stat of a file does not
- statx / locate of an existing origin file return `kXR_ok`
- mv (rename) returns ok and lands on the origin
- truncate shrinks and grows the origin file by name (both verified against the
  origin file size)

Note: this suite **skips** without a static `NGINX_BIN`. All fixes were also
verified live via the `xrd` client (truncate shrink/grow land on the origin;
missing→`NotFound`, read-only→`NotAuthorized`; checksum bilateral).

## Operational gotcha — never `kill -HUP` to swap the test gateway `.so`

On the `:21094` test gateway, swapping the freshly-built `.so` and sending the
nginx master a `kill -HUP` (reconfigure) killed the master mid-reconfigure.
**Restart the instance fresh instead of HUP-reloading it** when the module binary
has changed.

## Result and next step

All five pass-through gaps (statx, isdir, locate, rename, truncate) are closed and
checksum is bilateral. What remains is **latency, not correctness**: proxied
metadata ops pay 6–10× because every op does a cold TCP connect + full XRootD
login (no origin connection pool, no metadata cache). The `<1.5×` overhead plan is
P1 origin connection pool → P2 inline `dstat` dirlist → P3 short-TTL stat cache →
P4 pipelined statx / coalesced readv → P5 cut-through data path. See
[feature-gap-analysis.md](feature-gap-analysis.md) for the broader backlog.
