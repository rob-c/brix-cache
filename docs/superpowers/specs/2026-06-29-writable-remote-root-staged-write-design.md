# Writable Remote `root://` Backend + Optional Staging — Design Spec

**Goal:** make a node's **primary storage backend** a remote `root://` filesystem
(another server instance), with writes handled through the **generic SD
staged-write seam** — transparent write-through by default, write-back via a local
staging directory when one is configured. "Staged write" becomes a real per-backend
capability, not a cache bolt-on.

**Date:** 2026-06-29 · **Status:** design (approved approach: generic SD staged-write)

---

## 1. Problem

`sd_xroot` (the remote `root://` SD driver) is **read-only** — built by the cache
for byte *fill* only, never a writable primary. Write-through to a remote origin
*does* exist (`xrootd_write_through`, `src/cache/writethrough_flush.c`) but it is a
**cache bolt-on**: opt-in, and it always lands writes locally first. There is no
single, generic story for "this node's storage *is* a remote `root://`, write to it
like any other backend." The transparent proxy already forwards the full *live*
metadata phase-space (verified, `tests/run_proxy_metadata_phase.sh`), so the missing
piece is specifically a **writable remote backend with a durable local-staging
option** behind the same VFS seam every other backend uses.

## 2. Goal & modes

One config selects the node's backend; the presence of a staging directory selects
the write semantics — both driven by the **same** `xrootd_vfs_staged_*` seam:

```
  xrootd_storage_backend root://host:port      ← remote primary backend
  xrootd_storage_staging /local/scratch        ← OPTIONAL local staging store

                       VFS staged-write seam (src/fs/vfs_staged.c)
            ┌──────────────────────────┴───────────────────────────┐
   NO staging store                                   staging store configured
   = transparent WRITE-THROUGH                         = WRITE-BACK
   staged_write → origin kXR_write (per chunk)         staged_write → local POSIX
   staged_commit → origin truncate+sync+close          staged_commit → PROMOTE local
   (synchronous; remote is the truth; no local copy)      object to remote origin
                                                          (async, journaled, backpressured)
```

- **Mode A — transparent write-through (default, no staging store).** The client's
  write streams straight to the remote: open-for-write on the origin, `kXR_write`
  per chunk at its offset, `truncate`+`sync`+`close` on commit. **No local copy.**
  Synchronous — the client write completes when the origin acks; the remote is the
  single source of truth (strong durability, coupled to remote availability).
- **Mode B — write-back (staging store configured).** The phase-55 *staging store*
  (local POSIX, fast, random-write capable) absorbs the write; on commit the
  finished local object is **promoted** to the remote backend by the **existing**
  async flush engine — `writethrough_flush.c` (`origin_write_chunk` loop for
  anonymous origins, fork/exec `xrdcp` for GSI/token origins) + the durable **FRM
  journal** + the **crash-safe reparented runner** (`fs/xfer/`) + watermark
  backpressure. The client write acks on local landing.

## 3. Architecture — `sd_xroot` becomes writable

Fill the write slots on the `xrootd_sd_xroot_driver` vtable, each a thin wrapper
over the **already-complete** origin write wire client (`src/cache/origin_protocol.c`):

| SD slot | wraps | notes |
|---|---|---|
| `open` (write intent) | `xrootd_cache_origin_open_write` (update+delete+mkpath) | per-open `fhandle` |
| `pwrite(obj,buf,len,off)` | `xrootd_cache_origin_write_chunk` | arbitrary offset (kXR_write) |
| `ftruncate(obj,len)` | `xrootd_cache_origin_truncate` | |
| `fsync(obj)` | `xrootd_cache_origin_sync` | |
| `close(obj)` (write) | `xrootd_cache_origin_close_file` | already partially present |
| `staged_open/write/commit/abort` | the above, sequenced | Mode-A streaming seam |
| `unlink` | `xrootd_cache_origin_delete` | namespace (best-effort) |

New cap bits advertised when writable: `CAP_RANDOM_WRITE` (kXR_write is offset-based)
+ `CAP_TRUNCATE`. **No** `CAP_FD`/`SENDFILE` (memory-served, like all object stores).

**Auth boundary (important):** the in-process wire client is **anonymous** only.
- *Anonymous* origin → true Mode-A passthrough (in-process `kXR_write`).
- *Authenticated* origin (GSI proxy / bearer) → passthrough is **not** available
  in-process; such a node must run **Mode B** (the existing fork/exec `xrdcp`
  delegation is commit-time, i.e. inherently staged). This is a documented
  constraint, surfaced as a clear config error if `storage_staging` is absent for
  an authenticated remote backend.

## 4. Config

- **`xrootd_storage_backend root://host:port`** (extended) — today the directive
  takes a driver *name* (`posix`/`block`/`pblock`); extend it to accept a `root://`
  / `roots://` URL, which builds an `sd_xroot` instance in
  `vfs_backend_registry.c` (reusing the `cache_origin_*` host/port/tls/proxy/cadir
  conf for the connection). The URL form keeps one obvious knob.
- **`xrootd_storage_staging /local/scratch`** (new, optional) — the local POSIX
  staging store. Absent ⇒ Mode A. Present ⇒ Mode B. Its own root, distinct from the
  backend (validated, like `xrootd_cache_storage_backend`).
- Reuse `xrootd_wt_*` backpressure/watermark directives for Mode B (they already
  exist and govern staging fullness → throttle/`kXR_wait`).

## 5. Mode selection & the VFS pairing

The export binds a **backend instance** (remote `sd_xroot`) and a **staging
instance** (local `sd_posix`, or = backend when no staging dir). `vfs_staged.c`
routes `staged_open/write/commit` to the **staging** instance; `staged_commit`
then promotes to the **backend** instance:

- staging == backend (Mode A): promote is a no-op — the writes already went to the
  origin; commit = origin `truncate`+`sync`+`close`.
- staging != backend (Mode B): promote = the durable flush of the committed local
  object to the remote backend (the existing engine), then the local copy is
  reclaimed per cache policy.

This is exactly the phase-55 backend/staging split, now with a **remote** backend.

## 6. Durability & failure semantics

| | Mode A (passthrough) | Mode B (write-back) |
|---|---|---|
| client write acks when | origin acks the chunk/commit | local landing |
| source of truth | the remote origin | journal until flushed, then remote |
| remote down | write fails (surfaced to client) | accumulate in staging → HIGH watermark → backpressure (`kXR_wait`/throttle) |
| crash mid-write | nothing local to lose | FRM journal replay on restart (reparented runner) |
| auth origins | n/a (requires Mode B) | fork/exec `xrdcp` delegation |

## 7. Reuse — no new transfer engine

Everything durable already exists and is reused verbatim: the origin **write wire
path**, the **FRM journal**, the **crash-safe reparented runner** (`fs/xfer/`), the
**watermark backpressure**. This change is the **seam wiring** that exposes them as
a generic writable backend, plus the `sd_xroot` write slots.

## 8. Scope / non-goals (this change)

- **In:** the write **data path** + commit (Modes A/B), `unlink`/`mkdir` to the
  remote (origin client already has delete/mkpath), the config, the matrix update.
- **Out (follow-on):** `rename` and full `xattr`/`setattr` *forwarding* to the
  remote backend (a proxied node already covers live metadata; a remote-*backed*
  node's metadata forwarding is a separate slice). Authenticated-origin in-process
  passthrough (blocked by the anonymous wire client — Mode B covers it).

## 9. Testing

`tests/run_remote_backend_write.sh` — node **O** (origin `root://`, read-write) +
node **B** (remote backend → O):
1. **Mode A** (B has no staging): `xrdcp` a file *to* B → byte-exact on O; read back
   through B matches; **no** object left in any local store on B.
2. **Mode B** (B has `storage_staging`): write to B → object appears in B's staging,
   then flushes to O (journal entry created then cleared); O byte-exact; staging
   drains.
3. **Failure:** stop O mid-Mode-B → writes accumulate + backpressure engages; restart
   O → journal replay drains to O, byte-exact.
Plus the 3-per-change unit tests on the new `sd_xroot` write slots (success / origin
error → mapped errno / write to a read-only/denied origin path).

## 10. Phased plan (each independently shippable)

1. **`sd_xroot` write slots** — ✅ **DONE.** open-write/pwrite/ftruncate/fsync wrapping
   the origin wire client; caps gain `RANDOM_WRITE|TRUNCATE`. Anonymous.
2. **Remote backend selectable** — ✅ **DONE.** `xrootd_storage_backend root://host:port`
   parses → `conf->cache_origin_*` → `xrootd_vfs_backend_config_xroot()` builds an
   `sd_xroot` primary in `vfs_backend_registry.c`; default Mode-A passthrough. Required
   teaching the kXR handle path to accept a **no-fd primary** (additive `sd_obj.driver`
   gates in `fd_table.c` + `vfs_io_core.c` — no object/remote backend had been a root://
   *primary* before; pblock always had a block-0 fd). E2E: `tests/run_remote_backend_write.sh`
   (write→origin byte-exact, no local copy, read-back, stat, multi-chunk). Regressions
   green: POSIX roundtrip, pblock, cache-xroot read.
3. **Generic staged-write passthrough** — `staged_open/write/commit/abort` on
   `sd_xroot` so `vfs_staged.c` drives Mode A uniformly (WebDAV PUT / S3 POST /
   `root://` write all "just work").
4. **Staging-store mode** — `xrootd_storage_staging` pairs local-posix staging with
   the remote backend; `staged_commit` promotes via the existing flush engine +
   journal + backpressure (Mode B). Auth-origin guard.
5. **Docs + matrix** — flip the `sd_xroot` row's write/staged cells; document the
   two modes and the auth constraint.

## 11. Global constraints (repo rules)

No `goto`; functional/modular; all data byte I/O stays below the SD seam; 3 tests
per change; new `.c` → `./config` then `rm -rf objs && ./configure && make`; docs +
tests in the same change; **operator drives git**.
