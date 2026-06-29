# Unified VFS layering — one `vfs` + `backend` core under both the nginx server and the userland clients

**Date:** 2026-06-27
**Status:** Design (approved direction) — not yet implemented
**Author:** brainstorming session (Rob Currie + Claude)

## Problem

There are two parallel VFS abstractions:

- **Server** (`src/fs/`): `xrootd_vfs_*` — the data plane. `open`→handle, `pread`/`pwrite`/`fstat`/`truncate`/`sync`/`close`, `stat`/`opendir`/`mkdir`/`rename`/`unlink`/`xattr`, staged atomic commit. nginx-coupled (`ngx_pool_t`/`ngx_log_t`/`ngx_int_t`, AIO thread-pool jobs, sendfile chains, Prometheus metrics) and **export-confined** (every open via `openat2(RESOLVE_BENEATH)` under `root_canon`).
- **Client** (`client/lib/vfs*.c`): `xrdc_vfs_*` — a transfer endpoint. URL/scheme-addressed, credential-aware, `commit`/`abort` (temp→rename / MPU-complete), io_uring, `xrdc_status`, ngx-free. Backends: posix, block, **s3 (client of S3)**.

Candidate B already unified the **lowest** layer: both now do raw byte I/O through the shared `xrootd_sd_posix_driver` (`src/fs/backend/sd.h`, ngx-free in `libxrdproto`). What remains duplicated is the **VFS shell above the driver**: the handle lifecycle and the I/O-verb wrappers exist twice.

The two shells were previously deemed un-mergeable (different runtime, reach, security model). They are — *as monoliths*. But the divergent concerns are separable, and once separated the **middle** is shareable.

## Goal

Introduce one shared, ngx-free **`vfs`** core (handle + I/O verbs over the `backend`), used directly by the clients and wrapped by a server-only **`vfs_server`** adapter:

```
        module ─▶ vfs_server ─▶ vfs ─▶ backend          (nginx server)
        client ──────────────▶ vfs ─▶ backend           (userland tools)
```

Success criteria:
1. **One VFS contract + one place to add a backend** for both trees.
2. The shared `vfs` is ngx-free (clients keep 0 `ngx_` symbols; `libxrdproto` ngx-free guard passes).
3. The server's **export confinement** and nginx machinery (thread-pool, sendfile, metrics) live *only* in `vfs_server` — never shared with the client's unconfined opens.
4. Behaviour-preserving: the full conformance suite stays green at every migration step.

Non-goals: changing the wire protocol; merging `commit`/`abort` (they legitimately differ — see below); pushing client concerns (URL/credentials/io_uring/S3-client) into the server; a single dual-purpose monolith.

## The seam: `open` is policy, the I/O verbs are mechanism

The key insight from the current code:
- `src/fs/vfs_io_core.h` already keys the I/O **job on a bare `ngx_fd_t fd`** (`xrootd_vfs_job_read_init(job, fd, offset, …)`). The byte I/O touches no nginx state — it is one step from ngx-free.
- `src/fs/vfs_open.c` applies all confinement (`rootfd` / `RESOLVE_BENEATH` / `root_canon`) when *producing* the fd. Every verb after open just acts on the fd.

Therefore the split is clean:
- **`open` (+ confinement, + nginx lifecycle) = per-side policy** → lives in `vfs_server` (confined) and in the client adapter (unconfined URL open).
- **the verbs on the resulting fd/handle (`pread`/`pwrite`/`fstat`/`truncate`/`sync`/`close`, generic `stat`/`readdir`) = shared mechanism** → the `vfs` core.

## Architecture

### `backend` — unchanged (already shared)
`src/fs/backend/sd.h` + `sd_posix.c` (+ block, + future object). Capability-typed driver vtable, ngx-free under `XRDPROTO_NO_NGX`, in `libxrdproto`. No change.

### `vfs` — new shared core (ngx-free, in `libxrdproto`)
A new home (proposed `src/fs/core/`) holding the storage-neutral handle + verbs. Plain types only; dual-build via `#ifdef XRDPROTO_NO_NGX` exactly like `sd.h`.

Interface sketch (`src/fs/core/vfs_core.h`):

```c
typedef struct {                 /* one open handle, storage-neutral */
    xrootd_sd_obj_t  obj;        /* the bound backend object (fd or driver state) */
    uint32_t         caps;       /* from the backend driver */
} xvfs_file_t;

typedef struct { off_t size; time_t mtime, ctime; mode_t mode;
                 unsigned is_dir:1, is_reg:1; } xvfs_stat_t;

/* I/O verbs — operate on an ALREADY-OPENED handle. EINTR/short-I/O loops live
 * here (the backend ops are single-syscall primitives). Plain int returns. */
ssize_t xvfs_pread (xvfs_file_t *f, void *buf, size_t n, off_t off);
ssize_t xvfs_pwrite(xvfs_file_t *f, const void *buf, size_t n, off_t off);
int     xvfs_fstat (xvfs_file_t *f, xvfs_stat_t *out);
int     xvfs_ftruncate(xvfs_file_t *f, off_t len);
int     xvfs_fsync (xvfs_file_t *f);

/* Bind an already-opened fd (from a confined OR unconfined open) to a handle. */
void    xvfs_bind_fd(xvfs_file_t *f, int fd);

/* Generic namespace read verbs over a driver instance (path already resolved by
 * the caller's policy layer): stat / readdir. */
int     xvfs_stat_at (const xrootd_sd_driver_t *drv, /*inst*/void *inst,
                      const char *path, xvfs_stat_t *out);
```

The verbs are extracted from today's `src/fs/vfs_read.c`/`vfs_write.c`/`vfs_sync.c` bodies, which are already thin loops over `obj.driver->pread/...` (the same calls Candidate B put into the client).

### `vfs_server` — server-only adapter (the de-ngx'd residue of today's `src/fs/`)
Keeps everything nginx-shaped and security-critical:
- **Export-confined open**: `vfs_open.c`'s `rootfd`/`RESOLVE_BENEATH`/`root_canon` cascade → produces a confined fd, then `xvfs_bind_fd`.
- **AIO thread-pool**: `vfs_io_core.c`'s job dispatch wraps the shared verbs on a worker thread (the job already calls the driver; it now calls `xvfs_*`).
- **sendfile chains**: builds `ngx_buf_t`/`ngx_chain_t` from the handle's fd + `read_sendfile_fd` cap.
- **metrics**, **fd_cache**, **staged commit** (`vfs_staged.c` → `compat/staged_file.c`, export-confined), **scratch**, **copy**, **rename/unlink/mkdir/xattr** (the confined namespace mutations).
- The public `xrootd_vfs_*` API the proto handlers call stays **source-compatible** (thin wrappers over `vfs` core + the confined open), so `src/read/*`, `src/write/*`, `src/webdav/*`, `src/s3/*` callers don't change.

### client adapter — thin (the de-duplicated residue of today's `client/lib/vfs*.c`)
Keeps the client-only shell over the shared `vfs`:
- **URL/scheme resolution** + backend selection (`xrdc_vfs_open(url)` → pick posix/block/s3).
- **credential store** (S3/web).
- **io_uring** ring as the read/write fast-path override (else `xvfs_pread`/`xvfs_pwrite`).
- **unconfined open** (plain `open` of the user's path) → `xvfs_bind_fd`.
- **`commit`/`abort`** (posix temp→rename, s3 MPU-complete) — see divergence below.
- The **S3-client backend** stays a client-registered `vfs` backend the server never loads.

## Deliberately NOT shared

- **`commit` / `abort`**: server = export-confined staged rename (`compat/staged_file.c`, 42 ngx tokens, `RESOLVE_BENEATH`); client = unconfined temp→rename / MPU-complete. Different security model + different finalizers. Each side keeps its own `commit` as an adapter step over the shared verbs. (The common kernel is `fsync`+`rename` — ~2 syscalls — not worth extracting.)
- **`open`**: confined (server) vs URL/unconfined (client) — per-side policy by design.
- **thread-pool / sendfile / metrics / nginx lifecycle**: server-only, in `vfs_server`.
- **URL / credentials / io_uring / S3-client backend**: client-only.

## Dual-build mechanism

Same as the existing shared units: the `vfs` core `.c` files live under `src/fs/core/`, compiled `-DXRDPROTO_NO_NGX` into `libxrdproto` (add to `shared/xrdproto/Makefile` `NAMES`/rule) **and** into the module via `./config`. The client links `libxrdproto` and includes `fs/core/vfs_core.h` via `-I$(SRC)`. The `check-ngx-free.sh` guard keeps the core honest.

## Migration order (incremental, conformance-gated)

Each wave builds module + client and runs the relevant conformance before the next.

1. **Extract `vfs` core verbs.** Create `src/fs/core/vfs_core.{c,h}` with `xvfs_bind_fd` + `pread/pwrite/fstat/ftruncate/fsync` (lifted from `vfs_read/write/sync` + the `sd` calls). Wire into both builds. Standalone round-trip/unit test. *No caller changes yet.*
2. **Server I/O onto the core.** Re-point `vfs_io_core.c` job-execute + `vfs_read/write/sync/truncate` at `xvfs_*`. Confinement/threadpool/sendfile stay in `vfs_server`. Run the full root:// + WebDAV + S3 conformance.
3. **Client I/O onto the core.** Replace `client/lib/vfs_posix.c` / `vfs_block.c` plain paths with `xvfs_*` (they already call the driver after Candidate B — this collapses them to the shared verbs and removes the duplicate handle plumbing). Keep io_uring override + commit. Run client copy conformance.
4. **Unify the handle/stat structs.** Reconcile `xrootd_vfs_file_t` / `xrdc_vfs_file` / `xvfs_file_t` to one shared struct (+ per-side extension structs for ring/temp-path/cred). Re-point both.
5. **Generic namespace reads** (`stat`, `readdir`) into the core where the logic is identical; keep confined mutations (`mkdir`/`rename`/`unlink`) in `vfs_server`.
6. **Docs**: update `src/fs/README.md` + `client/lib/vfs.h` header to describe the `module→vfs_server→vfs→backend` / `client→vfs→backend` topology.

Stop after any wave: each is independently green and valuable.

## Testing

- Standalone unit test for the `vfs` core verbs (round-trip pread/pwrite/fstat/truncate/sync over a temp fd), built plain `gcc` like `zip_dir_unittest`.
- Per-wave: module build + `libxrdproto` ngx-free guard + client build with **0 `ngx_` symbols**.
- Conformance gates: root:// read/write/pgread/pgwrite/stat (server I/O), `test_native_*` + xrdcp roundtrips (client I/O), WebDAV/S3 GET (sendfile path stays in `vfs_server`).

## Risks

- **Hot path + security-critical.** The server data plane and its export confinement must be preserved exactly. Mitigation: confinement never moves into the shared core (stays in `vfs_server.open`); migrate one verb family per wave; conformance-gate each.
- **Handle-struct reconciliation** (wave 4) touches both trees — do it last, after the verbs are proven.
- **Moderate incremental dedup over Candidate B.** The raw I/O is already shared; this wave shares the VFS *boilerplate* + gives one contract. Worth it for the architecture, not for raw LoC. (Stated plainly so scope expectations are right.)

## Outcome

One `vfs` + `backend` core, two thin policy shells (`vfs_server` confined/nginx; client unconfined/URL/cred/io_uring). A new backend (e.g. object store) is written once and is reachable from both the server data plane and the userland tools — the strategic payoff that motivated Candidate B, now with the full VFS contract shared, not just the driver.
