# pblock privilege-drop hardening — blobs and `catalog.db` are never root-owned

> **Audience:** developers touching the `pblock` storage backend or its tier/VFS wiring.
> **Scope:** the worker-gated off-root privilege drop that guarantees `pblock`
> on-disk state (blob files, block dirs, the SQLite `catalog.db`) is never created
> as `root`, and the master-must-not-drop gotcha that governs where the drop is armed.
> **Companion docs:** [`pblock-storage-backend.md`](pblock-storage-backend.md),
> [`deployment-hardening.md`](deployment-hardening.md).

---

## Context

`pblock` (`src/fs/backend/pblock/`) is a POSIX drop-in that stores bulk content as
striped block files (`0600`), inside block directories (`0700`), and keeps the
entire logical namespace + metadata in one SQLite `catalog.db`. Unlike the POSIX
backends fronted by an impersonation broker, **`pblock` writes all of that on-disk
state as the worker process's own uid and never `chown`s** — per-principal
ownership in `pblock` is *synthetic*, recorded only inside the catalog (the `uid`/
`gid` columns), not reflected on the host filesystem.

That design has a sharp edge: if the nginx worker runs as **root** (an explicit
`user root;`, or any configuration that fails to drop privilege), every blob,
block directory, and the catalog DB would be created **root-owned** — a
privilege-escalation foothold that lets a client's uploaded data land on disk as
root. The hardening described here closes that hole independently of the `user`
directive.

## The privilege-drop model

The backstop is `brix_pblock_drop_privilege()` in
`src/fs/backend/pblock/sd_pblock_lifecycle.c`. Key properties:

- **ngx-free by design.** The file is shared with the standalone unit test, so it
  cannot call `ngx_log_*`. It uses libc `getpwnam` / `setgroups` / `setgid` /
  `setuid` and emits diagnostics via `fprintf(stderr, …)`, which nginx redirects
  into the worker `error_log`.
- **Called first, before any mkdir.** It runs at the top of `sd_pblock_init()`
  (same file) **before** the `pblock_mkdir_p` that creates on-disk state, and only
  when `conf->enforce_unprivileged` is set. If the drop is impossible it returns
  `-1` and `sd_pblock_init` **fails closed** (`errno = EPERM`, `NGX_ERROR` → the
  request 5xx's and no file is created).
- **Self-gating / idempotent no-op for the normal case.** The function returns `0`
  immediately when `geteuid() != 0`. So for the default `nobody` worker — and for
  every existing `pblock` test, and the impersonation-`map` service-account case —
  it does nothing. It only fires for a real root worker. Because a non-root worker
  never reaches the drop, the first drop also makes every later call in that worker
  short-circuit.
- **Drops to an unprivileged account.** It resolves `want_user` (falling back to
  `"nobody"`), **refuses a uid-0 or gid-0 target**, then performs
  `setgroups({gid})` → `setgid` → `setuid` permanently (real+eff+saved), re-reads
  `getuid`/`geteuid`, and **fails closed if either is still 0** (the drop "did not
  stick").
- **Account override.** The chosen account comes from `conf->unpriv_user`, which is
  NULL-defaulting to `"nobody"`. This is the standard nginx `user <acct>;` account;
  no new directive was added — `unpriv_user` is a NULL-defaulting fallback
  extension point.

Config fields live on `brix_sd_pblock_conf_t` in `src/fs/backend/sd_registry.h`:

```c
const char *unpriv_user;             /* root-worker fallback; NULL/"" ⇒ "nobody" */
unsigned    enforce_unprivileged:1;  /* worker build ⇒ drop off root pre-write */
```

`PBLOCK_DEFAULT_BLOCK_SIZE` is `64 MiB` (`src/fs/backend/pblock/sd_pblock_catalog.h`).
`pblock` **already stripes by default** — objects larger than `block_size` split
into `<blob_id>/0,1,2,…` — so striping ownership stays with the drop account and
required no change here.

## The master-must-not-drop gotcha

Not every `pblock` instance may drop, and the difference is **which process builds
the backend**:

- **Cache/stage pblock tiers** (`brix_cache_store pblock:`, `brix_stage_store
  pblock:`) are built **at config/startup time in the master (root)** for
  validation, **not** lazily. Dropping *there* would strip the master of the
  privilege it needs to open logs and fork workers. The symptom is a startup
  `nginx: [emerg] open() ".../logs/e.log" failed (13: Permission denied)`.
- **The PRIMARY pblock backend** (`brix_storage_backend pblock://`, the user PUT
  target) is built **per-worker** at request time — this is what actually creates
  the on-disk data, so it must drop.

The two production call sites therefore gate on the process type:

```c
conf.enforce_unprivileged = (ngx_process == NGX_PROCESS_WORKER);
```

- `src/fs/tier/tier_build.c` (`tier_build_pblock`)
- `src/fs/vfs/vfs_backend_registry_source.c` (`brix_vbr_build_pblock`)

The standalone unit tests leave the whole conf zero-initialized
(`brix_sd_pblock_conf_t conf = {0};` in
`src/fs/backend/pblock/sd_pblock_unittest.c` and
`sd_pblock_unittest_lab.c`), so `enforce_unprivileged` is 0 and the test never
drops.

## Files

| File | Role |
| --- | --- |
| `src/fs/backend/sd_registry.h` | `brix_sd_pblock_conf_t` — `unpriv_user`, `enforce_unprivileged` fields |
| `src/fs/backend/pblock/sd_pblock_lifecycle.c` | `brix_pblock_drop_privilege()` + the guarded call in `sd_pblock_init()` |
| `src/fs/backend/pblock/sd_pblock_catalog.h` | `PBLOCK_DEFAULT_BLOCK_SIZE` (64 MiB) |
| `src/fs/tier/tier_build.c` | cache/stage tier build — worker-gated `enforce_unprivileged` |
| `src/fs/vfs/vfs_backend_registry_source.c` | primary backend build — worker-gated `enforce_unprivileged` |
| `src/fs/backend/pblock/sd_pblock_unittest.c`, `sd_pblock_unittest_lab.c` | zero-init conf so the standalone tests never drop |
| `tests/test_pblock_privilege_drop.py` | root-only suite: root worker → `nobody` blobs/DB, striping stays `nobody`, fail-closed |

## Why

`pblock` has no impersonation broker and never chowns, so the only defence against
root-owned client data is to guarantee the *writing process itself* is
unprivileged before it touches disk. Doing that inside `sd_pblock_init` — fail-
closed, self-gating on `geteuid`, gated to workers via `enforce_unprivileged` —
makes the guarantee hold regardless of the operator's `user` directive, while
leaving the master (which must stay privileged to open logs and fork workers)
untouched.

## Testing & deployment notes

- Tests: `tests/test_pblock_privilege_drop.py` is root-only (it needs a real root
  worker to exercise the drop) and is a sibling of the
  [[gridmap-ownership-root-suite]] host-root suite. It asserts a root worker's
  blobs/DB end up `nobody`-owned, striping stays `nobody`, and the backend fails
  closed when it cannot drop.
- Deployment: the export path and the client body temp dir must be writable by the
  drop account — the same constraint as any unprivileged nginx worker. The
  registry harness `chmod`s the export `0777` as root; raw configs must provision
  it.
- The `cache_pblock_*` cmdscript tests are pre-existing-red on the root box
  (a `nobody` worker against a root-owned export with no chmod). An A/B check
  (disabling the drop fails identically) confirms this hardening is **not** the
  cause.
