# Backend Storage Metrics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Backend Storage dashboard panel + per-backend byte-I/O counters on both the dashboard snapshot and Prometheus `/metrics`, per spec `docs/superpowers/specs/2026-07-03-dashboard-backend-storage-metrics-design.md`.

**Architecture:** A bounded backend-id enum generated from `src/core/types/fs_list.h` indexes two new SHM counter arrays; bytes are attributed at three existing chokepoints (VFS observe helper, `xrootd_vfs_io_execute`, shared HTTP `serve_file_ranged`). Export identity/capacity comes from the existing VFS backend registry (extended to register default-POSIX exports), surfaced via `writer.c` Prometheus families and a new `dashboard_fill_storage()` snapshot section + panel.

**Tech Stack:** C (nginx module), jansson (dashboard JSON), pytest (integration), standalone gcc C unit test.

## Global Constraints

- **NO `goto`** anywhere; early-return + helper decomposition (CLAUDE.md HARD BLOCK).
- Functional/modular: one job per function, explicit data flow, no new globals beyond the X-macro-generated static tables.
- Coding standard: `docs/09-developer-guide/coding-standards.md` — WHAT/WHY/HOW doc blocks on every new function.
- Metric labels low-cardinality only (INVARIANT #8) — backend names come from the fixed `fs_list.h` census.
- Alloc: `ngx_palloc(r->pool, …)` in HTTP context; jansson objects use `json_object_set_new` (ownership transfer) exactly like the surrounding code.
- New source file ⇒ edit repo-root `./config` AND full rebuild: `cd /tmp/nginx-1.28.3 && rm -rf objs && ./configure --with-stream --with-stream_ssl_module --with-http_ssl_module --with-http_dav_module --with-threads --add-module=/home/rcurrie/HEP-x/nginx-xrootd && make -j$(nproc)` (configure over stale objs ⇒ mixed-ABI garbage — memory-documented gotcha). Tasks 2+ without new files use incremental `make -j$(nproc)` from `/tmp/nginx-1.28.3`.
- SHM layout changes (Task 2) require restarting any running test fleet, not reload.
- Commit to `main` directly after each task (Rob's no-branches rule). NEVER run destructive git commands.
- Working tree has unrelated uncommitted changes — `git add` ONLY the files each task names, never `git add -A`.

---

### Task 1: Backend-id enum surface (`xrootd_fs_id_t`)

**Files:**
- Modify: `src/core/types/fs_list.h` (append enum + decls before the final `#endif`)
- Create: `src/fs/backend/sd_fs_id.c`
- Modify: `./config` (add the new source file)
- Create: `tests/test_fs_id_map.c` (standalone unit test)

**Interfaces:**
- Produces: `typedef enum {... XROOTD_FS_ID_COUNT} xrootd_fs_id_t;` (in `fs_list.h`), `const char *xrootd_fs_id_name(int id);`, `int xrootd_fs_id_from_name(const char *name);` — used by Tasks 2, 4, 5.

- [ ] **Step 1: Write the failing unit test**

Create `tests/test_fs_id_map.c`:

```c
/*
 * test_fs_id_map.c — standalone unit test for the fs_list.h backend-id surface
 * (xrootd_fs_id_from_name / xrootd_fs_id_name).
 *
 * Build+run (no nginx tree needed — sd_fs_id.c is ngx-free):
 *   gcc -I src -o /tmp/test_fs_id_map tests/test_fs_id_map.c src/fs/backend/sd_fs_id.c && /tmp/test_fs_id_map
 */
#include <stdio.h>
#include <string.h>

#include "core/types/fs_list.h"

static int failures = 0;

static void
check(int cond, const char *what)
{
    if (cond) {
        printf("  ok   %s\n", what);
    } else {
        printf("  FAIL %s\n", what);
        failures++;
    }
}

int
main(void)
{
    int  id;
    char label[64];

    /* Roundtrip every census row: name -> id -> name. */
    for (id = 0; id < XROOTD_FS_ID_COUNT; id++) {
        const char *name = xrootd_fs_id_name(id);

        snprintf(label, sizeof(label), "row %d roundtrip (%s)", id, name);
        check(name != NULL && name[0] != '\0'
              && xrootd_fs_id_from_name(name) == id, label);
    }

    /* Known anchors present in every build. */
    check(xrootd_fs_id_from_name("posix") >= 0, "posix registered");
    check(xrootd_fs_id_from_name("cache") >= 0, "cache decorator registered");
    check(xrootd_fs_id_from_name("xroot") >= 0, "xroot origin registered");

    /* Negatives: unknown / NULL / out-of-range id. */
    check(xrootd_fs_id_from_name("nosuchfs") == -1, "unknown name -> -1");
    check(xrootd_fs_id_from_name(NULL) == -1, "NULL name -> -1");
    check(strcmp(xrootd_fs_id_name(-1), "?") == 0, "id -1 -> \"?\"");
    check(strcmp(xrootd_fs_id_name(XROOTD_FS_ID_COUNT), "?") == 0,
          "id COUNT -> \"?\"");

    printf(failures == 0 ? "ALL PASS\n" : "%d FAILURES\n", failures);
    return failures == 0 ? 0 : 1;
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `gcc -I src -o /tmp/test_fs_id_map tests/test_fs_id_map.c src/fs/backend/sd_fs_id.c && /tmp/test_fs_id_map`
Expected: FAIL — `sd_fs_id.c: No such file or directory` (and `XROOTD_FS_ID_COUNT` undeclared).

- [ ] **Step 3: Add the enum + decls to fs_list.h**

In `src/core/types/fs_list.h`, insert immediately BEFORE the final `#endif /* XROOTD_FS_LIST_H */` (after the `XROOTD_FS_SCHEME_LIST` block):

```c
/* ---- backend identity enum (activates the reserved ID column) ------------
 * One id per census row, generated from the same gated lists — a build
 * without CEPH/SQLITE simply has a smaller XROOTD_FS_ID_COUNT. Consumers:
 * the per-backend SHM byte counters (observability/metrics/metrics.h) index
 * by these ids; the exporters label by xrootd_fs_id_name(). The gate macros
 * are global -D CFLAGS (repo ./config), so every server TU agrees on
 * XROOTD_FS_ID_COUNT and the SHM layout stays consistent within a build. */
typedef enum {
#define XROOTD_FS_ROW_ENUM_ID(ID, sym, name, kind) XROOTD_FS_ID_##ID,
    XROOTD_FS_DRIVER_LIST(XROOTD_FS_ROW_ENUM_ID)
#undef XROOTD_FS_ROW_ENUM_ID
    XROOTD_FS_ID_COUNT
} xrootd_fs_id_t;

/* Name <-> id lookups over the census (fs/backend/sd_fs_id.c — ngx-free,
 * no driver externs, unit-testable standalone).
 * xrootd_fs_id_name: bounded label for exporters; "?" for out-of-range.
 * xrootd_fs_id_from_name: exact-match scan; -1 for NULL/unknown. */
const char *xrootd_fs_id_name(int id);
int xrootd_fs_id_from_name(const char *name);
```

- [ ] **Step 4: Create sd_fs_id.c**

Create `src/fs/backend/sd_fs_id.c`:

```c
/*
 * sd_fs_id.c — the census-backed backend-id lookups.
 *
 * WHAT: Implements xrootd_fs_id_name() / xrootd_fs_id_from_name(), the
 *       name<->xrootd_fs_id_t mapping generated from the central filesystem
 *       declaration (core/types/fs_list.h).
 * WHY:  The per-backend SHM byte counters index by a bounded enum; attribution
 *       sites hold a driver NAME (obj->driver->name / sd_backend_name), so one
 *       shared, generated map keeps the label set closed (INVARIANT #8) and
 *       adding a filesystem in fs_list.h extends it for free.
 * HOW:  An X-macro-expanded names[] array parallel to the enum. Kept ngx-free
 *       and free of driver externs so it links standalone (unit test) and adds
 *       zero coupling; the <=13-entry strcmp scan runs once per COMPLETED I/O
 *       op, which is noise against the syscall it accounts.
 */
#include <string.h>

#include "core/types/fs_list.h"

static const char *const xrootd_fs_id_names[] = {
#define XROOTD_FS_ROW_NAME(ID, sym, name, kind) name,
    XROOTD_FS_DRIVER_LIST(XROOTD_FS_ROW_NAME)
#undef XROOTD_FS_ROW_NAME
};

/* The census label for id ("posix", "pblock", ...); "?" when out of range. */
const char *
xrootd_fs_id_name(int id)
{
    if (id < 0 || id >= XROOTD_FS_ID_COUNT) {
        return "?";
    }
    return xrootd_fs_id_names[id];
}

/* Exact-match name -> id over the census; -1 for NULL or unknown names. */
int
xrootd_fs_id_from_name(const char *name)
{
    int id;

    if (name == NULL || name[0] == '\0') {
        return -1;
    }
    for (id = 0; id < XROOTD_FS_ID_COUNT; id++) {
        if (strcmp(xrootd_fs_id_names[id], name) == 0) {
            return id;
        }
    }
    return -1;
}
```

- [ ] **Step 5: Run unit test to verify it passes**

Run: `gcc -I src -o /tmp/test_fs_id_map tests/test_fs_id_map.c src/fs/backend/sd_fs_id.c && /tmp/test_fs_id_map`
Expected: `ALL PASS`, exit 0. (Note: standalone build has no `-DXROOTD_HAVE_*`, so only the 8 CORE rows enumerate — that's expected and correct.)

- [ ] **Step 6: Register the file in ./config**

In repo-root `./config`, find the line containing `src/fs/backend/sd_registry.c` inside `ngx_module_srcs` (grep for it) and add on the adjacent line, same continuation style:

```
                $ngx_addon_dir/src/fs/backend/sd_fs_id.c \
```

Also add `$ngx_addon_dir/src/core/types/fs_list.h` to the header deps list ONLY if it is not already there (grep first — it likely is, via sd_registry).

- [ ] **Step 7: Full rebuild (new source file)**

```bash
cd /tmp/nginx-1.28.3 && rm -rf objs && ./configure --with-stream --with-stream_ssl_module --with-http_ssl_module --with-http_dav_module --with-threads --add-module=/home/rcurrie/HEP-x/nginx-xrootd && make -j$(nproc)
```
Expected: exit 0 (this is a ~762-object rebuild; -Werror is on — any warning fails).

- [ ] **Step 8: Commit**

```bash
cd /home/rcurrie/HEP-x/nginx-xrootd && git add src/core/types/fs_list.h src/fs/backend/sd_fs_id.c config tests/test_fs_id_map.c && git commit -m "feat(fs): xrootd_fs_id_t — census-generated backend identity enum + name map"
```

---

### Task 2: Per-backend SHM byte counters + attribution at the three seams

**Files:**
- Modify: `src/observability/metrics/metrics.h` (unified struct, next to `io_bytes_read[XROOTD_PROTO_COUNT]` ~line 663)
- Modify: `src/observability/metrics/unified.h` (declaration, next to `xrootd_metric_op_done` ~line 125)
- Modify: `src/observability/metrics/unified.c` (implementation, next to `xrootd_metric_op_done` ~line 211)
- Modify: `src/fs/vfs/vfs_internal.h` (`xrootd_vfs_observe_ctx_op`, ~line 323)
- Modify: `src/fs/vfs/vfs_io_core.c` (`xrootd_vfs_io_execute`, ~line 689; header comment ~line 7)
- Modify: `src/fs/vfs/vfs.h` (new accessor decl, next to `xrootd_vfs_file_sendfile_fd` ~line 164)
- Modify: `src/fs/vfs/vfs_open.c` (accessor impl, next to `xrootd_vfs_file_sendfile_fd` ~line 612)
- Modify: `src/protocols/shared/file_serve.c` (three `bytes_sent` sites: ~lines 229, 280, 315)

**Interfaces:**
- Consumes: `xrootd_fs_id_from_name()` (Task 1).
- Produces: `void xrootd_metric_backend_bytes(const char *backend_name, xrootd_metric_op_t op, size_t bytes);` and `const char *xrootd_vfs_file_backend_name(const xrootd_vfs_file_t *fh);` plus SHM arrays `shm->unified.io_bytes_read_backend[XROOTD_FS_ID_COUNT]` / `io_bytes_written_backend[…]` — read by Tasks 4 and 5.

- [ ] **Step 1: Add the SHM arrays**

In `src/observability/metrics/metrics.h`, add `#include "core/types/fs_list.h"` next to the file's existing includes (top of file; check it isn't already included), then inside the unified `typedef struct` directly after the `io_bytes_written[XROOTD_PROTO_COUNT];` line:

```c
    /* Per-BACKEND byte totals (storage plane): bytes the storage-driver
     * instance moved, attributed at the VFS observe chokepoint (staged-commit
     * writes), xrootd_vfs_io_execute (root:// data plane), and the shared HTTP
     * serve helper (sendfile/memory/compressed GET). Indexed by the census
     * enum xrootd_fs_id_t (core/types/fs_list.h) — bounded, INVARIANT #8. A
     * staged upload counts into BOTH the stage store and the final backend at
     * promote: the semantic is bytes each backend performed, not client bytes. */
    ngx_atomic_t  io_bytes_read_backend[XROOTD_FS_ID_COUNT];
    ngx_atomic_t  io_bytes_written_backend[XROOTD_FS_ID_COUNT];
```

- [ ] **Step 2: Declare + implement the accounting helper**

In `src/observability/metrics/unified.h`, after the `xrootd_metric_op_done` declaration:

```c
/*
 * xrootd_metric_backend_bytes — add a completed data op's byte count to the
 * per-backend storage totals (io_bytes_{read,written}_backend). backend_name
 * is the storage driver's census name (fs_list.h); NULL ⇒ "posix" (the
 * default-instance convention everywhere in the VFS). Pure lock-free SHM
 * atomics — safe from thread-pool workers (no pools, logs, or request state).
 * No-ops on unknown names, non-READ/WRITE ops, zero bytes, or missing SHM.
 */
void xrootd_metric_backend_bytes(const char *backend_name,
    xrootd_metric_op_t op, size_t bytes);
```

In `src/observability/metrics/unified.c`, add `#include "core/types/fs_list.h"` beside the existing includes, and after `xrootd_metric_op_done`'s body:

```c
void
xrootd_metric_backend_bytes(const char *backend_name, xrootd_metric_op_t op,
    size_t bytes)
{
    ngx_xrootd_metrics_t *shm;
    int                   id;

    if (bytes == 0
        || (op != XROOTD_METRIC_OP_READ && op != XROOTD_METRIC_OP_WRITE))
    {
        return;
    }

    id = xrootd_fs_id_from_name(backend_name != NULL ? backend_name : "posix");
    if (id < 0) {
        return;
    }

    shm = xrootd_metrics_shared();
    if (shm == NULL) {
        return;
    }

    if (op == XROOTD_METRIC_OP_READ) {
        XROOTD_ATOMIC_ADD(&shm->unified.io_bytes_read_backend[id], bytes);
    } else {
        XROOTD_ATOMIC_ADD(&shm->unified.io_bytes_written_backend[id], bytes);
    }
}
```

- [ ] **Step 3: Seam (a) — observe chokepoint**

In `src/fs/vfs/vfs_internal.h`, inside `xrootd_vfs_observe_ctx_op`, directly after the `xrootd_metric_op_done(...)` call:

```c
    /* Per-backend storage byte totals (staged-commit writes, VFS-metered
     * reads). ctx->sd == NULL is the default-POSIX instance. */
    if (rc == NGX_OK && bytes > 0) {
        xrootd_metric_backend_bytes(
            ctx != NULL && ctx->sd != NULL ? xrootd_sd_backend_name(ctx->sd)
                                           : "posix",
            op, bytes);
    }
```

(`vfs_internal.h` already reaches `xrootd_metric_op_done` and `ctx->sd->driver`, so the needed headers are present; verify `xrootd_sd_backend_name` resolves — it is declared in `fs/backend/sd.h`, included via the vfs headers. If not, add the include to `vfs_internal.h`.)

- [ ] **Step 4: Seam (b) — root:// data plane in io_execute**

In `src/fs/vfs/vfs_io_core.c`:

(1) Extend the file's HOW comment (top block) with one line:

```
 *       Deliberate exception to "no metrics": xrootd_vfs_io_execute feeds the
 *       per-backend SHM byte totals via xrootd_metric_backend_bytes — pure
 *       lock-free atomics, POD-safe from thread-pool workers.
```

(2) Add `#include "observability/metrics/unified.h"` beside the existing includes.

(3) Add a small helper above `xrootd_vfs_io_execute` and rework the dispatcher's `return`s into `break`s so attribution runs post-switch:

```c
/* xrootd_vfs_io_account — post-op per-backend byte attribution: map the job's
 * op to a read/write direction and add job->nio bytes to the backend totals.
 * The job's obj names the bound driver; NULL ⇒ default POSIX. READV totals
 * attribute to the job's primary obj (segments could in principle span
 * handles — a bounded, deliberate approximation). Non-data ops no-op. */
static void
xrootd_vfs_io_account(const xrootd_vfs_job_t *job)
{
    xrootd_metric_op_t dir;

    if (job->nio <= 0) {
        return;
    }

    switch (job->op) {
    case XROOTD_VFS_IO_READ:
    case XROOTD_VFS_IO_PGREAD:
    case XROOTD_VFS_IO_READV:
        dir = XROOTD_METRIC_OP_READ;
        break;
    case XROOTD_VFS_IO_WRITE:
    case XROOTD_VFS_IO_WRITEV:
        dir = XROOTD_METRIC_OP_WRITE;
        break;
    default:
        return;
    }

    xrootd_metric_backend_bytes(
        job->obj.driver != NULL ? job->obj.driver->name : "posix",
        dir, (size_t) job->nio);
}
```

And in `xrootd_vfs_io_execute`, change each `case` from `xrootd_vfs_io_execute_X(job); return;` to `xrootd_vfs_io_execute_X(job); break;`, keep the trailing unknown-op `job->nio = -1; job->io_errno = EINVAL;` guarded so it only fires for unknown ops, and call the helper once at the end:

```c
void
xrootd_vfs_io_execute(xrootd_vfs_job_t *job)
{
    if (job == NULL) {
        return;
    }

    xrootd_vfs_io_reset_outputs(job);

    switch (job->op) {
    case XROOTD_VFS_IO_READ:     xrootd_vfs_io_execute_read(job);     break;
    case XROOTD_VFS_IO_WRITE:    xrootd_vfs_io_execute_write(job);    break;
    case XROOTD_VFS_IO_PGREAD:   xrootd_vfs_io_execute_pgread(job);   break;
    case XROOTD_VFS_IO_READV:    xrootd_vfs_io_execute_readv(job);    break;
    case XROOTD_VFS_IO_WRITEV:   xrootd_vfs_io_execute_writev(job);   break;
    case XROOTD_VFS_IO_SYNC:     xrootd_vfs_io_execute_sync(job);     break;
    case XROOTD_VFS_IO_TRUNCATE: xrootd_vfs_io_execute_truncate(job); break;
    case XROOTD_VFS_IO_OPENDIR:  xrootd_vfs_io_execute_opendir(job);  break;
    default:
        job->nio = -1;
        job->io_errno = EINVAL;
        return;
    }

    xrootd_vfs_io_account(job);
}
```

(Preserve the file's exact existing case body style if it differs — the semantic change is `return`→`break` + one post-switch call.)

- [ ] **Step 5: Seam (c) — shared HTTP serve helper + the fh accessor**

(1) In `src/fs/vfs/vfs.h`, next to the `xrootd_vfs_file_sendfile_fd` declaration:

```c
/* The census name of the backend serving this handle ("posix" for the default
 * instance or a NULL handle) — for per-backend byte attribution at serve time. */
const char *xrootd_vfs_file_backend_name(const xrootd_vfs_file_t *fh);
```

(2) In `src/fs/vfs/vfs_open.c`, next to `xrootd_vfs_file_sendfile_fd`:

```c
const char *
xrootd_vfs_file_backend_name(const xrootd_vfs_file_t *fh)
{
    if (fh == NULL || fh->ctx == NULL || fh->ctx->sd == NULL) {
        return "posix";
    }
    return xrootd_sd_backend_name(fh->ctx->sd);
}
```

(Check `vfs_open.c` includes `fs/backend/sd.h` — it uses driver vtables, so it does.)

(3) In `src/protocols/shared/file_serve.c`: add `#include "observability/metrics/unified.h"` (and `fs/vfs/vfs.h` is already included). At the TOP of `xrootd_http_serve_file_ranged`, right after the `ngx_memzero(result, sizeof(*result));`, capture the name while `fh` is alive:

```c
    /* Backend attribution label — captured now because every send path below
     * releases the vfs handle before the bytes are counted. */
    const char *backend_name = xrootd_vfs_file_backend_name(fh);
```

Then at each of the three `result->bytes_sent = …;` sites, add directly after:

- compressed site (`result->bytes_sent = bytes_out;`):
```c
            xrootd_metric_backend_bytes(backend_name, XROOTD_METRIC_OP_READ,
                                        (size_t) bytes_out);
```
- memory-backed site (`result->bytes_sent = send_len;` inside the `fd == NGX_INVALID_FILE` branch):
```c
            xrootd_metric_backend_bytes(backend_name, XROOTD_METRIC_OP_READ,
                                        (size_t) send_len);
```
- sendfile site (final `result->bytes_sent = send_len;`):
```c
    xrootd_metric_backend_bytes(backend_name, XROOTD_METRIC_OP_READ,
                                (size_t) send_len);
```

(HEAD requests never reach these sites (`r->header_only` early-returns) — zero-byte no-op guard in the helper covers the rest.)

- [ ] **Step 6: Build**

Run: `cd /tmp/nginx-1.28.3 && make -j$(nproc)`
Expected: exit 0, no warnings (-Werror). SHM struct grew — any RUNNING fleet must be fully restarted before integration tests (`tests/manage_test_servers.sh restart` if one is up).

- [ ] **Step 7: Commit**

```bash
cd /home/rcurrie/HEP-x/nginx-xrootd && git add src/observability/metrics/metrics.h src/observability/metrics/unified.h src/observability/metrics/unified.c src/fs/vfs/vfs_internal.h src/fs/vfs/vfs_io_core.c src/fs/vfs/vfs.h src/fs/vfs/vfs_open.c src/protocols/shared/file_serve.c && git commit -m "feat(metrics): per-backend storage byte totals — three-seam attribution (observe/io_execute/http-serve)"
```

(Counters are intentionally not yet exported — Task 3 surfaces them; the integration test lands in Task 5.)

---

### Task 3: Register default-POSIX exports + Prometheus storage families

**Files:**
- Modify: `src/fs/vfs/vfs_backend_config.c` (`xrootd_vfs_backend_config_str`, ~line 401)
- Modify: `src/observability/metrics/writer.c` (`xrootd_storage_backend_metrics_emit`, ~line 237)
- Test: extend `tests/run_storage_backend_metrics.sh` expectations only if it fails (it must keep passing).

**Interfaces:**
- Consumes: `xrootd_fs_id_from_name`/`xrootd_fs_id_name` (Task 1), SHM arrays (Task 2), existing `xrootd_vfs_backend_export_count/info`, `xrootd_fs_usage_stat` (`core/compat/fs_usage.h`), `xrootd_metrics_shared()`.
- Produces: default-posix exports visible in the registry (dashboard `/vfs`, info gauge, Task 4's fill); `/metrics` families `xrootd_storage_io_bytes_read/written{backend=}` and `xrootd_storage_bytes_total/used/available` + `xrootd_storage_occupancy_ratio{export=,backend=}`.

- [ ] **Step 1: Close the default-POSIX census gap**

In `src/fs/vfs/vfs_backend_config.c`, in `xrootd_vfs_backend_config_str`, directly after the `if (sb == NULL) { return NGX_OK; }` guard:

```c
    /* An export that names NO backend is the default-POSIX case. Phase-68 made
     * an EXPLICIT "posix" register; register the default too so the census
     * surfaces (dashboard /vfs + storage panel, /metrics info + capacity
     * gauges) see the most common configuration. Guard root_canon "/": a pure
     * cache node's namespace anchor is the whole host fs — never a census row. */
    if (sb->len == 0) {
        if (root_canon != NULL && root_canon[0] == '/'
            && root_canon[1] != '\0')
        {
            static const ngx_str_t posix_name = ngx_string("posix");

            xrootd_vfs_backend_config(root_canon, &posix_name, block_size);
        }
        return NGX_OK;
    }
```

Also grep for OTHER callers of `xrootd_vfs_backend_config_str` (`grep -rn "vfs_backend_config_str" src/ --include=*.c`) — expect `src/core/config/runtime_server.c` (stream) and `src/protocols/webdav/config.c` (HTTP). Check whether S3 exports register through the webdav shared merge or their own path; if S3 has a separate merge that never calls `config_str`, note it in the commit message (S3 exports stay invisible until they name a backend — pre-existing behavior, unchanged).

- [ ] **Step 2: Extend the Prometheus emit**

In `src/observability/metrics/writer.c`: add includes `#include "core/types/fs_list.h"` and `#include "core/compat/fs_usage.h"` (grep first; `metrics_internal.h` for `xrootd_metrics_shared` should already be reachable — verify).

Extend `xrootd_storage_backend_metrics_emit` — after the existing info-gauge loop, still inside the function:

```c
    /* Per-export capacity (live statvfs) for LOCAL backends. Remote/origin
     * backends (xroot/http/s3/ceph...) have no local filesystem behind
     * root_canon — emitting statvfs there would report the wrong volume. */
    mw_printf(mw,
        "# HELP xrootd_storage_bytes_total Backend export filesystem size in bytes (local backends).\n"
        "# TYPE xrootd_storage_bytes_total gauge\n"
        "# HELP xrootd_storage_bytes_used Backend export filesystem bytes used.\n"
        "# TYPE xrootd_storage_bytes_used gauge\n"
        "# HELP xrootd_storage_bytes_available Backend export filesystem bytes available.\n"
        "# TYPE xrootd_storage_bytes_available gauge\n"
        "# HELP xrootd_storage_occupancy_ratio Backend export filesystem occupancy (0-1).\n"
        "# TYPE xrootd_storage_occupancy_ratio gauge\n");
    for (i = 0; i < n; i++) {
        xrootd_vfs_backend_info_t info;
        xrootd_fs_usage_t         fsu;

        if (xrootd_vfs_backend_export_info(i, &info) != NGX_OK) {
            continue;
        }
        if (strcmp(info.backend, "posix") != 0
            && strcmp(info.backend, "pblock") != 0)
        {
            continue;
        }
        if (xrootd_fs_usage_stat(info.root_canon, &fsu) != NGX_OK) {
            continue;
        }
        mw_printf(mw,
            "xrootd_storage_bytes_total{export=\"%s\",backend=\"%s\"} %llu\n"
            "xrootd_storage_bytes_used{export=\"%s\",backend=\"%s\"} %llu\n"
            "xrootd_storage_bytes_available{export=\"%s\",backend=\"%s\"} %llu\n"
            "xrootd_storage_occupancy_ratio{export=\"%s\",backend=\"%s\"} %.6f\n",
            info.root_canon, info.backend, (unsigned long long) fsu.total_bytes,
            info.root_canon, info.backend, (unsigned long long) fsu.occupancy_bytes,
            info.root_canon, info.backend, (unsigned long long) fsu.available_bytes,
            info.root_canon, info.backend,
            (double) fsu.occupancy_ppm / 1000000.0);
    }

    /* Per-backend storage byte totals (Task-2 SHM arrays). Zero rows are
     * emitted too — a scraper needs the series to exist before traffic. */
    {
        ngx_xrootd_metrics_t *shm = xrootd_metrics_shared();
        int                   id;

        if (shm != NULL) {
            mw_printf(mw,
                "# HELP xrootd_storage_io_bytes_read Bytes read by each storage backend driver.\n"
                "# TYPE xrootd_storage_io_bytes_read counter\n");
            for (id = 0; id < XROOTD_FS_ID_COUNT; id++) {
                mw_printf(mw, "xrootd_storage_io_bytes_read{backend=\"%s\"} %lu\n",
                    xrootd_fs_id_name(id),
                    (unsigned long) ngx_atomic_fetch_add(
                        &shm->unified.io_bytes_read_backend[id], 0));
            }
            mw_printf(mw,
                "# HELP xrootd_storage_io_bytes_written Bytes written by each storage backend driver.\n"
                "# TYPE xrootd_storage_io_bytes_written counter\n");
            for (id = 0; id < XROOTD_FS_ID_COUNT; id++) {
                mw_printf(mw, "xrootd_storage_io_bytes_written{backend=\"%s\"} %lu\n",
                    xrootd_fs_id_name(id),
                    (unsigned long) ngx_atomic_fetch_add(
                        &shm->unified.io_bytes_written_backend[id], 0));
            }
        }
    }
```

Adjust: the existing function's early-return `if (n == 0) return;` must NOT skip the io-bytes block (byte counters are global, not per-export). Restructure to `if (n > 0) { …info gauge + capacity… }` followed by the io block; also fold the `ngx_uint_t i;`/`n` declarations accordingly, and verify the exact `xrootd_fs_usage_t` field names against `src/core/compat/fs_usage.h` before using them.

- [ ] **Step 3: Build + verify with the existing shell test**

```bash
cd /tmp/nginx-1.28.3 && make -j$(nproc) && bash /home/rcurrie/HEP-x/nginx-xrootd/tests/run_storage_backend_metrics.sh
```
Expected: build exit 0; `run_storage_backend_metrics.sh` all `ok` (guards the info gauge stayed intact).

- [ ] **Step 4: Quick smoke — new families appear**

Reuse the shell test's pattern manually or extend it: start a throwaway nginx with a posix webdav export + `/metrics`, then:

```bash
curl -s http://127.0.0.1:PORT/metrics | grep -E "xrootd_storage_(io_bytes|bytes_total|occupancy)"
```
Expected: `xrootd_storage_io_bytes_read{backend="posix"} 0` (all census rows), and for the posix export `xrootd_storage_bytes_total{export="…",backend="posix"} <nonzero>`.

- [ ] **Step 5: Commit**

```bash
cd /home/rcurrie/HEP-x/nginx-xrootd && git add src/fs/vfs/vfs_backend_config.c src/observability/metrics/writer.c && git commit -m "feat(metrics): storage capacity + per-backend io-bytes families; default-posix exports join the census"
```

---

### Task 4: Dashboard snapshot section (`storage`) + Backend Storage panel

**Files:**
- Modify: `src/observability/dashboard/api_snapshot.c` (new `dashboard_fill_storage` next to `dashboard_fill_cache` ~line 356; attach in `dashboard_build_snapshot` ~line 544)
- Modify: `src/observability/dashboard/page.c` (panel div ~line 58; renderer in `renderPanels()` ~line 100; update the field-list comment ~line 73)

**Interfaces:**
- Consumes: `xrootd_vfs_backend_export_count/info`, `xrootd_fs_usage_stat`, SHM arrays + `xrootd_fs_id_name` (Tasks 1–2).
- Produces: snapshot key `storage: { exports: [...], io: {...} }` — consumed by the page renderer and Task 5 tests.

- [ ] **Step 1: Write dashboard_fill_storage**

In `api_snapshot.c`, add includes `#include "fs/vfs/vfs_backend_registry.h"` and `#include "core/types/fs_list.h"` (fs_usage.h is already used — verify). Insert after `dashboard_fill_cache`:

```c
/*
 * dashboard_fill_storage — adds "exports" (per-export backend identity +
 * live-statvfs capacity for local backends) and "io" (per-backend byte
 * totals) to `target`. The identity source is the config-time VFS backend
 * registry (the same census behind /vfs and the storage-backend info gauge),
 * so it covers stream AND http exports. redact (anonymous tier) omits the
 * export root and origin host — numbers only, matching the cache panel.
 */
static void
dashboard_fill_storage(json_t *target, ngx_uint_t redact)
{
    ngx_xrootd_metrics_t *met = dashboard_metrics();
    ngx_uint_t            i, n;
    json_t               *exports, *io;

    exports = json_array();
    if (exports != NULL) {
        n = xrootd_vfs_backend_export_count();
        for (i = 0; i < n; i++) {
            xrootd_vfs_backend_info_t info;
            xrootd_fs_usage_t         fsu;
            json_t                   *e;
            int                       local;

            if (xrootd_vfs_backend_export_info(i, &info) != NGX_OK) {
                continue;
            }
            e = json_object();
            if (e == NULL) {
                continue;
            }
            local = strcmp(info.backend, "posix") == 0
                    || strcmp(info.backend, "pblock") == 0;

            json_object_set_new(e, "backend", json_string(info.backend));
            json_object_set_new(e, "remote",  local ? json_false() : json_true());
            json_object_set_new(e, "staging",
                info.staging ? json_true() : json_false());
            if (!redact) {   /* export path + upstream host are infra detail */
                json_object_set_new(e, "root", json_string(info.root_canon));
                if (info.host != NULL && info.host[0] != '\0') {
                    json_object_set_new(e, "origin_host", json_string(info.host));
                    json_object_set_new(e, "origin_port",
                        json_integer((json_int_t) info.port));
                }
            }
            if (local
                && xrootd_fs_usage_stat(info.root_canon, &fsu) == NGX_OK)
            {
                json_object_set_new(e, "bytes_total",
                    json_integer((json_int_t) fsu.total_bytes));
                json_object_set_new(e, "bytes_used",
                    json_integer((json_int_t) fsu.occupancy_bytes));
                json_object_set_new(e, "bytes_available",
                    json_integer((json_int_t) fsu.available_bytes));
                json_object_set_new(e, "occupancy_ratio",
                    json_real((double) fsu.occupancy_ppm / 1000000.0));
            }
            json_array_append_new(exports, e);
        }
        json_object_set_new(target, "exports", exports);
    }

    io = json_object();
    if (io != NULL && met != NULL) {
        int id;

        for (id = 0; id < XROOTD_FS_ID_COUNT; id++) {
            uint64_t rd = (uint64_t)
                met->unified.io_bytes_read_backend[id];
            uint64_t wr = (uint64_t)
                met->unified.io_bytes_written_backend[id];
            json_t  *b;

            if (rd == 0 && wr == 0) {
                continue;               /* idle backends stay out of the JSON */
            }
            b = json_object();
            if (b == NULL) {
                continue;
            }
            json_object_set_new(b, "bytes_read_total",
                json_integer((json_int_t) rd));
            json_object_set_new(b, "bytes_written_total",
                json_integer((json_int_t) wr));
            json_object_set_new(io, xrootd_fs_id_name(id), b);
        }
    }
    if (io != NULL) {
        json_object_set_new(target, "io", io);
    }
}
```

**Adapt to the file's local conventions:** `dashboard_metrics()` is a placeholder name — use whatever accessor `dashboard_fill_cache` uses to reach `met` (read its first lines: it resolves the SHM pointer with a NULL/`(void*)1` guard; reuse the identical pattern, including the empty-object fallback when SHM is absent — emit `"exports": []` and `"io": {}` in that case). Match the atomic-read style used in the file (direct read vs `ngx_atomic_fetch_add(&x, 0)`).

- [ ] **Step 2: Attach to the snapshot**

In `dashboard_build_snapshot` (~line 544), directly after the `cache` attach block, mirroring it exactly:

```c
    storage = json_object();
    if (storage) {
        dashboard_fill_storage(storage, redact);
        json_object_set_new(root, "storage", storage);
    }
```

Add `*storage` to the function's declaration line (`json_t *root, *history, *cache, *cluster, *cvmfs;`).

- [ ] **Step 3: Add the panel + renderer to page.c**

(1) Panel div — next to the existing Cache panel line (~line 58):

```c
"<div class=\"panel\"><h2>Backend Storage</h2><div id=\"storage-panel\"></div></div>\n"
```

(2) Renderer — inside the `renderPanels()` JS string (~line 100), append before the cluster-panel section (keep the whole thing one JS statement chain like its neighbors; `esc()` and `el()` helpers already exist):

```js
var st=(lastSnapshot&&lastSnapshot.storage)||{};var exs=st.exports||[];var sio=st.io||{};
el('storage-panel').innerHTML='<div class="metric">'+exs.length+' export'+(exs.length===1?'':'s')+'</div>'
+exs.slice(0,4).map(function(x){var cap=(x.bytes_total>0)?' '+Math.round((x.occupancy_ratio||0)*100)+'% of '+fmtBytes(x.bytes_total):(x.remote?' remote':'');
return '<div class="sub">'+esc(x.backend)+cap+'</div>'}).join('')
+Object.keys(sio).map(function(k){return '<div class="sub">'+esc(k)+' r '+fmtBytes(sio[k].bytes_read_total)+' / w '+fmtBytes(sio[k].bytes_written_total)+'</div>'}).join('');
```

Check whether a bytes-formatting helper already exists in page.c (grep for `function fmt` / `toFixed`); if none, add a minimal one to the same script block:

```js
function fmtBytes(n){n=n||0;var u=['B','KB','MB','GB','TB'];var i=0;while(n>=1024&&i<u.length-1){n/=1024;i++}return (i?n.toFixed(1):n)+u[i]}
```

(3) Update the page.c comment (~line 73) that enumerates snapshot field names to include `storage`.

**page.c is a C string literal of minified JS — escape every `"` as `\"` and keep each line's `"…"` quoting convention exactly.**

- [ ] **Step 4: Build + eyeball the JSON**

```bash
cd /tmp/nginx-1.28.3 && make -j$(nproc)
```
Then start the Task-3 smoke config with the dashboard enabled and:

```bash
curl -s http://127.0.0.1:PORT/xrootd/api/v1/snapshot -H "Cookie: <authed>" | python3 -m json.tool | grep -A12 '"storage"'
```
Expected: `storage.exports[0].backend == "posix"`, `bytes_total > 0`, `storage.io` present. (If auth setup is awkward here, defer verification to Task 5's pytest and just confirm the build.)

- [ ] **Step 5: Commit**

```bash
cd /home/rcurrie/HEP-x/nginx-xrootd && git add src/observability/dashboard/api_snapshot.c src/observability/dashboard/page.c && git commit -m "feat(dashboard): Backend Storage panel — export census + capacity + per-backend io bytes"
```

---

### Task 5: Integration test suite + regression sweep

**Files:**
- Create: `tests/test_storage_backend_panel.py`
- Run: existing dashboard/metrics suites.

**Interfaces:**
- Consumes: everything above. Model the fixture on `tests/test_dashboard_config_anon.py` (self-contained nginx, `_free_port()`, `NGINX_BIN` env, module-scoped fixture, `settings.HOST/BIND_HOST`).

- [ ] **Step 1: Write the integration tests**

Create `tests/test_storage_backend_panel.py` (adapt fixture details — dashboard auth directive names, login flow — from `test_dashboard_config_anon.py`, which shows the exact working config for an authed + anonymous dashboard; keep its structure):

```python
"""
Backend Storage observability tests (spec 2026-07-03).

Self-contained nginx: one default-POSIX WebDAV export + dashboard + /metrics,
plus a second server whose export names a root:// backend (dead origin — the
registry census is config-time, the origin is never contacted).

Asserts the five spec scenarios:
  1. capacity: storage.exports has backend "posix" with statvfs numbers, and
     /metrics carries xrootd_storage_bytes_total{...backend="posix"} — proving
     the default-POSIX census registration too;
  2. byte accounting: PUT then GET N bytes moves the posix written/read
     counters by >= N on BOTH surfaces;
  3. sendfile attribution: the GET above is the zero-copy path (cleartext
     posix) — the read counter movement guards the serve_file_ranged seam;
  4. remote export: the xroot-backed export reports remote:true and NO
     statvfs numbers, and nothing crashes;
  5. redaction: the anonymous snapshot's storage section carries no root/
     origin keys and no filesystem path; the authed one carries root.
"""

import json
import os
import time
import urllib.request

import pytest

from settings import BIND_HOST

NGINX_BIN = os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx")
N = 4 * 1024 * 1024  # transfer size: large enough to dwarf noise


# --- fixture: copy the server fixture pattern from test_dashboard_config_anon.py:
#     tmp_path_factory root, _free_port() x {webdav, metrics, dashboard},
#     default-posix export (xrootd_webdav on; NO storage_backend directive),
#     allow_write on, a second location with
#     xrootd_webdav_storage_backend root://127.0.0.1:1 (dead origin, distinct root),
#     location /metrics { xrootd_metrics on; }, dashboard with anonymous tier on,
#     write conf, spawn nginx, wait for ports, yield endpoints, terminate.


def _http(url, data=None, method=None, headers=None):
    req = urllib.request.Request(url, data=data, method=method,
                                 headers=headers or {})
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.status, r.read()


def _metric(text, name, **labels):
    """Sum all samples of `name` whose labels include **labels."""
    total, found = 0, False
    for line in text.splitlines():
        if not line.startswith(name + "{"):
            continue
        if all('%s="%s"' % kv in line for kv in labels.items()):
            total += int(float(line.rsplit(" ", 1)[1]))
            found = True
    return total if found else None


def test_capacity_and_census(server):
    _, body = _http(server.metrics_url)
    text = body.decode()
    assert _metric(text, "xrootd_storage_bytes_total", backend="posix"), \
        "default-posix export missing from capacity gauges (census gap?)"
    snap = json.loads(_http(server.authed_snapshot_url)[1])
    posix = [e for e in snap["storage"]["exports"] if e["backend"] == "posix"]
    assert posix and posix[0]["bytes_total"] > 0 and not posix[0]["remote"]


def test_byte_accounting_put_get(server):
    before = _http(server.metrics_url)[1].decode()
    w0 = _metric(before, "xrootd_storage_io_bytes_written", backend="posix") or 0
    r0 = _metric(before, "xrootd_storage_io_bytes_read", backend="posix") or 0

    payload = os.urandom(N)
    assert _http(server.webdav_url + "/acct.bin", data=payload,
                 method="PUT")[0] in (201, 204)
    status, got = _http(server.webdav_url + "/acct.bin")
    assert status == 200 and got == payload      # sendfile zero-copy serve

    after = _http(server.metrics_url)[1].decode()
    w1 = _metric(after, "xrootd_storage_io_bytes_written", backend="posix")
    r1 = _metric(after, "xrootd_storage_io_bytes_read", backend="posix")
    assert w1 - w0 >= N, f"written moved {w1 - w0}, want >= {N}"
    assert r1 - r0 >= N, f"read (sendfile seam) moved {r1 - r0}, want >= {N}"

    snap = json.loads(_http(server.authed_snapshot_url)[1])
    assert snap["storage"]["io"]["posix"]["bytes_read_total"] >= N


def test_remote_export_census(server):
    snap = json.loads(_http(server.authed_snapshot_url)[1])
    remote = [e for e in snap["storage"]["exports"] if e["backend"] == "xroot"]
    assert remote and remote[0]["remote"] is True
    assert "bytes_total" not in remote[0]


def test_anonymous_redaction(server):
    snap = json.loads(_http(server.anon_snapshot_url)[1])
    assert snap.get("anonymous") is True
    blob = json.dumps(snap["storage"])
    for e in snap["storage"]["exports"]:
        assert "root" not in e and "origin_host" not in e
    assert server.export_dir not in blob

    authed = json.loads(_http(server.authed_snapshot_url)[1])
    assert any("root" in e for e in authed["storage"]["exports"])
```

The fixture must expose `metrics_url`, `webdav_url`, `authed_snapshot_url`, `anon_snapshot_url`, `export_dir` — implement by mirroring `test_dashboard_config_anon.py`'s fixture and login helper verbatim (it already solves dashboard auth cookies and anonymous access).

- [ ] **Step 2: Run the new suite**

Run: `PYTHONPATH=tests pytest tests/test_storage_backend_panel.py -v -n0`
Expected: 4 passed. Debug via the instance's `error.log` on failure; if the byte counters don't move, verify with `curl /metrics` manually which seam missed (PUT ⇒ observe/staged seam; GET ⇒ serve seam).

- [ ] **Step 3: Root:// data-plane spot check (seam b)**

With the test fleet up (`tests/manage_test_servers.sh start`), run one xrdcp against the anon port and confirm movement:

```bash
curl -s http://localhost:9100/metrics | grep 'xrootd_storage_io_bytes_read{backend="posix"}'
xrdcp -f root://localhost:11094//<existing test file> /tmp/seam_b_check
curl -s http://localhost:9100/metrics | grep 'xrootd_storage_io_bytes_read{backend="posix"}'
```
Expected: counter increases by ≥ file size. (Adjust the file path to whatever the fleet exports; any existing file works.)

- [ ] **Step 4: Regression sweep**

```bash
PYTHONPATH=tests pytest tests/test_dashboard.py tests/test_dashboard_config_anon.py tests/test_dashboard_files.py -v -n0
bash tests/run_storage_backend_metrics.sh
bash tests/run_dashboard_vfs_browse.sh
PYTHONPATH=tests pytest tests/ -k "metrics" -v --tb=short -n0
```
Expected: all pass. Known risk: suites asserting `/vfs` export **counts** may see MORE exports now that default-posix registers — if one fails on a count, fix the TEST's expectation (the census growing is the intended behavior), and say so in the commit message.

- [ ] **Step 5: Commit**

```bash
cd /home/rcurrie/HEP-x/nginx-xrootd && git add tests/test_storage_backend_panel.py && git commit -m "test(storage): backend-storage panel + per-backend byte accounting integration suite"
```

---

## Self-review notes (already applied)

- Spec coverage: C1→Task 1, C2 (registry + posix gap)→Task 3.1, C3→Task 2.1-2, C4a/b/c→Task 2.3-5, C5→Task 4.1-2, C6→Task 3.2, C7→Task 4.3, tests 1–5→Task 5, test 6→Task 1.
- Type consistency: `xrootd_metric_backend_bytes(const char *, xrootd_metric_op_t, size_t)` and `xrootd_vfs_file_backend_name(const xrootd_vfs_file_t *)` used identically in Tasks 2–5; SHM arrays named `io_bytes_read_backend`/`io_bytes_written_backend` everywhere.
- Deliberate scope cuts (from spec): no `/v1/storage` flat endpoint; COPY bytes not attributed (read/write only); S3-export census parity deferred if S3 config never reaches `config_str` (verified + noted in Task 3.1).
