# xrdc_vfs + Common Credential Layer — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the `client/` tools (xrdcp, xrdfs, xrootdfs, …) one storage-backend abstraction (`xrdc_vfs`) so a copy endpoint can be local POSIX, a block device, or an S3/object store interchangeably, and one credential-acquisition layer (`xrdc_cred`) that discovers/loads/caches/refreshes GSI proxies, bearer tokens, Kerberos TGTs, SSS keytabs, and S3 keys for *both* the root:// handshake and the HTTP/S3 transports.

**Architecture:** Two independent, separately-shippable subsystems plus a thin integration part.
- **Part A — `xrdc_vfs`:** a capability-typed file handle (`open/pread/pwrite/fstat/truncate/sync/commit/abort/close`) over a backend vtable. The keystone is an explicit `commit` op so the POSIX temp-then-rename model and the S3 multipart-complete model both fit. POSIX backend wraps the *existing* `xrdc_disk_ring` (`lib/uring.c`) and fd code; block and s3 backends are new. It generalizes today's three ad-hoc seams (`pump_src_fn`/`pump_sink_fn` in `lib/copy.c`, the `be+pread/pwrite` pair in `lib/iobuf.h`, and `xrdc_disk_ring`).
- **Part B — `xrdc_cred`:** a credential store sitting *beneath* the existing `xrdc_sec_module` handshake (`lib/sec/sec.h`) and *beside* the HTTP/S3 transports. Per-kind handlers own discovery/load/refresh (consolidating logic currently scattered across `lib/sec/sec_gsi.c`, `sec_token.c`, `sec_sss.c`, `sec_krb5.c`, and `lib/credrefresh.c`). The sec modules and the web transports both read from it.
- **Part C — integration:** route `lib/copy.c`'s local endpoint through `xrdc_vfs`; build one `xrdc_cred_store` per tool invocation and feed it to both the VFS (s3 keys/bearer) and the connection auth path.

**Tech Stack:** C11, ngx-free client lib (`client/lib`), OpenSSL (proxy/TLS), libcurl-free HTTP (`lib/http.c`), io_uring (`lib/uring.c`, runtime-optional), `xrdc_status` error type, GNU Make (`client/Makefile`), pytest integration suite (`tests/test_client_*.py`) + standalone gcc unit tests (`tests/c/*.c`).

## Global Constraints

- **ngx-free:** No `ngx_*` types/headers anywhere in `client/`. The server's `src/fs/backend/sd.h` storage-driver seam MUST NOT be reused — sharing it into the client was tried in phase-55 and broke the build (reverted). The client VFS is its own abstraction.
- **No `goto`** in any `.c`/`.h` under `client/` you create or touch (early-return + helper decomposition). Existing `goto` in a function you edit must be refactored out (coding-standards §4).
- **Functional/modular:** one responsibility per function; pass state explicitly (no new globals); pure helpers with side effects at the edges; table/vtable dispatch over branch ladders (coding-standards §8).
- **Error type:** every fallible function takes `xrdc_status *st` and reports via `xrdc_status_set(st, kxr, sys_errno, fmt, ...)` (`lib/xrdc.h:501`). Return `0`/`-1` (int) or bytes/`-1` (ssize_t).
- **3 tests per behavioural change:** success + error + a security/negative case (CLAUDE.md core rule).
- **Build registration:** every new `lib/*.c` is added to `LIB_SRCS` in `client/Makefile` (line 97–104). New standalone unit tests are added as their own Make target near the `aio-smoke` target (`client/Makefile:205–209`).
- **Backwards compatibility:** existing CLI flags, env-var discovery order, and on-wire behaviour are preserved exactly. This is a refactor behind stable interfaces, not a behaviour change.
- **Naming:** new public symbols are `xrdc_vfs_*` / `xrdc_cred_*`; new files are `lib/vfs.h`, `lib/vfs_*.c`, `lib/cred.h`, `lib/cred_*.c`.

---

## File Structure

**Part A — VFS**
- `client/lib/vfs.h` — public façade + backend/handle vtable types (new).
- `client/lib/vfs.c` — façade dispatch: URL→backend resolution, the thin `xrdc_vfs_*` wrappers (new).
- `client/lib/vfs_posix.c` — POSIX backend: wraps `xrdc_disk_ring` + fd, temp+rename commit (new).
- `client/lib/vfs_block.c` — block-device backend: pwrite-in-place, fsync commit, no rename (new).
- `client/lib/vfs_s3.c` — S3/object backend: GET range read, multipart-upload write, MPU-complete commit; wraps `lib/s3.c` SigV4 (new).
- `client/tests/c/vfs_posix_unit.c` — standalone unit test for the POSIX backend + commit semantics (new).
- `client/tests/c/vfs_block_unit.c` — standalone unit test for the block backend (new).
- `client/lib/copy.c` — migrate the local endpoint from raw fd/pump to `xrdc_vfs` (modify; see Task A6 for exact anchors).

**Part B — Credentials**
- `client/lib/cred.h` — public store + per-kind handler contract (new).
- `client/lib/cred.c` — store: handler registry, cache, expiry, refresh orchestration (new).
- `client/lib/cred_x509.c` — GSI/X.509 proxy acquisition (moves `proxy_path()` logic out of `sec_gsi.c`) (new).
- `client/lib/cred_bearer.c` — bearer-token acquisition + oidc refresh (moves `sec_token.c` discovery + `credrefresh.c` oidc logic) (new).
- `client/lib/cred_krb5.c` — Kerberos ccache probe/refresh (moves `sec_krb5.c` discovery) (new).
- `client/lib/cred_sss.c` — SSS keytab discovery (wraps `xrdc_sss_keytab_default`) (new).
- `client/lib/cred_s3.c` — S3 access/secret discovery (env + file) (new).
- `client/tests/c/cred_unit.c` — standalone unit test: discovery precedence, expiry, refresh-gating (new).
- `client/lib/sec/sec_gsi.c`, `sec_token.c`, `sec_sss.c`, `sec_krb5.c` — `have_creds`/`first` delegate to `xrdc_cred_*` (modify).
- `client/lib/webfile.c`, `lib/s3.c` — take credentials from the store instead of threaded raw strings (modify, Part C).

**Part C — Integration**
- `client/lib/cli_conn.c` / `lib/cli_opts.c` — build one `xrdc_cred_store` from CLI/env (modify).
- `client/apps/xrdcp.c`, `apps/xrdfs.c`, `apps/xrootdfs.c` — pass the store down; accept `s3://` local endpoints (modify).

---

# PART A — `xrdc_vfs`

Produces working software on its own: after Part A, xrdcp's local read/write goes through `xrdc_vfs` with the POSIX backend (no behaviour change), and `xrdcp file:///a /dev/sdX` (block) and `xrdcp s3://… /local` / `xrdcp /local s3://…` work.

### Task A1: VFS public interface header

**Files:**
- Create: `client/lib/vfs.h`

**Interfaces:**
- Consumes: `xrdc_status` (`lib/xrdc.h:51`), `xrdc_status_set` (`lib/xrdc.h:501`).
- Produces: `xrdc_vfs_file`, `xrdc_vfs_ops`, `xrdc_vfs_backend`, `xrdc_vfs_open_opts`, `xrdc_vfs_stat`, the `xrdc_vfs_caps`/`xrdc_vfs_oflags` enums, and the façade functions `xrdc_vfs_open / _stat_url / _pread / _pwrite / _fstat / _truncate / _sync / _commit / _abort / _close / _get_caps`.

- [ ] **Step 1: Write the header**

```c
/* client/lib/vfs.h
 *
 * vfs.h — client storage-backend abstraction.
 *
 * WHAT: one open-file handle (pread/pwrite/fstat/truncate/sync/commit/abort/close)
 *       over a backend vtable, so a copy endpoint can be local POSIX, a block
 *       device, or an S3/object store interchangeably.
 * WHY:  copy.c hard-codes POSIX fds for the local endpoint and threads three
 *       different ad-hoc I/O seams (pump_src/sink_fn, iobuf be+pread/pwrite,
 *       xrdc_disk_ring). One handle unifies them and lets non-POSIX backends in.
 * HOW:  the keystone is commit(): POSIX finalises by fsync+rename(temp->final);
 *       block by fsync; S3 by multipart-complete. caps lets the copy engine pick
 *       a path (random-write vs append-only, atomic-temp vs native commit).
 *       ngx-free; never reuse the server's src/fs/backend/sd.h (phase-55 broke it).
 */
#ifndef XRDC_VFS_H
#define XRDC_VFS_H

#include "xrdc.h"
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>   /* ssize_t */

typedef enum {
    XRDC_VFS_READ   = 0x01,   /* open for reading                                  */
    XRDC_VFS_WRITE  = 0x02,   /* open for writing (create+truncate unless RESUME)  */
    XRDC_VFS_RESUME = 0x04,   /* writer: keep existing object, resume at offset     */
    XRDC_VFS_FORCE  = 0x08,   /* writer: overwrite an existing destination          */
} xrdc_vfs_oflags;

typedef enum {
    XRDC_VFS_CAP_RANDOM_WRITE = 0x01, /* pwrite at any offset (posix/block); 0=append/stream (s3) */
    XRDC_VFS_CAP_TRUNCATE     = 0x02,
    XRDC_VFS_CAP_ATOMIC_TEMP  = 0x04, /* commit = temp+rename (posix); 0=native commit (s3/block) */
    XRDC_VFS_CAP_FADVISE      = 0x08,
} xrdc_vfs_caps;

typedef struct {
    int64_t size;
    int64_t mtime;
    int     is_dir;
    int     exists;
} xrdc_vfs_stat;

typedef struct xrdc_cred_store xrdc_cred_store;   /* fwd decl (Part B); NULL for local */

typedef struct {
    int              io_uring;      /* XRDC_IO_URING_{OFF,AUTO,ON} for posix/block      */
    int64_t          expected_size; /* writer hint: <0 unknown; drives s3 single-PUT vs MPU */
    xrdc_cred_store *cred;          /* credential source for s3/web backends (NULL=local) */
} xrdc_vfs_open_opts;

typedef struct xrdc_vfs_file xrdc_vfs_file;

/* Per-handle vtable. A backend's open() allocates a concrete struct whose first
 * member is `xrdc_vfs_file base;` and sets base.ops/base.caps. */
typedef struct xrdc_vfs_ops {
    ssize_t (*pread)(xrdc_vfs_file *f, int64_t off, void *buf, size_t n, xrdc_status *st);
    int     (*pwrite)(xrdc_vfs_file *f, int64_t off, const void *buf, size_t n, xrdc_status *st);
    int     (*fstat)(xrdc_vfs_file *f, xrdc_vfs_stat *out, xrdc_status *st);
    int     (*truncate)(xrdc_vfs_file *f, int64_t size, xrdc_status *st);
    int     (*sync)(xrdc_vfs_file *f, xrdc_status *st);
    int     (*commit)(xrdc_vfs_file *f, xrdc_status *st); /* finalise: rename/MPU-complete/fsync */
    void    (*abort)(xrdc_vfs_file *f);                   /* discard partial: unlink temp / abort MPU */
    void    (*close)(xrdc_vfs_file *f);                   /* free handle (after commit OR abort) */
} xrdc_vfs_ops;

struct xrdc_vfs_file {
    const xrdc_vfs_ops *ops;
    uint32_t            caps;   /* xrdc_vfs_caps for this open handle */
};

typedef struct xrdc_vfs_backend {
    const char *scheme;         /* "file","block","s3","s3s" — matched against the URL */
    uint32_t    caps;           /* default caps advertised pre-open */
    int (*open)(const struct xrdc_vfs_backend *be, const char *url, int flags,
                const xrdc_vfs_open_opts *opts, xrdc_vfs_file **out, xrdc_status *st);
    int (*stat)(const struct xrdc_vfs_backend *be, const char *url,
                xrdc_vfs_stat *out, xrdc_status *st);
} xrdc_vfs_backend;

/* ---- Façade: the only surface copy.c/tools use. Resolves URL->backend. ---- */
int      xrdc_vfs_open(const char *url, int flags, const xrdc_vfs_open_opts *opts,
                       xrdc_vfs_file **out, xrdc_status *st);
int      xrdc_vfs_stat_url(const char *url, const xrdc_vfs_open_opts *opts,
                           xrdc_vfs_stat *out, xrdc_status *st);
ssize_t  xrdc_vfs_pread(xrdc_vfs_file *f, int64_t off, void *buf, size_t n, xrdc_status *st);
int      xrdc_vfs_pwrite(xrdc_vfs_file *f, int64_t off, const void *buf, size_t n, xrdc_status *st);
int      xrdc_vfs_fstat(xrdc_vfs_file *f, xrdc_vfs_stat *out, xrdc_status *st);
int      xrdc_vfs_truncate(xrdc_vfs_file *f, int64_t size, xrdc_status *st);
int      xrdc_vfs_sync(xrdc_vfs_file *f, xrdc_status *st);
int      xrdc_vfs_commit(xrdc_vfs_file *f, xrdc_status *st);
void     xrdc_vfs_abort(xrdc_vfs_file *f);
void     xrdc_vfs_close(xrdc_vfs_file *f);
uint32_t xrdc_vfs_get_caps(const xrdc_vfs_file *f);  /* note: distinct from the enum xrdc_vfs_caps */

#endif /* XRDC_VFS_H */
```

- [ ] **Step 2: Verify it compiles standalone**

Run: `cd client && gcc -std=c11 -I lib -fsyntax-only -x c lib/vfs.h`
Expected: no output, exit 0.

- [ ] **Step 3: Commit**

```bash
git add client/lib/vfs.h
git commit -m "feat(client): xrdc_vfs interface header"
```

### Task A2: Façade dispatch (`vfs.c`) + a stub backend registry

**Files:**
- Create: `client/lib/vfs.c`
- Modify: `client/Makefile:97` (add `lib/vfs.c` to `LIB_SRCS`)
- Test: `client/tests/c/vfs_posix_unit.c` (created here; exercised fully in A3)

**Interfaces:**
- Consumes: everything from `vfs.h`.
- Produces: `xrdc_vfs_register_backend(const xrdc_vfs_backend *be)` (internal, called by each backend's `xrdc_vfs_*_backend()` accessor) and the façade implementations. URL scheme parsing reuses `xrdc_is_web_url` (`lib/xrdc.h`) and `xrdc_weburl` parsing (`lib/url.c`) to detect `s3://`; a bare path or `file://` → "file"; `/dev/*` or `block://` → "block".

- [ ] **Step 1: Write the failing test (façade routes a bare path to the POSIX backend)**

```c
/* client/tests/c/vfs_posix_unit.c */
#include "../../lib/vfs.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    xrdc_status st = {0};
    char tmpl[] = "/tmp/vfs_unit_XXXXXX";
    int fd = mkstemp(tmpl); assert(fd >= 0); close(fd);

    xrdc_vfs_open_opts o = { .io_uring = 0, .expected_size = -1, .cred = NULL };
    xrdc_vfs_file *f = NULL;
    int rc = xrdc_vfs_open(tmpl, XRDC_VFS_READ, &o, &f, &st);
    assert(rc == 0 && f != NULL);
    assert((xrdc_vfs_get_caps(f) & XRDC_VFS_CAP_RANDOM_WRITE) != 0);  /* posix is random-write */
    xrdc_vfs_close(f);
    unlink(tmpl);
    printf("vfs façade routing OK\n");
    return 0;
}
```

- [ ] **Step 2: Run to verify it fails (link error: no backend)**

Run: `cd client && gcc -std=c11 -I lib tests/c/vfs_posix_unit.c lib/vfs.c -o /tmp/vfs_unit 2>&1 | head`
Expected: FAIL — undefined reference to the POSIX backend (A3 not done yet) or assertion if stubbed.

- [ ] **Step 3: Implement `vfs.c` façade + registry**

Implement: a small static array `static const xrdc_vfs_backend *g_backends[8]; static int g_n;` with `xrdc_vfs_register_backend()`; lazy registration via weak accessors `xrdc_vfs_posix_backend()`, `xrdc_vfs_block_backend()`, `xrdc_vfs_s3_backend()` called once on first `xrdc_vfs_open`. URL→scheme: if `xrdc_is_web_url(url)` and the parsed `xrdc_weburl.is_s3` → "s3"/"s3s"; else if `strncmp(url,"block://",8)==0` or path resolves under `/dev/` → "block"; else "file" (strip a leading `file://`). Each façade wrapper (`xrdc_vfs_pread` etc.) calls `f->ops->pread(f, …)`; `xrdc_vfs_get_caps` returns `f->caps`. No `goto`.

- [ ] **Step 4: Add to the build**

Edit `client/Makefile:99` — append `lib/vfs.c` to the `LIB_SRCS` continuation line.
Run: `cd client && make -j$(nproc) lib 2>&1 | grep -E ': (error|warning):' ; echo done`
Expected: `done` with no error/warning lines.

- [ ] **Step 5: Commit**

```bash
git add client/lib/vfs.c client/Makefile client/tests/c/vfs_posix_unit.c
git commit -m "feat(client): xrdc_vfs façade + backend registry"
```

### Task A3: POSIX backend (`vfs_posix.c`) — the reference, with temp+rename commit

**Files:**
- Create: `client/lib/vfs_posix.c`
- Modify: `client/Makefile:97` (add `lib/vfs_posix.c`)
- Test: `client/tests/c/vfs_posix_unit.c` (extend)

**Interfaces:**
- Consumes: `xrdc_disk_ring` + `xrdc_disk_ring_pread/_pwrite` (`lib/uring.h:56,69`), `XRDC_IO_URING_{OFF,AUTO,ON}` (`lib/xrdc.h`).
- Produces: `const xrdc_vfs_backend *xrdc_vfs_posix_backend(void);` and a concrete `vfs_posix_file` whose `open` honours `XRDC_VFS_WRITE` by opening a sibling temp (`make_temp_path` pattern, see `lib/copy.c` `make_temp_path` + `atomic_dest_finish`), `commit` = `fsync` + `rename(temp,final)`, `abort` = `unlink(temp)`. Caps: `RANDOM_WRITE|TRUNCATE|ATOMIC_TEMP|FADVISE`.

- [ ] **Step 1: Write the failing test (write→commit yields the bytes at the final path; abort leaves no temp)**

```c
/* append to client/tests/c/vfs_posix_unit.c main(), before return 0; */
{
    xrdc_status s2 = {0};
    char dst[] = "/tmp/vfs_commit_XXXXXX";
    int dfd = mkstemp(dst); assert(dfd >= 0); close(dfd); unlink(dst); /* want the name only */

    xrdc_vfs_open_opts wo = { .io_uring = 0, .expected_size = 5, .cred = NULL };
    xrdc_vfs_file *w = NULL;
    assert(xrdc_vfs_open(dst, XRDC_VFS_WRITE | XRDC_VFS_FORCE, &wo, &w, &s2) == 0);
    assert(xrdc_vfs_pwrite(w, 0, "hello", 5, &s2) == 0);
    assert(xrdc_vfs_commit(w, &s2) == 0);
    xrdc_vfs_close(w);

    char buf[8] = {0};
    xrdc_vfs_file *r = NULL;
    assert(xrdc_vfs_open(dst, XRDC_VFS_READ, &wo, &r, &s2) == 0);
    assert(xrdc_vfs_pread(r, 0, buf, 5, &s2) == 5);
    assert(memcmp(buf, "hello", 5) == 0);
    xrdc_vfs_close(r);
    unlink(dst);
    printf("vfs posix commit OK\n");
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd client && gcc -std=c11 -I lib tests/c/vfs_posix_unit.c lib/vfs.c lib/vfs_posix.c lib/uring.c lib/status.c -o /tmp/vfs_unit 2>&1 | head`
Expected: FAIL — `xrdc_vfs_posix_backend` undefined.

- [ ] **Step 3: Implement `vfs_posix.c`**

Implement the backend: `open()` resolves a real fd (read: `open(path,O_RDONLY)`; write: `make_temp_path(final,tmp,...)` then `open(tmp,O_WRONLY|O_CREAT|O_TRUNC,0644)`, honouring `XRDC_VFS_FORCE` against an existing `final` exactly as `lib/copy.c` does today around line 735). Wrap the fd in an `xrdc_disk_ring` when `io_uring != OFF` (`local_ring_select` logic from `copy.c:388`), else a plain-`pread`/`pwrite` fallback. `pread/pwrite` delegate to the ring or the fd. `commit` = `fsync(fd)` then `rename(tmp,final)`. `abort` = `unlink(tmp)`. `close` frees the ring + fd. Store `final`/`tmp` paths on the concrete struct. No `goto`.

- [ ] **Step 4: Run to verify both tests pass**

Run: `cd client && gcc -std=c11 -I lib tests/c/vfs_posix_unit.c lib/vfs.c lib/vfs_posix.c lib/uring.c lib/status.c -o /tmp/vfs_unit && /tmp/vfs_unit`
Expected: prints `vfs façade routing OK` and `vfs posix commit OK`, exit 0.

- [ ] **Step 5: Add to build + commit**

```bash
# append lib/vfs_posix.c to LIB_SRCS in client/Makefile, then:
cd client && make -j$(nproc) lib 2>&1 | grep -E ': (error|warning):'; echo done
git add client/lib/vfs_posix.c client/Makefile client/tests/c/vfs_posix_unit.c
git commit -m "feat(client): xrdc_vfs POSIX backend with temp+rename commit"
```

### Task A4: Block-device backend (`vfs_block.c`)

**Files:**
- Create: `client/lib/vfs_block.c`
- Modify: `client/Makefile:97`
- Test: `client/tests/c/vfs_block_unit.c` (new; uses a regular file as a stand-in "device")

**Interfaces:**
- Consumes: `xrdc_disk_ring` as POSIX does.
- Produces: `const xrdc_vfs_backend *xrdc_vfs_block_backend(void);`. Difference from POSIX: **no temp, no rename** — writer opens the target directly (`O_WRONLY`, no `O_CREAT|O_TRUNC` for an existing device); `commit` = `fsync` only; `abort` = no-op. Caps: `RANDOM_WRITE|FADVISE` (no `TRUNCATE`, no `ATOMIC_TEMP`). `fstat` reports device size via `BLKGETSIZE64` when `S_ISBLK`, else `st_size`.

- [ ] **Step 1: Write the failing test (in-place write is visible at the same path; no `.tmp` sibling created)**

```c
/* client/tests/c/vfs_block_unit.c */
#include "../../lib/vfs.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

int main(void) {
    xrdc_status st = {0};
    char dev[] = "/tmp/vfs_blk_XXXXXX";       /* regular file stands in for a block device */
    int fd = mkstemp(dev); assert(fd >= 0);
    assert(ftruncate(fd, 4096) == 0); close(fd);

    xrdc_vfs_open_opts o = { .io_uring = 0, .expected_size = -1, .cred = NULL };
    xrdc_vfs_file *w = NULL;
    char url[64]; snprintf(url, sizeof url, "block://%s", dev);
    assert(xrdc_vfs_open(url, XRDC_VFS_WRITE, &o, &w, &st) == 0);
    assert((xrdc_vfs_get_caps(w) & XRDC_VFS_CAP_ATOMIC_TEMP) == 0);    /* no temp/rename for block */
    assert(xrdc_vfs_pwrite(w, 512, "BLK", 3, &st) == 0);
    assert(xrdc_vfs_commit(w, &st) == 0);
    xrdc_vfs_close(w);

    char tmp[80]; snprintf(tmp, sizeof tmp, "%s.tmp", dev);
    assert(access(tmp, F_OK) != 0);                                /* no sibling temp left behind */

    int v = open(dev, O_RDONLY); char b[3];
    assert(pread(v, b, 3, 512) == 3 && memcmp(b, "BLK", 3) == 0); close(v);
    unlink(dev);
    printf("vfs block OK\n");
    return 0;
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd client && gcc -std=c11 -I lib tests/c/vfs_block_unit.c lib/vfs.c lib/vfs_posix.c lib/vfs_block.c lib/uring.c lib/status.c -o /tmp/vfs_blk 2>&1 | head`
Expected: FAIL — `xrdc_vfs_block_backend` undefined.

- [ ] **Step 3: Implement `vfs_block.c`** (per the Interfaces block above). No `goto`.

- [ ] **Step 4: Run to verify it passes**

Run: `cd client && gcc -std=c11 -I lib tests/c/vfs_block_unit.c lib/vfs.c lib/vfs_posix.c lib/vfs_block.c lib/uring.c lib/status.c -o /tmp/vfs_blk && /tmp/vfs_blk`
Expected: prints `vfs block OK`, exit 0.

- [ ] **Step 5: Add to build + commit**

```bash
cd client && make -j$(nproc) lib 2>&1 | grep -E ': (error|warning):'; echo done
git add client/lib/vfs_block.c client/Makefile client/tests/c/vfs_block_unit.c
git commit -m "feat(client): xrdc_vfs block-device backend (fsync commit, no rename)"
```

### Task A5: S3/object backend (`vfs_s3.c`)

**Files:**
- Create: `client/lib/vfs_s3.c`
- Modify: `client/Makefile:97`
- Test: `tests/test_client_web_transfer.py` (extend — runs against the module's own S3 endpoint, port 9001 per CLAUDE.md)

**Interfaces:**
- Consumes: `xrdc_weburl` (`lib/xrdc.h:90`), `xrdc_s3_sign_v4` (`lib/xrdc.h:409`), `xrdc_s3_sha256_hex` (`lib/xrdc.h:403`), the HTTP transport in `lib/http.c`, and (Part B) `xrdc_cred_store` for the S3 keys via `xrdc_cred_acquire(cred, XRDC_CRED_S3KEYS, …)`. Until Part B lands, read keys from `opts->cred == NULL` → env `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` directly (a 6-line local fallback, replaced in Task C2).
- Produces: `const xrdc_vfs_backend *xrdc_vfs_s3_backend(void);`. Caps: **no** `RANDOM_WRITE`, **no** `ATOMIC_TEMP` (append/stream only). `pread` = ranged `GET` (`Range: bytes=off-off+n-1`). Writer: if `expected_size >= 0` and small (≤ one part, e.g. 64 MiB) buffer-and-single-`PUT` at commit; else **multipart upload** — `CreateMultipartUpload` on open, each `pwrite` whose offset equals the running part boundary uploads a part (reject a non-sequential offset with `XRDC_EIO` "s3 backend requires sequential writes"), `commit` = `CompleteMultipartUpload`, `abort` = `AbortMultipartUpload`.

- [ ] **Step 1: Write the failing test (round-trip a file through s3:// via xrdcp)**

```python
# tests/test_client_web_transfer.py — add
def test_xrdcp_s3_roundtrip(tmp_path, s3_endpoint, s3_creds):
    src = tmp_path / "src.bin"; src.write_bytes(os.urandom(1 << 20))
    key = f"s3://{s3_endpoint}/bucket/vfs_rt.bin"
    # upload: local -> s3 (vfs s3 backend as the dest)
    assert run_xrdcp(str(src), key, env=s3_creds).returncode == 0
    # download: s3 -> local (vfs s3 backend as the source)
    out = tmp_path / "out.bin"
    assert run_xrdcp(key, str(out), env=s3_creds).returncode == 0
    assert out.read_bytes() == src.read_bytes()
```

- [ ] **Step 2: Run to verify it fails**

Run: `PYTHONPATH=tests pytest tests/test_client_web_transfer.py::test_xrdcp_s3_roundtrip -v`
Expected: FAIL — `s3://` dest currently not handled as a VFS endpoint.

- [ ] **Step 3: Implement `vfs_s3.c`** (per Interfaces). Reuse `lib/s3.c` for signing and `lib/http.c` for transport; do not re-implement SigV4. No `goto`.

- [ ] **Step 4: Wire the backend into the façade scheme map** (`vfs.c` A2 already routes `is_s3` → "s3"); ensure `xrdc_vfs_s3_backend()` is registered.

- [ ] **Step 5: Run to verify it passes**

Run: `tests/manage_test_servers.sh restart && PYTHONPATH=tests pytest tests/test_client_web_transfer.py::test_xrdcp_s3_roundtrip -v`
Expected: PASS.

- [ ] **Step 6: Add to build + commit**

```bash
cd client && make -j$(nproc) 2>&1 | grep -E ': (error|warning):'; echo done
git add client/lib/vfs_s3.c client/Makefile tests/test_client_web_transfer.py
git commit -m "feat(client): xrdc_vfs S3 backend (ranged GET / multipart PUT commit)"
```

### Task A6: Migrate `copy.c`'s local endpoint to `xrdc_vfs`

**Files:**
- Modify: `client/lib/copy.c` — the raw-fd local sites. Exact anchors (verified 2026-06-26):
  - download dest open/temp/rename: around `copy.c:735` (`access` existence check), `:742` (`make_temp_path`), `:748` (`open(tmp,…)`), `:782` (`atomic_dest_finish`).
  - upload source open/fstat: `:964`–`:981` (`open(su->path)`, `fstat`).
  - the local pump adapters: `pump_src_local_uring` / `pump_sink_local_uring` (`copy.c:371,381`) and `pump_local_t` (`copy.c:366`).
  - the disk-ring select: `local_ring_select` (`copy.c:388`).
- Test: `tests/test_client_xrdcp_bulk.py`, `tests/test_fs_ops.py` (existing regression — must stay green).

**Interfaces:**
- Consumes: all `xrdc_vfs_*` from Part A.
- Produces: no new public symbols — `copy_download`/`copy_upload` now hold an `xrdc_vfs_file *` for the local side instead of an `int fd` + `xrdc_disk_ring *`. The `pump_local_t` ctx becomes `{ xrdc_vfs_file *vf; }` and the two local pump adapters call `xrdc_vfs_pread`/`xrdc_vfs_pwrite`.

- [ ] **Step 1: Establish the regression baseline (must already pass)**

Run: `tests/manage_test_servers.sh restart && PYTHONPATH=tests pytest tests/test_client_xrdcp_bulk.py tests/test_fs_ops.py -q`
Expected: PASS (record the count; this is the invariant for Step 4).

- [ ] **Step 2: Replace `pump_local_t` + the two local adapters**

Change `pump_local_t` (`copy.c:366`) to `{ xrdc_vfs_file *vf; }`; rewrite `pump_src_local_uring`→`pump_src_local_vfs` to `return xrdc_vfs_pread(lc->vf, off, buf, cap, st);` and `pump_sink_local_uring`→`pump_sink_local_vfs` to `return xrdc_vfs_pwrite(lc->vf, off, buf, n, st);`. Delete `local_ring_select` (the ring choice now lives inside `vfs_posix.c`'s `open`).

- [ ] **Step 3: Route the dest/source opens through the VFS**

In `copy_download`: replace the `make_temp_path`/`open(tmp,…)`/`atomic_dest_finish` triad with `xrdc_vfs_open(du->path, XRDC_VFS_WRITE|(force?XRDC_VFS_FORCE:0), &o, &vf, st)`, then `xrdc_vfs_commit(vf,st)` on success / `xrdc_vfs_abort(vf)` on failure, then `xrdc_vfs_close(vf)`. In `copy_upload`/`download_stream_body`: replace `open(su->path,O_RDONLY)`+`fstat` with `xrdc_vfs_open(su->path, XRDC_VFS_READ, …)` + `xrdc_vfs_fstat`. Keep the stdio (`XRDC_SCHEME_STDIO`) path as-is (it is not a VFS object). No `goto`.

- [ ] **Step 4: Run the regression — same pass count as Step 1**

Run: `PYTHONPATH=tests pytest tests/test_client_xrdcp_bulk.py tests/test_fs_ops.py -q`
Expected: identical PASS count to Step 1 (no behaviour change).

- [ ] **Step 5: Commit**

```bash
git add client/lib/copy.c
git commit -m "refactor(client): route copy.c local endpoint through xrdc_vfs"
```

---

# PART B — `xrdc_cred` common credential layer

Independent of Part A. Produces working software on its own: after Part B, every protocol's credential discovery lives in one place, the root:// sec modules and the HTTP/S3 transports draw from the same store, and `--auto-refresh` covers all kinds uniformly.

### Task B1: Credential store interface header

**Files:**
- Create: `client/lib/cred.h`

**Interfaces:**
- Consumes: `xrdc_status`.
- Produces: `xrdc_cred_store`, `xrdc_cred_config`, `xrdc_cred_view`, `xrdc_cred_kind`, `xrdc_cred_handler`, and `xrdc_cred_store_new / _free / _acquire / _available`.

- [ ] **Step 1: Write the header**

```c
/* client/lib/cred.h
 *
 * cred.h — common credential acquisition for the client tools.
 *
 * WHAT: one store that discovers, loads, caches, and refreshes each credential
 *       kind (X.509 proxy, bearer token, Kerberos TGT, SSS keytab, S3 keys) and
 *       serves BOTH the root:// auth handshake (the lib/sec modules) and the HTTP/S3
 *       transports (webfile.c, s3.c) from a single source of truth.
 * WHY:  discovery/refresh logic is duplicated across sec_gsi.c/sec_token.c/
 *       sec_sss.c/sec_krb5.c/credrefresh.c, and the HTTP path acquires bearers
 *       separately from the root:// token module. One store removes the drift
 *       and lets --auto-refresh cover every kind uniformly.
 * HOW:  per-kind handlers (cred_x509.c etc.) implement available/acquire/refresh;
 *       the store caches the result with an expiry and re-acquires when a caller
 *       asks for a credential within min_remaining_s of expiry. ngx-free.
 */
#ifndef XRDC_CRED_H
#define XRDC_CRED_H

#include "xrdc.h"
#include <stdint.h>

typedef enum {
    XRDC_CRED_X509_PROXY = 0, /* GSI proxy PEM (root:// gsi + davs:// TLS client + http TPC) */
    XRDC_CRED_BEARER,         /* WLCG/OIDC bearer (root:// ztn + HTTP Authorization)          */
    XRDC_CRED_KRB5,           /* Kerberos TGT ccache                                          */
    XRDC_CRED_SSS,            /* shared-secret keytab                                          */
    XRDC_CRED_S3KEYS,         /* AWS access/secret for SigV4                                  */
    XRDC_CRED_KIND_COUNT
} xrdc_cred_kind;

/* A read-only snapshot a consumer uses. Strings are owned by the store and stay
 * valid until the next acquire of the SAME kind on the SAME store. */
typedef struct {
    xrdc_cred_kind kind;
    const char    *path;       /* proxy/keytab/ccache path, or NULL                 */
    const char    *token;      /* bearer string, or NULL                            */
    const char    *s3_access;  /* S3 access key, or NULL                            */
    const char    *s3_secret;  /* S3 secret key, or NULL                            */
    int64_t        not_after;  /* unix expiry; 0 = unknown/none                     */
} xrdc_cred_view;

/* Explicit overrides (from CLI flags); empty/NULL fields fall back to env/default
 * discovery — preserving today's per-protocol precedence exactly. */
typedef struct {
    const char *proxy_path;     /* --proxy   / $X509_USER_PROXY (else /tmp/x509up_u<uid>) */
    const char *bearer_literal; /* $BEARER_TOKEN                                          */
    const char *bearer_path;    /* $BEARER_TOKEN_FILE (else $XDG_RUNTIME_DIR/bt_u<uid>)   */
    const char *keytab_path;    /* $XrdSecSSSKT / $XrdSecsssKT / ~/.xrd/sss.keytab        */
    const char *ccache;         /* $KRB5CCNAME                                            */
    const char *s3_access;      /* --s3-access / $AWS_ACCESS_KEY_ID                       */
    const char *s3_secret;      /* --s3-secret / $AWS_SECRET_ACCESS_KEY                   */
    const char *oidc_account;   /* --oidc-account / $OIDC_ACCOUNT (bearer refresh)        */
    int         auto_refresh;   /* 1 = proactively re-acquire near expiry                 */
} xrdc_cred_config;

typedef struct xrdc_cred_store xrdc_cred_store;

xrdc_cred_store *xrdc_cred_store_new(const xrdc_cred_config *cfg);
void             xrdc_cred_store_free(xrdc_cred_store *s);

/* Acquire (discover+load, cached). If auto_refresh and the cached credential is
 * within min_remaining_s of expiry, re-acquire first. 0 + *view, or -1 (st) if no
 * usable credential of that kind exists. min_remaining_s <= 0 disables the check. */
int xrdc_cred_acquire(xrdc_cred_store *s, xrdc_cred_kind kind,
                      int min_remaining_s, xrdc_cred_view *view, xrdc_status *st);

/* Probe only (no load) — does a usable credential of this kind appear available?
 * Mirrors the sec-module have_creds() probe for auth pre-flight diagnostics. */
int xrdc_cred_available(xrdc_cred_store *s, xrdc_cred_kind kind);

/* Per-kind handler contract (implemented by cred_x509.c, cred_bearer.c, …). */
typedef struct {
    xrdc_cred_kind kind;
    int (*available)(const xrdc_cred_config *cfg);
    int (*acquire)(const xrdc_cred_config *cfg, xrdc_cred_view *out,
                   int64_t *not_after, xrdc_status *st);
    int (*refresh)(const xrdc_cred_config *cfg, xrdc_status *st);  /* NULL = no refresh */
} xrdc_cred_handler;

/* Handler accessors (NULL when compiled out, e.g. krb5 without XROOTD_HAVE_KRB5). */
const xrdc_cred_handler *xrdc_cred_x509(void);
const xrdc_cred_handler *xrdc_cred_bearer(void);
const xrdc_cred_handler *xrdc_cred_krb5(void);
const xrdc_cred_handler *xrdc_cred_sss(void);
const xrdc_cred_handler *xrdc_cred_s3keys(void);

#endif /* XRDC_CRED_H */
```

- [ ] **Step 2: Verify it compiles standalone**

Run: `cd client && gcc -std=c11 -I lib -fsyntax-only -x c lib/cred.h`
Expected: no output, exit 0.

- [ ] **Step 3: Commit**

```bash
git add client/lib/cred.h
git commit -m "feat(client): xrdc_cred common credential interface"
```

### Task B2: Store core (`cred.c`) — registry, cache, expiry, refresh gate

**Files:**
- Create: `client/lib/cred.c`
- Modify: `client/Makefile:97`
- Test: `client/tests/c/cred_unit.c` (new)

**Interfaces:**
- Consumes: the handler accessors from `cred.h`.
- Produces: `xrdc_cred_store_new/_free/_acquire/_available`. The store holds a `xrdc_cred_config cfg` (deep-copied), and a per-kind cache slot `{ int loaded; xrdc_cred_view view; char *owned strings; int64_t not_after; }`. `acquire` resolves the handler by `kind`, returns the cached view unless (a) not loaded or (b) `auto_refresh && not_after && now + min_remaining_s >= not_after` → call `handler->refresh` (if non-NULL) then `handler->acquire`, caching the result.

- [ ] **Step 1: Write the failing test (expiry gate + missing-credential error) with a stub handler**

```c
/* client/tests/c/cred_unit.c — uses a test seam: weak override of one accessor */
#include "../../lib/cred.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

/* exercise the public store behaviour against the real S3-keys handler, which is
 * pure env-discovery (no network): set/unset env and assert acquire/available. */
int main(void) {
    xrdc_status st = {0};

    /* error path: no S3 keys in the environment -> acquire fails cleanly */
    unsetenv("AWS_ACCESS_KEY_ID"); unsetenv("AWS_SECRET_ACCESS_KEY");
    xrdc_cred_config c0 = {0};
    xrdc_cred_store *s0 = xrdc_cred_store_new(&c0);
    xrdc_cred_view v;
    assert(xrdc_cred_available(s0, XRDC_CRED_S3KEYS) == 0);
    assert(xrdc_cred_acquire(s0, XRDC_CRED_S3KEYS, 0, &v, &st) == -1);
    xrdc_cred_store_free(s0);

    /* success path: keys present -> acquire returns them */
    setenv("AWS_ACCESS_KEY_ID", "AKIA_TEST", 1);
    setenv("AWS_SECRET_ACCESS_KEY", "secret_test", 1);
    xrdc_cred_config c1 = {0};
    xrdc_cred_store *s1 = xrdc_cred_store_new(&c1);
    assert(xrdc_cred_available(s1, XRDC_CRED_S3KEYS) == 1);
    assert(xrdc_cred_acquire(s1, XRDC_CRED_S3KEYS, 0, &v, &st) == 0);
    assert(strcmp(v.s3_access, "AKIA_TEST") == 0);
    assert(strcmp(v.s3_secret, "secret_test") == 0);
    xrdc_cred_store_free(s1);
    printf("cred store OK\n");
    return 0;
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd client && gcc -std=c11 -I lib tests/c/cred_unit.c lib/cred.c lib/cred_s3.c lib/status.c -o /tmp/cred_unit 2>&1 | head`
Expected: FAIL — `xrdc_cred_store_new` / `xrdc_cred_s3keys` undefined (cred.c + cred_s3.c not done; cred_s3.c lands in B6, but a minimal version can be stubbed here and completed there).

- [ ] **Step 3: Implement `cred.c`** (registry + cache + expiry gate per Interfaces). No `goto`.

- [ ] **Step 4: Run after B6** (the test depends on the real `cred_s3.c`; if implementing B-tasks in order, run this test at the end of B6). For B2 in isolation, substitute a local stub handler returning fixed keys and assert the cache/expiry logic.

- [ ] **Step 5: Add to build + commit**

```bash
cd client && make -j$(nproc) lib 2>&1 | grep -E ': (error|warning):'; echo done
git add client/lib/cred.c client/Makefile client/tests/c/cred_unit.c
git commit -m "feat(client): xrdc_cred store core (cache + expiry + refresh gate)"
```

### Task B3: X.509 proxy handler (`cred_x509.c`) — consolidate `sec_gsi` discovery

**Files:**
- Create: `client/lib/cred_x509.c`
- Modify: `client/Makefile:97`; `client/lib/sec/sec_gsi.c` (delegate `proxy_path`)
- Test: `tests/test_client_cred_preflight.py` (existing — must stay green), `client/tests/c/cred_unit.c` (extend)

**Interfaces:**
- Consumes: `xrdc_credfile_bio` (`lib/xrdc.h:961`) to validate/read the proxy; OpenSSL `X509` expiry to fill `not_after`.
- Produces: `xrdc_cred_x509()`. `available` = the `proxy_path()` probe from `sec_gsi.c:34-50` (`$X509_USER_PROXY` else `/tmp/x509up_u<uid>`, must exist + be readable). `acquire` fills `view.path` = resolved proxy path and `not_after` = the proxy cert's `notAfter`. `refresh` (when `cfg->auto_refresh`) = the voms/grid-proxy regeneration in `lib/credrefresh.c`.

- [ ] **Step 1: Write the failing test (proxy path discovery precedence)**

```c
/* append to cred_unit.c: $X509_USER_PROXY overrides the /tmp default */
{
    char tmpl[] = "/tmp/proxy_XXXXXX"; int fd = mkstemp(tmpl); assert(fd>=0); close(fd);
    setenv("X509_USER_PROXY", tmpl, 1);
    xrdc_cred_config c = {0}; xrdc_cred_store *s = xrdc_cred_store_new(&c);
    assert(xrdc_cred_available(s, XRDC_CRED_X509_PROXY) == 1);
    xrdc_cred_view v; xrdc_status st = {0};
    assert(xrdc_cred_acquire(s, XRDC_CRED_X509_PROXY, 0, &v, &st) == 0);
    assert(strcmp(v.path, tmpl) == 0);
    xrdc_cred_store_free(s); unsetenv("X509_USER_PROXY"); unlink(tmpl);
    printf("cred x509 discovery OK\n");
}
```

- [ ] **Step 2: Run to verify it fails**, then **Step 3: implement `cred_x509.c`** (move the `proxy_path`/expiry logic; `sec_gsi.c` keeps the AES wire-encryption but calls `xrdc_cred_acquire(... X509_PROXY ...)` for the path). **Step 4:** run `cred_unit` + `pytest tests/test_client_cred_preflight.py -q` (both green). **Step 5:** commit.

```bash
git add client/lib/cred_x509.c client/lib/sec/sec_gsi.c client/Makefile client/tests/c/cred_unit.c
git commit -m "feat(client): X.509 proxy credential handler; sec_gsi delegates discovery"
```

### Task B4: Bearer handler (`cred_bearer.c`) — consolidate `sec_token` + oidc refresh

**Files:**
- Create: `client/lib/cred_bearer.c`
- Modify: `client/Makefile:97`; `client/lib/sec/sec_token.c` (delegate); fold `lib/credrefresh.c`'s oidc-token path in.
- Test: `tests/test_client_autorefresh.py` (existing — must stay green), `cred_unit.c` (extend).

**Interfaces:**
- Consumes: env discovery order from `sec_token.c:86-139` (`$BEARER_TOKEN` → `$BEARER_TOKEN_FILE` → `$XDG_RUNTIME_DIR/bt_u<uid>`); JWT `exp` claim parse for `not_after` (decode the payload, read `exp`).
- Produces: `xrdc_cred_bearer()`. `acquire` fills `view.token` + `not_after` (from the JWT `exp`). `refresh` = `run_oidc_token(cfg->oidc_account, …)` (moved from `credrefresh.c:45`), installing the new token into the store cache.

- [ ] Steps mirror B3: failing test (env precedence: `$BEARER_TOKEN` beats `$BEARER_TOKEN_FILE`) → implement → `pytest tests/test_client_autorefresh.py -q` green → commit.

```bash
git commit -m "feat(client): bearer credential handler with oidc refresh; sec_token delegates"
```

### Task B5: Kerberos + SSS handlers (`cred_krb5.c`, `cred_sss.c`)

**Files:**
- Create: `client/lib/cred_krb5.c`, `client/lib/cred_sss.c`
- Modify: `client/Makefile:97`; `client/lib/sec/sec_krb5.c`, `sec_sss.c` (delegate)
- Test: `tests/test_krb5_auth.py` (krb5; needs the kdc harness), `cred_unit.c` (sss keytab discovery).

**Interfaces:**
- `xrdc_cred_krb5()`: `available` = `$KRB5CCNAME` (or default ccache) has a live TGT; `not_after` = TGT endtime; compiled to return NULL unless `XROOTD_HAVE_KRB5` (mirror `xrdc_sec_krb5`). `refresh` = NULL (TGT renewal is out of scope; `kinit` is the user's job — document this).
- `xrdc_cred_sss()`: `available`/`acquire` wrap `xrdc_sss_keytab_default` + `xrdc_sss_keytab_read` (already used by `sec_sss.c:48-49`); `view.path` = keytab path; `not_after` = 0 (keytab has no per-use expiry). `refresh` = NULL.

- [ ] Steps mirror B3 for each. Commit each handler separately.

```bash
git commit -m "feat(client): krb5 + sss credential handlers; sec modules delegate discovery"
```

### Task B6: S3-keys handler (`cred_s3.c`)

**Files:**
- Create: `client/lib/cred_s3.c`; Modify: `client/Makefile:97`
- Test: `client/tests/c/cred_unit.c` (the B2 test now links the real handler).

**Interfaces:**
- `xrdc_cred_s3keys()`: `available`/`acquire` from `cfg->s3_access/s3_secret` else `$AWS_ACCESS_KEY_ID`/`$AWS_SECRET_ACCESS_KEY` else `~/.aws/credentials` `[default]`. `not_after` = 0. `refresh` = NULL.

- [ ] Failing test = the B2 `cred_unit.c` cases; implement; run `/tmp/cred_unit` green; commit.

```bash
git commit -m "feat(client): S3-keys credential handler (env + ~/.aws/credentials)"
```

---

# PART C — Integration into the tools

Depends on A6 + B6. Wires one credential store per tool invocation into both the VFS (s3 keys/bearer) and the connection auth path.

### Task C1: Build one `xrdc_cred_store` from CLI/env in the tool front-ends

**Files:**
- Modify: `client/lib/cli_opts.c` (add `--proxy/--s3-access/--s3-secret/--oidc-account/--auto-refresh` parsing into an `xrdc_cred_config`), `client/lib/cli_conn.c` (construct the store, hang it off the shared connection context).
- Test: `tests/test_conf_client.py`, `tests/test_client_robustness.py` (regression).

**Interfaces:**
- Consumes: `xrdc_cred_store_new` (B2).
- Produces: a `xrdc_cred_store *` reachable from `xrdcp`/`xrdfs`/`xrootdfs` for both the VFS opts (`xrdc_vfs_open_opts.cred`) and the sec handshake.

- [ ] Failing test: `xrdcp --auto-refresh …` parses without error and the store is non-NULL (assert via a `--doctor`/diagnostic path that prints acquired credential kinds). Implement → regression green → commit.

### Task C2: Point the sec modules + web transports at the store

**Files:**
- Modify: `client/lib/sec/*.c` `have_creds`/`first` to call `xrdc_cred_available`/`_acquire` (replacing their inline discovery — the discovery code already moved to the handlers in B3–B6, so this is deleting the now-dead per-module probes and calling the store). `client/lib/webfile.c` + `lib/s3.c` to pull bearer/keys from the store instead of threaded raw-string params.
- Test: full client suite (`tests/test_client_*.py`) + `tests/test_a_webdav_clients.py`.

**Interfaces:** Consumes B + the C1 store handle.

- [ ] **Step 1: Regression baseline** — `PYTHONPATH=tests pytest tests/test_client_robustness.py tests/test_client_cred_preflight.py tests/test_client_autorefresh.py tests/test_a_webdav_clients.py -q` (record counts).
- [ ] **Step 2:** Replace the threaded `bearer` string in `webfile.c`/`s3.c` entry points with `xrdc_cred_acquire(store, XRDC_CRED_BEARER/_S3KEYS, refresh_window, &view, st)`.
- [ ] **Step 3:** Delete the now-duplicated inline discovery left in the sec modules; route through the store.
- [ ] **Step 4: Same pass counts as Step 1.**
- [ ] **Step 5: Commit.**

```bash
git commit -m "refactor(client): sec modules + web transports draw credentials from xrdc_cred store"
```

### Task C3: `s3://` as a first-class copy endpoint end-to-end

**Files:**
- Modify: `client/apps/xrdcp.c` (accept `s3://` on either side, routing the local-or-remote object through the VFS s3 backend with the store's keys), docs in `client/README` (or `docs/`).
- Test: `tests/test_client_web_transfer.py` (extend: `s3://`→`s3://`, `s3://`→local, local→`s3://`, and a block-device dest behind a loop file).

- [ ] Failing tests for the three S3 directions + one block dest → implement routing → green → commit.

```bash
git commit -m "feat(client): xrdcp supports s3:// and block:// endpoints via xrdc_vfs"
```

---

## Self-Review

**Spec coverage:**
- "local VFS layer so client tools may support S3 or block as well as POSIX" → Part A (A1 interface, A3 posix, A4 block, A5 s3, A6 copy.c migration, C3 end-to-end). ✔
- "common gsi/token/krb5/sss layer for acquiring credentials" → Part B (B1 interface, B3 gsi/x509, B4 token/bearer, B5 krb5+sss, B6 s3keys, B2 store) + C1/C2 wiring into both the root:// handshake and HTTP/S3 transports. ✔
- The commit-semantics crux (POSIX rename / S3 multipart / block fsync) → explicit `commit`/`abort` ops, exercised in A3/A4/A5 tests. ✔

**Placeholder scan:** no TBD/TODO; migration steps cite exact `file:line` anchors and the existing function/pattern to follow rather than fabricated diffs (the anchors were verified against the tree on 2026-06-26). New interfaces (`vfs.h`, `cred.h`) and all unit tests are given in full.

**Type consistency:** `xrdc_vfs_file`/`xrdc_vfs_ops`/`xrdc_vfs_open_opts` names match across A1–A6; `xrdc_cred_store`/`xrdc_cred_view`/`xrdc_cred_acquire` match across B1–C2; `xrdc_cred_store` is forward-declared in `vfs.h` (A1) exactly as defined in `cred.h` (B1), so `xrdc_vfs_open_opts.cred` and `xrdc_cred_store_new` agree.

**Known risks / decisions to confirm during execution:**
- S3 `pwrite` is sequential-only (multipart parts). `copy.c`'s pump is already sequential for the streaming path, so this fits; random-write callers (none today on the local-dest path) would get `XRDC_EIO`. Confirm no caller needs random-write to an S3 dest.
- krb5/sss `refresh` are NULL by design (TGT renewal / keytab rotation are out of scope). Documented in B5.
- Part A and Part B are independently shippable; if scope must shrink, ship Part A first (S3/block endpoints) or Part B first (unified credentials) without the other.

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-06-26-xrdc-vfs-and-credential-layer.md`. Two execution options:

1. **Subagent-Driven (recommended)** — a fresh subagent per task, review between tasks, fast iteration.
2. **Inline Execution** — execute tasks in this session with checkpoints for review.

Which approach?
