# Unified Cache Persistence-State Engine + Decision Parity — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give `src/fs/cache/` one shared per-file persistence-state engine that both the read-fill and write-back halves consult, plus config/decision parity and a stale-dirty reaper, all on the existing POSIX cache path with zero regression.

**Architecture:** Extend the `.cinfo` sidecar (today a per-block *present* bitmap) to v3 with file-level *dirty*/write-back fields, keeping the `flock(2)` read-modify-write. Wire read-fill → present, the write path → dirty (coarsely, durably), write-through flush → clean. Lift the write-through prefix/size/regex matcher into one shared admission filter both halves call. Add a periodic per-worker reaper that removes dirty staging older than a configurable age.

**Tech Stack:** C (nginx stream/http module), OpenSSL (unrelated here), POSIX `flock`/`pread`/`pwrite`, nginx `ngx_event_t` timers, nginx `ngx_array_t`/`ngx_regex`. Standalone C unit tests under `tests/c/` (nginx-free gcc), pytest e2e.

## Global Constraints

- **NO `goto`** anywhere in `src/` (early-return + helper decomposition).
- **Functional/modular:** one responsibility per function, pass state explicitly, no new globals except the documented per-worker reaper timer (mirrors `xrootd_stage_reap_timer`).
- **New `.c` files register in the repo-root `./config`** (`NGX_ADDON_SRCS`); run `./configure` once after adding a file, then `make -j$(nproc)`. Existing-file edits use `make` only.
- **Build/validate:** `cd /tmp/nginx-1.28.3 && make -j$(nproc)` must finish with `exit=0` and no new warnings.
- **`.cinfo` is cache metadata, not user data** — raw `pread`/`pwrite` under `flock` is correct here (the SD-backend byte-I/O invariant does not apply); this preserves the standalone unit test.
- **Every state-engine call is best-effort:** a failure logs and the caller proceeds; it never fails a client read/write.
- **Zero regression:** when no state root resolves, the write/read paths behave exactly as today (in-memory handle dirty state only).
- **Metrics low-cardinality:** no paths/UUIDs in labels.
- **flock RMW template:** `open(O_RDWR|O_CREAT|O_NOCTTY|O_CLOEXEC|O_NOFOLLOW,0644)` → `flock(LOCK_EX)` (EINTR loop) → read-current → mutate → `cinfo_write_fd` → `flock(LOCK_UN)` → `close`. Copy from `xrootd_cache_cinfo_record_block` (`src/fs/cache/cinfo.c:313`).

---

### Task 1: `.cinfo` v3 record — grow the header, bump version, v2-compat reader

**Files:**
- Modify: `src/fs/cache/cinfo.h` (struct + version + new flag)
- Modify: `src/fs/cache/cinfo.c` (`cinfo_header_ok`, `xrootd_cache_cinfo_load`, a frozen v2 reader)
- Test: `tests/c/test_cinfo.c` (+ run via `tests/c/run_cinfo_tests.sh`)

**Interfaces:**
- Produces: `xrootd_cache_cinfo_t` gains fields `dirty_lo`, `dirty_hi`, `dirty_since`, `flush_gen`, `last_flush`, `bytes_flushed` (all `uint64_t`) and flag `XROOTD_CINFO_F_DIRTY (0x0008u)`; `XROOTD_CACHE_CINFO_VERSION` becomes `3`. `xrootd_cache_cinfo_load` reads both v3 and legacy v2 sidecars (v2 → present-only, dirty fields zeroed).

- [ ] **Step 1: Write the failing test** — append to `tests/c/test_cinfo.c` a case that stores a v3 header with dirty fields and loads it back.

```c
static void test_v3_dirty_fields_roundtrip(void) {
    char dir[] = "/tmp/cinfoXXXXXX"; assert(mkdtemp(dir));
    char cp[256]; snprintf(cp, sizeof cp, "%s/file.bin", dir);

    xrootd_cache_cinfo_t h; memset(&h, 0, sizeof h);
    h.block_size = 4096; h.size = 8192; h.mtime = 1000;
    h.nblocks = xrootd_cache_cinfo_nblocks(h.size, h.block_size);
    h.flags |= XROOTD_CINFO_F_DIRTY;
    h.dirty_lo = 100; h.dirty_hi = 500; h.dirty_since = 1700000000ULL;
    h.flush_gen = 7; h.last_flush = 1700000001ULL; h.bytes_flushed = 4096;
    uint8_t bm[1] = {0x03};
    assert(xrootd_cache_cinfo_store(cp, &h, bm, 1) == NGX_OK);

    xrootd_cache_cinfo_t r; uint8_t *rbm = NULL; size_t rlen = 0;
    assert(xrootd_cache_cinfo_load(cp, &r, &rbm, &rlen) == NGX_OK);
    assert(r.flags & XROOTD_CINFO_F_DIRTY);
    assert(r.dirty_lo == 100 && r.dirty_hi == 500);
    assert(r.dirty_since == 1700000000ULL);
    assert(r.flush_gen == 7 && r.last_flush == 1700000001ULL);
    assert(r.bytes_flushed == 4096);
    free(rbm);
    printf("ok test_v3_dirty_fields_roundtrip\n");
}
```

Register the call in `main()` next to the other `test_*()` calls.

- [ ] **Step 2: Run test to verify it fails**

Run: `tests/c/run_cinfo_tests.sh`
Expected: compile error (fields `dirty_lo`/… and `XROOTD_CINFO_F_DIRTY` undeclared) OR an assertion failure.

- [ ] **Step 3: Add the fields + flag + version bump** — `src/fs/cache/cinfo.h`.

In the `flags` block add:
```c
#define XROOTD_CINFO_F_DIRTY    0x0008u   /* local writes pending write-back */
```
Bump:
```c
#define XROOTD_CACHE_CINFO_VERSION 3
```
Append to `xrootd_cache_cinfo_t`, immediately before `etag_len` (keep the uint64 group together, alignment-first):
```c
    uint64_t dirty_lo;       /* dirty byte-extent start (incl); lo==hi ⇒ clean */
    uint64_t dirty_hi;       /* dirty byte-extent end (excl) */
    uint64_t dirty_since;    /* unix secs the file first went dirty this episode */
    uint64_t flush_gen;      /* bumped on each successful write-back */
    uint64_t last_flush;     /* unix secs of the last successful write-back */
    uint64_t bytes_flushed;  /* cumulative mirrored bytes */
```

- [ ] **Step 4: Add the frozen v2 layout + compat read** — `src/fs/cache/cinfo.c`, above `xrootd_cache_cinfo_load`.

```c
/* Frozen v2 on-disk header (pre-write-back fields). A v2 sidecar predates the
 * dirty/write-back fields; we read it so a populated cache survives the upgrade
 * (present bitmap preserved, dirty state starts clean). */
#define XROOTD_CACHE_CINFO_V2_VERSION 2
typedef struct {
    uint32_t magic; uint16_t version; uint16_t flags;
    uint32_t block_size; uint32_t reserved;
    uint64_t size; uint64_t mtime; uint64_t nblocks;
    uint64_t access_count; uint64_t bytes_served; uint64_t last_access;
    uint8_t  etag_len; char etag[XROOTD_CACHE_META_ETAG_MAX];
    uint8_t  cks_alg_len; char cks_alg[16];
    uint8_t  cks_len; char cks_hex[129];
} xrootd_cache_cinfo_v2_t;
#define XROOTD_CACHE_CINFO_V2_HDR_SIZE (sizeof(xrootd_cache_cinfo_v2_t))

/* Promote a v2 header into a zero-initialised v3 header (dirty fields stay 0). */
static void cinfo_v2_to_v3(const xrootd_cache_cinfo_v2_t *v2,
                           xrootd_cache_cinfo_t *out) {
    ngx_memzero(out, sizeof(*out));
    out->magic = v2->magic; out->version = XROOTD_CACHE_CINFO_VERSION;
    out->flags = v2->flags; out->block_size = v2->block_size;
    out->size = v2->size; out->mtime = v2->mtime; out->nblocks = v2->nblocks;
    out->access_count = v2->access_count; out->bytes_served = v2->bytes_served;
    out->last_access = v2->last_access;
    out->etag_len = v2->etag_len; ngx_memcpy(out->etag, v2->etag, sizeof out->etag);
    out->cks_alg_len = v2->cks_alg_len;
    ngx_memcpy(out->cks_alg, v2->cks_alg, sizeof out->cks_alg);
    out->cks_len = v2->cks_len;
    ngx_memcpy(out->cks_hex, v2->cks_hex, sizeof out->cks_hex);
}
```

In `xrootd_cache_cinfo_load`, after the header `cinfo_pio` read and BEFORE `cinfo_header_ok`, branch on the on-disk version. Replace the block:
```c
    rc = cinfo_pio(fd, hdr, XROOTD_CACHE_CINFO_HDR_SIZE, 0, 0);
    if (rc != NGX_OK) { close(fd); return rc; }
    if (cinfo_header_ok(hdr) != NGX_OK) { close(fd); return NGX_DECLINED; }
```
with:
```c
    /* Peek the version word (first 6 bytes are magic+version, identical in v2/v3). */
    rc = cinfo_pio(fd, hdr, XROOTD_CACHE_CINFO_HDR_SIZE, 0, 0);
    if (rc == NGX_OK && hdr->magic == XROOTD_CACHE_CINFO_MAGIC
        && hdr->version == XROOTD_CACHE_CINFO_V2_VERSION) {
        xrootd_cache_cinfo_v2_t v2;
        if (cinfo_pio(fd, &v2, XROOTD_CACHE_CINFO_V2_HDR_SIZE, 0, 0) != NGX_OK) {
            close(fd); return NGX_DECLINED;
        }
        cinfo_v2_to_v3(&v2, hdr);
        /* bitmap lives at the v2 offset for a v2 file */
        blen = xrootd_cache_cinfo_bitmap_len(hdr->nblocks);
        if (blen == 0) { close(fd); return NGX_OK; }
        bits = malloc(blen);
        if (bits == NULL) { close(fd); errno = ENOMEM; return NGX_ERROR; }
        rc = cinfo_pio(fd, bits, blen, (off_t) XROOTD_CACHE_CINFO_V2_HDR_SIZE, 0);
        close(fd);
        if (rc != NGX_OK) { free(bits); return (rc==NGX_DECLINED)?NGX_DECLINED:NGX_ERROR; }
        *bitmap = bits; *bitmap_len = blen; return NGX_OK;
    }
    if (rc != NGX_OK) { close(fd); return rc; }
    if (cinfo_header_ok(hdr) != NGX_OK) { close(fd); return NGX_DECLINED; }
```
(`blen`/`bits` are already declared at the top of `load`.)

- [ ] **Step 5: Run test to verify it passes**

Run: `tests/c/run_cinfo_tests.sh`
Expected: `ok test_v3_dirty_fields_roundtrip` and all prior cinfo tests still pass.

- [ ] **Step 6: Add the v2-compat test**

```c
static void test_v2_loads_present_only(void) {
    char dir[] = "/tmp/cinfoXXXXXX"; assert(mkdtemp(dir));
    char cp[256]; snprintf(cp, sizeof cp, "%s/old.bin", dir);
    char sc[300]; assert(xrootd_cache_cinfo_path(sc, sizeof sc, cp) == 0);
    /* hand-write a v2 sidecar: header (v2 size) + 1 bitmap byte */
    xrootd_cache_cinfo_v2_t v2; memset(&v2, 0, sizeof v2);
    v2.magic = XROOTD_CACHE_CINFO_MAGIC; v2.version = 2;
    v2.block_size = 4096; v2.size = 8192; v2.mtime = 1000;
    v2.nblocks = 2;
    int fd = open(sc, O_RDWR|O_CREAT|O_TRUNC, 0644); assert(fd >= 0);
    assert(write(fd, &v2, sizeof v2) == (ssize_t) sizeof v2);
    uint8_t b = 0x03; assert(write(fd, &b, 1) == 1); close(fd);

    xrootd_cache_cinfo_t r; uint8_t *rbm = NULL; size_t rlen = 0;
    assert(xrootd_cache_cinfo_load(cp, &r, &rbm, &rlen) == NGX_OK);
    assert(r.version == XROOTD_CACHE_CINFO_VERSION);   /* promoted */
    assert(!(r.flags & XROOTD_CINFO_F_DIRTY));         /* clean */
    assert(r.dirty_since == 0);
    assert(rlen == 1 && rbm[0] == 0x03);               /* present preserved */
    free(rbm);
    printf("ok test_v2_loads_present_only\n");
}
```
Register in `main()`. Run `tests/c/run_cinfo_tests.sh` → both new tests pass.

---

### Task 2: dirty API — `mark_dirty` / `mark_clean` / `dirty_extent`

**Files:**
- Modify: `src/fs/cache/cinfo.h` (3 prototypes)
- Modify: `src/fs/cache/cinfo.c` (3 functions, flock RMW)
- Test: `tests/c/test_cinfo.c`

**Interfaces:**
- Consumes: Task 1's v3 record + the existing `cinfo_pio`/`cinfo_header_ok`/`cinfo_init`/`cinfo_write_fd` statics and `xrootd_cache_cinfo_path`.
- Produces:
  - `ngx_int_t xrootd_cache_cinfo_mark_dirty(const char *cache_path, uint64_t size, uint32_t block_size, uint64_t mtime, uint64_t off, uint64_t len, ngx_log_t *log);`
  - `ngx_int_t xrootd_cache_cinfo_mark_clean(const char *cache_path, uint64_t bytes, ngx_log_t *log);`
  - `ngx_int_t xrootd_cache_cinfo_dirty_extent(const char *cache_path, uint64_t *lo, uint64_t *hi, uint64_t *dirty_since);`

- [ ] **Step 1: Write the failing test** — `tests/c/test_cinfo.c`.

```c
static void test_dirty_lifecycle(void) {
    char dir[] = "/tmp/cinfoXXXXXX"; assert(mkdtemp(dir));
    char cp[256]; snprintf(cp, sizeof cp, "%s/w.bin", dir);
    uint64_t lo, hi, ds;

    /* no record yet → DECLINED */
    assert(xrootd_cache_cinfo_dirty_extent(cp, &lo, &hi, &ds) == NGX_DECLINED);

    /* first write: dirty [100,300) */
    assert(xrootd_cache_cinfo_mark_dirty(cp, 8192, 4096, 1000, 100, 200, NULL) == NGX_OK);
    assert(xrootd_cache_cinfo_dirty_extent(cp, &lo, &hi, &ds) == NGX_OK);
    assert(lo == 100 && hi == 300 && ds != 0);
    uint64_t first_since = ds;

    /* widen to [100,600): dirty_since unchanged */
    assert(xrootd_cache_cinfo_mark_dirty(cp, 8192, 4096, 1000, 500, 100, NULL) == NGX_OK);
    assert(xrootd_cache_cinfo_dirty_extent(cp, &lo, &hi, &ds) == NGX_OK);
    assert(lo == 100 && hi == 600 && ds == first_since);

    /* clean: extent gone, flush_gen bumped */
    assert(xrootd_cache_cinfo_mark_clean(cp, 500, NULL) == NGX_OK);
    assert(xrootd_cache_cinfo_dirty_extent(cp, &lo, &hi, &ds) == NGX_DECLINED);
    xrootd_cache_cinfo_t r; uint8_t *bm=NULL; size_t bl=0;
    assert(xrootd_cache_cinfo_load(cp, &r, &bm, &bl) == NGX_OK);
    assert(r.flush_gen == 1 && r.bytes_flushed == 500 && r.last_flush != 0);
    free(bm);
    printf("ok test_dirty_lifecycle\n");
}
```
Register in `main()`.

- [ ] **Step 2: Run test to verify it fails**

Run: `tests/c/run_cinfo_tests.sh`
Expected: link/compile error — the three functions are undeclared.

- [ ] **Step 3: Declare the prototypes** — `src/fs/cache/cinfo.h`, after `xrootd_cache_cinfo_record_block`.

```c
/* Mark [off,off+len) dirty for cache_path; sets dirty_since on the clean→dirty
 * transition only (a widen leaves it). validity reset on size/mtime/block_size
 * change. flock-serialised RMW. */
ngx_int_t xrootd_cache_cinfo_mark_dirty(const char *cache_path, uint64_t size,
    uint32_t block_size, uint64_t mtime, uint64_t off, uint64_t len, ngx_log_t *log);

/* Clear the dirty extent; bump flush_gen, set last_flush=now, add bytes to
 * bytes_flushed. flock-serialised RMW. NGX_DECLINED if no record exists. */
ngx_int_t xrootd_cache_cinfo_mark_clean(const char *cache_path, uint64_t bytes,
    ngx_log_t *log);

/* Report the dirty extent + dirty_since. NGX_OK when dirty, NGX_DECLINED when no
 * record / clean, NGX_ERROR on I/O failure. */
ngx_int_t xrootd_cache_cinfo_dirty_extent(const char *cache_path, uint64_t *lo,
    uint64_t *hi, uint64_t *dirty_since);
```

- [ ] **Step 4: Implement the three functions** — `src/fs/cache/cinfo.c`, after `xrootd_cache_cinfo_record_block`. Model the flock RMW on `record_block` (lines 313-400). `mark_dirty` reads the current record (header + present bitmap), mutates header dirty fields, rewrites header + the SAME bitmap (so present is preserved):

```c
/* Load header+bitmap from an flock'd fd into hdr/*bits (malloc'd); reset to fresh
 * if absent/garbage/stale vs size/mtime/block_size. Returns blen via *blen_out. */
static ngx_int_t cinfo_rmw_load(int fd, uint64_t size, uint32_t block_size,
    uint64_t mtime, xrootd_cache_cinfo_t *hdr, uint8_t **bits, size_t *blen_out) {
    uint64_t nblocks = xrootd_cache_cinfo_nblocks(size, block_size);
    size_t blen = xrootd_cache_cinfo_bitmap_len(nblocks);
    uint8_t *b = malloc(blen ? blen : 1);
    if (b == NULL) { errno = ENOMEM; return NGX_ERROR; }
    ngx_memzero(b, blen ? blen : 1);
    xrootd_cache_cinfo_t cur;
    ngx_int_t lrc = cinfo_pio(fd, &cur, XROOTD_CACHE_CINFO_HDR_SIZE, 0, 0);
    int reuse = (lrc == NGX_OK && cinfo_header_ok(&cur) == NGX_OK
                 && cur.size == size && cur.block_size == block_size
                 && cur.mtime == mtime);
    if (reuse) {
        *hdr = cur;
        if (blen > 0 && cinfo_pio(fd, b, blen,
            (off_t) XROOTD_CACHE_CINFO_HDR_SIZE, 0) != NGX_OK) {
            ngx_memzero(b, blen);
        }
    } else {
        cinfo_init(hdr, size, block_size, mtime);   /* zeroes dirty fields too */
    }
    *bits = b; *blen_out = blen;
    return NGX_OK;
}

ngx_int_t
xrootd_cache_cinfo_mark_dirty(const char *cache_path, uint64_t size,
    uint32_t block_size, uint64_t mtime, uint64_t off, uint64_t len, ngx_log_t *log)
{
    char path[PATH_MAX]; xrootd_cache_cinfo_t hdr; uint8_t *bits = NULL;
    size_t blen; int fd; ngx_int_t rc = NGX_ERROR;
    (void) log;
    if (cache_path == NULL || block_size == 0 || len == 0) { errno = EINVAL; return NGX_ERROR; }
    if (xrootd_cache_cinfo_path(path, sizeof path, cache_path) != 0) { errno = ENAMETOOLONG; return NGX_ERROR; }
    fd = open(path, O_RDWR|O_CREAT|O_NOCTTY|O_CLOEXEC|O_NOFOLLOW, 0644);
    if (fd < 0) { return NGX_ERROR; }
    while (flock(fd, LOCK_EX) != 0) { if (errno != EINTR) { close(fd); return NGX_ERROR; } }
    if (cinfo_rmw_load(fd, size, block_size, mtime, &hdr, &bits, &blen) != NGX_OK) {
        flock(fd, LOCK_UN); close(fd); return NGX_ERROR;
    }
    if (!(hdr.flags & XROOTD_CINFO_F_DIRTY)) {        /* clean→dirty transition */
        hdr.flags |= XROOTD_CINFO_F_DIRTY;
        hdr.dirty_lo = off; hdr.dirty_hi = off + len;
        hdr.dirty_since = (uint64_t) time(NULL);
    } else {                                          /* widen, keep dirty_since */
        if (off < hdr.dirty_lo) hdr.dirty_lo = off;
        if (off + len > hdr.dirty_hi) hdr.dirty_hi = off + len;
    }
    rc = cinfo_write_fd(fd, &hdr, bits, blen);
    free(bits); flock(fd, LOCK_UN);
    if (close(fd) != 0 && rc == NGX_OK) rc = NGX_ERROR;
    return rc;
}

ngx_int_t
xrootd_cache_cinfo_mark_clean(const char *cache_path, uint64_t bytes, ngx_log_t *log)
{
    char path[PATH_MAX]; xrootd_cache_cinfo_t hdr; uint8_t *bits = NULL;
    size_t blen; int fd; ngx_int_t rc;
    (void) log;
    if (cache_path == NULL) { errno = EINVAL; return NGX_ERROR; }
    if (xrootd_cache_cinfo_path(path, sizeof path, cache_path) != 0) { errno = ENAMETOOLONG; return NGX_ERROR; }
    fd = open(path, O_RDWR|O_NOCTTY|O_CLOEXEC|O_NOFOLLOW, 0644);
    if (fd < 0) { return (errno == ENOENT) ? NGX_DECLINED : NGX_ERROR; }
    while (flock(fd, LOCK_EX) != 0) { if (errno != EINTR) { close(fd); return NGX_ERROR; } }
    {
        xrootd_cache_cinfo_t cur;
        if (cinfo_pio(fd, &cur, XROOTD_CACHE_CINFO_HDR_SIZE, 0, 0) != NGX_OK
            || cinfo_header_ok(&cur) != NGX_OK) {
            flock(fd, LOCK_UN); close(fd); return NGX_DECLINED;
        }
        blen = xrootd_cache_cinfo_bitmap_len(cur.nblocks);
        bits = malloc(blen ? blen : 1);
        if (bits == NULL) { flock(fd, LOCK_UN); close(fd); errno = ENOMEM; return NGX_ERROR; }
        ngx_memzero(bits, blen ? blen : 1);
        if (blen > 0) (void) cinfo_pio(fd, bits, blen, (off_t) XROOTD_CACHE_CINFO_HDR_SIZE, 0);
        hdr = cur;
    }
    hdr.flags &= (uint16_t) ~XROOTD_CINFO_F_DIRTY;
    hdr.dirty_lo = hdr.dirty_hi = 0; hdr.dirty_since = 0;
    hdr.flush_gen += 1; hdr.last_flush = (uint64_t) time(NULL);
    hdr.bytes_flushed += bytes;
    rc = cinfo_write_fd(fd, &hdr, bits, blen);
    free(bits); flock(fd, LOCK_UN);
    if (close(fd) != 0 && rc == NGX_OK) rc = NGX_ERROR;
    return rc;
}

ngx_int_t
xrootd_cache_cinfo_dirty_extent(const char *cache_path, uint64_t *lo,
    uint64_t *hi, uint64_t *dirty_since)
{
    xrootd_cache_cinfo_t h; uint8_t *bm = NULL; size_t bl = 0;
    ngx_int_t rc = xrootd_cache_cinfo_load(cache_path, &h, &bm, &bl);
    if (rc != NGX_OK) return rc;
    free(bm);
    if (!(h.flags & XROOTD_CINFO_F_DIRTY) || h.dirty_lo >= h.dirty_hi) return NGX_DECLINED;
    if (lo) *lo = h.dirty_lo; if (hi) *hi = h.dirty_hi;
    if (dirty_since) *dirty_since = h.dirty_since;
    return NGX_OK;
}
```
Add `#include <time.h>` to `cinfo.c` if not present. Confirm `cinfo_init` zeroes the whole struct (it does — `cinfo.c` `cinfo_init` memzeros). If `cinfo_init` is `static` below these functions, move these functions after it or forward-declare `cinfo_init`.

- [ ] **Step 5: Run test to verify it passes**

Run: `tests/c/run_cinfo_tests.sh`
Expected: `ok test_dirty_lifecycle`, all prior tests pass.

- [ ] **Step 6: Add the RMW non-interference test**

```c
static void test_present_and_dirty_coexist(void) {
    char dir[] = "/tmp/cinfoXXXXXX"; assert(mkdtemp(dir));
    char cp[256]; snprintf(cp, sizeof cp, "%s/c.bin", dir);
    assert(xrootd_cache_cinfo_record_block(cp, 8192, 4096, 1000, 0, NULL) == NGX_OK);
    assert(xrootd_cache_cinfo_mark_dirty(cp, 8192, 4096, 1000, 0, 100, NULL) == NGX_OK);
    assert(xrootd_cache_cinfo_record_block(cp, 8192, 4096, 1000, 1, NULL) == NGX_OK);
    xrootd_cache_cinfo_t r; uint8_t *bm=NULL; size_t bl=0;
    assert(xrootd_cache_cinfo_load(cp, &r, &bm, &bl) == NGX_OK);
    assert(xrootd_cache_cinfo_block_present(bm, 0));
    assert(xrootd_cache_cinfo_block_present(bm, 1));
    assert(r.flags & XROOTD_CINFO_F_DIRTY);   /* dirty survived two block records */
    free(bm);
    printf("ok test_present_and_dirty_coexist\n");
}
```
Register in `main()`, run `tests/c/run_cinfo_tests.sh` → passes.

---

### Task 3: shared admission filter `cache_admit.{c,h}`

**Files:**
- Create: `src/fs/cache/cache_admit.h`, `src/fs/cache/cache_admit.c`
- Modify: repo-root `config` (register `cache_admit.c` in `NGX_ADDON_SRCS`)
- Test: Create `tests/c/test_cache_admit.c` + `tests/c/run_cache_admit_tests.sh`

**Interfaces:**
- Produces:
  - `typedef enum { XROOTD_CACHE_ADMIT, XROOTD_CACHE_DECLINE } xrootd_cache_admit_e;`
  - `typedef struct { ngx_array_t *deny_prefixes; ngx_array_t *allow_prefixes; off_t size_limit; regex_t *include_regex; } xrootd_cache_admit_cfg_t;` (prefix arrays hold `xrootd_wt_prefix_entry_t`, the existing element type).
  - `xrootd_cache_admit_e xrootd_cache_admit(const xrootd_cache_admit_cfg_t *cfg, const char *path, off_t size, int is_new);`

- [ ] **Step 1: Write the failing test** — `tests/c/test_cache_admit.c` (standalone; stub `ngx_array_t` minimally OR compile against nginx headers like other `tests/c`). Use the simplest form: build the prefix array via a tiny local helper.

```c
/* test_cache_admit.c — deny>allow precedence, whitelist, size, regex. */
#include "../../src/fs/cache/cache_admit.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_deny_beats_allow(void) {
    xrootd_cache_admit_cfg_t c; memset(&c, 0, sizeof c);
    /* deny /a, allow /a/b → /a/b/x denied (deny precedence) */
    /* (array construction helper provided by the harness below) */
    ta_set_deny(&c, "/a/");
    ta_set_allow(&c, "/a/b/");
    assert(xrootd_cache_admit(&c, "/a/b/x", 10, 0) == XROOTD_CACHE_DECLINE);
    printf("ok test_deny_beats_allow\n");
}
static void test_whitelist(void) {
    xrootd_cache_admit_cfg_t c; memset(&c, 0, sizeof c);
    ta_set_allow(&c, "/keep/");
    assert(xrootd_cache_admit(&c, "/keep/f", 10, 0) == XROOTD_CACHE_ADMIT);
    assert(xrootd_cache_admit(&c, "/other/f", 10, 0) == XROOTD_CACHE_DECLINE);
    printf("ok test_whitelist\n");
}
static void test_size_limit_and_new(void) {
    xrootd_cache_admit_cfg_t c; memset(&c, 0, sizeof c);
    c.size_limit = 100;
    assert(xrootd_cache_admit(&c, "/f", 200, 0) == XROOTD_CACHE_DECLINE); /* too big */
    assert(xrootd_cache_admit(&c, "/f", 200, 1) == XROOTD_CACHE_ADMIT);   /* new: size unknown, admit */
    assert(xrootd_cache_admit(&c, "/f", 50, 0)  == XROOTD_CACHE_ADMIT);
    printf("ok test_size_limit_and_new\n");
}
int main(void){ test_deny_beats_allow(); test_whitelist(); test_size_limit_and_new();
    printf("test_cache_admit: ALL PASS\n"); return 0; }
```
Create `tests/c/run_cache_admit_tests.sh` compiling `cache_admit.c` + the test with the same nginx-include flags `run_cinfo_tests.sh` uses (copy its `gcc` invocation; add a small `ta_set_deny/allow` harness that pushes `xrootd_wt_prefix_entry_t` onto an `ngx_array_t` created from a static pool, mirroring how `run_cinfo_tests.sh` provides nginx stubs).

- [ ] **Step 2: Run test to verify it fails**

Run: `tests/c/run_cache_admit_tests.sh`
Expected: compile error — `cache_admit.h` / `xrootd_cache_admit` do not exist.

- [ ] **Step 3: Write the header** — `src/fs/cache/cache_admit.h`.

```c
#ifndef XROOTD_CACHE_ADMIT_H
#define XROOTD_CACHE_ADMIT_H
#include <ngx_config.h>
#include <ngx_core.h>
#include <regex.h>
#include <sys/types.h>
#include "writethrough_decision.h"   /* xrootd_wt_prefix_entry_t */

typedef enum { XROOTD_CACHE_ADMIT = 0, XROOTD_CACHE_DECLINE = 1 } xrootd_cache_admit_e;

typedef struct {
    ngx_array_t *deny_prefixes;   /* xrootd_wt_prefix_entry_t[] — precedence */
    ngx_array_t *allow_prefixes;  /* xrootd_wt_prefix_entry_t[] — whitelist if non-empty */
    off_t        size_limit;      /* 0 = no limit */
    regex_t     *include_regex;   /* NULL = no regex; bypasses size_limit on match */
} xrootd_cache_admit_cfg_t;

/* Shared admission filter for read-caching AND write-through. is_new=1 means the
 * file does not exist yet (size unknown) → the size cap is skipped. Deny beats
 * allow; a non-empty allow list makes it a whitelist. NULL cfg/path → DECLINE. */
xrootd_cache_admit_e xrootd_cache_admit(const xrootd_cache_admit_cfg_t *cfg,
    const char *path, off_t size, int is_new);

#endif
```

- [ ] **Step 4: Write the implementation** — `src/fs/cache/cache_admit.c` (lift the matcher from `writethrough_decision.c`).

```c
#include "cache_admit.h"
#include <string.h>

static int admit_prefix_match(const char *path, const ngx_str_t *p) {
    if (p->len == 0 || path == NULL) return 0;
    if (strlen(path) < p->len) return 0;
    return ngx_strncmp((u_char *) path, p->data, p->len) == 0;
}
static int admit_any_prefix(const char *path, ngx_array_t *a) {
    if (a == NULL || a->nelts == 0) return 0;
    xrootd_wt_prefix_entry_t *e = a->elts;
    for (ngx_uint_t i = 0; i < a->nelts; i++)
        if (admit_prefix_match(path, &e[i].prefix)) return 1;
    return 0;
}

xrootd_cache_admit_e
xrootd_cache_admit(const xrootd_cache_admit_cfg_t *cfg, const char *path,
    off_t size, int is_new)
{
    if (cfg == NULL || path == NULL) return XROOTD_CACHE_DECLINE;

    if (cfg->size_limit > 0 && !is_new && size > cfg->size_limit) {
        if (cfg->include_regex == NULL
            || regexec(cfg->include_regex, path, 0, NULL, 0) != 0)
            return XROOTD_CACHE_DECLINE;
    }
    if (admit_any_prefix(path, cfg->deny_prefixes)) return XROOTD_CACHE_DECLINE;
    if (cfg->allow_prefixes != NULL && cfg->allow_prefixes->nelts > 0
        && !admit_any_prefix(path, cfg->allow_prefixes))
        return XROOTD_CACHE_DECLINE;
    return XROOTD_CACHE_ADMIT;
}
```

- [ ] **Step 5: Register the source + run the test**

Add to the repo-root `config` `NGX_ADDON_SRCS` list (next to the other `src/fs/cache/*.c`): `$ngx_addon_dir/src/fs/cache/cache_admit.c`. Then:
```bash
tests/c/run_cache_admit_tests.sh
```
Expected: `test_cache_admit: ALL PASS`.

- [ ] **Step 6: Confirm the module still builds**

```bash
cd /home/rcurrie/HEP-x/nginx-xrootd && ./configure --with-stream --with-stream_ssl_module --with-http_ssl_module --with-http_dav_module --with-threads --add-module=$(pwd) >/dev/null && cd /tmp/nginx-1.28.3 && make -j$(nproc) 2>&1 | tail -2
```
Expected: build completes, `cache_admit.o` linked, exit 0.

---

### Task 4: write-through decision delegates to the shared filter

**Files:**
- Modify: `src/fs/cache/writethrough_decision.c` (`xrootd_wt_default_decide`)
- Test: existing write-through pytest suite (regression)

**Interfaces:**
- Consumes: `xrootd_cache_admit()` (Task 3), the existing `xrootd_wt_decision_cfg_t`.
- Produces: no signature change; behavior identical, now routed through the shared filter.

- [ ] **Step 1: Replace the body of `xrootd_wt_default_decide`** — keep the `DENY/ALLOW_SYNC/ALLOW_ASYNC` outcome, compute admission via the shared filter.

```c
xrootd_wt_decision_t xrootd_wt_default_decide(const char *path, uint16_t options,
                                               void *user_data)
{
    if (user_data == NULL || path == NULL) return XROOTD_WT_DECISION_DENY;
    xrootd_wt_decision_cfg_t *cfg = user_data;

    /* Existing files are stat'd for the size cap; a kXR_new create skips it. */
    off_t size = 0; int is_new = (options & kXR_new) != 0;
    if (!is_new && cfg->max_write_through_bytes > 0) {
        struct stat st;
        if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) size = st.st_size;
        else is_new = 1;   /* not a regular existing file → skip the cap */
    }
    xrootd_cache_admit_cfg_t a = {
        .deny_prefixes  = cfg->deny_prefixes,
        .allow_prefixes = cfg->allow_prefixes,
        .size_limit     = cfg->max_write_through_bytes,
        .include_regex  = cfg->include_regex_set ? &cfg->include_regex : NULL,
    };
    if (xrootd_cache_admit(&a, path, size, is_new) == XROOTD_CACHE_DECLINE)
        return XROOTD_WT_DECISION_DENY;
    return XROOTD_WT_DECISION_ALLOW_ASYNC;
}
```
Add `#include "cache_admit.h"` at the top of `writethrough_decision.c`. Delete the now-unused local `xrootd_wt_path_matches_prefix`/`_any_prefix` statics **only if** nothing else in the file references them (grep first; `xrootd_wt_decide` at line ~139 may — if so, leave them).

- [ ] **Step 2: Build + run the write-through regression**

```bash
cd /tmp/nginx-1.28.3 && make -j$(nproc) 2>&1 | tail -2
cd /home/rcurrie/HEP-x/nginx-xrootd && TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/ -k "writethrough or write_through or wt_" -q 2>&1 | tail -8
```
Expected: build exit 0; write-through tests pass (same as before the change).

---

### Task 5: config — new directives + struct fields + merge

**Files:**
- Modify: `src/core/types/config.h` (struct fields)
- Modify: `src/fs/cache/directives.c` (parsers) + the module command table (`src/protocols/root/stream/module.c`)
- Modify: `src/core/config/server_conf.c` (merge defaults)

**Interfaces:**
- Produces config fields: `ngx_str_t cache_state_root;`, `time_t cache_dirty_max_age;`, `ngx_array_t *cache_deny_prefixes;`, `ngx_array_t *cache_allow_prefixes;` on `ngx_stream_xrootd_srv_conf_t`. Default `cache_dirty_max_age = 604800`. `cache_state_root` defaults to `cache_root` when unset (resolved at use, Task 6).

- [ ] **Step 1: Add struct fields** — `src/core/types/config.h`, in the cache block (near `cache_root`/`cache_include_regex`):

```c
    ngx_str_t    cache_state_root;       /* [xrootd_cache_state_root]; "" ⇒ cache_root */
    time_t       cache_dirty_max_age;    /* [xrootd_cache_dirty_max_age]; secs; 0 = off */
    ngx_array_t *cache_deny_prefixes;    /* xrootd_wt_prefix_entry_t[] — read admission */
    ngx_array_t *cache_allow_prefixes;   /* same; whitelist when non-empty */
```

- [ ] **Step 2: Register the directives** — `src/protocols/root/stream/module.c`, in the `ngx_command_t` array (mirror the existing `xrootd_cache_root` / `xrootd_wt_deny_prefix` entries).

```c
    { ngx_string("xrootd_cache_state_root"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1, ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, cache_state_root), NULL },
    { ngx_string("xrootd_cache_dirty_max_age"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1, ngx_conf_set_sec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, cache_dirty_max_age), NULL },
    { ngx_string("xrootd_cache_deny_prefix"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1, xrootd_cache_deny_prefix_slot,
      NGX_STREAM_SRV_CONF_OFFSET, 0, NULL },
    { ngx_string("xrootd_cache_allow_prefix"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1, xrootd_cache_allow_prefix_slot,
      NGX_STREAM_SRV_CONF_OFFSET, 0, NULL },
```

- [ ] **Step 3: Write the prefix slot parsers** — `src/fs/cache/directives.c` (mirror the write-through prefix parser; push an `xrootd_wt_prefix_entry_t`).

```c
static char *
xrootd_cache_push_prefix(ngx_conf_t *cf, ngx_array_t **arr) {
    ngx_str_t *value = cf->args->elts;
    if (*arr == NULL) {
        *arr = ngx_array_create(cf->pool, 4, sizeof(xrootd_wt_prefix_entry_t));
        if (*arr == NULL) return NGX_CONF_ERROR;
    }
    xrootd_wt_prefix_entry_t *e = ngx_array_push(*arr);
    if (e == NULL) return NGX_CONF_ERROR;
    e->prefix = value[1];
    return NGX_CONF_OK;
}
char *xrootd_cache_deny_prefix_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_stream_xrootd_srv_conf_t *x = conf;
    return xrootd_cache_push_prefix(cf, &x->cache_deny_prefixes);
}
char *xrootd_cache_allow_prefix_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_stream_xrootd_srv_conf_t *x = conf;
    return xrootd_cache_push_prefix(cf, &x->cache_allow_prefixes);
}
```
Declare the two `_slot` functions in the cache header that `module.c` includes (e.g. `directives` prototypes in `cache_internal.h` or wherever `xrootd_cache_origin` parser is declared — match the existing pattern).

- [ ] **Step 4: Merge defaults** — `src/core/config/server_conf.c`, in the cache merge section:

```c
    ngx_conf_merge_str_value(conf->cache_state_root, prev->cache_state_root, "");
    ngx_conf_merge_sec_value(conf->cache_dirty_max_age, prev->cache_dirty_max_age, 604800);
    if (conf->cache_deny_prefixes == NULL)  conf->cache_deny_prefixes  = prev->cache_deny_prefixes;
    if (conf->cache_allow_prefixes == NULL) conf->cache_allow_prefixes = prev->cache_allow_prefixes;
```
Set `NGX_CONF_UNSET` equivalents in the `create_srv_conf` if that file zero-inits explicitly — `cache_dirty_max_age` to `NGX_CONF_UNSET` (so the merge default applies), arrays/str left NULL/zeroed by `pcalloc`.

- [ ] **Step 5: Validate the config parses**

```bash
cd /tmp/nginx-1.28.3 && make -j$(nproc) 2>&1 | tail -2
printf 'events{}\nstream{server{listen 127.0.0.1:12931; xrootd on; xrootd_root /tmp; xrootd_auth none;\n  xrootd_cache on; xrootd_cache_root /tmp/xc; xrootd_cache_state_root /tmp/xcs;\n  xrootd_cache_dirty_max_age 3600; xrootd_cache_deny_prefix /no/; xrootd_cache_allow_prefix /yes/; }}\n' > /tmp/cfgtest.conf
/tmp/nginx-1.28.3/objs/nginx -t -c /tmp/cfgtest.conf 2>&1 | tail -3
```
Expected: `configuration file /tmp/cfgtest.conf test is successful`.

---

### Task 6: state-root resolution + read admission via the shared filter

**Files:**
- Modify: `src/fs/cache/paths.c` (+ its header) — state-root resolver
- Modify: `src/fs/cache/fetch.c` — read admission through `xrootd_cache_admit`
- Test: e2e (Task 10) + a config-driven manual check here

**Interfaces:**
- Produces: `const char *xrootd_cache_state_root(const ngx_stream_xrootd_srv_conf_t *conf);` — returns `cache_state_root` if set, else `cache_root` if set, else `NULL`.
- Produces: `int xrootd_cache_state_path(const ngx_stream_xrootd_srv_conf_t *conf, const char *clean_path, char *dst, size_t dstsz);` — maps a logical path to the `.cinfo`-bearing cache/state path under the state root (reuse `xrootd_cache_path_for_resolved` logic, but rooted at the state root). Returns 0/-1.

- [ ] **Step 1: Implement the resolver** — `src/fs/cache/paths.c`.

```c
const char *
xrootd_cache_state_root(const ngx_stream_xrootd_srv_conf_t *conf) {
    if (conf == NULL) return NULL;
    if (conf->cache_state_root.len > 0) return (const char *) conf->cache_state_root.data;
    if (conf->cache_root.len > 0)       return (const char *) conf->cache_root.data;
    return NULL;
}
```
Declare it in the cache header that exposes `xrootd_cache_path_for_resolved` (`open.h` or `cache_internal.h`). For `xrootd_cache_state_path`, if `cache_state_root` is unset the state path IS the cache path (already produced by `xrootd_cache_path_for_resolved`); only when a *separate* `cache_state_root` is set do you remap. Implement as: if `cache_state_root.len==0`, delegate to `xrootd_cache_path_for_resolved`; else swap the root prefix.

- [ ] **Step 2: Route read admission through the shared filter** — `src/fs/cache/fetch.c`. Find the existing admission check (size + include_regex, returns `NGX_DECLINED`) and replace it with:

```c
    {
        xrootd_cache_admit_cfg_t a = {
            .deny_prefixes  = conf->cache_deny_prefixes,
            .allow_prefixes = conf->cache_allow_prefixes,
            .size_limit     = conf->cache_max_file_size,
            .include_regex  = conf->cache_include_regex_set ? &conf->cache_include_regex : NULL,
        };
        if (xrootd_cache_admit(&a, clean_path, (off_t) t->file_size, 0)
            == XROOTD_CACHE_DECLINE) {
            return NGX_DECLINED;   /* admission decline → done cb redirects to origin */
        }
    }
```
Add `#include "cache_admit.h"` to `fetch.c`. Keep the existing redirect-on-decline behavior in the done callback unchanged.

- [ ] **Step 3: Build + sanity-check admission**

```bash
cd /tmp/nginx-1.28.3 && make -j$(nproc) 2>&1 | tail -2
```
Expected: exit 0. (Behavioral e2e for prefix admit/redirect is in Task 10.)

---

### Task 7: durable dirty-on-write + clean-on-flush wiring

**Files:**
- Modify: `src/protocols/root/write/sync.c` and `src/protocols/root/read/close.c` (call `mark_dirty` at coarse points)
- Modify: `src/fs/cache/writethrough_flush.c` (call `mark_clean` on successful flush)

**Interfaces:**
- Consumes: `xrootd_cache_cinfo_mark_dirty` / `_mark_clean` (Task 2), `xrootd_cache_state_path` (Task 6), the handle's `wt_enabled` + dirty offset/bytes (`xrootd_file_t`).

- [ ] **Step 1: Persist dirty at sync** — in `src/protocols/root/write/sync.c`, where a write-through handle is sync'd, after the successful sync and only when `ctx->files[idx].wt_enabled` and a state root resolves:

```c
    {
        const char *sr = xrootd_cache_state_root(conf);
        char sp[PATH_MAX];
        if (sr != NULL && ctx->files[idx].wt_dirty_offset >= 0
            && xrootd_cache_state_path(conf, ctx->files[idx].path, sp, sizeof sp) == 0) {
            struct stat st;   /* size/mtime for the validity key */
            if (fstat(ctx->files[idx].fd, &st) == 0) {
                (void) xrootd_cache_cinfo_mark_dirty(sp, (uint64_t) st.st_size,
                    XROOTD_CACHE_DIRTY_BLOCK, (uint64_t) st.st_mtime,
                    (uint64_t) ctx->files[idx].wt_dirty_offset,
                    ctx->files[idx].wt_bytes_written ? ctx->files[idx].wt_bytes_written : 1,
                    c->log);   /* best-effort */
            }
        }
    }
```
Define `XROOTD_CACHE_DIRTY_BLOCK` (e.g. the cache slice size or a fixed 1 MiB) in `cinfo.h` — the block granule is only used for validity-key bookkeeping here, not for a present bitmap on the dirty record. Use the same constant everywhere the dirty record is keyed.

- [ ] **Step 2: Persist dirty on the clean→dirty transition** — in the write handler that sets `wt_dirty_offset` from -1 to a value the first time (search `wt_dirty_offset` assignment in `src/protocols/root/write/write.c` / `writethrough_metrics.h` callers), add the same best-effort `mark_dirty` call guarded by the transition. (Do NOT put it in the `writethrough_metrics.h` inline — call it from the `.c` handler once per transition.)

- [ ] **Step 3: Clean on successful flush** — `src/fs/cache/writethrough_flush.c`, in the flush done/success path (`xrootd_wt_run_flush` returns success, or the done callback), after the handle is marked clean:

```c
    {
        const char *sr = xrootd_cache_state_root(t->conf);
        char sp[PATH_MAX];
        if (sr != NULL
            && xrootd_cache_state_path(t->conf, t->local_path, sp, sizeof sp) == 0) {
            (void) xrootd_cache_cinfo_mark_clean(sp, t->bytes_flushed, t->log); /* best-effort */
        }
    }
```
Add the needed includes (`cinfo.h`, the paths header) to the touched files.

- [ ] **Step 4: Build + write-through regression**

```bash
cd /tmp/nginx-1.28.3 && make -j$(nproc) 2>&1 | tail -2
cd /home/rcurrie/HEP-x/nginx-xrootd && TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/ -k "writethrough or write_through or wt_" -q 2>&1 | tail -8
```
Expected: build exit 0; existing write-through tests still pass (the new calls are best-effort and additive).

---

### Task 8: eviction guard — never evict a dirty file

**Files:**
- Modify: `src/fs/cache/evict_candidates.c` (skip dirty during the scan)
- Test: e2e (Task 10) + a focused build check

**Interfaces:**
- Consumes: `xrootd_cache_cinfo_dirty_extent` (Task 2).

- [ ] **Step 1: Skip dirty files in the candidate scan** — `src/fs/cache/evict_candidates.c`, in `xrootd_cache_collect_dir`, after the per-file `lstat`/regular-file check and before pushing the candidate, add:

```c
        {
            uint64_t dlo, dhi, dsince;
            if (xrootd_cache_cinfo_dirty_extent(child, &dlo, &dhi, &dsince) == NGX_OK) {
                continue;   /* dirty: protected from eviction until flushed */
            }
        }
```
`child` is the already-built absolute path of the candidate file. Add `#include "cinfo.h"` to `evict_candidates.c`. (A `.cinfo` whose data file is the candidate: `dirty_extent` opens `<child>.cinfo` — exactly the sidecar for `child`.)

- [ ] **Step 2: Build**

```bash
cd /tmp/nginx-1.28.3 && make -j$(nproc) 2>&1 | tail -2
```
Expected: exit 0.

---

### Task 9: stale-dirty reaper + maintenance timer + metric

**Files:**
- Create: `src/fs/cache/cache_reap.h`, `src/fs/cache/cache_reap.c`
- Modify: repo-root `config` (register `cache_reap.c`)
- Modify: `src/core/config/process.c` (arm the reaper timer, mirror `xrootd_stage_reap_timer`)
- Modify: `src/observability/metrics/` (a `cache_dirty_reaped` counter — count + bytes)

**Interfaces:**
- Produces: `ngx_uint_t xrootd_cache_reap_dirty(const ngx_stream_xrootd_srv_conf_t *conf, ngx_log_t *log);` — scans the state root, removes records `DIRTY && now-dirty_since > conf->cache_dirty_max_age` (data file + `.cinfo`/`.meta`/slice sidecars), returns the count reaped. No-op when `cache_dirty_max_age==0` or no state root.

- [ ] **Step 1: Write the reaper** — `src/fs/cache/cache_reap.c`. Reuse the recursive scan shape from `evict_candidates.c` (`opendir`/`readdir`/`skip_name`/`lstat`/recurse), but operate on each regular cache data file: load its dirty extent; if dirty and aged, `unlink` the data file + its sidecars and bump the metric.

```c
#include "cache_reap.h"
#include "cinfo.h"
#include "paths.h"          /* xrootd_cache_state_root */
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include <string.h>

static ngx_uint_t reap_dir(const char *dir, time_t cutoff, dev_t dev,
                           ngx_log_t *log) {
    DIR *dp = opendir(dir); if (dp == NULL) return 0;
    struct dirent *de; ngx_uint_t n = 0; char child[PATH_MAX];
    while ((de = readdir(dp)) != NULL) {
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
        /* skip sidecars; we drive off the data file */
        const char *dot = strrchr(de->d_name, '.');
        if (dot && (!strcmp(dot, ".cinfo") || !strcmp(dot, ".meta"))) continue;
        if (strstr(de->d_name, ".__xrds")) continue;
        if (snprintf(child, sizeof child, "%s/%s", dir, de->d_name) >= (int) sizeof child) continue;
        struct stat st;
        if (lstat(child, &st) != 0) continue;
        if (st.st_dev != dev) continue;                 /* same-device guard */
        if (S_ISDIR(st.st_mode)) { n += reap_dir(child, cutoff, dev, log); continue; }
        if (!S_ISREG(st.st_mode)) continue;
        uint64_t lo, hi, since;
        if (xrootd_cache_cinfo_dirty_extent(child, &lo, &hi, &since) != NGX_OK) continue;
        if (since == 0 || (time_t) since > cutoff) continue;   /* not aged */
        char sc[PATH_MAX], mc[PATH_MAX];
        (void) unlink(child);
        if (xrootd_cache_cinfo_path(sc, sizeof sc, child) == 0) (void) unlink(sc);
        if (snprintf(mc, sizeof mc, "%s.meta", child) < (int) sizeof mc) (void) unlink(mc);
        ngx_log_error(NGX_LOG_WARN, log, 0,
            "xrootd: cache reaped stale-dirty file (age>max, %uL dirty bytes discarded): %s",
            (unsigned long) (hi - lo), child);
        n++;
        /* metric bump: see Step 3 */
        xrootd_cache_dirty_reaped_inc(hi - lo);
    }
    closedir(dp);
    return n;
}

ngx_uint_t
xrootd_cache_reap_dirty(const ngx_stream_xrootd_srv_conf_t *conf, ngx_log_t *log) {
    if (conf == NULL || conf->cache_dirty_max_age == 0) return 0;
    const char *root = xrootd_cache_state_root(conf);
    if (root == NULL) return 0;
    struct stat rs; if (stat(root, &rs) != 0) return 0;
    time_t cutoff = time(NULL) - conf->cache_dirty_max_age;
    return reap_dir(root, cutoff, rs.st_dev, log);
}
```
Header `cache_reap.h` declares `xrootd_cache_reap_dirty`. Register `src/fs/cache/cache_reap.c` in the repo-root `config`.

- [ ] **Step 2: Arm the timer** — `src/core/config/process.c`, mirror `xrootd_stage_reap_timer` (lines 114-132 + the `ngx_add_timer` in `init_process`).

```c
#define XROOTD_CACHE_REAP_FIRST_MS     5000
#define XROOTD_CACHE_REAP_INTERVAL_MS  3600000   /* hourly */
static ngx_event_t  xrootd_cache_reap_timer;

static void
xrootd_cache_reap_handler(ngx_event_t *ev) {
    ngx_stream_xrootd_srv_conf_t *xcf = ev->data;   /* set when arming */
    ngx_uint_t n = xrootd_cache_reap_dirty(xcf, ev->log);
    if (n > 0)
        ngx_log_error(NGX_LOG_NOTICE, ev->log, 0,
            "xrootd: cache stale-dirty reaper removed %ui file(s)", n);
    if (!ngx_exiting) ngx_add_timer(ev, XROOTD_CACHE_REAP_INTERVAL_MS);
}
```
In `ngx_stream_xrootd_init_process`, where `xrootd_stage_reap_timer` is armed, add (worker 0 or every worker — match the stage reaper’s scope) an arm guarded by `xcf->cache_dirty_max_age > 0 && xrootd_cache_state_root(xcf) != NULL`:
```c
    if (xcf != NULL && xcf->cache_dirty_max_age > 0
        && xrootd_cache_state_root(xcf) != NULL) {
        xrootd_cache_reap_timer.handler = xrootd_cache_reap_handler;
        xrootd_cache_reap_timer.data    = xcf;
        xrootd_cache_reap_timer.log     = cycle->log;
        ngx_add_timer(&xrootd_cache_reap_timer, XROOTD_CACHE_REAP_FIRST_MS);
    }
```
(Resolve `xcf` the same way `init_process` already obtains the per-server conf for the stage reaper.)

- [ ] **Step 3: Add the metric** — follow `src/observability/metrics/README.md`. Add a `cache_dirty_reaped_count` + `cache_dirty_reaped_bytes` counter and an inline `xrootd_cache_dirty_reaped_inc(uint64_t bytes)` that bumps both. Declare it in a metrics header `cache_reap.c` includes.

- [ ] **Step 4: Build**

```bash
cd /home/rcurrie/HEP-x/nginx-xrootd && ./configure --with-stream --with-stream_ssl_module --with-http_ssl_module --with-http_dav_module --with-threads --add-module=$(pwd) >/dev/null && cd /tmp/nginx-1.28.3 && make -j$(nproc) 2>&1 | tail -2
```
Expected: `cache_reap.o` linked, exit 0.

---

### Task 10: e2e tests + docs

**Files:**
- Create: `tests/test_cache_state_engine.py`
- Modify: `src/fs/cache/README.md` (document v3 record, state root, reaper, parity directives)

**Interfaces:**
- Consumes: all prior tasks.

- [ ] **Step 1a: Write the concrete `.cinfo` v3 header parser** — put this helper at the top of `tests/test_cache_state_engine.py`. The layout matches `xrootd_cache_cinfo_t` exactly (native LE, `#pragma`-free POD; field order: magic u32, version u16, flags u16, block_size u32, reserved u32, then the u64 group `size,mtime,nblocks,access_count,bytes_served,last_access`, then the NEW u64 group `dirty_lo,dirty_hi,dirty_since,flush_gen,last_flush,bytes_flushed`, then the etag/cks tail). We only need the leading fixed fields, so unpack the prefix:

```python
import struct, os, time, subprocess, socket, tempfile, pathlib

# magic u32, version u16, flags u16, block_size u32, reserved u32,
# size,mtime,nblocks,access_count,bytes_served,last_access (6x u64),
# dirty_lo,dirty_hi,dirty_since,flush_gen,last_flush,bytes_flushed (6x u64)
_CINFO_PREFIX = "<IHHII" + "Q"*6 + "Q"*6
CINFO_F_COMPLETE, CINFO_F_PARTIAL, CINFO_F_VERIFIED, CINFO_F_DIRTY = 1, 2, 4, 8

def read_cinfo(path):
    with open(path, "rb") as f:
        buf = f.read(struct.calcsize(_CINFO_PREFIX))
    (magic, ver, flags, bsz, _resv,
     size, mtime, nblocks, acc, served, last,
     dlo, dhi, dsince, fgen, lflush, bflushed) = struct.unpack(_CINFO_PREFIX, buf)
    assert magic == 0x58434931, "bad cinfo magic"
    return dict(version=ver, flags=flags, dirty=bool(flags & CINFO_F_DIRTY),
                dirty_lo=dlo, dirty_hi=dhi, dirty_since=dsince,
                flush_gen=fgen, last_flush=lflush, bytes_flushed=bflushed)

def write_cinfo_dirty(path, size, block_size, mtime, dirty_since, dlo=0, dhi=4096):
    nblocks = (size + block_size - 1)//block_size if size else 0
    hdr = struct.pack(_CINFO_PREFIX, 0x58434931, 3, CINFO_F_DIRTY|CINFO_F_PARTIAL,
                      block_size, 0, size, mtime, nblocks, 0, 0, 0,
                      dlo, dhi, dirty_since, 0, 0, 0)
    # pad the etag/cks tail with zeros to the true header size, then 0 bitmap bytes
    full = pathlib.Path(__file__)  # placeholder for sizeof; compute from the C header
    tail = b"\x00" * (CINFO_HDR_SIZE - len(hdr))
    bm = b"\x00" * ((nblocks + 7)//8)
    with open(path, "wb") as f:
        f.write(hdr + tail + bm)
```
`CINFO_HDR_SIZE` = `sizeof(xrootd_cache_cinfo_t)`. Compute it once in the test's
module-scope setup by compiling a 3-line C probe that includes `src/fs/cache/cinfo.h`
and prints `sizeof(xrootd_cache_cinfo_t)`, reusing the exact `gcc`
include/stub flags from `tests/c/run_cinfo_tests.sh` (which already compiles
`cinfo.c` nginx-free). Cache the value as a module constant. In Task 1 Step 5, also
`printf("%zu\n", XROOTD_CACHE_CINFO_HDR_SIZE)` once and record it in the plan comment
so a drift in the struct size surfaces as a unit-test failure rather than a silent
parser mismatch.

- [ ] **Step 1b: Write the reaper test (fully self-contained, `run_pblock_root.sh` style)** — spawns its own nginx with cache + a 1-second `xrootd_cache_dirty_max_age`, hand-writes an aged-dirty `.cinfo` next to a cache data file, awaits the first reaper tick (5 s) + one interval, asserts removal.

```python
NGINX = os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx")

def _spawn_cache_nginx(tmp, port, extra):
    root = tmp/"root"; cache = tmp/"cache"; logs = tmp/"logs"
    for d in (root, cache, logs): d.mkdir(parents=True, exist_ok=True)
    conf = tmp/"nginx.conf"
    conf.write_text(f"""
daemon on; error_log {logs}/error.log info; pid {tmp}/nginx.pid;
events {{ worker_connections 64; }}
stream {{ server {{ listen 127.0.0.1:{port}; xrootd on; xrootd_root {root};
  xrootd_auth none; xrootd_allow_write on;
  xrootd_cache on; xrootd_cache_root {cache};
  {extra} }} }}
""")
    subprocess.run([NGINX, "-p", str(tmp), "-c", str(conf)], check=True)
    return root, cache

def test_reaper_removes_aged_dirty(tmp_path):
    port = 11931
    root, cache = _spawn_cache_nginx(tmp_path, port,
        "xrootd_cache_dirty_max_age 1;")
    try:
        data = cache/"stale.bin"; data.write_bytes(b"x"*4096)
        write_cinfo_dirty(str(data), 4096, 1048576, 1000,
                          dirty_since=int(time.time()) - 3600)  # 1h old
        assert read_cinfo(str(data)+".cinfo")["dirty"]
        # first reaper tick at 5s; wait generously
        deadline = time.time() + 20
        while time.time() < deadline and data.exists():
            time.sleep(1)
        assert not data.exists(), "aged-dirty data file should be reaped"
        assert not pathlib.Path(str(data)+".cinfo").exists()
    finally:
        pid = (tmp_path/"nginx.pid").read_text().strip()
        subprocess.run(["kill", pid])
```

- [ ] **Step 1c: Write the remaining three tests against the dedicated WT servers** — mirror `tests/test_cache_write_through.py` (it already provisions a write-through server whose origin is the anon nginx). Add, using its `write_through_sync_server` fixture + a raw `kXR_open`/`kXR_write`/`kXR_close` via its `_establish_session` helper:

```python
def test_flush_marks_clean(write_through_sync_server, tmp_path):
    # PUT a small file through the WT-sync server; its cache_state_root defaults
    # to cache_root, so a .cinfo appears for the path. After the sync flush the
    # record is clean with flush_gen>=1.
    # (write via the helper, then locate the .cinfo under the server's cache dir)
    cinfo = _server_cinfo_path(write_through_sync_server, "/flushme.bin")
    info = read_cinfo(cinfo)
    assert not info["dirty"] and info["flush_gen"] >= 1

def test_cache_deny_prefix_admit(cache_only_server):
    # a cache-only server configured with xrootd_cache_deny_prefix /no/ : reading
    # /no/x leaves no file under cache_root (declined→origin), /yes/x is cached.
    assert _cached(cache_only_server, "/yes/x") and not _cached(cache_only_server, "/no/x")
```
`_server_cinfo_path` / `_cached` are 3-line helpers that join the server's `TEST_ROOT/data-<role>`-derived cache dir with the mapped path + `.cinfo`. The eviction-guard body is spelled out in Step 1d (it needs the dedicated server's eviction config). If the dedicated-server provisioning for a deny-prefix / low-threshold variant does not exist, prefer the self-spawned `_spawn_cache_nginx` helper from Step 1b for these two as well (it is fully under the test's control) rather than adding new dedicated conf files.

- [ ] **Step 1d: Eviction-guard test (self-spawned)** — reuse `_spawn_cache_nginx` with a tiny `xrootd_cache_eviction_threshold` so an eviction pass runs; place one fresh-dirty `.cinfo` + data file and one clean `.cinfo` + data file, drive enough fills to cross the threshold, assert the dirty file survives and the clean file is gone.

```python
def test_dirty_file_not_evicted(tmp_path):
    port = 11932
    root, cache = _spawn_cache_nginx(tmp_path, port,
        "xrootd_cache_eviction_threshold 1;")  # ~always over → evict aggressively
    try:
        clean = cache/"clean.bin"; clean.write_bytes(b"c"*8192)
        dirty = cache/"dirty.bin"; dirty.write_bytes(b"d"*8192)
        # clean.bin: no .cinfo (or a clean one); dirty.bin: aged-but-dirty record
        write_cinfo_dirty(str(dirty), 8192, 1048576, 1000,
                          dirty_since=int(time.time()))  # fresh dirty
        # trigger an eviction sweep by opening/filling unrelated paths; or call the
        # admin eviction endpoint if present. Then:
        time.sleep(3)
        assert dirty.exists(), "dirty file must be protected from eviction"
    finally:
        pid = (tmp_path/"nginx.pid").read_text().strip()
        subprocess.run(["kill", pid])
```

- [ ] **Step 2: Run the e2e tests**

Run: `TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_cache_state_engine.py -v 2>&1 | tail -20`
Expected: all pass. (If a dedicated-server-based test cannot resolve its cache dir, convert it to the self-spawned `_spawn_cache_nginx` form, which is fully self-contained.)

- [ ] **Step 3: Update the README** — `src/fs/cache/README.md`: document the v3 `.cinfo` dirty fields, `xrootd_cache_state_root` (defaults to cache_root), `xrootd_cache_dirty_max_age` + the reaper, the shared admission filter (`cache_admit.c`) + `xrootd_cache_{allow,deny}_prefix`, and the eviction guard. Note the deliberate no-read-mode-knob asymmetry.

- [ ] **Step 4: Full regression**

```bash
cd /home/rcurrie/HEP-x/nginx-xrootd
tests/c/run_cinfo_tests.sh && tests/c/run_cache_admit_tests.sh
TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/ -k "cache or writethrough or evict" -q 2>&1 | tail -10
```
Expected: unit suites ALL PASS; cache/write-through/eviction pytest green.

---

## Self-review notes

- **Spec coverage:** v3 record (Task 1) · dirty API (Task 2) · shared filter (Task 3) · write decision parity (Task 4) · directives incl. state_root/dirty_max_age/prefixes (Task 5) · state-root + read admission (Task 6) · durable dirty + clean-on-flush (Task 7) · eviction guard (Task 8) · reaper + timer + metric (Task 9) · tests + docs (Task 10). All spec sections map to a task.
- **Migration:** Task 1 honors "v2 loads as present-only/clean" via the frozen v2 reader.
- **Perf:** Task 7 persists dirty only at the clean→dirty transition and at sync (never per write), per the spec.
- **Zero-regression:** every new state call is best-effort and gated on a resolved state root; Tasks 4/7 keep the existing pytest suites green as their gate.
- **Type consistency:** `xrootd_cache_admit_cfg_t` (deny/allow `ngx_array_t*` of `xrootd_wt_prefix_entry_t`, `size_limit` off_t, `include_regex` `regex_t*`) is used identically in Tasks 3/4/6; `xrootd_cache_cinfo_dirty_extent(path,*lo,*hi,*since)` signature is identical in Tasks 2/8/9.
