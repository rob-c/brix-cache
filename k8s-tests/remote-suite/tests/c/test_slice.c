/*
 * test_slice.c — standalone unit tests for the Phase 26 slice library
 * (src/fs/cache/slice.c).
 *
 * This links against the real compiled slice.o + meta.o objects from the nginx
 * build and provides tiny stubs for the two externals slice.o needs that live
 * elsewhere in the cache module (brix_cache_file_ready, ngx_log_error_core).
 * It needs no running server, so it works even when the integration test host
 * is unavailable.  Build + run via tests/c/run_slice_tests.sh.
 *
 * The slice.h struct/prototypes are forward-declared here (rather than including
 * slice.h, which pulls in the full nginx headers) so the test compiles with a
 * plain gcc.  The struct layout MUST match src/fs/cache/slice.h exactly.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

typedef uintptr_t ngx_uint_t;
typedef intptr_t  ngx_int_t;

#define NGX_OK        0
#define NGX_ERROR    -1
#define NGX_DECLINED -5

#define SLICE_128M (128u * 1024u * 1024u)

/* Mirror of brix_slice_t from src/fs/cache/slice.h (layout must match). */
typedef struct {
    off_t       file_start;
    off_t       file_end;
    off_t       req_start;
    off_t       req_end;
    ngx_uint_t  idx;
    char        path[PATH_MAX];
    int         ready;
} brix_slice_t;

/* Slice library under test (defined in slice.o). */
ngx_int_t  brix_slice_path(const char *cache_path, size_t slice_size,
    ngx_uint_t slice_idx, char *out, size_t outsz);
ngx_int_t  brix_slice_enumerate(const char *cache_path, off_t file_size,
    size_t slice_size, off_t req_start, off_t req_end,
    brix_slice_t *out, ngx_uint_t max_out, ngx_uint_t *nout);
ngx_int_t  brix_slice_meta_base(const char *cache_path, char *out, size_t outsz);
ngx_int_t  brix_slice_meta_validate(const char *cache_path, off_t origin_size,
    const char *origin_etag, void *log);
ngx_int_t  brix_slice_meta_write(const char *cache_path, off_t origin_size,
    const char *origin_etag, uint64_t mtime, void *log);
ngx_uint_t brix_slice_evict_all(const char *cache_path, void *log);

/* ---- Stubs for the cache-module externals slice.o / meta.o reference. ---- */

/* meta.o records last_access via nginx's ngx_time() macro, which expands to
 * ngx_cached_time->sec.  In the live module ngx_cached_time is maintained by the
 * event loop; the standalone unit test has no nginx runtime, so provide a backing
 * struct (layout matches ngx_time_t: time_t sec first) to resolve the link. */
typedef struct { time_t sec; ngx_uint_t msec; } ngx_time_t;
static ngx_time_t      _stub_cached_time;
volatile ngx_time_t   *ngx_cached_time = &_stub_cached_time;

int
brix_cache_file_ready(const char *path)
{
    /* A slice is "ready" iff the final (non-.part) file exists. */
    return (access(path, F_OK) == 0) ? 1 : 0;
}

/* Mirrors src/fs/cache/paths.c: appends ".meta".  Stubbed here so the test need
 * not link paths.o (which pulls in the whole path module). */
int
brix_cache_meta_path(char *dst, size_t dstsz, const char *cache_path)
{
    int n = snprintf(dst, dstsz, "%s.meta", cache_path);
    return (n < 0 || (size_t) n >= dstsz) ? NGX_ERROR : NGX_OK;
}

/* Mirrors src/fs/cache/cinfo.c: appends ".cinfo" (slice.o drops it on evict). */
int
brix_cache_cinfo_path(char *dst, size_t dstsz, const char *cache_path)
{
    int n = snprintf(dst, dstsz, "%s.cinfo", cache_path);
    return (n < 0 || (size_t) n >= dstsz) ? NGX_ERROR : NGX_OK;
}

/* Never actually invoked (the test passes a zeroed log so log_level == 0 and
 * the ngx_log_error macro short-circuits), but needed for link resolution. */
void
ngx_log_error_core(ngx_uint_t level, void *log, int err, const char *fmt, ...)
{
    (void) level; (void) log; (void) err; (void) fmt;
}

/* ---- Test harness ---- */

static int g_pass = 0;
static int g_fail = 0;
static char g_fake_log[256];   /* zeroed -> log_level 0 -> no logging */

#define CHECK(cond, msg) do {                                              \
        if (cond) { g_pass++; }                                            \
        else { g_fail++; printf("  FAIL: %s  (%s:%d)\n", msg, __FILE__, __LINE__); } \
    } while (0)

static void
touch(const char *path)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd >= 0) { (void) write(fd, "x", 1); close(fd); }
}

static void
test_slice_path(void)
{
    char out[PATH_MAX];
    ngx_int_t rc;

    printf("test_slice_path\n");

    rc = brix_slice_path("/cache/store/run3.root", SLICE_128M, 0,
                           out, sizeof(out));
    CHECK(rc == NGX_OK, "slice 0 path returns OK");
    CHECK(strcmp(out, "/cache/store/run3.root.__xrds_131072k_0") == 0,
          "slice 0 filename matches convention");

    rc = brix_slice_path("/cache/store/run3.root", SLICE_128M, 7,
                           out, sizeof(out));
    CHECK(rc == NGX_OK && strcmp(out,
          "/cache/store/run3.root.__xrds_131072k_7") == 0,
          "slice 7 filename matches convention");

    /* Security/error: a too-small output buffer must fail, not overflow. */
    {
        char tiny[8];
        rc = brix_slice_path("/cache/store/run3.root", SLICE_128M, 0,
                               tiny, sizeof(tiny));
        CHECK(rc == NGX_ERROR, "path too long -> NGX_ERROR (no overflow)");
    }

    /* Different slice size -> different name (auto-invalidation property). */
    rc = brix_slice_path("/c/f", 64u * 1024 * 1024, 1, out, sizeof(out));
    CHECK(rc == NGX_OK && strcmp(out, "/c/f.__xrds_65536k_1") == 0,
          "64m slice encodes size in filename");
}

static void
test_enumerate(const char *dir)
{
    char            cache_path[PATH_MAX];
    brix_slice_t  slices[16];
    ngx_uint_t      n;
    ngx_int_t       rc;

    printf("test_enumerate\n");
    snprintf(cache_path, sizeof(cache_path), "%s/run3.root", dir);

    /* file_size 300 MiB, request [100 MiB, 300 MiB) -> slices 0,1,2. */
    rc = brix_slice_enumerate(cache_path, 300LL * 1024 * 1024, SLICE_128M,
                                100LL * 1024 * 1024, 300LL * 1024 * 1024,
                                slices, 16, &n);
    CHECK(rc == NGX_OK, "enumerate spanning range returns OK");
    CHECK(n == 3, "range 100m-300m spans 3 slices (0,1,2)");
    CHECK(slices[0].idx == 0 && slices[2].idx == 2, "slice indices 0..2");
    /* First slice: req_start clamps to 100 MiB, file_start is 0. */
    CHECK(slices[0].req_start == 100LL * 1024 * 1024
          && slices[0].file_start == 0, "slice 0 req_start clamped to 100m");
    /* Last slice clamps file_end to file_size (300 MiB), not 384 MiB. */
    CHECK(slices[2].file_end == 300LL * 1024 * 1024,
          "last slice file_end clamped to file_size");
    CHECK(slices[2].req_end == 300LL * 1024 * 1024,
          "last slice req_end clamped to file_size");

    /* Readiness: create slices 0 and 1 only. */
    touch(slices[0].path);
    touch(slices[1].path);
    rc = brix_slice_enumerate(cache_path, 300LL * 1024 * 1024, SLICE_128M,
                                100LL * 1024 * 1024, 300LL * 1024 * 1024,
                                slices, 16, &n);
    CHECK(rc == NGX_OK && n == 3, "re-enumerate ok");
    CHECK(slices[0].ready == 1 && slices[1].ready == 1,
          "present slices marked ready");
    CHECK(slices[2].ready == 0, "absent slice marked not ready");

    /* Single byte at offset 0 -> exactly slice 0. */
    rc = brix_slice_enumerate(cache_path, 300LL * 1024 * 1024, SLICE_128M,
                                0, 1, slices, 16, &n);
    CHECK(rc == NGX_OK && n == 1 && slices[0].idx == 0,
          "1-byte read at 0 -> slice 0 only");

    /* Cap: a 4 GiB range at 128 MiB slices spans 32 slices > 16 -> DECLINED. */
    rc = brix_slice_enumerate(cache_path, 8LL * 1024 * 1024 * 1024,
                                SLICE_128M, 0, 4LL * 1024 * 1024 * 1024,
                                slices, 16, &n);
    CHECK(rc == NGX_DECLINED, "range over MAX_PER_REQUEST slices -> DECLINED");

    /* Bad args. */
    rc = brix_slice_enumerate(cache_path, 0, SLICE_128M, 50, 10,
                                slices, 16, &n);
    CHECK(rc == NGX_ERROR, "req_end <= req_start -> NGX_ERROR");
}

static void
test_meta(const char *dir)
{
    char       cache_path[PATH_MAX];
    ngx_int_t  rc;

    printf("test_meta\n");
    snprintf(cache_path, sizeof(cache_path), "%s/meta_file.root", dir);

    /* No meta yet -> "unknown" -> NGX_OK (caller proceeds). */
    rc = brix_slice_meta_validate(cache_path, 12345, "etagA", g_fake_log);
    CHECK(rc == NGX_OK, "missing meta validates as OK (unknown)");

    /* Write meta, then a matching validate succeeds. */
    rc = brix_slice_meta_write(cache_path, 12345, "etagA", 999, g_fake_log);
    CHECK(rc == NGX_OK, "meta write OK");
    rc = brix_slice_meta_validate(cache_path, 12345, "etagA", g_fake_log);
    CHECK(rc == NGX_OK, "matching size+etag validates OK");

    /* Size change -> mismatch -> NGX_DECLINED (stale). */
    rc = brix_slice_meta_validate(cache_path, 99999, "etagA", g_fake_log);
    CHECK(rc == NGX_DECLINED, "size mismatch -> DECLINED");

    /* Etag change -> mismatch -> NGX_DECLINED. */
    rc = brix_slice_meta_validate(cache_path, 12345, "etagB", g_fake_log);
    CHECK(rc == NGX_DECLINED, "etag mismatch -> DECLINED");
}

static void
test_evict_all(const char *dir)
{
    char        cache_path[PATH_MAX];
    char        p[PATH_MAX];
    ngx_uint_t  removed;
    ngx_int_t   rc;

    printf("test_evict_all\n");
    snprintf(cache_path, sizeof(cache_path), "%s/evict_file.root", dir);

    /* Create slices 0,1,2, a .part sibling, and the meta sidecar. */
    for (ngx_uint_t i = 0; i < 3; i++) {
        rc = brix_slice_path(cache_path, SLICE_128M, i, p, sizeof(p));
        CHECK(rc == NGX_OK, "build slice path for evict");
        touch(p);
    }
    rc = brix_slice_path(cache_path, SLICE_128M, 1, p, sizeof(p));
    strncat(p, ".ngx-xrootd-part", sizeof(p) - strlen(p) - 1);
    touch(p);                                           /* in-progress .part */
    brix_slice_meta_write(cache_path, 100, "e", 0, g_fake_log);

    removed = brix_slice_evict_all(cache_path, g_fake_log);
    CHECK(removed >= 4, "evict removed >= 4 files (3 slices + .part)");

    /* Verify the slice files are gone. */
    rc = brix_slice_path(cache_path, SLICE_128M, 0, p, sizeof(p));
    CHECK(access(p, F_OK) != 0, "slice 0 unlinked after evict");

    /* Security: a sibling file in the SAME dir but a DIFFERENT base must NOT
     * be touched by the glob. */
    snprintf(p, sizeof(p), "%s/other_file.root.__xrds_131072k_0", dir);
    touch(p);
    brix_slice_evict_all(cache_path, g_fake_log);     /* evict evict_file.* */
    CHECK(access(p, F_OK) == 0, "unrelated base's slice not evicted");
    unlink(p);
}

int
main(void)
{
    char tmpl[] = "/tmp/xrds_test_XXXXXX";
    char *dir = mkdtemp(tmpl);

    if (dir == NULL) {
        perror("mkdtemp");
        return 2;
    }

    printf("== slice library unit tests (dir=%s) ==\n", dir);
    test_slice_path();
    test_enumerate(dir);
    test_meta(dir);
    test_evict_all(dir);

    printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
