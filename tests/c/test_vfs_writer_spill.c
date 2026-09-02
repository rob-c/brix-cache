/*
 * test_vfs_writer_spill.c — the writer's SPILL mode (phase-107 C1) reorders
 * honestly: absorb any offset into a local scratch, publish only a complete
 * object, and answer capacity with ENOSPC — never a truncated object.
 *
 * WHAT: drives brix_vfs_writer_spill_{enter,put,drain,discard} — the real
 *       vfs_writer_spill.o — through the T1 promotion, out-of-order absorption
 *       with extent coalescing, the sequential T2 drain into a spy staged
 *       session, the T3 discard, and every refusal class (no scratch root,
 *       rewind, overlap, spill_max/T4, coverage hole).
 * WHY:  The reorder buffer is what turns "every reordered upload on http/remote
 *       fails" into a supported configuration; its refusals are load-bearing
 *       security/correctness edges (a hole must never be zero-filled into a
 *       published object, a capacity failure must abort the staged session so
 *       nothing partial publishes, and the scratch must live under the SERVICE
 *       spill root, never the export). A wire test sees only the response;
 *       this unit pins each transition hermetically.
 * HOW:  links the real vfs_writer_spill.o with its whole cross-TU closure as
 *       spies: the backend-registry spill lookup answers a test-controlled
 *       root/cap, the staged session records exactly what the drain streams
 *       (offset-checked, byte-compared), the metric recorders count, and the
 *       temp namer mirrors the owned-temp shape. Real ngx pool objects supply
 *       ngx_palloc/ngx_pnalloc.
 *
 * Cases (success + error + security-negative):
 *   success:      T1 enter flips SEQUENTIAL→SPILL, creates the scratch under
 *                 the spill root, bumps the active gauge; reverse-order puts
 *                 coalesce to one extent run and the drain hands the staged spy
 *                 a byte-exact sequential stream; discard unlinks the scratch,
 *                 drops the gauge, and is idempotent.
 *   error:        no spill root → ENOSPC and the session STAYS SEQUENTIAL; a
 *                 rewind below the staged prefix → EINVAL (stays SEQUENTIAL);
 *                 an overlapping extent → EINVAL (stays SPILL — client error,
 *                 not capacity); a drain over a coverage hole → EINVAL with
 *                 the staged session never touched.
 *   security-neg: spill_max exceeded (at entry and mid-put, T4) aborts the
 *                 staged session WITH temp removal and unlinks the scratch —
 *                 no partial object anywhere — and parks the session FAILED;
 *                 the scratch is created 0600, with the owned-temp reaper name,
 *                 strictly under the spill root and never under the export.
 *
 * Build+run: see tests/cmdscripts/c_object_units.py ("vfs_writer_spill").
 */
#include "fs/vfs/vfs_writer_internal.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* ---- spy state ---------------------------------------------------------- */
static const char *g_spill_root;     /* what the backend registry answers      */
static off_t       g_spill_max;
static int         g_tmp_counter;

#define SPY_OBJ_MAX  (4u << 20)
static u_char      g_staged_buf[SPY_OBJ_MAX];  /* what the drain streamed      */
static off_t       g_staged_cursor;  /* spy enforces the sequential contract   */
static int         g_staged_writes;
static int         g_staged_aborts;
static unsigned    g_abort_remove_tmp;

static int         g_metric_bytes_calls;
static size_t      g_metric_bytes_sum;
static int         g_metric_refused;
static int         g_metric_active;  /* gauge: sum of the +/-1 deltas          */

static void
reset_spies(void)
{
    g_spill_root         = NULL;
    g_spill_max          = 0;
    memset(g_staged_buf, 0, sizeof(g_staged_buf));
    g_staged_cursor      = 0;
    g_staged_writes      = 0;
    g_staged_aborts      = 0;
    g_abort_remove_tmp   = 0;
    g_metric_bytes_calls = 0;
    g_metric_bytes_sum   = 0;
    g_metric_refused     = 0;
    g_metric_active      = 0;
}

/* ---- cross-TU closure of vfs_writer_spill.o ------------------------------ */

ngx_int_t
brix_vfs_backend_spill(const char *root_canon, const char **root_out,
    off_t *max_out)
{
    (void) root_canon;
    *root_out = g_spill_root;
    *max_out  = g_spill_max;
    return g_spill_root != NULL ? NGX_OK : NGX_ERROR;
}

/* Owned-temp shape (".xrd-tmp.<pid>.") so the reaper-name assertion is real. */
ngx_int_t
brix_make_tmp_path(const char *base_path, char *out, size_t out_sz)
{
    int n = snprintf(out, out_sz, "%s.xrd-tmp.%d.%08x", base_path,
                     (int) getpid(), (unsigned) ++g_tmp_counter);
    return (n > 0 && (size_t) n < out_sz) ? NGX_OK : NGX_ERROR;
}

ngx_int_t
brix_vfs_pwrite_full(ngx_fd_t fd, const u_char *buf, size_t len, off_t off)
{
    while (len > 0) {
        ssize_t n = pwrite(fd, buf, len, off);

        if (n <= 0) {
            return NGX_ERROR;
        }
        buf += n; len -= (size_t) n; off += n;
    }
    return NGX_OK;
}

ngx_int_t
brix_vfs_pread_full(ngx_fd_t fd, u_char *buf, size_t len, off_t off,
    size_t *got)
{
    *got = 0;
    while (*got < len) {
        ssize_t n = pread(fd, buf + *got, len - *got, off + (off_t) *got);

        if (n < 0) {
            return NGX_ERROR;
        }
        if (n == 0) {
            break;                       /* short read: scratch too small */
        }
        *got += (size_t) n;
    }
    return NGX_OK;
}

/* The staged spy IS the sequential contract: an out-of-order drain write here
 * would be exactly the driver-corruption the spill exists to prevent. */
ngx_int_t
brix_vfs_staged_write(brix_vfs_staged_t *st, const void *buf, size_t len,
    off_t off)
{
    (void) st;
    assert(off == g_staged_cursor && "drain must stream sequentially");
    assert((size_t) off + len <= sizeof(g_staged_buf));
    memcpy(g_staged_buf + off, buf, len);
    g_staged_cursor = off + (off_t) len;
    g_staged_writes++;
    return NGX_OK;
}

void
brix_vfs_staged_abort(brix_vfs_staged_t *st, unsigned remove_tmp)
{
    (void) st;
    g_staged_aborts++;
    g_abort_remove_tmp = remove_tmp;
}

void
brix_metric_vfs_spill_bytes(brix_proto_t proto, size_t bytes)
{
    (void) proto;
    g_metric_bytes_calls++;
    g_metric_bytes_sum += bytes;
}

void
brix_metric_vfs_spill_refused(brix_proto_t proto)
{
    (void) proto;
    g_metric_refused++;
}

void
brix_metric_vfs_spill_active(int delta)
{
    g_metric_active += delta;
}

/* ---- harness ------------------------------------------------------------- */

static ngx_log_t       g_log;
static ngx_pool_t     *g_pool;
static brix_vfs_ctx_t  g_ctx;
static char            g_root_dir[128];   /* mkdtemp'd service spill root      */
static char            g_export_dir[160]; /* a sibling "export" for the        */
                                          /* never-under-the-export assertion  */
static int             g_staged_dummy;

static void
writer_init(brix_vfs_writer_t *w, off_t staged_cursor)
{
    memset(w, 0, sizeof(*w));
    w->ctx           = &g_ctx;
    w->pool          = g_pool;
    w->log           = &g_log;
    w->st            = (brix_vfs_staged_t *) &g_staged_dummy;
    w->staged_cursor = staged_cursor;
    w->mode          = BRIX_VFS_WRITER_SEQUENTIAL;
    w->spill.fd      = NGX_INVALID_FILE;
}

static int
scratch_on_disk(const brix_vfs_writer_t *w, struct stat *st)
{
    return w->spill.path != NULL
        && stat((const char *) w->spill.path, st) == 0;
}

/* ---- success ------------------------------------------------------------- */

static void
test_success_enter_creates_scratch_and_promotes(void)
{
    brix_vfs_writer_t w;
    struct stat       st;

    reset_spies();
    g_spill_root = g_root_dir;
    writer_init(&w, 0);
    assert(brix_vfs_writer_spill_enter(&w, 2 << 20, 4096) == NGX_OK);
    assert(w.mode == BRIX_VFS_WRITER_SPILL);
    assert(g_metric_active == 1);
    assert(scratch_on_disk(&w, &st));
    brix_vfs_writer_spill_discard(&w);
}

static void
test_success_reverse_order_drain_is_byte_exact(void)
{
    enum { CHUNK = 64 * 1024, N = 8 };
    static u_char     ref[CHUNK * N];
    brix_vfs_writer_t w;
    int               i;

    reset_spies();
    g_spill_root = g_root_dir;
    for (i = 0; i < (int) sizeof(ref); i++) {
        ref[i] = (u_char) (i * 31 + 7);
    }
    writer_init(&w, 0);
    assert(brix_vfs_writer_spill_enter(&w, (N - 1) * CHUNK, CHUNK) == NGX_OK);
    for (i = N - 1; i >= 0; i--) {          /* strictly reverse order */
        assert(brix_vfs_writer_spill_put(&w, ref + i * CHUNK, CHUNK,
                                         (off_t) i * CHUNK) == NGX_OK);
    }
    assert(w.spill.n_ext == 1 && "exact-touch neighbours must coalesce");
    assert(w.spill.ext[0].start == 0);
    assert(w.spill.ext[0].end == (off_t) sizeof(ref));
    assert(g_metric_bytes_sum == sizeof(ref));

    assert(brix_vfs_writer_spill_drain(&w) == NGX_OK);
    assert(g_staged_cursor == (off_t) sizeof(ref));
    assert(memcmp(g_staged_buf, ref, sizeof(ref)) == 0);
    brix_vfs_writer_spill_discard(&w);
}

static void
test_success_discard_unlinks_and_is_idempotent(void)
{
    brix_vfs_writer_t w;
    struct stat       st;
    char              kept[PATH_MAX];

    reset_spies();
    g_spill_root = g_root_dir;
    writer_init(&w, 0);
    assert(brix_vfs_writer_spill_enter(&w, 4096, 1) == NGX_OK);
    snprintf(kept, sizeof(kept), "%s", (const char *) w.spill.path);
    brix_vfs_writer_spill_discard(&w);
    assert(stat(kept, &st) != 0 && "discard must unlink the scratch");
    assert(g_metric_active == 0);
    brix_vfs_writer_spill_discard(&w);      /* idempotent */
    assert(g_metric_active == 0);
}

/* ---- error ---------------------------------------------------------------- */

static void
test_error_no_spill_root_is_enospc_stays_sequential(void)
{
    brix_vfs_writer_t w;

    reset_spies();
    g_spill_root = NULL;                     /* nothing configured */
    writer_init(&w, 0);
    errno = 0;
    assert(brix_vfs_writer_spill_enter(&w, 4096, 4096) == NGX_ERROR);
    assert(errno == ENOSPC);
    assert(w.mode == BRIX_VFS_WRITER_SEQUENTIAL);
    assert(g_metric_refused == 1);
    assert(g_staged_aborts == 0 && "an in-order continuation must still work");
}

static void
test_error_rewind_below_staged_prefix_is_einval(void)
{
    brix_vfs_writer_t w;

    reset_spies();
    g_spill_root = g_root_dir;
    writer_init(&w, 1 << 20);                /* 1 MiB already staged */
    errno = 0;
    assert(brix_vfs_writer_spill_enter(&w, 4096, 4096) == NGX_ERROR);
    assert(errno == EINVAL);
    assert(w.mode == BRIX_VFS_WRITER_SEQUENTIAL);
    assert(g_metric_refused == 1);
}

static void
test_error_overlap_is_einval_stays_spill(void)
{
    static const u_char blk[4096];
    brix_vfs_writer_t   w;

    reset_spies();
    g_spill_root = g_root_dir;
    writer_init(&w, 0);
    assert(brix_vfs_writer_spill_enter(&w, 8192, sizeof(blk)) == NGX_OK);
    assert(brix_vfs_writer_spill_put(&w, blk, sizeof(blk), 8192) == NGX_OK);
    errno = 0;
    assert(brix_vfs_writer_spill_put(&w, blk, sizeof(blk), 8192 + 100)
           == NGX_ERROR);
    assert(errno == EINVAL);
    assert(w.mode == BRIX_VFS_WRITER_SPILL && "client error, not capacity");
    assert(g_staged_aborts == 0);
    brix_vfs_writer_spill_discard(&w);
}

static void
test_error_drain_refuses_holes_untouched_staged(void)
{
    static const u_char blk[4096];
    brix_vfs_writer_t   w;

    reset_spies();
    g_spill_root = g_root_dir;
    writer_init(&w, 0);
    assert(brix_vfs_writer_spill_enter(&w, 8192, sizeof(blk)) == NGX_OK);
    assert(brix_vfs_writer_spill_put(&w, blk, sizeof(blk), 0) == NGX_OK);
    assert(brix_vfs_writer_spill_put(&w, blk, sizeof(blk), 8192) == NGX_OK);
    errno = 0;                               /* [4096,8192) never sent */
    assert(brix_vfs_writer_spill_drain(&w) == NGX_ERROR);
    assert(errno == EINVAL);
    assert(g_staged_writes == 0 && "a hole must never be zero-filled through");
    assert(g_metric_refused == 1);
    brix_vfs_writer_spill_discard(&w);
}

/* ---- security-negative ---------------------------------------------------- */

static void
test_secneg_spill_max_at_entry_aborts_staged(void)
{
    brix_vfs_writer_t w;

    reset_spies();
    g_spill_root = g_root_dir;
    g_spill_max  = 1 << 20;                  /* brix_vfs_spill_max 1m */
    writer_init(&w, 0);
    errno = 0;                               /* triggering extent spans 4 MiB */
    assert(brix_vfs_writer_spill_enter(&w, 4 << 20, 4096) == NGX_ERROR);
    assert(errno == ENOSPC);
    assert(w.mode == BRIX_VFS_WRITER_FAILED);
    assert(g_staged_aborts == 1 && g_abort_remove_tmp == 1);
    assert(w.spill.fd == NGX_INVALID_FILE && "refused before creating any scratch");
    assert(g_metric_refused == 1);
}

static void
test_secneg_spill_max_mid_put_leaves_no_partial_object(void)
{
    static const u_char blk[4096];
    brix_vfs_writer_t   w;
    struct stat         st;
    char                kept[PATH_MAX];

    reset_spies();
    g_spill_root = g_root_dir;
    g_spill_max  = 1 << 20;
    writer_init(&w, 0);
    assert(brix_vfs_writer_spill_enter(&w, 8192, sizeof(blk)) == NGX_OK);
    assert(brix_vfs_writer_spill_put(&w, blk, sizeof(blk), 8192) == NGX_OK);
    snprintf(kept, sizeof(kept), "%s", (const char *) w.spill.path);
    errno = 0;                               /* pushes the span past the cap */
    assert(brix_vfs_writer_spill_put(&w, blk, sizeof(blk), 2 << 20)
           == NGX_ERROR);
    assert(errno == ENOSPC);
    assert(w.mode == BRIX_VFS_WRITER_FAILED);
    assert(g_staged_aborts == 1 && g_abort_remove_tmp == 1);
    assert(stat(kept, &st) != 0 && "T4 must unlink the scratch too");
    assert(g_metric_active == 0);
}

static void
test_secneg_scratch_is_private_under_spill_root_never_export(void)
{
    brix_vfs_writer_t w;
    struct stat       st;
    size_t            rlen = strlen(g_root_dir);

    reset_spies();
    g_spill_root = g_root_dir;
    writer_init(&w, 0);
    assert(brix_vfs_writer_spill_enter(&w, 4096, 1) == NGX_OK);
    assert(scratch_on_disk(&w, &st));
    assert((st.st_mode & 07777) == 0600 && "scratch must be private");
    assert(strncmp((const char *) w.spill.path, g_root_dir, rlen) == 0
           && ((const char *) w.spill.path)[rlen] == '/'
           && "scratch must live under the SERVICE spill root");
    assert(strncmp((const char *) w.spill.path, g_export_dir,
                   strlen(g_export_dir)) != 0
           && "scratch must never land under the export");
    assert(strstr((const char *) w.spill.path, ".xrd-tmp.") != NULL
           && "an orphan must be reclaimable by the owned-temp reaper");
    brix_vfs_writer_spill_discard(&w);
}

int
main(void)
{
    const char *tmp = getenv("TMPDIR");

    snprintf(g_root_dir, sizeof(g_root_dir), "%s/spillunit.XXXXXX",
             tmp != NULL && tmp[0] != '\0' ? tmp : "/tmp");
    assert(mkdtemp(g_root_dir) != NULL);
    snprintf(g_export_dir, sizeof(g_export_dir), "%s/export", g_root_dir);
    g_ctx.root_canon    = g_export_dir;      /* the ctx's EXPORT, distinct */
    g_ctx.metrics_proto = BRIX_PROTO_ROOT;
    g_pool = ngx_create_pool(4096, &g_log);
    assert(g_pool != NULL);

    test_success_enter_creates_scratch_and_promotes();
    test_success_reverse_order_drain_is_byte_exact();
    test_success_discard_unlinks_and_is_idempotent();
    test_error_no_spill_root_is_enospc_stays_sequential();
    test_error_rewind_below_staged_prefix_is_einval();
    test_error_overlap_is_einval_stays_spill();
    test_error_drain_refuses_holes_untouched_staged();
    test_secneg_spill_max_at_entry_aborts_staged();
    test_secneg_spill_max_mid_put_leaves_no_partial_object();
    test_secneg_scratch_is_private_under_spill_root_never_export();

    ngx_destroy_pool(g_pool);
    (void) rmdir(g_root_dir);
    printf("vfs_writer_spill: 10 cases OK\n");
    return 0;
}
