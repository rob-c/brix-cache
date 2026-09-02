/*
 * test_vfs_lock_gate.c — the four lock-expiry states of the cross-protocol
 * lock gate (phase-107 C7).
 *
 * WHAT: drives brix_vfs_require_unlocked() / _at() / _many() through every
 *       verdict the gate can reach: the four record states (absent /
 *       live-owned / live-foreign / expired), ancestor coverage
 *       (depth-infinity vs depth-0, up to and including the export root), the
 *       three enforcement modes (strict refuses, advisory books-warns-admits,
 *       off reads nothing), the strict fail-closed on an unreadable record,
 *       the EINVAL guards, and the batch form's parent-chain memo (n + 2
 *       probes for a flat batch; the exact-node probe never skipped; an
 *       advisory breach never seeds the memo).
 * WHY:  a wire test sees only the response. It cannot see that OFF mode read
 *       zero xattrs, that an expired record was left in place un-reaped, that
 *       the walk probed exactly the ancestor chain and nothing else, or that
 *       the refusal metric booked in advisory mode where the CLIENT saw
 *       success — each of which is contract, not implementation detail.
 * HOW:  links the REAL vfs_lock_gate.o and the REAL lock_record.o (encode/
 *       decode/ascend are the format under test), and supplies the remaining
 *       cross-TU closure as counting stubs: the quiet xattr read (a path-keyed
 *       in-memory record table), the backend-registry mode lookup, and the
 *       refusal metric. No filesystem, no pool, no backend. The expired-is-
 *       absent-without-reaping proof is structural as well as behavioural:
 *       this binary links no mutation symbol at all, so the gate COULD not
 *       reap — and the record table is asserted intact after the call.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "fs/vfs/vfs.h"
#include "fs/vfs/vfs_internal.h"
#include "fs/vfs/vfs_policy.h"
#include "core/compat/lock_record.h"

/* ---- clock: the gate reads ngx_time() (= ngx_cached_time->sec) ---------- */

#define TEST_NOW 1000000

static ngx_time_t      g_time = { TEST_NOW, 0, 0 };
volatile ngx_time_t   *ngx_cached_time = &g_time;

/* ---- stub: the backend registry's per-export enforcement mode ----------- */

static ngx_uint_t g_mode = BRIX_VFS_LOCK_STRICT;
static int        g_mode_lookups;

ngx_uint_t
brix_vfs_backend_lock_enforcement(const char *root_canon)
{
    (void) root_canon;
    g_mode_lookups++;
    return g_mode;
}

/* ---- stub: the refusal metric ------------------------------------------- */

static int g_metric_bookings;

void
brix_metric_vfs_lock_refused(brix_proto_t proto)
{
    (void) proto;
    g_metric_bookings++;
}

/* ---- stub: the op-name table (advisory warn text only) ------------------ */

const char *
brix_vfs_mutation_op_name(brix_vfs_mutation_op_t op)
{
    (void) op;
    return "open";
}

/* ---- stub: the quiet xattr read — a path-keyed record table ------------- */

#define MAX_RECORDS 4

typedef struct {
    const char *path;         /* absolute path carrying a lock record   */
    char        raw[BRIX_LOCK_XATTR_MAXLEN];
    size_t      rawlen;
} lock_entry_t;

static lock_entry_t g_records[MAX_RECORDS];
static int          g_nrecords;
static int          g_probes;               /* total quiet reads           */
static char         g_probed[8][64];        /* probe order, for walk shape */
static const char  *g_fault_path;           /* this path faults ...        */
static int          g_fault_errno;          /* ... with this errno         */

ssize_t
brix_vfs_getxattr_quiet_at(brix_vfs_ctx_t *ctx, const char *path,
    const char *name, void *buf, size_t bufsz)
{
    int i;

    (void) ctx;
    (void) name;

    if (g_probes < 8) {
        snprintf(g_probed[g_probes], sizeof(g_probed[0]), "%s", path);
    }
    g_probes++;

    if (g_fault_path != NULL && strcmp(path, g_fault_path) == 0) {
        errno = g_fault_errno;
        return -1;
    }

    for (i = 0; i < g_nrecords; i++) {
        if (strcmp(g_records[i].path, path) == 0) {
            if (g_records[i].rawlen > bufsz) {
                errno = ERANGE;
                return -1;
            }
            memcpy(buf, g_records[i].raw, g_records[i].rawlen);
            return (ssize_t) g_records[i].rawlen;
        }
    }

    errno = ENODATA;
    return -1;
}

/* ---- harness ------------------------------------------------------------- */

static int g_failures;

#define CHECK(cond, what)                                                     \
    do {                                                                      \
        if (!(cond)) {                                                        \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, what);    \
            g_failures++;                                                     \
        }                                                                     \
    } while (0)

static void
reset(void)
{
    g_nrecords      = 0;
    g_probes        = 0;
    g_mode_lookups  = 0;
    g_metric_bookings = 0;
    g_fault_path    = NULL;
    g_fault_errno   = 0;
    g_mode          = BRIX_VFS_LOCK_STRICT;
    memset(g_probed, 0, sizeof(g_probed));
    memset(g_records, 0, sizeof(g_records));
}

static void
add_record(const char *path, const char *token, int64_t expires,
    int depth_infinity)
{
    brix_lock_record_t rec;
    lock_entry_t      *e = &g_records[g_nrecords++];

    memset(&rec, 0, sizeof(rec));
    snprintf(rec.token, sizeof(rec.token), "%s", token);
    snprintf(rec.owner, sizeof(rec.owner), "test-owner");
    rec.expires        = expires;
    rec.exclusive      = 1;
    rec.depth_infinity = depth_infinity ? 1 : 0;

    e->path = path;
    CHECK(brix_lock_record_encode(&rec, e->raw, sizeof(e->raw)) == NGX_OK,
          "record encode");
    e->rawlen = strlen(e->raw);
}

static void
make_ctx(brix_vfs_ctx_t *ctx, const char *path)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->root_canon             = "/root";
    ctx->metrics_proto          = BRIX_PROTO_ROOT;
    ctx->resolved.resolved.data = (u_char *) path;
    ctx->resolved.resolved.len  = strlen(path);
    ctx->resolved.is_confined   = 1;
    /* log stays NULL: the advisory warn is guarded, and no test needs it */
}

int
main(void)
{
    brix_vfs_ctx_t ctx;
    ngx_int_t      rc;

    /* 1. absent everywhere: OK, and the walk probes exactly the ancestor
     *    chain target -> export root, once each, in ascending order. */
    reset();
    make_ctx(&ctx, "/root/a/b/f");
    rc = brix_vfs_require_unlocked(&ctx, BRIX_VFS_MUTATE_OPEN);
    CHECK(rc == NGX_OK, "absent: OK");
    CHECK(g_probes == 4, "absent: 4 levels probed");
    CHECK(strcmp(g_probed[0], "/root/a/b/f") == 0
          && strcmp(g_probed[1], "/root/a/b") == 0
          && strcmp(g_probed[2], "/root/a") == 0
          && strcmp(g_probed[3], "/root") == 0,
          "absent: walk order target -> export root");
    CHECK(g_metric_bookings == 0, "absent: no refusal booked");

    /* 2. live foreign lock on the target, strict: EBUSY, metric books once,
     *    and the walk stopped at the refusing level. */
    reset();
    make_ctx(&ctx, "/root/a/b/f");
    add_record("/root/a/b/f", "opaquelocktoken:t-1", TEST_NOW + 900, 0);
    errno = 0;
    rc = brix_vfs_require_unlocked(&ctx, BRIX_VFS_MUTATE_OPEN);
    CHECK(rc == NGX_ERROR && errno == EBUSY, "live foreign: EBUSY");
    CHECK(g_metric_bookings == 1, "live foreign: metric booked once");
    CHECK(g_probes == 1, "live foreign: refusal at first level stops walk");

    /* 3. live lock, token presented (raw If-header value contains the token
     *    as a substring — the edge's own match): owned, mutation proceeds. */
    reset();
    make_ctx(&ctx, "/root/a/b/f");
    ctx.lock_token = "(<opaquelocktoken:t-1>)";
    add_record("/root/a/b/f", "opaquelocktoken:t-1", TEST_NOW + 900, 0);
    rc = brix_vfs_require_unlocked(&ctx, BRIX_VFS_MUTATE_OPEN);
    CHECK(rc == NGX_OK, "owned: OK");
    CHECK(g_metric_bookings == 0, "owned: nothing booked");

    /* 3b. a DIFFERENT token presented: still foreign, still refused. */
    reset();
    make_ctx(&ctx, "/root/a/b/f");
    ctx.lock_token = "(<opaquelocktoken:someone-elses>)";
    add_record("/root/a/b/f", "opaquelocktoken:t-1", TEST_NOW + 900, 0);
    errno = 0;
    rc = brix_vfs_require_unlocked(&ctx, BRIX_VFS_MUTATE_OPEN);
    CHECK(rc == NGX_ERROR && errno == EBUSY, "wrong token: EBUSY");

    /* 4. EXPIRED record on the target: treated as absent — and NOT reaped.
     *    Structurally this binary links no mutation symbol, so the gate could
     *    not reap; behaviourally the record table is untouched and the walk
     *    continued past the expired level to the root. */
    reset();
    make_ctx(&ctx, "/root/a/b/f");
    add_record("/root/a/b/f", "opaquelocktoken:t-1", TEST_NOW - 1, 0);
    rc = brix_vfs_require_unlocked(&ctx, BRIX_VFS_MUTATE_OPEN);
    CHECK(rc == NGX_OK, "expired: treated as absent");
    CHECK(g_probes == 4, "expired: walk continued to the root");
    CHECK(g_nrecords == 1 && g_records[0].rawlen > 0,
          "expired: record left in place (not reaped)");
    CHECK(g_metric_bookings == 0, "expired: nothing booked");

    /* 5. depth-infinity live foreign lock on an ANCESTOR covers the target. */
    reset();
    make_ctx(&ctx, "/root/a/b/f");
    add_record("/root/a", "opaquelocktoken:t-2", TEST_NOW + 900, 1);
    errno = 0;
    rc = brix_vfs_require_unlocked(&ctx, BRIX_VFS_MUTATE_REMOVE);
    CHECK(rc == NGX_ERROR && errno == EBUSY, "depth-infinity ancestor: EBUSY");

    /* 5b. depth-0 lock on the same ancestor does NOT cover the target. */
    reset();
    make_ctx(&ctx, "/root/a/b/f");
    add_record("/root/a", "opaquelocktoken:t-2", TEST_NOW + 900, 0);
    rc = brix_vfs_require_unlocked(&ctx, BRIX_VFS_MUTATE_REMOVE);
    CHECK(rc == NGX_OK, "depth-0 ancestor: no coverage");

    /* 5c. depth-infinity lock on the EXPORT ROOT itself covers everything. */
    reset();
    make_ctx(&ctx, "/root/a/b/f");
    add_record("/root", "opaquelocktoken:t-3", TEST_NOW + 900, 1);
    errno = 0;
    rc = brix_vfs_require_unlocked(&ctx, BRIX_VFS_MUTATE_MKDIR);
    CHECK(rc == NGX_ERROR && errno == EBUSY, "root collection lock: EBUSY");

    /* 6. ADVISORY: the same live foreign lock admits the mutation, but the
     *    refusal metric still books — that count is the migration signal. */
    reset();
    g_mode = BRIX_VFS_LOCK_ADVISORY;
    make_ctx(&ctx, "/root/a/b/f");
    add_record("/root/a/b/f", "opaquelocktoken:t-1", TEST_NOW + 900, 0);
    rc = brix_vfs_require_unlocked(&ctx, BRIX_VFS_MUTATE_OPEN);
    CHECK(rc == NGX_OK, "advisory: admitted");
    CHECK(g_metric_bookings == 1, "advisory: breach still booked");

    /* 7. OFF: no probe at all — the gate reads nothing it will not use. */
    reset();
    g_mode = BRIX_VFS_LOCK_OFF;
    make_ctx(&ctx, "/root/a/b/f");
    add_record("/root/a/b/f", "opaquelocktoken:t-1", TEST_NOW + 900, 0);
    rc = brix_vfs_require_unlocked(&ctx, BRIX_VFS_MUTATE_OPEN);
    CHECK(rc == NGX_OK, "off: OK");
    CHECK(g_probes == 0, "off: zero xattr reads");
    CHECK(g_mode_lookups == 1, "off: decided by the registry lookup");

    /* 8. a HARD read fault (EIO, not absent-class): strict cannot prove
     *    unlocked and fails closed with the fault's errno ... */
    reset();
    make_ctx(&ctx, "/root/a/b/f");
    g_fault_path  = "/root/a/b";
    g_fault_errno = EIO;
    errno = 0;
    rc = brix_vfs_require_unlocked(&ctx, BRIX_VFS_MUTATE_OPEN);
    CHECK(rc == NGX_ERROR && errno == EIO, "strict fault: fail closed, EIO");
    CHECK(g_metric_bookings == 0, "strict fault: not a lock refusal");

    /* 8b. ... while advisory logs on and completes the walk. */
    reset();
    g_mode = BRIX_VFS_LOCK_ADVISORY;
    make_ctx(&ctx, "/root/a/b/f");
    g_fault_path  = "/root/a/b";
    g_fault_errno = EIO;
    rc = brix_vfs_require_unlocked(&ctx, BRIX_VFS_MUTATE_OPEN);
    CHECK(rc == NGX_OK, "advisory fault: admitted");
    CHECK(g_probes == 4, "advisory fault: walk completed");

    /* 9. guards: out-of-range op and an unconfined ctx are EINVAL. */
    reset();
    make_ctx(&ctx, "/root/a/b/f");
    errno = 0;
    rc = brix_vfs_require_unlocked(&ctx, BRIX_VFS_MUTATE_OP_COUNT);
    CHECK(rc == NGX_ERROR && errno == EINVAL, "op out of range: EINVAL");
    CHECK(g_probes == 0, "op out of range: nothing probed");

    reset();
    make_ctx(&ctx, "/root/a/b/f");
    ctx.resolved.is_confined = 0;
    errno = 0;
    rc = brix_vfs_require_unlocked(&ctx, BRIX_VFS_MUTATE_OPEN);
    CHECK(rc == NGX_ERROR && errno == EINVAL, "unconfined: EINVAL");
    CHECK(g_probes == 0, "unconfined: nothing probed");

    /* 10. the _at variant gates an ALTERNATE confined path (a two-name op's
     *     second name) with the ctx's own token and mode. */
    reset();
    make_ctx(&ctx, "/root/src");
    add_record("/root/dst", "opaquelocktoken:t-9", TEST_NOW + 900, 0);
    errno = 0;
    rc = brix_vfs_require_unlocked_at(&ctx, "/root/dst",
                                      BRIX_VFS_MUTATE_RENAME);
    CHECK(rc == NGX_ERROR && errno == EBUSY, "_at: destination lock refuses");
    CHECK(strcmp(g_probed[0], "/root/dst") == 0, "_at: walks the alt path");

    reset();
    make_ctx(&ctx, "/root/src");
    errno = 0;
    rc = brix_vfs_require_unlocked_at(&ctx, NULL, BRIX_VFS_MUTATE_RENAME);
    CHECK(rc == NGX_ERROR && errno == EINVAL, "_at: NULL path is EINVAL");

    /* 11. the _many batch form: the parent-chain memo. A flat batch walks the
     *     shared chain ONCE — n + 2 probes, not 3n — while every key still
     *     gets its exact-node probe. */
    {
        static const char *flat[3] =
            { "/root/d/f1", "/root/d/f2", "/root/d/f3" };
        static const char *split[3] =
            { "/root/d1/f", "/root/d1/g", "/root/d2/h" };
        static const char *bad[2] = { "/root/d/f1", NULL };

        /* 11a. absent everywhere: 5 probes (f1's full walk, then one exact
         *      probe per remaining key), never the parent chain again. */
        reset();
        make_ctx(&ctx, "/root/d/f1");
        rc = brix_vfs_require_unlocked_many(&ctx, flat, 3,
                                            BRIX_VFS_MUTATE_REMOVE);
        CHECK(rc == NGX_OK, "many absent: OK");
        CHECK(g_probes == 5, "many absent: n + 2 probes");
        CHECK(strcmp(g_probed[0], "/root/d/f1") == 0
              && strcmp(g_probed[1], "/root/d") == 0
              && strcmp(g_probed[2], "/root") == 0
              && strcmp(g_probed[3], "/root/d/f2") == 0
              && strcmp(g_probed[4], "/root/d/f3") == 0,
              "many absent: memo skips only the proven chain");

        /* 11b. exact-node lock on a LATER key: the memo must never hide the
         *      exact probe. Atomic strict refusal at that key. */
        reset();
        make_ctx(&ctx, "/root/d/f1");
        add_record("/root/d/f2", "opaquelocktoken:t-4", TEST_NOW + 900, 0);
        errno = 0;
        rc = brix_vfs_require_unlocked_many(&ctx, flat, 3,
                                            BRIX_VFS_MUTATE_REMOVE);
        CHECK(rc == NGX_ERROR && errno == EBUSY,
              "many exact-later: EBUSY");
        CHECK(g_probes == 4 && g_metric_bookings == 1,
              "many exact-later: refused at key 2's own probe, key 3 untried");

        /* 11c. depth-infinity lock on the shared parent: the FIRST key's walk
         *      refuses; nothing after it is examined. */
        reset();
        make_ctx(&ctx, "/root/d/f1");
        add_record("/root/d", "opaquelocktoken:t-5", TEST_NOW + 900, 1);
        errno = 0;
        rc = brix_vfs_require_unlocked_many(&ctx, flat, 3,
                                            BRIX_VFS_MUTATE_REMOVE);
        CHECK(rc == NGX_ERROR && errno == EBUSY, "many ancestor: EBUSY");
        CHECK(g_probes == 2 && g_metric_bookings == 1,
              "many ancestor: atomic — first key's walk, nothing more");

        /* 11d. the same conflict under ADVISORY: an admitted breach never
         *      seeds the memo, so the refusal metric books PER KEY exactly as
         *      the per-path gate would. */
        reset();
        g_mode = BRIX_VFS_LOCK_ADVISORY;
        make_ctx(&ctx, "/root/d/f1");
        add_record("/root/d", "opaquelocktoken:t-5", TEST_NOW + 900, 1);
        rc = brix_vfs_require_unlocked_many(&ctx, flat, 3,
                                            BRIX_VFS_MUTATE_REMOVE);
        CHECK(rc == NGX_OK, "many advisory: admitted");
        CHECK(g_metric_bookings == 3,
              "many advisory: breach booked per key (memo not seeded)");

        /* 11e. a parent switch mid-batch invalidates the memo for exactly one
         *      full walk: 3 + 1 + 3 probes across two directories. */
        reset();
        make_ctx(&ctx, "/root/d1/f");
        rc = brix_vfs_require_unlocked_many(&ctx, split, 3,
                                            BRIX_VFS_MUTATE_REMOVE);
        CHECK(rc == NGX_OK, "many split: OK");
        CHECK(g_probes == 7, "many split: 3 + 1 + 3 probes");
        CHECK(strcmp(g_probed[3], "/root/d1/g") == 0
              && strcmp(g_probed[4], "/root/d2/h") == 0
              && strcmp(g_probed[5], "/root/d2") == 0
              && strcmp(g_probed[6], "/root") == 0,
              "many split: second directory walked in full");

        /* 11f. OFF reads nothing; a NULL array or NULL element is EINVAL
         *      before any probe. */
        reset();
        g_mode = BRIX_VFS_LOCK_OFF;
        make_ctx(&ctx, "/root/d/f1");
        rc = brix_vfs_require_unlocked_many(&ctx, flat, 3,
                                            BRIX_VFS_MUTATE_REMOVE);
        CHECK(rc == NGX_OK && g_probes == 0, "many off: zero reads");

        reset();
        make_ctx(&ctx, "/root/d/f1");
        errno = 0;
        rc = brix_vfs_require_unlocked_many(&ctx, NULL, 3,
                                            BRIX_VFS_MUTATE_REMOVE);
        CHECK(rc == NGX_ERROR && errno == EINVAL, "many: NULL array EINVAL");

        reset();
        make_ctx(&ctx, "/root/d/f1");
        errno = 0;
        rc = brix_vfs_require_unlocked_many(&ctx, bad, 2,
                                            BRIX_VFS_MUTATE_REMOVE);
        CHECK(rc == NGX_ERROR && errno == EINVAL,
              "many: NULL element EINVAL");
        CHECK(g_probes == 3, "many: only the valid key ahead was probed");
    }

    if (g_failures) {
        fprintf(stderr, "%d check(s) failed\n", g_failures);
        return 1;
    }

    printf("test_vfs_lock_gate: all checks passed\n");
    return 0;
}
