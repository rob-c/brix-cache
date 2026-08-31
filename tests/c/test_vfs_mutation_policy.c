/*
 * test_vfs_mutation_policy.c — the phase-105 VFS mutation-policy kernel.
 *
 * WHAT: proves the whole of vfs_policy.o: the config-derivation helper, the
 *       bounded operation-name table, the four decision forms (pure, ctx,
 *       confined-ctx, carried), the policy-bearing export operation context,
 *       and the raw-open-flag classifier. Every refusal is checked for the
 *       EXACT errno the plan promises (EROFS for a read-only endpoint, EINVAL
 *       for a malformed request) and for exactly one metric observation.
 * WHY:  this kernel is the single point at which "may this request modify
 *       exported storage?" is decided. If it fails open for a stray policy
 *       value, answers EACCES instead of EROFS, double-counts, or lets an
 *       out-of-range operation through, then every mutation entry point in the
 *       VFS inherits the defect at once — and the read-only guarantee stops
 *       being a VFS invariant and goes back to being an edge habit.
 * HOW:  vfs_policy.o names exactly one cross-TU symbol
 *       (brix_metric_vfs_mutation_denied), so the harness links the ONE real
 *       object and supplies that recorder as a spy. The result is fully
 *       hermetic: no pool, no log, no backend registry, no filesystem, and the
 *       denial counter is directly observable rather than inferred.
 *
 * Cases:
 *   success:      ALLOWED permits every operation in the vocabulary through
 *                 all four forms with errno untouched and no denial recorded;
 *                 brix_vfs_policy_from_write_enable(1) is the only input that
 *                 yields ALLOWED; the op-name table answers every enum value
 *                 with its stable lowercase label; _op_ctx_init/_from carry the
 *                 log, root, policy and proto verbatim; a provably read-only
 *                 open (O_RDONLY, no O_CREAT/O_TRUNC/O_APPEND) is not a
 *                 mutation.
 *   error:        a NULL ctx, a NULL export bundle and an out-of-range
 *                 operation are EINVAL — a malformed request, never answered
 *                 with the endpoint's write posture and never counted as a
 *                 read-only denial; an unconfined path is EINVAL even when the
 *                 endpoint is read-only, because confinement is decided first.
 *   security-neg: READ_ONLY refuses with EROFS (never EACCES) through all four
 *                 forms, exactly once per refusal, attributed to the caller's
 *                 protocol; a zeroed ctx, a zeroed export bundle and a
 *                 zeroed carried policy all fail CLOSED; a policy value outside
 *                 the enum (2, 255, -1 — an uninitialised or corrupted slot)
 *                 is READ_ONLY rather than "non-zero means writable", and
 *                 _op_ctx_init normalises it on the way in so a stray integer
 *                 cannot open an endpoint; NGX_CONF_UNSET does not enable
 *                 writes; and every write-shaped open flag word is classified
 *                 as a mutation.
 *
 * Build+run: see tests/cmdscripts/c_object_units.py ("vfs_mutation_policy").
 */
#include "fs/vfs/vfs.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>

/* ---- the spy recorder ----------------------------------------------------
 * vfs_policy.o's only cross-TU reference. Counting here is what makes "exactly
 * one sample per refusal, none on success, none on a malformed request"
 * checkable rather than assumed. */
static ngx_uint_t   g_denials;
static brix_proto_t g_last_proto;
static ngx_uint_t   g_last_op;

void
brix_metric_vfs_mutation_denied(brix_proto_t proto, ngx_uint_t op)
{
    g_denials++;
    g_last_proto = proto;
    g_last_op = op;
}

static void
reset_spy(void)
{
    g_denials = 0;
    g_last_proto = BRIX_PROTO_COUNT;
    g_last_op = (ngx_uint_t) -1;
}

/* A ctx carrying `policy`, resolved to a confined path unless `confined` is 0.
 * Zeroed first, exactly as a real caller's stack ctx is. */
static void
ctx_build(brix_vfs_ctx_t *ctx, brix_vfs_mutation_policy_t policy, int confined)
{
    static u_char path[] = "/export/data/object";

    memset(ctx, 0, sizeof(*ctx));
    ctx->metrics_proto = BRIX_PROTO_WEBDAV;
    ctx->root_canon = "/export";
    ctx->mutation_policy = policy;
    ctx->resolved.resolved.data = path;
    ctx->resolved.resolved.len = sizeof(path) - 1;
    ctx->resolved.is_confined = confined ? 1 : 0;
}

/* Assert `rc` is a refusal carrying exactly `expect_errno`, and that the denial
 * counter moved by `expect_samples`. */
static void
assert_refused(ngx_int_t rc, int expect_errno, ngx_uint_t expect_samples)
{
    assert(rc == NGX_ERROR);
    assert(errno == expect_errno);
    assert(errno != EACCES);
    assert(g_denials == expect_samples);
}

static void
test_success(void)
{
    brix_vfs_ctx_t            ctx;
    brix_vfs_export_op_ctx_t  opctx;
    ngx_log_t                 log;
    int                       op;

    /* Only the exact enabled flag opens the endpoint. */
    assert(brix_vfs_policy_from_write_enable(1) == BRIX_VFS_MUTATION_ALLOWED);

    /* Every operation in the vocabulary passes under an ALLOWED policy, through
     * all four forms, without touching errno or the denial counter. */
    ctx_build(&ctx, BRIX_VFS_MUTATION_ALLOWED, 1);
    brix_vfs_export_op_ctx_init(&opctx, &log, "/export",
        BRIX_VFS_MUTATION_ALLOWED, BRIX_PROTO_S3);

    for (op = 0; op < (int) BRIX_VFS_MUTATE_OP_COUNT; op++) {
        reset_spy();
        errno = 0;
        assert(brix_vfs_require_mutation_policy(BRIX_VFS_MUTATION_ALLOWED,
                   (brix_vfs_mutation_op_t) op) == NGX_OK);
        assert(brix_vfs_require_mutation(&ctx,
                   (brix_vfs_mutation_op_t) op) == NGX_OK);
        assert(brix_vfs_require_confined_mutation(&ctx,
                   (brix_vfs_mutation_op_t) op) == NGX_OK);
        assert(brix_vfs_require_carried_mutation(BRIX_VFS_MUTATION_ALLOWED,
                   BRIX_PROTO_ROOT, (brix_vfs_mutation_op_t) op) == NGX_OK);
        assert(brix_vfs_export_require_mutation(&opctx,
                   (brix_vfs_mutation_op_t) op) == NGX_OK);
        assert(errno == 0);
        assert(g_denials == 0);
    }

    /* One closed vocabulary, one label per value, no duplicates and no empty
     * string — metrics and structured logs read the same table. */
    assert(strcmp(brix_vfs_mutation_op_name(BRIX_VFS_MUTATE_OPEN), "open") == 0);
    assert(strcmp(brix_vfs_mutation_op_name(BRIX_VFS_MUTATE_WRITE),
               "write") == 0);
    assert(strcmp(brix_vfs_mutation_op_name(BRIX_VFS_MUTATE_TRUNCATE),
               "truncate") == 0);
    assert(strcmp(brix_vfs_mutation_op_name(BRIX_VFS_MUTATE_SYNC),
               "sync") == 0);
    assert(strcmp(brix_vfs_mutation_op_name(BRIX_VFS_MUTATE_MKDIR),
               "mkdir") == 0);
    assert(strcmp(brix_vfs_mutation_op_name(BRIX_VFS_MUTATE_REMOVE),
               "remove") == 0);
    assert(strcmp(brix_vfs_mutation_op_name(BRIX_VFS_MUTATE_RENAME),
               "rename") == 0);
    assert(strcmp(brix_vfs_mutation_op_name(BRIX_VFS_MUTATE_COPY),
               "copy") == 0);
    assert(strcmp(brix_vfs_mutation_op_name(BRIX_VFS_MUTATE_SETATTR),
               "setattr") == 0);
    assert(strcmp(brix_vfs_mutation_op_name(BRIX_VFS_MUTATE_XATTR),
               "xattr") == 0);
    assert(strcmp(brix_vfs_mutation_op_name(BRIX_VFS_MUTATE_PUBLISH),
               "publish") == 0);

    for (op = 0; op < (int) BRIX_VFS_MUTATE_OP_COUNT; op++) {
        const char *name = brix_vfs_mutation_op_name(
            (brix_vfs_mutation_op_t) op);
        int         other;

        assert(name != NULL && name[0] != '\0');
        assert(strcmp(name, "unknown") != 0);

        for (other = 0; other < op; other++) {
            assert(strcmp(name, brix_vfs_mutation_op_name(
                       (brix_vfs_mutation_op_t) other)) != 0);
        }
    }

    /* The export bundle carries the request's authority verbatim — it is the
     * only sanctioned bridge onto the ctx-less raw helpers. */
    brix_vfs_export_op_ctx_init(&opctx, &log, "/export",
        BRIX_VFS_MUTATION_ALLOWED, BRIX_PROTO_GRIDFTP);
    assert(opctx.log == &log);
    assert(strcmp(opctx.root_canon, "/export") == 0);
    assert(opctx.mutation_policy == BRIX_VFS_MUTATION_ALLOWED);
    assert(opctx.proto == BRIX_PROTO_GRIDFTP);

    ctx.log = &log;
    memset(&opctx, 0, sizeof(opctx));
    brix_vfs_export_op_ctx_from(&opctx, &ctx);
    assert(opctx.log == &log);
    assert(opctx.root_canon == ctx.root_canon);
    assert(opctx.mutation_policy == BRIX_VFS_MUTATION_ALLOWED);
    assert(opctx.proto == BRIX_PROTO_WEBDAV);

    /* A provably read-only open is not a mutation: refusing it would break
     * reads on a read-only export. */
    assert(brix_vfs_open_flags_mutate(O_RDONLY) == 0);
    assert(brix_vfs_open_flags_mutate(O_RDONLY | O_CLOEXEC | O_NOFOLLOW) == 0);
    assert(brix_vfs_open_flags_mutate(O_RDONLY | O_DIRECTORY) == 0);

    printf("ok success\n");
}

static void
test_error(void)
{
    brix_vfs_ctx_t            ctx;
    brix_vfs_export_op_ctx_t  opctx;

    /* A missing context or bundle is a programming error, not a policy
     * question: EINVAL, and never counted as a read-only denial. */
    reset_spy();
    errno = 0;
    assert_refused(brix_vfs_require_mutation(NULL, BRIX_VFS_MUTATE_WRITE),
        EINVAL, 0);

    reset_spy();
    errno = 0;
    assert_refused(brix_vfs_export_require_mutation(NULL,
        BRIX_VFS_MUTATE_WRITE), EINVAL, 0);

    reset_spy();
    errno = 0;
    assert_refused(brix_vfs_require_confined_mutation(NULL,
        BRIX_VFS_MUTATE_MKDIR), EINVAL, 0);

    /* An operation outside the closed vocabulary is EINVAL through every form,
     * under an ALLOWED policy as much as a read-only one — the vocabulary is a
     * bound on the metric label, so an unbounded value must not reach it. */
    ctx_build(&ctx, BRIX_VFS_MUTATION_ALLOWED, 1);
    brix_vfs_export_op_ctx_init(&opctx, NULL, "/export",
        BRIX_VFS_MUTATION_ALLOWED, BRIX_PROTO_S3);

    reset_spy();
    errno = 0;
    assert_refused(brix_vfs_require_mutation_policy(BRIX_VFS_MUTATION_ALLOWED,
        BRIX_VFS_MUTATE_OP_COUNT), EINVAL, 0);

    reset_spy();
    errno = 0;
    assert_refused(brix_vfs_require_mutation(&ctx,
        (brix_vfs_mutation_op_t) 999), EINVAL, 0);

    reset_spy();
    errno = 0;
    assert_refused(brix_vfs_require_carried_mutation(BRIX_VFS_MUTATION_ALLOWED,
        BRIX_PROTO_ROOT, (brix_vfs_mutation_op_t) -1), EINVAL, 0);

    reset_spy();
    errno = 0;
    assert_refused(brix_vfs_export_require_mutation(&opctx,
        BRIX_VFS_MUTATE_OP_COUNT), EINVAL, 0);

    /* An unresolved or escaped path is a malformed request, answered before —
     * and instead of — the endpoint's write posture, so a read-only export
     * never discloses its posture to a path it would have rejected anyway. */
    ctx_build(&ctx, BRIX_VFS_MUTATION_READ_ONLY, 0);
    reset_spy();
    errno = 0;
    assert_refused(brix_vfs_require_confined_mutation(&ctx,
        BRIX_VFS_MUTATE_REMOVE), EINVAL, 0);

    ctx_build(&ctx, BRIX_VFS_MUTATION_ALLOWED, 0);
    reset_spy();
    errno = 0;
    assert_refused(brix_vfs_require_confined_mutation(&ctx,
        BRIX_VFS_MUTATE_REMOVE), EINVAL, 0);

    /* An out-of-range op is refused BEFORE the label table is indexed, and the
     * table itself answers a bounded fallback rather than reading past its
     * end. */
    assert(strcmp(brix_vfs_mutation_op_name(BRIX_VFS_MUTATE_OP_COUNT),
               "unknown") == 0);
    assert(strcmp(brix_vfs_mutation_op_name((brix_vfs_mutation_op_t) 4096),
               "unknown") == 0);
    assert(strcmp(brix_vfs_mutation_op_name((brix_vfs_mutation_op_t) -1),
               "unknown") == 0);

    /* The NULL-tolerant constructors are no-ops, not faults. */
    brix_vfs_export_op_ctx_init(NULL, NULL, NULL, BRIX_VFS_MUTATION_ALLOWED,
        BRIX_PROTO_ROOT);
    brix_vfs_export_op_ctx_from(NULL, &ctx);

    printf("ok error\n");
}

/* Every refusal form under a read-only endpoint: EROFS, never EACCES, exactly
 * one sample, attributed to the caller's own protocol. */
static void
readonly_refuses_everywhere(void)
{
    brix_vfs_ctx_t            ctx;
    brix_vfs_export_op_ctx_t  opctx;

    ctx_build(&ctx, BRIX_VFS_MUTATION_READ_ONLY, 1);

    reset_spy();
    errno = 0;
    assert_refused(brix_vfs_require_mutation_policy(
        BRIX_VFS_MUTATION_READ_ONLY, BRIX_VFS_MUTATE_WRITE), EROFS, 0);

    reset_spy();
    errno = 0;
    assert_refused(brix_vfs_require_mutation(&ctx, BRIX_VFS_MUTATE_XATTR),
        EROFS, 1);
    assert(g_last_proto == BRIX_PROTO_WEBDAV);
    assert(g_last_op == (ngx_uint_t) BRIX_VFS_MUTATE_XATTR);

    reset_spy();
    errno = 0;
    assert_refused(brix_vfs_require_confined_mutation(&ctx,
        BRIX_VFS_MUTATE_MKDIR), EROFS, 1);
    assert(g_last_op == (ngx_uint_t) BRIX_VFS_MUTATE_MKDIR);

    reset_spy();
    errno = 0;
    assert_refused(brix_vfs_require_carried_mutation(
        BRIX_VFS_MUTATION_READ_ONLY, BRIX_PROTO_OCI,
        BRIX_VFS_MUTATE_PUBLISH), EROFS, 1);
    assert(g_last_proto == BRIX_PROTO_OCI);
    assert(g_last_op == (ngx_uint_t) BRIX_VFS_MUTATE_PUBLISH);

    brix_vfs_export_op_ctx_init(&opctx, NULL, "/export",
        BRIX_VFS_MUTATION_READ_ONLY, BRIX_PROTO_GRIDFTP);
    reset_spy();
    errno = 0;
    assert_refused(brix_vfs_export_require_mutation(&opctx,
        BRIX_VFS_MUTATE_COPY), EROFS, 1);
    assert(g_last_proto == BRIX_PROTO_GRIDFTP);
    assert(g_last_op == (ngx_uint_t) BRIX_VFS_MUTATE_COPY);
}

static void
test_security_negative(void)
{
    brix_vfs_ctx_t            ctx;
    brix_vfs_export_op_ctx_t  opctx;
    int                       op;
    int                       i;
    /* Values a slot could hold if it were never initialised, corrupted, or
     * merged from an unset ngx_flag_t. None of them may read as writable. */
    static const int          strays[] = { 2, 3, 255, -1, 0x7fffffff };

    readonly_refuses_everywhere();

    /* A zeroed ctx — the shape of a hand-built or partially-filled one — is
     * READ_ONLY, and refuses every operation in the vocabulary. */
    memset(&ctx, 0, sizeof(ctx));
    ctx.resolved.resolved.data = (u_char *) "/export/x";
    ctx.resolved.resolved.len = sizeof("/export/x") - 1;
    ctx.resolved.is_confined = 1;
    assert(ctx.mutation_policy == BRIX_VFS_MUTATION_READ_ONLY);

    for (op = 0; op < (int) BRIX_VFS_MUTATE_OP_COUNT; op++) {
        reset_spy();
        errno = 0;
        assert_refused(brix_vfs_require_confined_mutation(&ctx,
            (brix_vfs_mutation_op_t) op), EROFS, 1);
        assert(g_last_op == (ngx_uint_t) op);
    }

    /* A zeroed export bundle is READ_ONLY for the same reason, and a carried
     * policy that was never assigned refuses too. */
    memset(&opctx, 0, sizeof(opctx));
    reset_spy();
    errno = 0;
    assert_refused(brix_vfs_export_require_mutation(&opctx,
        BRIX_VFS_MUTATE_WRITE), EROFS, 1);

    reset_spy();
    errno = 0;
    assert_refused(brix_vfs_require_carried_mutation(
        (brix_vfs_mutation_policy_t) 0, BRIX_PROTO_ROOT,
        BRIX_VFS_MUTATE_WRITE), EROFS, 1);

    /* "Non-zero means writable" would be a fail-open: only the exact ALLOWED
     * value permits a mutation, and _op_ctx_init normalises a stray integer on
     * the way in so it cannot be laundered into an open endpoint. */
    for (i = 0; i < (int) (sizeof(strays) / sizeof(strays[0])); i++) {
        brix_vfs_mutation_policy_t stray = (brix_vfs_mutation_policy_t)
            strays[i];

        reset_spy();
        errno = 0;
        assert_refused(brix_vfs_require_mutation_policy(stray,
            BRIX_VFS_MUTATE_WRITE), EROFS, 0);

        ctx_build(&ctx, stray, 1);
        reset_spy();
        errno = 0;
        assert_refused(brix_vfs_require_confined_mutation(&ctx,
            BRIX_VFS_MUTATE_WRITE), EROFS, 1);

        brix_vfs_export_op_ctx_init(&opctx, NULL, "/export", stray,
            BRIX_PROTO_S3);
        assert(opctx.mutation_policy == BRIX_VFS_MUTATION_READ_ONLY);
        reset_spy();
        errno = 0;
        assert_refused(brix_vfs_export_require_mutation(&opctx,
            BRIX_VFS_MUTATE_WRITE), EROFS, 1);

        /* The same laundering attempt through the configuration helper: an
         * unmerged NGX_CONF_UNSET (-1) or any other value is READ_ONLY. */
        assert(brix_vfs_policy_from_write_enable((ngx_flag_t) strays[i])
                   == BRIX_VFS_MUTATION_READ_ONLY);
    }

    assert(brix_vfs_policy_from_write_enable(0)
               == BRIX_VFS_MUTATION_READ_ONLY);
    assert(brix_vfs_policy_from_write_enable(NGX_CONF_UNSET)
               == BRIX_VFS_MUTATION_READ_ONLY);

    /* A NULL ctx yields a CLOSED bundle rather than an empty-but-writable one,
     * so a bridge built from a missing request cannot mutate. */
    memset(&opctx, 0xff, sizeof(opctx));
    brix_vfs_export_op_ctx_from(&opctx, NULL);
    assert(opctx.mutation_policy == BRIX_VFS_MUTATION_READ_ONLY);
    assert(opctx.root_canon == NULL);
    reset_spy();
    errno = 0;
    assert_refused(brix_vfs_export_require_mutation(&opctx,
        BRIX_VFS_MUTATE_RENAME), EROFS, 1);

    /* The derived bundle can never WIDEN the request's authority: a read-only
     * ctx produces a read-only bundle. */
    ctx_build(&ctx, BRIX_VFS_MUTATION_READ_ONLY, 1);
    brix_vfs_export_op_ctx_from(&opctx, &ctx);
    assert(opctx.mutation_policy == BRIX_VFS_MUTATION_READ_ONLY);

    /* Every write-shaped open must take the kernel first; O_RDONLY paired with
     * a creating or size-changing flag is a mutation, not a read. */
    assert(brix_vfs_open_flags_mutate(O_WRONLY) == 1);
    assert(brix_vfs_open_flags_mutate(O_RDWR) == 1);
    assert(brix_vfs_open_flags_mutate(O_WRONLY | O_CREAT | O_TRUNC) == 1);
    assert(brix_vfs_open_flags_mutate(O_RDONLY | O_CREAT) == 1);
    assert(brix_vfs_open_flags_mutate(O_RDONLY | O_TRUNC) == 1);
    assert(brix_vfs_open_flags_mutate(O_RDONLY | O_APPEND) == 1);
    assert(brix_vfs_open_flags_mutate(O_RDWR | O_CLOEXEC | O_NOFOLLOW) == 1);

    printf("ok security-negative\n");
}

int
main(void)
{
    test_success();
    test_error();
    test_security_negative();
    printf("PASS test_vfs_mutation_policy\n");
    return 0;
}
