/*
 * vfs_policy_model_test.c — phase-115 W9.5: EXHAUSTIVE verification of the
 * typed VFS mutation-policy kernel (src/fs/vfs/vfs_policy.c).
 *
 * WHAT: Sweeps the kernel's decision functions over their COMPLETE 32-bit
 *       input domains — every one of the 4,294,967,296 values a policy word,
 *       an operation word or an open-flag word can hold — and checks the SIZE
 *       and the MEMBERSHIP of each answer set against a closed form derived
 *       from the contract, not from the code.  A representative-domain pass
 *       adds the structural properties (agreement between the five decision
 *       forms, NULL handling, ordering, denial counting, purity).
 *
 * WHY:  tests/c/test_vfs_mutation_policy.c already asserts these properties on
 *       hand-picked values, and (verified 2026-09-07 by mutation testing) it
 *       kills every structural weakening of the kernel.  What a sampled test
 *       cannot do is refute a MAGIC CONSTANT: `if (policy == 7) return NGX_OK;`
 *       passes every hand-picked case and opens every export in the fleet to a
 *       single corrupt word.  INVARIANT #12 is a claim about every input, so
 *       W9.5 states it as one — "of all 2^32 policy words, EXACTLY ONE opens an
 *       endpoint" is a sentence a sample can never justify and this sweep can.
 *
 * HOW:  1. Stub the kernel's two cross-TU symbols; the metric recorder is a
 *          SPY, because "exactly one denial per refusal" is itself a property.
 *       2. `--sweep=<name>` runs one 32-bit sweep (~5 s each); no argument runs
 *          the structural properties only; `--sweep=all` runs everything.
 *          Splitting them is what keeps mutation testing affordable: a mutant
 *          only needs the sweep that can see it.
 *       3. Every check prints its own PASS line naming the size it proved, so a
 *          property that stops running cannot hide behind ALL PASSED.
 *
 * Every loop below is a COMPLETE enumeration of its axis.  If one is ever
 * turned into a sample, W9.5 stops being a verification — the driver
 * (tests/test_phase115_vfs_policy_model.py) pins the printed sizes for that
 * reason.
 */
#include <ngx_config.h>
#include <ngx_core.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

#include "fs/vfs/vfs.h"

/* ---- the linker's two demands, one of them a spy --------------------------
 * brix_metric_vfs_mutation_denied: a SPY — the denial-counting property needs
 * to observe it directly rather than infer it.
 * brix_vfs_backend_n2n: the op-ctx builder consults the backend registry,
 * which takes no part in the decision; NULL is the no-mapping answer. */
volatile ngx_cycle_t *ngx_cycle = NULL;

void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...)
{
    (void) level; (void) log; (void) err; (void) fmt;
}

static long spy_calls;
static long spy_last_op = -1;

void
brix_metric_vfs_mutation_denied(brix_proto_t proto, ngx_uint_t op)
{
    (void) proto;
    spy_calls++;
    spy_last_op = (long) op;
}

const brix_n2n_cfg_t *
brix_vfs_backend_n2n(const char *root_canon)
{
    (void) root_canon;
    return NULL;
}

/* ---- harness -------------------------------------------------------------- */

static int failures;

#define REQUIRE(prop, cond, ...)                                              \
    do {                                                                      \
        if (!(cond)) {                                                        \
            printf("FAIL [%s] ", (prop));                                     \
            printf(__VA_ARGS__);                                              \
            printf("\n");                                                     \
            failures++;                                                       \
        }                                                                     \
    } while (0)

#define DOMAIN_32 4294967296LL

/* ---- exhaustive sweep 1: the policy axis ---------------------------------
 * THE security statement, in its strongest form.  Of every value a policy word
 * can hold — a zeroed slot, an unmerged NGX_CONF_UNSET, a torn write, a stale
 * enum from a reloaded config, an attacker-chosen integer — exactly one opens
 * an endpoint, and it is the one the contract names. */
static void
sweep_policy(void)
{
    long long i, opened = 0, wrong_errno = 0;
    long long opener = -1;

    for (i = 0; i < DOMAIN_32; i++) {
        brix_vfs_mutation_policy_t p = (brix_vfs_mutation_policy_t) (int) i;

        errno = 0;
        if (brix_vfs_require_mutation_policy(p, BRIX_VFS_MUTATE_WRITE)
            == NGX_OK)
        {
            opened++;
            opener = (long long) (int) i;
        } else if (errno != EROFS) {
            wrong_errno++;
        }
    }

    REQUIRE("S1", opened == 1,
            "%lld of 2^32 policy words open an endpoint, not 1", opened);
    REQUIRE("S1", opener == (long long) BRIX_VFS_MUTATION_ALLOWED,
            "the opening policy word is %lld, not BRIX_VFS_MUTATION_ALLOWED",
            opener);
    REQUIRE("S1", wrong_errno == 0,
            "%lld policy refusals answered something other than EROFS",
            wrong_errno);
    printf("PASS S1 exhaustive policy axis: 1 of 4294967296 words opens\n");
}

/* ---- exhaustive sweep 2: the operation axis ------------------------------
 * The vocabulary is closed.  On a writable endpoint exactly the 16 named
 * operations are permitted and every other word is EINVAL; on a read-only one
 * the same 16 are EROFS and, crucially, still exactly 16 — a magic operation
 * that slipped past the range check would show up as a 17th. */
static void
sweep_ops(void)
{
    long long i, allowed = 0, refused = 0, invalid = 0, misnamed = 0;
    long long out_of_range_named = 0;

    for (i = 0; i < DOMAIN_32; i++) {
        brix_vfs_mutation_op_t op = (brix_vfs_mutation_op_t) (int) i;
        int in_vocab = (i < BRIX_VFS_MUTATE_OP_COUNT);

        errno = 0;
        if (brix_vfs_require_mutation_policy(BRIX_VFS_MUTATION_ALLOWED, op)
            == NGX_OK)
        {
            allowed++;
            if (!in_vocab) {
                out_of_range_named++;
            }
        } else if (errno == EINVAL) {
            invalid++;
        }

        errno = 0;
        if (brix_vfs_require_mutation_policy(BRIX_VFS_MUTATION_READ_ONLY, op)
            != NGX_OK && errno == EROFS)
        {
            refused++;
        }

        if (in_vocab && strcmp(brix_vfs_mutation_op_name(op), "unknown") == 0) {
            misnamed++;
        }
        if (!in_vocab && strcmp(brix_vfs_mutation_op_name(op), "unknown") != 0) {
            misnamed++;
        }
    }

    REQUIRE("S2", allowed == (long long) BRIX_VFS_MUTATE_OP_COUNT,
            "%lld operation words are permitted, not %lld", allowed,
            (long long) BRIX_VFS_MUTATE_OP_COUNT);
    REQUIRE("S2", out_of_range_named == 0,
            "%lld operation words outside the vocabulary were permitted",
            out_of_range_named);
    REQUIRE("S2", refused == (long long) BRIX_VFS_MUTATE_OP_COUNT,
            "%lld operation words are refused with EROFS, not %lld", refused,
            (long long) BRIX_VFS_MUTATE_OP_COUNT);
    REQUIRE("S2", invalid == DOMAIN_32 - BRIX_VFS_MUTATE_OP_COUNT,
            "%lld operation words are EINVAL, not %lld", invalid,
            DOMAIN_32 - BRIX_VFS_MUTATE_OP_COUNT);
    REQUIRE("S2", misnamed == 0,
            "%lld operation words carry the wrong kind of metric label",
            misnamed);
    printf("PASS S2 exhaustive operation axis: %d of 4294967296 words in "
           "vocabulary\n", (int) BRIX_VFS_MUTATE_OP_COUNT);
}

/* ---- exhaustive sweep 3: the raw open-flag classifier --------------------
 * Pins the classifier's exact EXTENSION rather than its behaviour on chosen
 * words.  A flag word is provably read-only iff its access mode is O_RDONLY
 * (1 of 4) and none of the three creation/size-changing bits is set (1 of 8),
 * so the read-only set must have exactly 2^32 / 4 / 8 = 2^27 members.  Any
 * magic exemption makes that number wrong. */
static void
sweep_flags(void)
{
    long long i, readonly = 0, unsound = 0;
    const long long expect = DOMAIN_32 / 4 / 8;

    for (i = 0; i < DOMAIN_32; i++) {
        int flags = (int) i;

        if (brix_vfs_open_flags_mutate(flags) != 0) {
            continue;
        }
        readonly++;
        if ((flags & O_ACCMODE) != O_RDONLY
            || (flags & (O_CREAT | O_TRUNC | O_APPEND)) != 0)
        {
            unsound++;
        }
    }

    REQUIRE("S3", unsound == 0,
            "%lld flag words are classified read-only but can modify the "
            "object or the namespace", unsound);
    REQUIRE("S3", readonly == expect,
            "%lld flag words classify read-only, not the %lld the contract "
            "implies", readonly, expect);
    printf("PASS S3 exhaustive open-flag axis: %lld of 4294967296 words are "
           "provably read-only\n", readonly);
}

/* ---- exhaustive sweep 4: agreement between the five decision forms -------
 * A handle, an off-thread job, a confined path and a request context must not
 * be able to answer the same question differently.  Sweeping the whole policy
 * domain through all five is what excludes a backdoor hidden in the form the
 * hand-written cases exercise least. */
static char sweep_ctx_path[] = "/export/object";

static void
sweep_ctx_init(brix_vfs_ctx_t *ctx, long long policy)
{
    ngx_memzero(ctx, sizeof(*ctx));
    ctx->mutation_policy = (brix_vfs_mutation_policy_t) (int) policy;
    ctx->metrics_proto = BRIX_PROTO_ROOT;
    ctx->resolved.resolved.data = (u_char *) sweep_ctx_path;
    ctx->resolved.resolved.len = sizeof(sweep_ctx_path) - 1;
    ctx->resolved.is_confined = 1;
}

static void
sweep_forms(void)
{
    long long i, disagreements = 0;
    long long opens[5] = { 0, 0, 0, 0, 0 };
    int        k;

    for (i = 0; i < DOMAIN_32; i++) {
        brix_vfs_mutation_policy_t p = (brix_vfs_mutation_policy_t) (int) i;
        brix_vfs_mutation_op_t op = BRIX_VFS_MUTATE_WRITE;
        brix_vfs_ctx_t ctx;
        brix_vfs_export_op_ctx_t opctx;
        int verdict[5];

        sweep_ctx_init(&ctx, i);
        brix_vfs_export_op_ctx_from(&opctx, &ctx);

        verdict[0] = brix_vfs_require_mutation_policy(p, op) == NGX_OK;
        verdict[1] = brix_vfs_require_mutation(&ctx, op) == NGX_OK;
        verdict[2] = brix_vfs_require_confined_mutation(&ctx, op) == NGX_OK;
        verdict[3] = brix_vfs_require_carried_mutation(p, BRIX_PROTO_ROOT, op)
                     == NGX_OK;
        verdict[4] = brix_vfs_export_require_mutation(&opctx, op) == NGX_OK;

        for (k = 0; k < 5; k++) {
            opens[k] += verdict[k];
            if (verdict[k] != verdict[0]) {
                disagreements++;
            }
        }
    }

    REQUIRE("S4", disagreements == 0,
            "%lld (policy, form) pairs disagree with the pure kernel",
            disagreements);
    for (k = 0; k < 5; k++) {
        REQUIRE("S4", opens[k] == 1,
                "decision form %lld opens on %lld policy words, not 1",
                (long long) k, (long long) opens[k]);
    }
    printf("PASS S4 exhaustive form agreement: all 5 forms open on the same "
           "1 of 4294967296 words\n");
}

/* ---- exhaustive sweep 5: config derivation and op-ctx normalisation ------
 * Two narrowings that stand between a configuration file and the kernel.
 * `allow_write` reaches the server as an ngx_flag_t whose unmerged value is
 * NGX_CONF_UNSET (-1), so "non-zero means writable" would read a directive
 * nobody wrote as permission; and every derived operation context must leave
 * the closed two-value domain intact, so a corrupt word cannot ride out to a
 * thread-pool job. */
static void
sweep_derive(void)
{
    long long i, from_flag = 0, unnormalised = 0, widened = 0;
    long long flag_opener = -1;

    for (i = 0; i < DOMAIN_32; i++) {
        long long v = (long long) (int) i;
        brix_vfs_mutation_policy_t p = (brix_vfs_mutation_policy_t) (int) i;
        brix_vfs_export_op_ctx_t opctx;

        if (brix_vfs_policy_from_write_enable((ngx_flag_t) v)
            == BRIX_VFS_MUTATION_ALLOWED)
        {
            from_flag++;
            flag_opener = v;
        }

        brix_vfs_export_op_ctx_init(&opctx, NULL, NULL, p, BRIX_PROTO_ROOT);
        if (opctx.mutation_policy != BRIX_VFS_MUTATION_ALLOWED
            && opctx.mutation_policy != BRIX_VFS_MUTATION_READ_ONLY)
        {
            unnormalised++;
        }
        if (opctx.mutation_policy == BRIX_VFS_MUTATION_ALLOWED
            && p != BRIX_VFS_MUTATION_ALLOWED)
        {
            widened++;
        }
    }

    REQUIRE("S5", from_flag == 1,
            "%lld allow_write values yield ALLOWED, not 1", from_flag);
    REQUIRE("S5", flag_opener == 1,
            "allow_write == %lld yields ALLOWED; only 1 may", flag_opener);
    REQUIRE("S5", unnormalised == 0,
            "%lld policy words survive op-ctx derivation unnormalised",
            unnormalised);
    REQUIRE("S5", widened == 0,
            "%lld policy words are WIDENED to ALLOWED by op-ctx derivation",
            widened);
    printf("PASS S5 exhaustive derivation: 1 of 4294967296 allow_write values "
           "opens, 0 widened\n");
}

/* ---- structural properties (representative domain) -----------------------
 * These are claims about SHAPE, not about values, so they are checked on the
 * boundary representatives rather than swept: a NULL pointer, an unconfined
 * path, the order of two refusals, the arity of the denial counter, and the
 * absence of hidden state. */
static const long REPRS[] = {
    BRIX_VFS_MUTATION_READ_ONLY, BRIX_VFS_MUTATION_ALLOWED,
    -1 /* NGX_CONF_UNSET */, 2, 3, 255, 256, -2,
    (long) INT_MAX, (long) INT_MIN
};
#define N_REPRS (sizeof(REPRS) / sizeof(REPRS[0]))

/* T1: every NULL-shaped input fails closed, and an UNCONFINED path is answered
 * EINVAL rather than EROFS.  The order is the point: an unconfined path is a
 * malformed request, so answering it with the endpoint's write posture would
 * disclose that posture to a caller whose path never resolved. */
static void
t1_null_and_unconfined_fail_closed(void)
{
    brix_vfs_ctx_t ctx;
    brix_vfs_export_op_ctx_t opctx;

    errno = 0;
    REQUIRE("T1", brix_vfs_require_mutation(NULL, BRIX_VFS_MUTATE_WRITE)
            == NGX_ERROR, "NULL ctx permitted a write");
    REQUIRE("T1", errno == EINVAL, "NULL ctx gave errno %lld", (long long) errno);

    errno = 0;
    REQUIRE("T1", brix_vfs_export_require_mutation(NULL, BRIX_VFS_MUTATE_WRITE)
            == NGX_ERROR, "NULL bundle permitted a write");
    REQUIRE("T1", errno == EINVAL, "NULL bundle gave errno %lld", (long long) errno);

    brix_vfs_export_op_ctx_from(&opctx, NULL);
    REQUIRE("T1", opctx.mutation_policy == BRIX_VFS_MUTATION_READ_ONLY,
            "a bundle derived from a NULL ctx is not READ_ONLY");

    sweep_ctx_init(&ctx, BRIX_VFS_MUTATION_ALLOWED);
    ctx.resolved.is_confined = 0;
    errno = 0;
    REQUIRE("T1",
        brix_vfs_require_confined_mutation(&ctx, BRIX_VFS_MUTATE_WRITE)
        == NGX_ERROR, "an unconfined path was permitted");
    REQUIRE("T1", errno == EINVAL,
            "an unconfined path gave errno %lld, not EINVAL",
            (long long) errno);

    sweep_ctx_init(&ctx, BRIX_VFS_MUTATION_READ_ONLY);
    ctx.resolved.is_confined = 0;
    errno = 0;
    (void) brix_vfs_require_confined_mutation(&ctx, BRIX_VFS_MUTATE_WRITE);
    REQUIRE("T1", errno == EINVAL,
            "an unconfined path on a read-only export gave errno %lld — "
            "confinement must be judged first", (long long) errno);

    printf("PASS T1 NULL and unconfined inputs fail closed, in that order\n");
}

/* T2: exactly one denial is counted per policy refusal, attributed to the
 * operation that was refused; none for a permitted call, and none for a
 * malformed one — a counter that also counts bad input cannot tell an operator
 * that an endpoint is refusing writes. */
static void
t2_each_refusal_is_counted_exactly_once(void)
{
    ngx_uint_t p;
    long       op;

    for (p = 0; p < N_REPRS; p++) {
        for (op = 0; op < (long) BRIX_VFS_MUTATE_OP_COUNT; op++) {
            brix_vfs_ctx_t ctx;
            long expect = (REPRS[p] == BRIX_VFS_MUTATION_ALLOWED) ? 0 : 1;

            sweep_ctx_init(&ctx, REPRS[p]);
            spy_calls = 0;
            spy_last_op = -1;
            (void) brix_vfs_require_mutation(&ctx,
                       (brix_vfs_mutation_op_t) op);
            REQUIRE("T2", spy_calls == expect,
                    "policy %lld op %lld counted %lld denial(s)",
                    (long long) REPRS[p], (long long) op,
                    (long long) spy_calls);
            if (expect == 1) {
                REQUIRE("T2", spy_last_op == op,
                        "policy %lld op %lld counted against op %lld",
                        (long long) REPRS[p], (long long) op,
                        (long long) spy_last_op);
            }
        }
    }

    /* A malformed request is not a policy denial. */
    for (p = 0; p < N_REPRS; p++) {
        brix_vfs_ctx_t ctx;

        sweep_ctx_init(&ctx, REPRS[p]);
        spy_calls = 0;
        (void) brix_vfs_require_mutation(&ctx,
                   (brix_vfs_mutation_op_t) BRIX_VFS_MUTATE_OP_COUNT);
        REQUIRE("T2", spy_calls == 0,
                "an out-of-vocabulary op counted %lld denial(s) under policy "
                "%lld", (long long) spy_calls, (long long) REPRS[p]);
    }
    printf("PASS T2 one denial per refusal, none per success or bad input\n");
}

/* T3: the kernel is PURE.  The representative domain is swept forwards and
 * then backwards; identical verdict vectors mean no call-order dependence and
 * no hidden state, which is what licenses running the gate BEFORE leaf
 * resolution, credential selection and cache invalidation (INVARIANT #12). */
static void
t3_kernel_is_pure_and_order_independent(void)
{
    char fwd[N_REPRS * BRIX_VFS_MUTATE_OP_COUNT];
    char rev[N_REPRS * BRIX_VFS_MUTATE_OP_COUNT];
    long p, op, i;

    for (p = 0; p < (long) N_REPRS; p++) {
        for (op = 0; op < (long) BRIX_VFS_MUTATE_OP_COUNT; op++) {
            fwd[p * BRIX_VFS_MUTATE_OP_COUNT + op] =
                (char) (brix_vfs_require_mutation_policy(
                    (brix_vfs_mutation_policy_t) REPRS[p],
                    (brix_vfs_mutation_op_t) op) == NGX_OK);
        }
    }
    for (p = (long) N_REPRS - 1; p >= 0; p--) {
        for (op = (long) BRIX_VFS_MUTATE_OP_COUNT - 1; op >= 0; op--) {
            rev[p * BRIX_VFS_MUTATE_OP_COUNT + op] =
                (char) (brix_vfs_require_mutation_policy(
                    (brix_vfs_mutation_policy_t) REPRS[p],
                    (brix_vfs_mutation_op_t) op) == NGX_OK);
        }
    }
    for (i = 0; i < (long) (N_REPRS * BRIX_VFS_MUTATE_OP_COUNT); i++) {
        REQUIRE("T3", fwd[i] == rev[i],
                "input %lld: forward %lld != reverse %lld",
                (long long) i, (long long) fwd[i], (long long) rev[i]);
    }
    printf("PASS T3 kernel pure: forward and reverse sweeps identical\n");
}

/* T4: the operation names an operator sees on a metric are unique, so two
 * families of refusal can never be read as one (INVARIANT #8). */
static void
t4_operation_names_are_unique(void)
{
    long i, j;

    for (i = 0; i < (long) BRIX_VFS_MUTATE_OP_COUNT; i++) {
        const char *a = brix_vfs_mutation_op_name((brix_vfs_mutation_op_t) i);

        REQUIRE("T4", a != NULL && a[0] != '\0', "op %lld has no name", (long long) i);
        for (j = i + 1; j < (long) BRIX_VFS_MUTATE_OP_COUNT; j++) {
            REQUIRE("T4",
                strcmp(a, brix_vfs_mutation_op_name(
                              (brix_vfs_mutation_op_t) j)) != 0,
                "ops %lld and %lld share a metric label",
                (long long) i, (long long) j);
        }
    }
    printf("PASS T4 %d operation labels, all distinct\n",
           (int) BRIX_VFS_MUTATE_OP_COUNT);
}

/* ---- entry point ---------------------------------------------------------
 * The structural properties always run; a 32-bit sweep costs about five
 * seconds, so the caller names the ones it needs.  Mutation testing depends on
 * that: a mutant is only worth the sweep that can see it. */
static const struct {
    const char  *name;
    void       (*run)(void);
} sweeps[] = {
    { "policy", sweep_policy },
    { "ops",    sweep_ops    },
    { "flags",  sweep_flags  },
    { "forms",  sweep_forms  },
    { "derive", sweep_derive },
};

/* Returns the number of sweeps run, so a misspelled --sweep= is a failure and
 * not a silent no-op.  Without this the checker answers ALL PASSED for
 * `--sweep=polciy`, having proved nothing at all — which is exactly the shape
 * of vacuity this whole file exists to refute. */
static size_t
run_sweeps(const char *which)
{
    int     all = (strcmp(which, "all") == 0);
    size_t  i, ran = 0;

    for (i = 0; i < sizeof(sweeps) / sizeof(sweeps[0]); i++) {
        if (all || strcmp(which, sweeps[i].name) == 0) {
            sweeps[i].run();
            ran++;
        }
    }
    return ran;
}

int
main(int argc, char **argv)
{
    int i;

    t1_null_and_unconfined_fail_closed();
    t2_each_refusal_is_counted_exactly_once();
    t3_kernel_is_pure_and_order_independent();
    t4_operation_names_are_unique();

    for (i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--sweep=", 8) != 0) {
            printf("FAIL [args] unknown argument %s\n", argv[i]);
            failures++;
            continue;
        }
        if (run_sweeps(argv[i] + 8) == 0) {
            printf("FAIL [args] no such sweep: %s\n", argv[i] + 8);
            failures++;
        }
    }

    if (failures != 0) {
        printf("%d PROPERTY VIOLATION(S)\n", failures);
        return 1;
    }
    printf("ALL PASSED\n");
    return 0;
}
