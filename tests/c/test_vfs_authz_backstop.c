/* Focused unit for the Phase-108 authorization backstop and gate ordering. */
#include "fs/vfs/vfs_internal.h"
#include "auth/authz/auth_gate.h"
#include "core/types/config.h"

#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static ngx_int_t eval_rc;
static unsigned eval_calls;
static brix_authz_identity_query_t last_query;
static unsigned metric_count[BRIX_AUTHZ_BACKSTOP_RESULT_N];
static char order_tape[8];
static size_t order_len;

void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...)
{
    (void) level; (void) log; (void) err; (void) fmt;
}

static void
reset_spy(void)
{
    eval_rc = NGX_OK;
    eval_calls = 0;
    memset(&last_query, 0, sizeof(last_query));
    memset(metric_count, 0, sizeof(metric_count));
    memset(order_tape, 0, sizeof(order_tape));
    order_len = 0;
}

static void
tape(char event)
{
    if (order_len + 1 < sizeof(order_tape)) {
        order_tape[order_len++] = event;
        order_tape[order_len] = '\0';
    }
}

void *
brix_authz_acc_entity(ngx_pool_t *pool, brix_identity_t *identity,
    const char *peer)
{
    (void) pool; (void) identity; (void) peer;
    return (void *) 1;
}

ngx_int_t
brix_authz_check_identity(const brix_authz_identity_query_t *query)
{
    tape('A');
    eval_calls++;
    last_query = *query;
    return eval_rc;
}

void
brix_metric_vfs_authz_backstop(brix_proto_t proto, ngx_uint_t result)
{
    (void) proto;
    assert(result < BRIX_AUTHZ_BACKSTOP_RESULT_N);
    metric_count[result]++;
}

const char *
brix_metric_vfs_authz_backstop_result_name(ngx_uint_t result)
{
    static const char *const names[] = {
        "agree", "edge_missing", "no_rules", "unbound"
    };
    return result < BRIX_AUTHZ_BACKSTOP_RESULT_N ? names[result] : "invalid";
}

const char *
brix_vfs_mutation_op_name(brix_vfs_mutation_op_t op)
{
    (void) op;
    return "unit";
}

const char *
brix_vfs_export_relative(const brix_vfs_ctx_t *ctx, const char *path)
{
    size_t n = strlen(ctx->root_canon);
    return strncmp(ctx->root_canon, path, n) == 0 ? path + n : path;
}

int
brix_path_within_root(const char *root, const char *path)
{
    size_t n = strlen(root);
    return strncmp(root, path, n) == 0
        && (path[n] == '\0' || path[n] == '/');
}

ngx_int_t
brix_vfs_require_mutation(const brix_vfs_ctx_t *ctx,
    brix_vfs_mutation_op_t op)
{
    (void) op;
    tape('P');
    if (ctx == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    if (ctx->mutation_policy != BRIX_VFS_MUTATION_ALLOWED) {
        errno = EROFS;
        return NGX_ERROR;
    }
    return NGX_OK;
}

ngx_int_t
brix_vfs_require_confined_mutation(const brix_vfs_ctx_t *ctx,
    brix_vfs_mutation_op_t op)
{
    return brix_vfs_require_mutation(ctx, op);
}

static brix_vfs_ctx_t
make_ctx(brix_authz_backstop_mode_t mode, int with_rules)
{
    static ngx_array_t rules;
    brix_vfs_ctx_t ctx;

    memset(&ctx, 0, sizeof(ctx));
    memset(&rules, 0, sizeof(rules));
    rules.nelts = with_rules ? 1 : 0;
    ctx.metrics_proto = BRIX_PROTO_ROOT;
    ctx.root_canon = "/srv";
    ctx.resolved.resolved.data = (u_char *) "/srv/data";
    ctx.resolved.resolved.len = sizeof("/srv/data") - 1;
    ctx.resolved.is_confined = 1;
    ctx.mutation_policy = BRIX_VFS_MUTATION_ALLOWED;
    brix_vfs_ctx_bind_authz(&ctx, with_rules ? &rules : NULL, NULL,
                            NULL, BRIX_AUTHDB_FORMAT_NATIVE, "127.0.0.1", mode);
    return ctx;
}

static void
test_privilege_mapping(void)
{
    int also_delete = 0;

    assert(brix_vfs_authz_level_for_op(BRIX_VFS_MUTATE_WRITE, NULL)
           == BRIX_AUTH_UPDATE);
    assert(brix_vfs_authz_level_for_op(BRIX_VFS_MUTATE_MKDIR, NULL)
           == BRIX_AUTH_MKDIR);
    assert(brix_vfs_authz_level_for_op(BRIX_VFS_MUTATE_REMOVE, NULL)
           == BRIX_AUTH_DELETE);
    assert(brix_vfs_authz_level_for_op(BRIX_VFS_MUTATE_RENAME, &also_delete)
           == BRIX_AUTH_UPDATE);
    assert(also_delete == 1);
    assert(brix_vfs_authz_level_for_op(BRIX_VFS_MUTATE_DEDUP, NULL) == 0);
}

static void
test_agree_and_two_name_mapping(void)
{
    brix_vfs_ctx_t ctx = make_ctx(BRIX_AUTHZ_BACKSTOP_ENFORCE, 1);

    reset_spy();
    assert(brix_vfs_require_authorized(&ctx, BRIX_VFS_MUTATE_RENAME) == NGX_OK);
    assert(last_query.needed_privs == BRIX_AUTH_DELETE);
    assert(last_query.acc_op == BRIX_AOP_RENAME);
    assert(strcmp(last_query.logical_path, "/data") == 0);
    assert(metric_count[BRIX_AUTHZ_BACKSTOP_AGREE] == 1);

    assert(brix_vfs_require_authorized_target(&ctx, "/srv/dst",
                                               BRIX_VFS_MUTATE_RENAME) == NGX_OK);
    assert(last_query.needed_privs == BRIX_AUTH_UPDATE);
    assert(last_query.acc_op == BRIX_AOP_UPDATE);
    puts("ok test_backstop_agrees_with_edge");
}

static void
test_unbound_and_no_rules_are_distinct(void)
{
    brix_vfs_ctx_t unbound;
    brix_vfs_ctx_t no_rules = make_ctx(BRIX_AUTHZ_BACKSTOP_ENFORCE, 0);

    memset(&unbound, 0, sizeof(unbound));
    unbound.root_canon = "/srv";
    unbound.resolved.resolved.data = (u_char *) "/srv/data";
    unbound.resolved.resolved.len = sizeof("/srv/data") - 1;
    unbound.resolved.is_confined = 1;
    unbound.authz.mode = BRIX_AUTHZ_BACKSTOP_ENFORCE;

    reset_spy();
    errno = 0;
    assert(brix_vfs_require_authorized(&unbound, BRIX_VFS_MUTATE_WRITE)
           == NGX_ERROR);
    assert(errno == EACCES);
    assert(metric_count[BRIX_AUTHZ_BACKSTOP_UNBOUND] == 1);
    assert(eval_calls == 0);

    reset_spy();
    assert(brix_vfs_require_authorized(&no_rules, BRIX_VFS_MUTATE_WRITE)
           == NGX_OK);
    assert(metric_count[BRIX_AUTHZ_BACKSTOP_NO_RULES] == 1);
    assert(eval_calls == 0);
    puts("ok test_backstop_unbound_refuses");
    puts("ok test_backstop_no_rules_is_distinguishable");
}

static void
test_observe_and_enforce(void)
{
    brix_vfs_ctx_t observe = make_ctx(BRIX_AUTHZ_BACKSTOP_OBSERVE, 1);
    brix_vfs_ctx_t enforce = make_ctx(BRIX_AUTHZ_BACKSTOP_ENFORCE, 1);

    reset_spy();
    eval_rc = NGX_ERROR;
    assert(brix_vfs_require_authorized(&observe, BRIX_VFS_MUTATE_WRITE)
           == NGX_OK);
    assert(metric_count[BRIX_AUTHZ_BACKSTOP_EDGE_MISSING] == 1);

    reset_spy();
    eval_rc = NGX_ERROR;
    errno = 0;
    assert(brix_vfs_require_authorized(&enforce, BRIX_VFS_MUTATE_WRITE)
           == NGX_ERROR);
    assert(errno == EACCES);
    puts("ok test_backstop_observe_never_refuses");
    puts("ok test_edge_gate_removed_still_refused");
}

static void
test_read_and_unmapped_refuse(void)
{
    brix_vfs_ctx_t ctx = make_ctx(BRIX_AUTHZ_BACKSTOP_ENFORCE, 1);

    reset_spy();
    eval_rc = NGX_ERROR;
    assert(brix_vfs_require_authorized_read(&ctx) == NGX_ERROR);
    assert(last_query.needed_privs == BRIX_AUTH_READ);
    assert(last_query.acc_op == BRIX_AOP_READ);

    reset_spy();
    errno = 0;
    assert(brix_vfs_require_authorized(&ctx, BRIX_VFS_MUTATE_DEDUP)
           == NGX_ERROR);
    assert(errno == EACCES);
    assert(eval_calls == 0);
    puts("ok test_backstop_reads_are_gated_too");
    puts("ok test_backstop_unmapped_op_refuses");
}

static void
test_denial_matrix(void)
{
    brix_vfs_ctx_t ctx = make_ctx(BRIX_AUTHZ_BACKSTOP_ENFORCE, 1);
    ngx_uint_t     op;

    for (op = 0; op < BRIX_VFS_MUTATE_OP_COUNT; op++) {
        reset_spy();
        eval_rc = NGX_ERROR;
        errno = 0;
        assert(brix_vfs_require_authorized(&ctx,
                   (brix_vfs_mutation_op_t) op) == NGX_ERROR);
        assert(errno == EACCES);
    }
    puts("ok test_backstop_never_more_permissive");
}

static void
test_policy_precedes_authorization(void)
{
    brix_vfs_ctx_t ctx = make_ctx(BRIX_AUTHZ_BACKSTOP_ENFORCE, 1);

    reset_spy();
    ctx.mutation_policy = BRIX_VFS_MUTATION_READ_ONLY;
    eval_rc = NGX_ERROR;
    errno = 0;
    assert(brix_vfs_gate_mutation(&ctx, BRIX_VFS_MUTATE_WRITE) == NGX_ERROR);
    assert(errno == EROFS);
    assert(strcmp(order_tape, "P") == 0);
    assert(eval_calls == 0);

    reset_spy();
    ctx.mutation_policy = BRIX_VFS_MUTATION_ALLOWED;
    assert(brix_vfs_gate_mutation(&ctx, BRIX_VFS_MUTATE_WRITE) == NGX_OK);
    assert(strcmp(order_tape, "PA") == 0);
    puts("ok test_backstop_after_erofs");
}

static void
test_handle_snapshot_rechecks_authorization(void)
{
    brix_vfs_ctx_t  ctx = make_ctx(BRIX_AUTHZ_BACKSTOP_ENFORCE, 1);
    brix_vfs_file_t fh;

    memset(&fh, 0, sizeof(fh));
    fh.path = "/srv/data";
    fh.root_canon = ctx.root_canon;
    fh.mutation_policy = ctx.mutation_policy;
    fh.metrics_proto = ctx.metrics_proto;
    fh.authz = ctx.authz;
    fh.identity = ctx.identity;

    reset_spy();
    eval_rc = NGX_ERROR;
    assert(brix_vfs_gate_file_mutation(&fh, BRIX_VFS_MUTATE_SYNC)
           == NGX_ERROR);
    assert(errno == EACCES);
    assert(strcmp(order_tape, "PA") == 0);

    reset_spy();
    fh.mutation_policy = BRIX_VFS_MUTATION_READ_ONLY;
    assert(brix_vfs_gate_file_mutation(&fh, BRIX_VFS_MUTATE_TRUNCATE)
           == NGX_ERROR);
    assert(errno == EROFS);
    assert(strcmp(order_tape, "P") == 0);
    puts("ok test_backstop_handle_snapshot");
}

int
main(void)
{
    test_privilege_mapping();
    test_agree_and_two_name_mapping();
    test_unbound_and_no_rules_are_distinct();
    test_observe_and_enforce();
    test_read_and_unmapped_refuse();
    test_denial_matrix();
    test_policy_precedes_authorization();
    test_handle_snapshot_rechecks_authorization();
    puts("vfs authz backstop: all tests passed");
    return 0;
}
