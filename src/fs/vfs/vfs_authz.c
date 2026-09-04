/*
 * vfs_authz.c — authorization backstop shared by every VFS entry point.
 *
 * The protocol edge remains the primary authorization boundary and owns its
 * wire response. This file independently re-evaluates the same rule engines
 * after the read-only mutation policy and before locks or storage. OBSERVE is
 * deliberately non-refusing; ENFORCE maps every undecidable/denied result to
 * EACCES. Metrics use only the bounded protocol/result axes.
 */
#include "vfs_internal.h"
#include "vfs_authz.h"

#include "auth/authz/auth_gate.h"
#include "auth/authz/acc/acc.h"
#include "auth/authz/acc/privs.h"
#include "fs/path/path_internal.h"

_Static_assert(BRIX_AUTHZ_BACKSTOP_RESULT_N
               == BRIX_AUTHZ_BACKSTOP_RESULT_COUNT,
               "authorization result metric mirror drift");

typedef struct {
    uint32_t      privilege;
    brix_acc_op_t acc_op;
} brix_vfs_authz_need_t;

void
brix_vfs_ctx_bind_authz(brix_vfs_ctx_t *vctx,
    ngx_array_t *authdb_rules, ngx_array_t *vo_rules,
    void *acc_tables, ngx_uint_t acc_format,
    const char *peer, brix_authz_backstop_mode_t mode)
{
    size_t peer_len;

    if (vctx == NULL) {
        return;
    }

    vctx->authz.authdb_rules = authdb_rules;
    vctx->authz.vo_rules = vo_rules;
    vctx->authz.acc_tables = acc_tables;
    vctx->authz.acc_format = acc_format;
    if (peer != NULL) {
        peer_len = ngx_min(ngx_strlen(peer), sizeof(vctx->authz.peer) - 1);
        ngx_memcpy(vctx->authz.peer, peer, peer_len);
        vctx->authz.peer[peer_len] = '\0';
    } else {
        vctx->authz.peer[0] = '\0';
    }
    vctx->authz.mode = mode <= BRIX_AUTHZ_BACKSTOP_ENFORCE
        ? mode : BRIX_AUTHZ_BACKSTOP_OBSERVE;
    vctx->authz.acc_entity = acc_format == BRIX_AUTHDB_FORMAT_XRDACC
        ? brix_authz_acc_entity(vctx->pool, vctx->identity,
              vctx->authz.peer[0] != '\0' ? vctx->authz.peer : NULL)
        : NULL;
    vctx->authz.bound = 1;
}

void
brix_vfs_ctx_bind_no_authz_rules(brix_vfs_ctx_t *vctx,
    brix_authz_backstop_mode_t mode)
{
    brix_vfs_ctx_bind_authz(vctx, NULL, NULL, NULL,
                            BRIX_AUTHDB_FORMAT_NATIVE, NULL, mode);
}

uint32_t
brix_vfs_authz_level_for_op(brix_vfs_mutation_op_t op, int *also_delete)
{
    if (also_delete != NULL) {
        *also_delete = 0;
    }
    if ((ngx_uint_t) op >= BRIX_VFS_MUTATE_OP_COUNT) {
        return 0;
    }

    if (op <= BRIX_VFS_MUTATE_SYNC
        || (op >= BRIX_VFS_MUTATE_SETATTR && op <= BRIX_VFS_MUTATE_LOCK))
    {
        return BRIX_AUTH_UPDATE;
    }

    switch (op) {
    case BRIX_VFS_MUTATE_MKDIR:
        return BRIX_AUTH_MKDIR;
    case BRIX_VFS_MUTATE_REMOVE:
        return BRIX_AUTH_DELETE;
    case BRIX_VFS_MUTATE_RENAME:
    case BRIX_VFS_MUTATE_COPY:
        if (also_delete != NULL) {
            *also_delete = 1;
        }
        return BRIX_AUTH_UPDATE;
    default: return 0;
    }
}

static brix_acc_op_t
brix_vfs_authz_two_name_acc(brix_vfs_mutation_op_t op, int destination)
{
    if (destination) {
        return BRIX_AOP_UPDATE;
    }
    return op == BRIX_VFS_MUTATE_RENAME ? BRIX_AOP_RENAME
                                         : BRIX_AOP_DELETE;
}

static brix_acc_op_t
brix_vfs_authz_acc_op(brix_vfs_mutation_op_t op, int destination)
{
    if (op == BRIX_VFS_MUTATE_RENAME || op == BRIX_VFS_MUTATE_COPY) {
        return brix_vfs_authz_two_name_acc(op, destination);
    }
    if ((op >= BRIX_VFS_MUTATE_WRITE && op <= BRIX_VFS_MUTATE_SYNC)
        || (op >= BRIX_VFS_MUTATE_SETATTR && op <= BRIX_VFS_MUTATE_PUBLISH))
    {
        return BRIX_AOP_UPDATE;
    }
    if (op >= BRIX_VFS_MUTATE_STAGE && op <= BRIX_VFS_MUTATE_EVICT) {
        return BRIX_AOP_STAGE;
    }
    switch (op) {
    case BRIX_VFS_MUTATE_MKDIR: return BRIX_AOP_MKDIR;
    case BRIX_VFS_MUTATE_REMOVE: return BRIX_AOP_DELETE;
    case BRIX_VFS_MUTATE_LOCK: return BRIX_AOP_LOCK;
    case BRIX_VFS_MUTATE_OPEN: return BRIX_AOP_UPDATE;
    default: return BRIX_AOP_ANY;
    }
}

static int
brix_vfs_authz_has_rules(const brix_vfs_ctx_t *ctx)
{
    const brix_vfs_authz_t *a = &ctx->authz;

    return (a->authdb_rules != NULL && a->authdb_rules->nelts != 0)
        || (a->vo_rules != NULL && a->vo_rules->nelts != 0)
        || (a->acc_format == BRIX_AUTHDB_FORMAT_XRDACC
            && a->acc_tables != NULL
            && ((brix_acc_tables_t *) a->acc_tables)->rule_count != 0)
        || (ctx->identity != NULL
            && (ctx->identity->auth_method & BRIX_AUTHN_TOKEN));
}

static ngx_int_t
brix_vfs_authz_outcome(const brix_vfs_ctx_t *ctx,
    brix_authz_backstop_result_t result, const char *operation)
{
    brix_metric_vfs_authz_backstop(brix_vfs_metrics_proto(ctx), result);

    if (result == BRIX_AUTHZ_BACKSTOP_AGREE
        || result == BRIX_AUTHZ_BACKSTOP_NO_RULES)
    {
        return NGX_OK;
    }

    if (ctx->log != NULL) {
        ngx_log_error(NGX_LOG_WARN, ctx->log, 0,
                      "brix: VFS authorization backstop result=%s op=%s",
                      brix_metric_vfs_authz_backstop_result_name(result),
                      operation != NULL ? operation : "read");
    }
    if (ctx->authz.mode != BRIX_AUTHZ_BACKSTOP_ENFORCE) {
        return NGX_OK;
    }

    brix_io_monitor_record_err(ctx->io_monitor, BRIX_ERR_FORBIDDEN);
    errno = EACCES;
    return NGX_ERROR;
}

static brix_vfs_authz_need_t
brix_vfs_authz_need(brix_vfs_mutation_op_t op, int destination)
{
    brix_vfs_authz_need_t need;
    int                   also_delete;

    need.privilege = brix_vfs_authz_level_for_op(op, &also_delete);
    if (also_delete && !destination) {
        need.privilege = BRIX_AUTH_DELETE;
    }
    need.acc_op = brix_vfs_authz_acc_op(op, destination);
    return need;
}

static void
brix_vfs_authz_query_init(const brix_vfs_ctx_t *ctx, const char *path,
    brix_authz_identity_query_t *query)
{
    ngx_memzero(query, sizeof(*query));
    query->pool = ctx->pool;
    query->log = ctx->log;
    query->identity = ctx->identity;
    query->authdb_rules = ctx->authz.authdb_rules;
    query->vo_rules = ctx->authz.vo_rules;
    query->acc_tables = ctx->authz.acc_tables;
    query->acc_entity = ctx->authz.acc_entity;
    query->acc_format = ctx->authz.acc_format;
    query->peer_ip = ctx->authz.peer[0] != '\0' ? ctx->authz.peer : NULL;
    query->logical_path = brix_vfs_export_relative(ctx, path);
    query->resolved_path = path;
}

static ngx_int_t
brix_vfs_require_authorized_at(const brix_vfs_ctx_t *ctx, const char *path,
    brix_vfs_mutation_op_t op, int destination)
{
    brix_authz_identity_query_t query;
    brix_vfs_authz_need_t       need;

    if (ctx == NULL || path == NULL || path[0] == '\0') {
        errno = EINVAL;
        return NGX_ERROR;
    }
    if (!ctx->authz.bound) {
        return brix_vfs_authz_outcome(ctx, BRIX_AUTHZ_BACKSTOP_UNBOUND,
                                      brix_vfs_mutation_op_name(op));
    }
    if (ctx->authz.mode == BRIX_AUTHZ_BACKSTOP_OFF) {
        return NGX_OK;
    }
    if (!brix_vfs_authz_has_rules(ctx)) {
        return brix_vfs_authz_outcome(ctx, BRIX_AUTHZ_BACKSTOP_NO_RULES,
                                      brix_vfs_mutation_op_name(op));
    }

    need = brix_vfs_authz_need(op, destination);
    if (need.privilege == 0 || need.acc_op == BRIX_AOP_ANY) {
        return brix_vfs_authz_outcome(ctx, BRIX_AUTHZ_BACKSTOP_EDGE_MISSING,
                                      brix_vfs_mutation_op_name(op));
    }
    brix_vfs_authz_query_init(ctx, path, &query);
    query.needed_privs = need.privilege;
    query.acc_op = need.acc_op;
    query.need_write = 1;

    return brix_vfs_authz_outcome(ctx,
        brix_authz_check_identity(&query) == NGX_OK
            ? BRIX_AUTHZ_BACKSTOP_AGREE
            : BRIX_AUTHZ_BACKSTOP_EDGE_MISSING,
        brix_vfs_mutation_op_name(op));
}

ngx_int_t
brix_vfs_require_authorized(const brix_vfs_ctx_t *ctx,
    brix_vfs_mutation_op_t op)
{
    return brix_vfs_require_authorized_at(ctx, brix_vfs_ctx_path(ctx), op, 0);
}

ngx_int_t
brix_vfs_require_authorized_target(const brix_vfs_ctx_t *ctx,
    const char *path, brix_vfs_mutation_op_t op)
{
    if (ctx == NULL || ctx->root_canon == NULL
        || !brix_path_within_root(ctx->root_canon, path))
    {
        errno = EINVAL;
        return NGX_ERROR;
    }
    return brix_vfs_require_authorized_at(ctx, path, op, 1);
}

static ngx_int_t
brix_vfs_require_authorized_read_as(const brix_vfs_ctx_t *ctx,
    uint32_t privilege, brix_acc_op_t acc_op, const char *operation)
{
    brix_authz_identity_query_t query;
    const char                 *path;

    if (brix_vfs_require_confined(ctx) != NGX_OK) {
        return NGX_ERROR;
    }
    path = brix_vfs_ctx_path(ctx);
    if (!ctx->authz.bound) {
        return brix_vfs_authz_outcome(ctx, BRIX_AUTHZ_BACKSTOP_UNBOUND,
                                      operation);
    }
    if (ctx->authz.mode == BRIX_AUTHZ_BACKSTOP_OFF) {
        return NGX_OK;
    }
    if (!brix_vfs_authz_has_rules(ctx)) {
        return brix_vfs_authz_outcome(ctx, BRIX_AUTHZ_BACKSTOP_NO_RULES,
                                      operation);
    }

    brix_vfs_authz_query_init(ctx, path, &query);
    query.needed_privs = privilege;
    query.acc_op = acc_op;
    query.need_write = 0;

    return brix_vfs_authz_outcome(ctx,
        brix_authz_check_identity(&query) == NGX_OK
            ? BRIX_AUTHZ_BACKSTOP_AGREE
            : BRIX_AUTHZ_BACKSTOP_EDGE_MISSING,
        operation);
}

ngx_int_t
brix_vfs_require_authorized_read(const brix_vfs_ctx_t *ctx)
{
    return brix_vfs_require_authorized_read_as(ctx, BRIX_AUTH_READ,
                                               BRIX_AOP_READ, "read");
}

ngx_int_t
brix_vfs_require_authorized_lookup(const brix_vfs_ctx_t *ctx)
{
    return brix_vfs_require_authorized_read_as(ctx, BRIX_AUTH_LOOKUP,
                                               BRIX_AOP_STAT, "lookup");
}

ngx_int_t
brix_vfs_gate_confined(const brix_vfs_ctx_t *ctx,
    brix_vfs_mutation_op_t op)
{
    if (brix_vfs_require_confined_mutation(ctx, op) != NGX_OK) {
        return NGX_ERROR;
    }
    return brix_vfs_require_authorized(ctx, op);
}

ngx_int_t
brix_vfs_gate_mutation(const brix_vfs_ctx_t *ctx,
    brix_vfs_mutation_op_t op)
{
    if (brix_vfs_require_mutation(ctx, op) != NGX_OK) {
        return NGX_ERROR;
    }
    return brix_vfs_require_authorized(ctx, op);
}

ngx_int_t
brix_vfs_gate_file_mutation(const brix_vfs_file_t *fh,
    brix_vfs_mutation_op_t op)
{
    brix_vfs_ctx_t scope;

    if (fh == NULL || fh->path == NULL || fh->root_canon == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }

    ngx_memzero(&scope, sizeof(scope));
    scope.pool = fh->pool;
    scope.log = fh->log;
    scope.metrics_proto = fh->metrics_proto;
    scope.root_canon = fh->root_canon;
    scope.identity = fh->identity;
    scope.authz = fh->authz;
    scope.mutation_policy = fh->mutation_policy;
    scope.io_monitor = fh->io_monitor;
    scope.resolved.resolved.data = (u_char *) fh->path;
    scope.resolved.resolved.len = ngx_strlen(fh->path);
    scope.resolved.is_confined = 1;
    return brix_vfs_gate_mutation(&scope, op);
}
