/* Shared link closure for VFS object units extended by Phase 108. */
#include "fs/vfs/vfs_authz.h"
#include "fs/vfs/vfs_backend_registry.h"
#include "fs/path/n2n_stage.h"

#include <errno.h>
#include <string.h>

/* The production evaluator receives this by pointer. Its layout is irrelevant
 * to these gate-ordering units, so keep the link stub free of stream headers. */
typedef struct brix_authz_identity_query_stub_s brix_authz_identity_query_t;

const char *brix_vfs_export_relative_root(const char *resolved,
    const char *root_canon);

static ngx_int_t  authz_eval_rc = NGX_OK;
static unsigned   authz_eval_calls;

void
brix_test_authz_eval_set(ngx_int_t rc)
{
    authz_eval_rc = rc;
    authz_eval_calls = 0;
}

unsigned
brix_test_authz_eval_calls(void)
{
    return authz_eval_calls;
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
    (void) query;
    authz_eval_calls++;
    return authz_eval_rc;
}

void
brix_metric_vfs_authz_backstop(brix_proto_t proto, ngx_uint_t result)
{
    (void) proto; (void) result;
}

const char *
brix_metric_vfs_authz_backstop_result_name(ngx_uint_t result)
{
    (void) result;
    return "unit";
}

int
brix_path_within_root(const char *root, const char *path)
{
    size_t n;

    if (root == NULL || path == NULL) {
        return 0;
    }
    n = strlen(root);
    return strncmp(root, path, n) == 0
        && (path[n] == '\0' || path[n] == '/');
}

ngx_int_t
brix_path_resolved_to_pfn(const brix_vfs_ctx_t *ctx,
    const char *resolved_path, char *pfn, size_t cap)
{
    const char *logical = brix_vfs_export_relative(ctx, resolved_path);
    size_t      len = logical != NULL ? strlen(logical) : 0;

    if (logical == NULL || pfn == NULL || len >= cap) {
        errno = len >= cap ? ENAMETOOLONG : EINVAL;
        return NGX_ERROR;
    }
    memcpy(pfn, logical, len + 1);
    return NGX_OK;
}

ngx_int_t
brix_path_export_to_pfn(const char *root_canon, const brix_n2n_cfg_t *cfg,
    const char *path, char *pfn, size_t cap)
{
    const char *logical = brix_vfs_export_relative_root(path, root_canon);
    size_t      len = logical != NULL ? strlen(logical) : 0;

    (void) cfg;
    if (logical == NULL || pfn == NULL || len >= cap) {
        errno = len >= cap ? ENAMETOOLONG : EINVAL;
        return NGX_ERROR;
    }
    memcpy(pfn, logical, len + 1);
    return NGX_OK;
}

const brix_n2n_cfg_t *
brix_vfs_backend_n2n(const char *root_canon)
{
    (void) root_canon;
    return NULL;
}
