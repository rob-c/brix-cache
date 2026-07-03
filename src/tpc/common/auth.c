#include "auth.h"

/*
 * auth.c — authorization gate for third-party-copy initiation.
 *
 * WHAT: Implements brix_tpc_check_authz(), which decides whether a given
 *       identity may launch a TPC for a (src_path, dst_path) pair: read access
 *       to the source, write access to the destination.
 *
 * WHY: A TPC moves data on the user's behalf between two endpoints, so the
 *      initiating identity's token scope must actually permit the read and the
 *      write. This check runs before the transport begins so an unauthorised
 *      copy is rejected up front rather than failing mid-stream. S3 SigV4
 *      identities are blocked outright because their request-signed model does
 *      not carry a delegable scope suitable for third-party transfers.
 *
 * HOW: The static brix_tpc_check_scope_path() copies each ngx_str_t path into
 *      a NUL-terminated PATH_MAX buffer (rejecting over-long paths) and defers
 *      to brix_identity_check_token_scope() with the required read/write bit.
 *      A NULL/empty path is treated as "no constraint" (NGX_OK). The public
 *      entry point first rejects BRIX_AUTHN_S3KEY identities, then checks the
 *      source for read and the destination for write, returning NGX_OK only when
 *      both pass and NGX_DECLINED otherwise.
 */

#include <limits.h>

static ngx_int_t
brix_tpc_check_scope_path(const brix_identity_t *identity,
    const ngx_str_t *path, int need_write, ngx_log_t *log)
{
    char local_path[PATH_MAX];

    if (path == NULL || path->data == NULL || path->len == 0) {
        return NGX_OK;
    }

    if (path->len >= sizeof(local_path)) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "brix_tpc: authorization path is too long");
        return NGX_DECLINED;
    }

    ngx_memcpy(local_path, path->data, path->len);
    local_path[path->len] = '\0';

    if (brix_identity_check_token_scope(identity, local_path, need_write)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "brix_tpc: token scope denied %s access to \"%s\"",
                      need_write ? "write" : "read", local_path);
        return NGX_DECLINED;
    }

    return NGX_OK;
}

/*
 * Authorize a TPC initiated by `identity`: require read scope on src_path and
 * write scope on dst_path. S3 SigV4 identities are refused outright. Either path
 * may be NULL/empty to skip its check. Returns NGX_OK if permitted, else
 * NGX_DECLINED.
 */
ngx_int_t
brix_tpc_check_authz(const brix_identity_t *identity,
    const ngx_str_t *src_path, const ngx_str_t *dst_path, ngx_log_t *log)
{
    if (identity != NULL && (identity->auth_method & BRIX_AUTHN_S3KEY)) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "brix_tpc: S3 SigV4 identities cannot initiate TPC");
        return NGX_DECLINED;
    }

    if (brix_tpc_check_scope_path(identity, src_path, 0, log) != NGX_OK) {
        return NGX_DECLINED;
    }

    if (brix_tpc_check_scope_path(identity, dst_path, 1, log) != NGX_OK) {
        return NGX_DECLINED;
    }

    return NGX_OK;
}
