/*
 * copy_authorization.c - exact and recursive authorization for local COPY.
 *
 * WHAT: Owns paired logical/resolved COPY decisions and maps recursive source
 *       children onto their caller-visible final destination paths.
 *
 * WHY: COPY has independent source/destination authority, while collection
 *      execution operates on resolved source and unpublished staging paths.
 *      Keeping that translation in one unit prevents policy/storage spelling
 *      drift and keeps copy.c below the file-size gate.
 *
 * HOW: Exact root checks use the shared WebDAV/VFS evaluator; child callbacks
 *      derive a confined suffix, reconstruct both logical paths, and require
 *      source READ plus destination UPDATE/CREATE/DELETE before each sink.
 */

#include "webdav.h"
#include "copy_internal.h"
#include "fs/path/path.h"
#include "fs/vfs/vfs_authz.h"

#include <stdio.h>
#include <sys/stat.h>

/* ---- Authorize one exact COPY operand -----------------------------------
 *
 * WHAT: Evaluates one paired logical/resolved COPY resource and returns NGX_OK
 *       or the edge-owned HTTP refusal.
 *
 * WHY: Source read, destination create/update, and overwrite deletion are
 *      distinct decisions that must share the representation-safe evaluator.
 *
 * HOW: Fill an exact VFS authorization descriptor from explicit inputs and
 *      delegate to the authoritative WebDAV resource gate.
 */
ngx_int_t
webdav_copy_authorize(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, const char *logical_path,
    const char *resolved_path, const char *operation, uint32_t needed_privs,
    brix_acc_op_t acc_op, int need_write)
{
    brix_vfs_authz_exact_t exact = {
        .logical_path = logical_path,
        .resolved_path = resolved_path,
        .operation = operation,
        .needed_privs = needed_privs,
        .acc_op = acc_op,
        .need_write = need_write ? 1 : 0,
    };

    return webdav_authorize_resource(r, conf, &exact);
}

/* ---- Append a checked relative suffix to a logical or resolved root -----
 *
 * WHAT: Writes `root[/]relative` to `out` and returns NGX_OK or 414 when the
 *       bounded buffer cannot hold the complete path.
 *
 * WHY: Recursive authorization must derive child policy names without
 *      truncation or separator ambiguity.
 *
 * HOW: Select an empty separator for roots ending in '/', format once, and
 *      reject every negative or truncated result.
 */
static ngx_int_t
webdav_copy_append_relative(const char *root, const char *relative,
    char *out, size_t out_size)
{
    size_t root_len;
    int    written;

    if (root == NULL || relative == NULL || out == NULL || out_size == 0) {
        return NGX_HTTP_FORBIDDEN;
    }
    if (relative[0] == '\0') {
        if (ngx_strlen(root) >= out_size) {
            return NGX_HTTP_REQUEST_URI_TOO_LARGE;
        }
        ngx_cpystrn((u_char *) out, (const u_char *) root, out_size);
        return NGX_OK;
    }

    root_len = ngx_strlen(root);
    written = snprintf(out, out_size, "%s%s%s", root,
        root_len > 0 && root[root_len - 1] == '/' ? "" : "/", relative);
    return written >= 0 && (size_t) written < out_size
        ? NGX_OK : NGX_HTTP_REQUEST_URI_TOO_LARGE;
}

/* ---- Map one recursive source child to its policy path pair -------------
 *
 * WHAT: Produces the logical source, logical final destination, and resolved
 *       final destination for a confined source child. Returns NGX_OK or a
 *       fail-closed HTTP status.
 *
 * WHY: The copy walker writes into an unpublished staging tree, but policy is
 *      defined on the caller-visible final destination.
 *
 * HOW: Derive the checked suffix relative to the resolved source root, then
 *      append it independently to each stored logical/resolved root.
 */
static ngx_int_t
webdav_copy_map_child(const webdav_copy_authz_ctx_t *authz,
    const char *source_child, char *source_logical, char *dest_logical,
    char *dest_resolved)
{
    char      relative[WEBDAV_MAX_PATH];
    ngx_int_t rc;

    if (authz == NULL || authz->r == NULL
        || !brix_resolved_relative_to_root(authz->r->connection->log,
            authz->src_resolved, source_child, relative, sizeof(relative)))
    {
        return NGX_HTTP_FORBIDDEN;
    }

    rc = webdav_copy_append_relative(authz->src_logical, relative,
                                     source_logical, WEBDAV_MAX_PATH);
    if (rc != NGX_OK) {
        return rc;
    }
    rc = webdav_copy_append_relative(authz->dst_logical, relative,
                                     dest_logical, WEBDAV_MAX_PATH);
    if (rc != NGX_OK) {
        return rc;
    }
    return webdav_copy_append_relative(authz->dst_resolved, relative,
                                       dest_resolved, WEBDAV_MAX_PATH);
}

/* ---- Initialize request-bound COPY authorization state -----------------
 *
 * WHAT: Copies the request pointer, configuration pointer, and four path roots
 *       into `authz`; NULL inputs leave a zeroed fail-closed context.
 *
 * WHY: Collection execution needs stable by-value paths and one shared mapper
 *      for copy and overwrite-removal guards.
 *
 * HOW: Zero the destination, retain request/config lifetimes, and bounded-copy
 *      every logical/resolved root from the validated request.
 */
void
webdav_copy_authz_init(webdav_copy_authz_ctx_t *authz,
    ngx_http_request_t *r, ngx_http_brix_webdav_loc_conf_t *conf,
    const webdav_copy_req_t *req)
{
    if (authz == NULL) {
        return;
    }
    ngx_memzero(authz, sizeof(*authz));
    if (r == NULL || conf == NULL || req == NULL) {
        return;
    }

    authz->r = r;
    authz->conf = conf;
    ngx_cpystrn((u_char *) authz->src_logical,
                (const u_char *) req->src_logical,
                sizeof(authz->src_logical));
    ngx_cpystrn((u_char *) authz->src_resolved,
                (const u_char *) req->src_path,
                sizeof(authz->src_resolved));
    ngx_cpystrn((u_char *) authz->dst_logical,
                (const u_char *) req->dest_decoded,
                sizeof(authz->dst_logical));
    ngx_cpystrn((u_char *) authz->dst_resolved,
                (const u_char *) req->dst_path,
                sizeof(authz->dst_resolved));
}

/* ---- Report whether COPY must retain caller-bound authorization ---------
 *
 * WHAT: Returns non-zero when the request's VFS context carries an effective
 *       native, VO, XrdAcc, or token rule set.
 *
 * WHY: A collection with active rules must execute its per-child guards on the
 *      request thread; an allow-all export may retain identity-free offload.
 *
 * HOW: Build the canonical request context on the source root and delegate to
 *      the VFS evaluator's canonical rule-presence predicate.
 */
int
webdav_copy_authz_has_effective_rules(const webdav_copy_authz_ctx_t *authz)
{
    brix_vfs_ctx_t vctx;

    if (authz == NULL || authz->r == NULL || authz->conf == NULL) {
        return 1;
    }
    webdav_vfs_ctx_build(authz->r, authz->src_resolved, &vctx);
    return brix_vfs_authz_has_effective_rules(&vctx);
}

/* ---- Authorize one recursive COPY child --------------------------------
 *
 * WHAT: Requires READ on the source child and destination UPDATE plus CREATE
 *       for a fresh target or DELETE for a replacement. Returns NGX_OK or the
 *       first fail-closed HTTP refusal.
 *
 * WHY: Root authorization does not cover narrower child rules, and the walker
 *      otherwise reads/creates descendants without caller authority.
 *
 * HOW: Map the child to final paths, authorize source READ and baseline
 *      destination UPDATE before probing, then require CREATE or DELETE.
 */
ngx_int_t
webdav_copy_authorize_child(void *cookie, const char *src,
    const char *staged_dst, int is_dir)
{
    webdav_copy_authz_ctx_t *authz = cookie;
    char                     src_logical[WEBDAV_MAX_PATH];
    char                     dst_logical[WEBDAV_MAX_PATH];
    char                     dst_resolved[WEBDAV_MAX_PATH];
    struct stat              dst_sb;
    ngx_int_t                rc;

    (void) staged_dst;
    (void) is_dir;

    rc = webdav_copy_map_child(authz, src, src_logical, dst_logical,
                               dst_resolved);
    if (rc != NGX_OK) {
        return rc;
    }
    rc = webdav_copy_authorize(authz->r, authz->conf, src_logical, src,
                               "COPY source child", BRIX_AUTH_READ,
                               BRIX_AOP_READ, 0);
    if (rc != NGX_OK) {
        return rc;
    }
    rc = webdav_copy_authorize(authz->r, authz->conf, dst_logical,
                               dst_resolved, "COPY destination child",
                               BRIX_AUTH_UPDATE, BRIX_AOP_UPDATE, 1);
    if (rc != NGX_OK) {
        return rc;
    }
    if (webdav_copy_probe(authz->r, dst_resolved, &dst_sb) != NGX_OK) {
        return webdav_copy_authorize(authz->r, authz->conf, dst_logical,
            dst_resolved, "COPY create destination child", BRIX_AUTH_UPDATE,
            BRIX_AOP_CREATE, 1);
    }
    return webdav_copy_authorize(authz->r, authz->conf, dst_logical,
        dst_resolved, "COPY replace destination child", BRIX_AUTH_DELETE,
        BRIX_AOP_DELETE, 1);
}

/* ---- Authorize deletion of one existing destination path ---------------
 *
 * WHAT: Requires DELETE authority on one resolved destination-tree path and
 *       returns NGX_OK or the exact HTTP refusal.
 *
 * WHY: Replacing a collection recursively destroys descendants that may carry
 *      narrower rules than the destination root.
 *
 * HOW: Derive the checked suffix beneath the final destination root, append it
 *      to the logical root, and invoke the exact resource evaluator.
 */
ngx_int_t
webdav_copy_authorize_delete(void *cookie, const char *path, int is_dir)
{
    webdav_copy_authz_ctx_t *authz = cookie;
    char                     relative[WEBDAV_MAX_PATH];
    char                     logical[WEBDAV_MAX_PATH];
    ngx_int_t                rc;

    (void) is_dir;

    if (authz == NULL || authz->r == NULL
        || !brix_resolved_relative_to_root(authz->r->connection->log,
            authz->dst_resolved, path, relative, sizeof(relative)))
    {
        return NGX_HTTP_FORBIDDEN;
    }
    rc = webdav_copy_append_relative(authz->dst_logical, relative, logical,
                                     sizeof(logical));
    if (rc != NGX_OK) {
        return rc;
    }
    return webdav_copy_authorize(authz->r, authz->conf, logical, path,
        "COPY delete destination child", BRIX_AUTH_DELETE,
        BRIX_AOP_DELETE, 1);
}
