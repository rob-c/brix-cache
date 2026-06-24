/*
 * op_path.c — unified path extractor + resolver for namespace operations.
 *
 * Centralises the repeated extract_path → depth_check → resolve sequence
 * that was previously duplicated across 10+ handler files.
 *
 * Phase 8: resolution no longer calls realpath(3).  Confinement is enforced by
 * the kernel at the actual filesystem operation (openat2 RESOLVE_BENEATH via the
 * beneath API), so this layer only has to (1) reject obviously-bad paths the same
 * way the old xrootd_validate_components_cstr() did — length, depth, and the
 * forbidden "."/".." components — and (2) reproduce the per-mode existence
 * semantics the old resolve_path* variants provided (EXISTING needs the target,
 * WRITE needs the parent directory) using xrootd_stat_beneath() rather than a
 * realpath() that would have failed.  `resolved` is filled with the lexical
 * root_canon + reqpath join (xrootd_beneath_full_path); it is used downstream for
 * ACL prefix matching and access logging, NOT as a confinement boundary — the
 * boundary is RESOLVE_BENEATH at the op.  A path that escapes the export root is
 * rejected by the kernel (EXDEV) when the operation runs.
 */
#include "ngx_xrootd_module.h"
#include "path/op_path.h"
#include "path/beneath.h"
#include "path/path_internal.h"

#include <sys/stat.h>

/*
 * Validate each path component the way the retired realpath resolver's
 * xrootd_validate_components_cstr() did: reject "." and ".." segments outright.
 * RESOLVE_BENEATH would block a "../" that escapes the root, but a within-root
 * "/a/../b" was historically rejected here too — keep that behaviour so the
 * resolver's contract is unchanged.  Returns 1 if any component is forbidden.
 */
int
xrootd_op_path_forbidden_component(const char *reqpath)
{
    const char *p = reqpath;
    const char *seg;

    while (*p != '\0') {
        while (*p == '/') {
            p++;
        }
        if (*p == '\0') {
            break;
        }
        seg = p;
        while (*p != '\0' && *p != '/') {
            p++;
        }
        if (xrootd_path_component_forbidden(seg, (size_t) (p - seg))) {
            return 1;
        }
    }
    return 0;
}

/*
 * Existence gate replacing the realpath()-failure path of the old resolvers.
 *   want_dir < 0 : no check (NOEXIST).
 *   want_dir = 0 : the target itself must exist (EXISTING).
 *   want_dir = 1 : the target's PARENT directory must exist (WRITE).
 * Returns NGX_OK when the requirement is met, NGX_DECLINED otherwise.
 */
static ngx_int_t
op_path_existence_gate(ngx_stream_xrootd_srv_conf_t *conf,
                       const char *reqpath, int want_dir)
{
    struct stat st;

    if (want_dir < 0) {
        return NGX_OK;                  /* NOEXIST: nothing to verify */
    }

    if (want_dir == 0) {
        /* EXISTING: the target name must resolve, confined, to something present.
         * LSTAT (not stat) so a symlink — including a dangling one — counts as
         * present: rm/chmod/mv operate on the name itself, and rm of a symlink must
         * succeed (it never dereferences the final component). This gate is only the
         * ACL/logging existence check; the confined *_beneath ops remain the security
         * boundary, so not following the final link here weakens nothing. */
        return xrootd_lstat_beneath(conf->rootfd, reqpath, &st) == 0
               ? NGX_OK : NGX_DECLINED;
    }

    /* WRITE: the parent directory must already exist (target may not). Derive
     * the parent by trimming the last '/'-separated component. */
    {
        char        parent[XROOTD_MAX_PATH + 1];
        size_t      len = ngx_strlen(reqpath);
        const char *slash;

        while (len > 1 && reqpath[len - 1] == '/') {
            len--;                      /* ignore trailing slashes for the split */
        }
        slash = reqpath + len;
        while (slash > reqpath && *(slash - 1) != '/') {
            slash--;
        }
        /* slash now points just past the parent's trailing '/'. */
        {
            size_t plen = (size_t) (slash - reqpath);
            if (plen <= 1) {
                /* parent is the export root itself — always present. */
                return NGX_OK;
            }
            if (plen >= sizeof(parent)) {
                return NGX_DECLINED;
            }
            ngx_memcpy(parent, reqpath, plen);
            parent[plen] = '\0';
        }
        if (xrootd_stat_beneath(conf->rootfd, parent, &st) != 0
            || !S_ISDIR(st.st_mode))
        {
            return NGX_DECLINED;
        }
        return NGX_OK;
    }
}

/*
 * xrootd_path_resolve_beneath — validate reqpath and apply the per-mode
 * existence gate without realpath(), filling `resolved` with the confined
 * lexical join.  Shared by xrootd_resolve_op_path() and direct multi-path
 * callers (kXR_mv).  reqpath must already be extracted from the wire.
 *
 * Returns:
 *   NGX_OK       — valid and the existence requirement is met; resolved filled.
 *   NGX_DECLINED — path is well-formed but the existence gate failed
 *                  (EXISTING: target missing; WRITE: parent dir missing) → 404.
 *   NGX_ERROR    — malformed path (depth, "."/"..", WRITE trailing slash, or
 *                  the join overflowed resolved_sz) → 4xx ArgInvalid.
 */
ngx_int_t
xrootd_path_resolve_beneath(ngx_stream_xrootd_srv_conf_t *conf,
                            const char *reqpath, xrootd_path_mode_t mode,
                            char *resolved, size_t resolved_sz)
{
    int  want_dir;
    int  strip_trailing_slash;
    int  ok;
    char norm[XROOTD_MAX_PATH + 1];

    if (xrootd_count_path_depth(reqpath) != NGX_OK
        || xrootd_op_path_forbidden_component(reqpath))
    {
        return NGX_ERROR;
    }

    switch (mode) {
    case XROOTD_PATH_EXISTING: want_dir = 0;  strip_trailing_slash = 0; break;
    case XROOTD_PATH_WRITE:    want_dir = 1;  strip_trailing_slash = 1; break;
    case XROOTD_PATH_NOEXIST:  want_dir = -1; strip_trailing_slash = 0; break;
    case XROOTD_PATH_EITHER:   want_dir = 1;  strip_trailing_slash = 0; break;
    default:                   want_dir = 0;  strip_trailing_slash = 0; break;
    }

    /* A write/create target with a trailing slash is NORMALIZED, not rejected,
     * exactly as the reference's Squash collapses it: "mkdir /d/" -> /d and
     * "open /f/" -> /f. (We previously returned ArgInvalid, so `mkdir /d/` —
     * which stock accepts — failed.) Scoped to the create modes so a stat/cat of
     * "/file/" keeps its existing file-vs-dir error behavior. */
    if (strip_trailing_slash) {
        size_t rl = ngx_strlen(reqpath);
        if (rl > 1 && reqpath[rl - 1] == '/') {
            if (rl >= sizeof(norm)) {
                return NGX_ERROR;
            }
            ngx_memcpy(norm, reqpath, rl + 1);
            while (rl > 1 && norm[rl - 1] == '/') {
                norm[--rl] = '\0';
            }
            reqpath = norm;
        }
    }

    ok = (op_path_existence_gate(conf, reqpath, want_dir) == NGX_OK);
    if (!ok && mode == XROOTD_PATH_EITHER) {
        ok = (op_path_existence_gate(conf, reqpath, 0) == NGX_OK);
    }
    if (!ok) {
        return NGX_DECLINED;
    }

    if (xrootd_beneath_full_path(conf->common.root_canon, reqpath,
                                 resolved, resolved_sz) >= (int) resolved_sz)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}

int
xrootd_reject_dotdot_path(xrootd_ctx_t *ctx, ngx_connection_t *c,
                          ngx_uint_t op_id, const char *op_name,
                          const char *reqpath)
{
    if (!xrootd_path_has_dotdot(reqpath)) {
        return 0;
    }
    xrootd_log_path_warning(c->log, "xrootd: path traversal attempt", reqpath);
    xrootd_log_access(ctx, c, op_name, reqpath, "-",
                      0, kXR_ArgInvalid, "invalid path", 0);
    XROOTD_OP_ERR(ctx, op_id);
    ctx->write_rc = xrootd_send_error(ctx, c, kXR_ArgInvalid, "invalid path");
    return 1;
}

ngx_int_t
xrootd_resolve_op_path(xrootd_ctx_t *ctx, ngx_connection_t *c,
                        ngx_uint_t op_id, const char *op_name,
                        ngx_stream_xrootd_srv_conf_t *conf,
                        xrootd_path_mode_t mode,
                        char *reqpath, size_t reqpath_sz,
                        char *resolved, size_t resolved_sz)
{
    ngx_int_t rc;

    if (ctx->payload == NULL || ctx->cur_dlen == 0) {
        xrootd_log_access(ctx, c, op_name, "-", "-",
                          0, kXR_ArgMissing, "no path given", 0);
        XROOTD_OP_ERR(ctx, op_id);
        ctx->write_rc = xrootd_send_error(ctx, c, kXR_ArgMissing,
                                          "no path given");
        return NGX_DONE;
    }

    if (!xrootd_extract_path(c->log, ctx->payload, ctx->cur_dlen,
                             reqpath, reqpath_sz, 1)) {
        xrootd_log_access(ctx, c, op_name, "-", "-",
                          0, kXR_ArgInvalid, "invalid path payload", 0);
        XROOTD_OP_ERR(ctx, op_id);
        ctx->write_rc = xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                          "invalid path payload");
        return NGX_DONE;
    }

    rc = xrootd_path_resolve_beneath(conf, reqpath, mode,
                                     resolved, resolved_sz);
    if (rc == NGX_ERROR) {
        /*
         * Restore the error-log diagnostic the retired realpath resolver
         * (xrootd_validate_components_cstr) emitted: a rejected "."/".."
         * traversal is recorded in the error log with control bytes escaped,
         * so operators retain visibility into traversal attempts.  Depth and
         * join-overflow rejections fall through to the access log only.
         */
        if (xrootd_op_path_forbidden_component(reqpath)) {
            xrootd_log_path_warning(c->log, "xrootd: path traversal attempt",
                                    reqpath);
        }
        xrootd_log_access(ctx, c, op_name, reqpath, "-",
                          0, kXR_ArgInvalid, "invalid path", 0);
        XROOTD_OP_ERR(ctx, op_id);
        ctx->write_rc = xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                          "invalid path");
        return NGX_DONE;
    }
    if (rc == NGX_DECLINED) {
        xrootd_log_access(ctx, c, op_name, reqpath, "-",
                          0, kXR_NotFound, "no such file or directory", 0);
        XROOTD_OP_ERR(ctx, op_id);
        ctx->write_rc = xrootd_send_error(ctx, c, kXR_NotFound,
                                          "no such file or directory");
        return NGX_DONE;
    }

    return NGX_OK;
}
