#include "query_internal.h"
#include "prepare_internal.h"
#include "fs/path/beneath.h"
#include "fs/xfer/stage_request_registry.h"

#include <errno.h>
#include <sys/stat.h>
#include <time.h>
#include "core/compat/alloc_guard.h"

/*
 * prepare_check.c — per-path validation + authorization for kXR_prepare.
 *
 * WHAT: brix_prepare_check_path() validates ONE newline-separated path from the
 *       prepare payload: length/extract/forbidden-component pre-checks, confined
 *       stat, and the three prepare authorization tiers. Split out of prepare.c
 *       to keep both files under the size cap; the scan pipeline in prepare.c is
 *       the sole caller (prototype in prepare_internal.h).
 */

static ngx_flag_t
brix_prepare_has_forbidden_component(const char *path)
{
    const char *p = path;

    while (*p != '\0') {
        const char *seg;
        size_t      len;

        while (*p == '/') {
            p++;
        }

        seg = p;
        while (*p != '\0' && *p != '/') {
            p++;
        }

        len = (size_t) (p - seg);
        if ((len == 1 && seg[0] == '.')
            || (len == 2 && seg[0] == '.' && seg[1] == '.'))
        {
            return 1;
        }
    }

    return 0;
}
/* WHY: kXR_prepare rejects paths containing dot (.) or double-dot (..) components to prevent directory traversal into parent exports. Used as a fast pre-check before full path resolution — avoids expensive resolve_path() calls on obviously invalid paths. */
/* HOW: Scans path character-by-character, skipping leading '/' separators; extracts each segment between slashes via seg→p pointer arithmetic. For each segment checks len==1 && seg[0]=='.' or len==2 && seg[0]=='.' && seg[1]=='.' — if match returns 1 (forbidden). Returns 0 if no forbidden components found after full scan. Static helper used exclusively by brix_prepare_check_path(). */

static ngx_int_t
brix_prepare_check_fail(brix_ctx_t *ctx, ngx_connection_t *c,
    const char *path, uint16_t errcode, const char *errmsg)
{
    ngx_int_t rc;

    rc = brix_prepare_send_fail(ctx, c, path, errcode, errmsg);
    return (rc == NGX_OK) ? NGX_DONE : rc;
}
/* WHY: kXR_prepare check_path callers need NGX_DONE (continue processing) vs NGX_ERROR (abort). This helper converts the brix_send_error() result into the appropriate return code — NGX_OK from send_error becomes NGX_DONE for graceful continuation, other results pass through as abort codes. Used by check_path to distinguish between "error logged but continue" and "fatal error" returns. */
/* HOW: Calls brix_prepare_send_fail(ctx, c, path, errcode, errmsg) — if result == NGX_OK returns NGX_DONE (graceful continuation), otherwise returns the raw result code unchanged. Static helper used exclusively by check_path(). */

/*
 * WHAT: run the three prepare authorization tiers (authdb VO/ACL, VO identity
 *       ACL, token scope) on one resolved path.
 * WHY:  the existing-file and noerrs-absent branches of check_path must apply
 *       the SAME gate on the SAME paths (verdict parity between "exists" and
 *       "absent") — factoring it here removes the duplication AND guarantees the
 *       two branches can never drift apart.  Authorization is a property of the
 *       identity + logical path, not of on-disk existence.
 * HOW:  each tier that denies sends its specific error via check_fail and its rc
 *       (NGX_DONE/error) is returned; NGX_OK only when all three pass.
 */
static ngx_int_t
prepare_path_authz(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const char *pathbuf, const char *full_path)
{
    if (brix_authz_check(ctx, c, conf, pathbuf, full_path, "PREPARE",
                           BRIX_AUTH_READ, BRIX_AOP_STAGE) != NGX_OK) {
        return brix_prepare_check_fail(ctx, c, full_path, kXR_NotAuthorized,
                                         "not authorized");
    }
    if (brix_check_vo_acl_identity(c->log, full_path, conf->vo_rules,
                                     ctx->identity) != NGX_OK) {
        return brix_prepare_check_fail(ctx, c, full_path, kXR_NotAuthorized,
                                         "VO not authorized");
    }
    if (brix_check_token_scope(ctx, pathbuf, 0) != NGX_OK) {
        return brix_prepare_check_fail(ctx, c, pathbuf, kXR_NotAuthorized,
                                         "token scope denied");
    }
    return NGX_OK;
}

/*
 * Map a confined-stat failure (non-noerrs, or non-ENOENT errno) to the wire
 * error: ENOENT/ENOTDIR → kXR_NotFound, EACCES/EPERM → kXR_NotAuthorized, any
 * other errno → kXR_IOError.  Returns the check_fail rc (NGX_DONE/error).
 */
static ngx_int_t
prepare_stat_error(brix_ctx_t *ctx, ngx_connection_t *c,
    const char *pathbuf, const char *full_path)
{
    if (errno == ENOENT || errno == ENOTDIR) {
        return brix_prepare_check_fail(ctx, c, pathbuf, kXR_NotFound,
                                         "file not found");
    }
    if (errno == EACCES || errno == EPERM) {
        return brix_prepare_check_fail(ctx, c, full_path, kXR_NotAuthorized,
                                         "not authorized");
    }
    return brix_prepare_check_fail(ctx, c, full_path, kXR_IOError,
                                     "prepare stat failed");
}

ngx_int_t
brix_prepare_check_path(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const u_char *line, size_t line_len,
    ngx_flag_t noerrs, ngx_uint_t *missing,
    char *out_resolved)   /* PATH_MAX buffer filled with absolute path on
                             auth-pass paths; '\0' if path cannot be resolved.
                             Pass NULL when staging collection is not needed. */
{
    char         pathbuf[BRIX_MAX_PATH + 1];
    char         full_path[PATH_MAX];
    struct stat  st;

    if (line_len > BRIX_MAX_PATH) {
        return brix_prepare_check_fail(ctx, c, "-", kXR_ArgTooLong,
                                         "prepare path too long");
    }

    if (!brix_extract_path(c->log, line, line_len, pathbuf,
                             sizeof(pathbuf), 1)) {
        return brix_prepare_check_fail(ctx, c, "-", kXR_ArgInvalid,
                                         "invalid prepare path");
    }

    if (brix_prepare_has_forbidden_component(pathbuf)) {
        return brix_prepare_check_fail(ctx, c, pathbuf, kXR_ArgInvalid,
                                         "invalid prepare path");
    }

    /* phase74-fp: pathbuf is the request path, full_path the output buf. */
    brix_beneath_full_path(conf->common.root_canon, pathbuf,  /* NOLINT(readability-suspicious-call-argument) */
                             full_path, sizeof(full_path));

    /*
     * CONTRACT: the same "file is absent" condition (ENOENT/ENOTDIR from the
     * confined stat) has two outcomes selected by the kXR_noerrs flag:
     *   - noerrs set  → not an error. The path is counted in *missing and the
     *     request still succeeds, so a client can prepare/stage files that do
     *     not exist on disk yet (tape nearline recall, not-yet-cached objects).
     *   - noerrs clear → kXR_NotFound, failing the request on the first miss.
     * EACCES/EPERM and any other errno always fail regardless of noerrs.
     */
    if (brix_stat_beneath(conf->rootfd, pathbuf, &st) != 0) {
        if ((errno == ENOENT || errno == ENOTDIR) && noerrs) {
            (*missing)++;
            /* SECURITY: authorization is a property of the IDENTITY + LOGICAL
             * PATH, not of on-disk existence. A prepare/stage of a not-yet-
             * materialised object (tape nearline recall, not-yet-cached) must
             * still prove the caller may READ/STAGE this namespace path —
             * otherwise an unauthorized principal drives recalls or enumerates
             * the namespace via prepare, and later serves the recalled bytes from
             * the shared cache. Run the SAME three tiers, on the SAME paths, as
             * the existing-file branch below (verdict parity between "exists" and
             * "absent"); only then supply the staging path. */
            {
                ngx_int_t arc = prepare_path_authz(ctx, c, conf, pathbuf,
                                                     full_path);
                if (arc != NGX_OK) {
                    return arc;
                }
            }
            /* For staging: supply absolute path even if file doesn't exist yet
             * (tape nearline / not-yet-created). */
            if (out_resolved != NULL) {
                ngx_cpystrn((u_char *) out_resolved, (u_char *) full_path,
                            PATH_MAX);
            }
            return NGX_OK;
        }
        return prepare_stat_error(ctx, c, pathbuf, full_path);
    }

    {
        ngx_int_t arc = prepare_path_authz(ctx, c, conf, pathbuf, full_path);
        if (arc != NGX_OK) {
            return arc;
        }
    }

    /* Copy the absolute export path for the staging command; only authorized
     * paths reach here so the staging hook can trust the value. */
    if (out_resolved != NULL) {
        ngx_cpystrn((u_char *) out_resolved, (u_char *) full_path, PATH_MAX);
    }

    if (S_ISDIR(st.st_mode)) {
        if (noerrs) {
            (*missing)++;
            return NGX_OK;
        }
        return brix_prepare_check_fail(ctx, c, pathbuf, kXR_isDirectory,
                                         "prepare target is a directory");
    }

    return NGX_OK;
}
