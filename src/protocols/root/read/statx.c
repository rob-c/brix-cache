/*
 * statx.c — kXR_statx opcode: batched metadata query over multiple paths.
 */

#include "statx.h"
#include "stat.h"
#include "core/ngx_brix_module.h"
#include "protocols/root/path/op_path.h"  /* brix_root_vfs_bind_deleg (phase-70) */
#include "fs/path/beneath.h"
#include "fs/path/reserved_names.h"   /* brix_is_internal_name — hide sidecars */
#include "core/compat/alloc_guard.h"

#include <stdlib.h>   /* realpath */

#define BRIX_STATX_MAX_PATHS  256
/* kXR_statx returns exactly ONE flag byte per requested path — a packed byte
 * array, no separators, no NUL (reference XrdXrootdXeq.cc:3194-3203):
 * kXR_file(0) / kXR_isDir(2) / kXR_other(4) / kXR_offline(8). An inaccessible or
 * missing path yields kXR_offline. (We previously emitted a full "id size flags
 * mtime" text line per path — a kXR_stat body — which no standard statx parser
 * could read.) */
#define BRIX_STATX_BUF_MAX    BRIX_STATX_MAX_PATHS

/* Append-cursor over the packed flag-byte response buffer: ptr is the write
 * head, end the one-past-last writable byte.  Bundled so the per-path processor
 * stays within the ≤5-parameter budget. */
typedef struct {
    u_char       *ptr;
    const u_char *end;
} brix_statx_rsp_t;

/* Advance *cursor over one NUL-terminated path in the kXR_statx payload,
 * returning the path (NULL at end).  Bounds-checked against end. */
static ngx_flag_t
brix_statx_next_path(const u_char **cursor, const u_char *end,
    char *path, size_t path_size)
{
    const u_char *path_start;
    size_t        path_len;

    /* kXR_statx paths are NEWLINE-separated in the request (reference do_Statx
     * tokenizes a '\n' list); the final path may lack a trailing newline. (We
     * previously split on '\0', so a standard client's newline list was read as
     * one giant path.) */
    path_start = *cursor;
    while (*cursor < end && **cursor != '\n') {
        (*cursor)++;
    }

    path_len = (size_t) (*cursor - path_start);
    if (*cursor < end) {
        (*cursor)++;   /* skip the '\n' separator */
    }

    if (path_len == 0 || path_len >= path_size) {
        return 0;
    }

    ngx_memcpy(path, path_start, path_len);
    path[path_len] = '\0';

    return 1;
}

/*
 * WHAT:  Follow an in-export symlink whose target is a host-ABSOLUTE path, when
 *        the confined stat has already failed with ENOENT.
 * WHY:   RESOLVE_IN_ROOT chroots an absolute symlink target to ENOENT, whereas
 *        stock XRootD follows it on the real filesystem.  We match stock while
 *        staying confined: the realpath must canonically resolve inside the
 *        export root before we read its metadata through the VFS.
 * HOW:   Guard on ENOENT + a configured root; realpath() the full path, verify
 *        it is prefix-bounded by root_canon at a '/' or end boundary, then VFS
 *        probe.  On success fills *st and returns 1; otherwise returns 0 and
 *        leaves *st untouched.
 */
static int
brix_statx_symlink_fallback_stat(brix_ctx_t *ctx,
    ngx_stream_brix_srv_conf_t *conf, ngx_connection_t *c,
    const char *full_path, struct stat *st)
{
    char            real[PATH_MAX];
    size_t          rl;
    brix_vfs_ctx_t  rvctx;
    brix_vfs_stat_t rvst;

    if (errno != ENOENT || conf->common.root_canon[0] == '\0') {
        return 0;
    }

    rl = ngx_strlen(conf->common.root_canon);
    /* rl bound keeps the real[rl] prefix-boundary probe inside the buffer even
     * for a maximal-length configured export root. */
    if (rl >= sizeof(real)
        || realpath(full_path, real) == NULL
        || ngx_strncmp(real, conf->common.root_canon, rl) != 0
        || (real[rl] != '/' && real[rl] != '\0'))
    {
        return 0;
    }

    /* Canonical target confirmed within the export root; read its metadata
     * through the VFS (chain already resolved). */
    brix_vfs_ctx_init(&rvctx, c->pool, c->log, BRIX_PROTO_ROOT,
        conf->common.root_canon, NULL, conf->common.allow_write,
        0 /* is_tls */, ctx->identity, real);
    brix_vfs_ctx_bind_backend_cred(&rvctx,
        &conf->common.storage_credential_dir,
        conf->common.storage_credential_fallback);
    brix_root_vfs_bind_deleg(ctx, conf, &rvctx);
    if (brix_vfs_probe(&rvctx, 0 /* follow */, &rvst) != NGX_OK) {
        return 0;
    }

    brix_vfs_to_struct_stat(&rvst, st);
    return 1;
}

/*
 * WHAT:  Apply the STAT authorization gate (authdb + VO ACL + token scope) to a
 *        single statx path.
 * WHY:   W4 — STATX must refuse exactly what a single STAT op would refuse.
 *        STATX previously skipped the authdb check, so an authdb-denied path
 *        could leak real metadata via the batched stat.
 * HOW:   Returns NGX_OK when all three checks pass, NGX_ERROR on any denial.
 */
static ngx_int_t
brix_statx_path_authorized(brix_ctx_t *ctx, ngx_stream_brix_srv_conf_t *conf,
    ngx_connection_t *c, const char *full_path, const char *reqpath_buf)
{
    if (brix_check_authdb(ctx, full_path, BRIX_AUTH_LOOKUP) != NGX_OK
        || brix_check_vo_acl_identity(c->log, full_path, conf->vo_rules,
                                        ctx->identity) != NGX_OK
        || brix_check_token_scope(ctx, reqpath_buf, 0) != NGX_OK)
    {
        return NGX_ERROR;
    }
    return NGX_OK;
}

/*
 * WHAT:  Compute the single kXR_statx flag byte for a successfully stat'd path.
 * WHY:   The reference do_Statx emits ONLY kXR_isDir or kXR_file (plus
 *        kXR_offline via the FRM/residency probe) — there is NO kXR_other in
 *        statx, so a FIFO / socket / device stats as kXR_file(0), exactly as
 *        stock. (Plain kXR_stat does use kXR_other; statx deliberately does
 *        not.)
 * HOW:   isDir → kXR_isDir else kXR_file; OR in kXR_offline when the VFS
 *        residency probe (built with a NULL identity, matching the original
 *        inline block) reports NEARLINE/OFFLINE.  Returns the packed byte.
 */
static u_char
brix_statx_compute_flag(ngx_stream_brix_srv_conf_t *conf,
    ngx_connection_t *c, const char *full_path, const struct stat *st)
{
    u_char              flag;
    brix_vfs_ctx_t      rvc;
    brix_sd_residency_t res;

    if (S_ISDIR(st->st_mode)) {
        flag = (u_char) kXR_isDir;
    } else {
        flag = (u_char) kXR_file;          /* 0 — incl. non-regular */
    }

    brix_vfs_ctx_init(&rvc, c->pool, c->log, BRIX_PROTO_ROOT,
        conf->common.root_canon, NULL, conf->common.allow_write,
        0 /* is_tls */, NULL, full_path);
    if (brix_vfs_residency(&rvc, &res, NULL) == NGX_OK
        && (res == BRIX_SD_RES_NEARLINE || res == BRIX_SD_RES_OFFLINE))
    {
        flag |= (u_char) kXR_offline;
    }

    return flag;
}

/*
 * WHAT:  Process one statx path — internal-name/authz/stat checks, then append
 *        its flag byte to the response buffer.
 * WHY:   Isolates the per-path pipeline so the batch loop stays a thin driver.
 *        The reference do_Statx returns an ERROR (fsError) on the FIRST path
 *        whose stat/authz fails — it does NOT emit a per-path sentinel and
 *        continue — so any failure here terminates the batch with a kXR_error,
 *        matching XrdXrootdXeq.cc:do_Statx and every standard statx parser.
 * HOW:   On any denial/miss the BRIX_RETURN_ERR macro logs, meters and sends the
 *        kXR_error, returning the wire result (which the caller propagates).  A
 *        full response buffer returns NGX_ABORT (caller breaks the batch).  On
 *        success the flag byte is written via rsp->ptr and NGX_DONE is returned
 *        to signal the caller to continue the batch.
 */
static ngx_int_t
brix_statx_process_path(brix_ctx_t *ctx, ngx_stream_brix_srv_conf_t *conf,
    ngx_connection_t *c, const char *reqpath_buf, brix_statx_rsp_t *rsp)
{
    char        full_path[PATH_MAX];
    struct stat st;

    /* Internal artifacts (sidecars, upload temps) are invisible → report as
     * absent, same as a stat miss. */
    if (brix_is_internal_name(reqpath_buf)) {
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_STATX, "STATX", reqpath_buf, "-",
                          kXR_NotFound, "file not found");
    }

    /* Resolve and stat the path. */
    brix_beneath_full_path(conf->common.root_canon, reqpath_buf,
                             full_path, sizeof(full_path));

    if (rsp->ptr >= rsp->end) {
        return NGX_ABORT;
    }

    if (brix_statx_path_authorized(ctx, conf, c, full_path, reqpath_buf)
        != NGX_OK)
    {
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_STATX, "STATX", reqpath_buf, "-",
                          kXR_NotAuthorized, "permission denied");
    }

    if (brix_stat_beneath(conf->rootfd, reqpath_buf, &st) != 0
        && !brix_statx_symlink_fallback_stat(ctx, conf, c, full_path, &st))
    {
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_STATX, "STATX", reqpath_buf, "-",
                          brix_kxr_from_errno(errno), strerror(errno));
    }

    *rsp->ptr++ = brix_statx_compute_flag(conf, c, full_path, &st);
    return NGX_DONE;
}

/* Handle kXR_statx — stat each newline-separated path in the request and return
 * one packed flag byte per path. */
ngx_int_t
brix_handle_statx(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf)
{
    const u_char    *cursor, *end;
    u_char          *rsp_buf;
    brix_statx_rsp_t rsp;
    char             reqpath_buf[BRIX_MAX_PATH + 1];
    char             detail[32];
    int              n_paths = 0;

    if (ctx->recv.cur_dlen == 0 || ctx->recv.payload == NULL) {
        BRIX_OP_ERR(ctx, BRIX_OP_STATX);
        return brix_send_error(ctx, c, kXR_ArgMissing, "no paths given");
    }

    BRIX_PALLOC_OR_RETURN(rsp_buf, c->pool, BRIX_STATX_BUF_MAX, NGX_ERROR);

    rsp.ptr = rsp_buf;
    rsp.end = rsp_buf + BRIX_STATX_BUF_MAX;
    cursor  = ctx->recv.payload;
    end     = ctx->recv.payload + ctx->recv.cur_dlen;

    while (cursor < end && n_paths < BRIX_STATX_MAX_PATHS) {
        ngx_int_t rc;

        if (!brix_statx_next_path(&cursor, end, reqpath_buf,
                                    sizeof(reqpath_buf)))
        {
            continue;
        }

        n_paths++;

        rc = brix_statx_process_path(ctx, conf, c, reqpath_buf, &rsp);
        if (rc == NGX_ABORT) {
            break;       /* response buffer full — stop the batch */
        }
        if (rc != NGX_DONE) {
            return rc;   /* per-path error already sent — terminate the batch */
        }
    }

    snprintf(detail, sizeof(detail), "%d_paths", n_paths);
    brix_log_access(ctx, c, "STATX", "-", detail, 1, 0, NULL, 0);
    BRIX_OP_OK(ctx, BRIX_OP_STATX);

    return brix_send_ok(ctx, c, rsp_buf,
                          (uint32_t)((size_t)(rsp.ptr - rsp_buf)));
}
