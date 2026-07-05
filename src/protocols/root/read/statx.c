/*
 * statx.c — kXR_statx opcode: batched metadata query over multiple paths.
 */

#include "statx.h"
#include "stat.h"
#include "core/ngx_brix_module.h"
#include "fs/path/beneath.h"
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

/* Handle kXR_statx — stat each NUL-separated path in the request and return one
 * inline stat line (or flag byte) per path. */
ngx_int_t
brix_handle_statx(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf)
{
    const u_char *cursor, *end;
    u_char       *rsp_buf, *rsp_ptr;
    u_char       *rsp_end;
    char          reqpath_buf[BRIX_MAX_PATH + 1];
    char          full_path[PATH_MAX];
    struct stat   st;
    int           n_paths = 0;

    if (ctx->recv.cur_dlen == 0 || ctx->recv.payload == NULL) {
        BRIX_OP_ERR(ctx, BRIX_OP_STATX);
        return brix_send_error(ctx, c, kXR_ArgMissing, "no paths given");
    }

    BRIX_PALLOC_OR_RETURN(rsp_buf, c->pool, BRIX_STATX_BUF_MAX, NGX_ERROR);

    rsp_ptr = rsp_buf;
    rsp_end = rsp_buf + BRIX_STATX_BUF_MAX;
    cursor  = ctx->recv.payload;
    end     = ctx->recv.payload + ctx->recv.cur_dlen;

    while (cursor < end && n_paths < BRIX_STATX_MAX_PATHS) {
        if (!brix_statx_next_path(&cursor, end, reqpath_buf,
                                    sizeof(reqpath_buf)))
        {
            continue;
        }

        n_paths++;

        /* Resolve and stat the path. */
        brix_beneath_full_path(conf->common.root_canon, reqpath_buf,
                                 full_path, sizeof(full_path));
        /*
         * W4 — apply the SAME authorization gate STAT uses (authdb + VO ACL +
         * token scope), not just VO ACL + scope.  Previously STATX skipped the
         * authdb check, so an authdb-denied path could leak real metadata via
         * the batched stat where the single STAT op would have refused it.
         * A denial here falls through to the per-path "inaccessible" sentinel,
         * preserving STATX's partial-result semantics.
         */
        if (rsp_ptr >= rsp_end) {
            break;
        }

        /* The reference do_Statx returns an ERROR (fsError) on the FIRST path
         * whose stat fails — it does NOT emit a per-path sentinel and continue.
         * kXR_offline is reserved for a path that stat()s OK but reports mode==-1
         * (a tape-staged file), handled via the FRM probe below. A missing or
         * authz-denied path therefore terminates the batch with a kXR_error,
         * matching XrdXrootdXeq.cc:do_Statx and every standard statx parser. */
        if (brix_check_authdb(ctx, full_path, BRIX_AUTH_LOOKUP) != NGX_OK
            || brix_check_vo_acl_identity(c->log, full_path, conf->vo_rules,
                                            ctx->identity) != NGX_OK
            || brix_check_token_scope(ctx, reqpath_buf, 0) != NGX_OK)
        {
            BRIX_RETURN_ERR(ctx, c, BRIX_OP_STATX, "STATX", reqpath_buf,
                              "-", kXR_NotAuthorized, "permission denied");
        }
        if (brix_stat_beneath(conf->rootfd, reqpath_buf, &st) != 0) {
            /* Follow fallback for an in-export symlink with a host-ABSOLUTE
             * target (RESOLVE_IN_ROOT chroots it to ENOENT; stock follows on the
             * real fs).  Match stock, confined via realpath within the export. */
            int       ok = 0;
            if (errno == ENOENT && conf->common.root_canon[0] != '\0') {
                char   real[PATH_MAX];
                size_t rl = ngx_strlen(conf->common.root_canon);
                if (realpath(full_path, real) != NULL
                    && ngx_strncmp(real, conf->common.root_canon, rl) == 0
                    && (real[rl] == '/' || real[rl] == '\0'))
                {
                    /* Canonical target confirmed within the export root; read
                     * its metadata through the VFS (chain already resolved). */
                    brix_vfs_ctx_t  rvctx;
                    brix_vfs_stat_t rvst;

                    brix_vfs_ctx_init(&rvctx, c->pool, c->log,
                        BRIX_PROTO_ROOT, conf->common.root_canon, NULL,
                        conf->common.allow_write, 0 /* is_tls */, NULL, real);
                    if (brix_vfs_probe(&rvctx, 0 /* follow */, &rvst)
                        == NGX_OK)
                    {
                        brix_vfs_to_struct_stat(&rvst, &st);
                        ok = 1;
                    }
                }
            }
            if (!ok) {
                BRIX_RETURN_ERR(ctx, c, BRIX_OP_STATX, "STATX", reqpath_buf,
                                  "-", brix_kxr_from_errno(errno),
                                  strerror(errno));
            }
        }

        {
            /* One flag byte per path. The reference do_Statx emits ONLY
             * kXR_isDir or kXR_file (plus kXR_offline for a tape-staged file via
             * the FRM probe below) — there is NO kXR_other in statx, so a FIFO /
             * socket / device stats as kXR_file(0), exactly as stock. (Plain
             * kXR_stat does use kXR_other; statx deliberately does not.) */
            u_char flag;

            if (S_ISDIR(st.st_mode)) {
                flag = (u_char) kXR_isDir;
            } else {
                flag = (u_char) kXR_file;          /* 0 — incl. non-regular */
            }
            {
                brix_vfs_ctx_t      _rvc;
                brix_sd_residency_t _res;

                brix_vfs_ctx_init(&_rvc, c->pool, c->log, BRIX_PROTO_ROOT,
                    conf->common.root_canon, NULL, conf->common.allow_write,
                    0 /* is_tls */, NULL, full_path);
                if (brix_vfs_residency(&_rvc, &_res, NULL) == NGX_OK
                    && (_res == BRIX_SD_RES_NEARLINE
                        || _res == BRIX_SD_RES_OFFLINE))
                {
                    flag |= (u_char) kXR_offline;
                }
            }
            *rsp_ptr++ = flag;
        }
    }

    {
        char detail[32];

        snprintf(detail, sizeof(detail), "%d_paths", n_paths);
        brix_log_access(ctx, c, "STATX", "-", detail, 1, 0, NULL, 0);
    }
    BRIX_OP_OK(ctx, BRIX_OP_STATX);

    return brix_send_ok(ctx, c, rsp_buf,
                          (uint32_t)((size_t)(rsp_ptr - rsp_buf)));
}
