#include "../ngx_xrootd_module.h"
#include "stat.h"
#include "../manager/registry.h"
#include "../manager/pending.h"
#include "../cms/cms_internal.h"
#include <string.h>

/* Return kXR_cachersp if reqpath (client's clean path) exists in cache_root. */
int
xrootd_cache_path_flag(const ngx_stream_xrootd_srv_conf_t *conf, const char *reqpath)
{
    char        cache_path[PATH_MAX];
    struct stat cst;
    int         n;

    if (!conf->cache || conf->cache_root.len == 0 || reqpath == NULL) {
        return 0;
    }

    n = snprintf(cache_path, sizeof(cache_path), "%s%s",
                 (char *) conf->cache_root.data, reqpath);
    if (n < 0 || (size_t) n >= sizeof(cache_path)) {
        return 0;
    }

    return (stat(cache_path, &cst) == 0 && S_ISREG(cst.st_mode))
           ? kXR_cachersp : 0;
}

ngx_int_t xrootd_handle_stat(xrootd_ctx_t *ctx, ngx_connection_t *c, ngx_stream_xrootd_srv_conf_t *conf)
{
    ClientStatRequest *req = (ClientStatRequest *) ctx->hdr_buf;
    struct stat        st;
    char               full_path[PATH_MAX];
    char               reqpath_buf[XROOTD_MAX_PATH + 1];
    char               body[256];
    ngx_flag_t         is_vfs;
    const char        *reqpath = NULL;
    ngx_int_t          validate_rc;
    int                extra_flags = 0;

    is_vfs = (req->options & kXR_vfs) ? 1 : 0;

    /*
     * kXR_stat is dual-mode like upstream XRootD:
     *   - dlen > 0 means the payload names a path to resolve and stat(2)
     *   - dlen == 0 means the opaque handle identifies an already-open fd
     *
     * The logging path and the syscall target are deliberately separated in the
     * handle case: logs use the cached canonical path, while fstat() uses the fd.
     */

    if (ctx->cur_dlen > 0 && ctx->payload != NULL) {
        /* Path-based stat */
        if (!xrootd_extract_path(c->log, ctx->payload, ctx->cur_dlen,
                                 reqpath_buf, sizeof(reqpath_buf), 1)) {
            XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_STAT, "STAT", "-", "-",
                              kXR_ArgInvalid, "invalid path payload");
        }
        reqpath = reqpath_buf;
        /* Manager mode: redirect to a registered data server. */
        if (conf->manager_mode) {
            char     redir_host[256];
            uint16_t redir_port;

            /* tried/triedrc: if the client has already visited every server
             * that holds this path and they returned enoent, stop redirecting
             * and answer not-found — otherwise the client redirect-loops. */
            if (xrootd_manager_tried_exhausted(ctx->payload, ctx->cur_dlen,
                                               reqpath)) {
                XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_STAT, "STAT", reqpath, "-",
                                  kXR_NotFound,
                                  "file not found on any data server");
            }

            if (xrootd_srv_select(reqpath, 0, redir_host,
                                  sizeof(redir_host), &redir_port)) {
                XROOTD_RETURN_REDIR(ctx, c, XROOTD_OP_STAT, "STAT",
                                    reqpath, "registry",
                                    redir_host, redir_port);
            }

            /* Registry miss — ask CMS parent if configured. */
            if (conf->cms_ctx != NULL) {
                uint32_t streamid;

                streamid = ngx_xrootd_cms_next_streamid(conf->cms_ctx);
                if (xrootd_pending_insert(streamid, ngx_pid, c->fd,
                                          c->number,
                                          ctx->cur_streamid,
                                          conf->cms_locate_timeout) == NGX_OK)
                {
                    ctx->cms_wait_streamid = streamid;
                    ctx->state = XRD_ST_WAITING_CMS;
                    ngx_add_timer(c->read, conf->cms_locate_timeout);
                    if (ngx_xrootd_cms_send_locate(conf->cms_ctx, streamid,
                                                   reqpath) == NGX_OK)
                    {
                        return NGX_AGAIN;
                    }
                    ngx_del_timer(c->read);
                    ctx->state = XRD_ST_REQ_HEADER;
                    xrootd_pending_remove(streamid, ngx_pid);
                }
            }
        }

        xrootd_beneath_full_path(conf->common.root_canon, reqpath,
                                  full_path, sizeof(full_path));

        if (xrootd_auth_gate(ctx, c, XROOTD_OP_STAT, "STAT",
                              reqpath, full_path, conf,
                              XROOTD_AUTH_LOOKUP, 0) != NGX_OK) {
            return ctx->write_rc;
        }

        if (xrootd_stat_beneath(conf->rootfd, reqpath, &st) != 0) {
            XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_STAT, "STAT", reqpath, "-",
                              xrootd_kxr_from_errno(errno),
                              strerror(errno));
        }

        extra_flags = xrootd_cache_path_flag(conf, reqpath);

    } else {
        /* Handle-based stat: fhandle[0] is our slot index. */
        /* The cached path is only for logging; the real metadata comes from fstat(). */
        int idx = (int)(unsigned char) req->fhandle[0];

        if (!xrootd_validate_file_handle(ctx, c, idx, "STAT",
                                         XROOTD_OP_STAT, &validate_rc)) {
            return validate_rc;
        }

        full_path[0] = '\0';
        ngx_cpystrn((u_char *) full_path,
                    (u_char *) (ctx->files[idx].path != NULL
                                ? ctx->files[idx].path : "-"),
                    sizeof(full_path));

        if (ctx->files[idx].slice_mode) {
            /*
             * Slice-mode handles park their fd on /dev/null (Phase 26), so
             * fstat() would report size 0.  The real file size was learned
             * from the origin at open time and stored in cached_size; synthesize
             * a regular-file stat from it so the client sees the true length.
             */
            ngx_memzero(&st, sizeof(st));
            st.st_mode = S_IFREG | 0644;
            st.st_size = (off_t) ctx->files[idx].cached_size;
            st.st_nlink = 1;
            st.st_mtime = ngx_time();
        } else if (fstat(ctx->files[idx].fd, &st) != 0) {
            XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_STAT, "STAT", full_path, "-",
                              kXR_IOError, strerror(errno));
        }

        extra_flags = (ctx->files[idx].from_cache || ctx->files[idx].slice_mode)
                          ? kXR_cachersp : 0;
    }

    /* Convert the host stat struct into the exact ASCII body the client expects. */
    xrootd_make_stat_body(&st, is_vfs, extra_flags, body, sizeof(body));

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: kXR_stat ok: %s", body);

    xrootd_log_access(ctx, c, "STAT",
                      (reqpath && reqpath[0]) ? reqpath : full_path,
                      is_vfs ? "vfs" : "-",
                      1, 0, NULL, 0);
    XROOTD_OP_OK(ctx, XROOTD_OP_STAT);

    return xrootd_send_ok(ctx, c, body, (uint32_t)(strlen(body) + 1));
}
