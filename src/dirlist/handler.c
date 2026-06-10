/*
 * Directory listing handler — implements the kXR_dirlist operation.
 * Clients request a directory listing and receive entries as newline-delimited
 * text, optionally with per-entry stat information and checksum tokens.
 * The response is sent in 64KB chunks using kXR_oksofar continuation frames,
 * ending with a single kXR_ok frame to signal completion.
 */

#include "../ngx_xrootd_module.h"
#include "../aio/aio.h"
#include "../manager/registry.h"
#include "dcksm.h"

/*
 * xrootd_dirlist_name_is_unsafe — detect control characters in a directory
 * entry name that would corrupt the newline-delimited kXR_dirlist wire format.
 *
 * The XRootD dirlist response separates entries with '\n'.  A filename
 * containing '\n' (or any other byte < 0x20) would be misinterpreted as a
 * record separator by the client.  Such filenames are skipped silently.
 *
 * Returns 1 (unsafe, skip this entry), 0 (safe to include).
 */
static ngx_flag_t
xrootd_dirlist_name_is_unsafe(const char *name)
{
    const u_char *p;

    for (p = (const u_char *) name; *p != '\0'; p++) {
        if (*p < 0x20 || *p == 0x7f) {
            return 1;
        }
    }

    return 0;
}

/*
 * xrootd_handle_dirlist — handle kXR_dirlist: enumerate a directory and send
 * the entries as a multi-frame kXR_oksofar ... kXR_ok response.
 *
 * Wire format (ClientDirlistRequest):
 *   options: bitfield controlling response content:
 *     kXR_dstat  (0x01) — include per-entry stat info
 *     kXR_dcksm  (0x02) — include per-entry checksum (implies kXR_dstat)
 *   payload: NUL-terminated path, optionally followed by CGI "?cks.type=algo"
 *
 * Response format: a flat text block with one entry per line, each terminated
 * by '\n'.  If kXR_dstat is set, each entry is followed by a stat body
 * (stat-line format: "f|d|p flags mtime size").  Entries with control
 * characters in their names are silently skipped to prevent wire corruption.
 *
 * A 65536-byte chunk buffer is accumulated and flushed as kXR_oksofar frames;
 * the final flush uses kXR_ok to signal end-of-listing.
 */
ngx_int_t
xrootd_handle_dirlist(xrootd_ctx_t *ctx, ngx_connection_t *c,
                      ngx_stream_xrootd_srv_conf_t *conf)
{
    ClientDirlistRequest *req = (ClientDirlistRequest *) ctx->hdr_buf;
    u_char                options;
    char                  resolved[PATH_MAX];
    char                  reqpath[XROOTD_MAX_PATH + 1];
    DIR                  *dp;
    struct dirent        *de;
    ngx_flag_t            want_stat;
    u_char               *chunk;
    size_t                chunk_cap = 65536;
    size_t                chunk_pos = 0;
    char                  statbuf[256];
    char                  cksum_algo[32];
    char                  bad_algo[32];
    ngx_int_t             rc;
    ngx_flag_t            want_cksum;
    int                   dfd;

/* ------------------------------------------------------------------ */
/* Section: Request Parsing & Auth Checks                              */
/* ------------------------------------------------------------------ */

    options = req->options;
    want_cksum = (options & kXR_dcksm) ? 1 : 0;
    want_stat = (options & (kXR_dstat | kXR_dcksm)) ? 1 : 0;

    if (ctx->payload == NULL || ctx->cur_dlen == 0) {
        xrootd_log_access(ctx, c, "DIRLIST", "-", "-",
                          0, kXR_ArgMissing, "no path given", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_DIRLIST);
        return xrootd_send_error(ctx, c, kXR_ArgMissing, "no path given");
    }

    if (want_cksum
        && xrootd_dirlist_checksum_algorithm(ctx->payload, ctx->cur_dlen,
                                             cksum_algo, sizeof(cksum_algo),
                                             bad_algo, sizeof(bad_algo))
           != NGX_OK)
    {
        char errmsg[128];

        snprintf(errmsg, sizeof(errmsg), "%s checksum not supported.",
                 bad_algo[0] ? bad_algo : "requested");
        xrootd_log_access(ctx, c, "DIRLIST", "-", "dcksm",
                          0, kXR_ServerError, errmsg, 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_DIRLIST);
        return xrootd_send_error(ctx, c, kXR_ServerError, errmsg);
    }

    if (!want_cksum) {
        ngx_cpystrn((u_char *) cksum_algo, (u_char *) "adler32",
                    sizeof(cksum_algo));
    }

    if (!xrootd_extract_path(c->log, ctx->payload, ctx->cur_dlen,
                             reqpath, sizeof(reqpath), 1)) {
        xrootd_log_access(ctx, c, "DIRLIST", "-", "-",
                          0, kXR_ArgInvalid, "invalid path payload", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_DIRLIST);
        return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                 "invalid path payload");
    }

    /* Manager mode: redirect dirlist to a registered data server. */
    if (conf->manager_mode) {
        char     redir_host[256];
        uint16_t redir_port;

        if (xrootd_srv_select(reqpath, 0, redir_host,
                              sizeof(redir_host), &redir_port)) {
            xrootd_log_access(ctx, c, "DIRLIST", reqpath, "registry",
                              1, 0, NULL, 0);
            XROOTD_OP_OK(ctx, XROOTD_OP_DIRLIST);
            return xrootd_send_redirect(ctx, c, redir_host, redir_port);
        }
        XROOTD_OP_ERR(ctx, XROOTD_OP_DIRLIST);
        return xrootd_send_error(ctx, c, kXR_Overloaded,
                                 "no data server available");
    }

    if (!xrootd_resolve_path(c->log, &conf->common.root,
                             reqpath, resolved, sizeof(resolved))) {
        xrootd_log_access(ctx, c, "DIRLIST", reqpath, "-",
                          0, kXR_NotFound, "directory not found", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_DIRLIST);
        return xrootd_send_error(ctx, c, kXR_NotFound, "directory not found");
    }

    if (xrootd_check_authdb(ctx, resolved, XROOTD_AUTH_LOOKUP) != NGX_OK) {
        xrootd_log_access(ctx, c, "DIRLIST", resolved, "-",
                          0, kXR_NotAuthorized, "authdb denied", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_DIRLIST);
        return xrootd_send_error(ctx, c, kXR_NotAuthorized, "not authorized");
    }

    if (xrootd_check_vo_acl_identity(c->log, resolved, conf->vo_rules,
                                     ctx->identity) != NGX_OK) {
        xrootd_log_access(ctx, c, "DIRLIST", resolved, "-",
                          0, kXR_NotAuthorized, "VO not authorized", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_DIRLIST);
        return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                 "VO not authorized");
    }

    if (xrootd_check_token_scope(ctx, reqpath, 0) != NGX_OK) {
        xrootd_log_access(ctx, c, "DIRLIST", reqpath, "-",
                          0, kXR_NotAuthorized, "token scope denied", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_DIRLIST);
        return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                 "token scope denied");
    }

    /*
     * Offload directory iteration + checksum computation to the nginx thread
     * pool so the event loop is not blocked during fstatat / hash-on-miss.
     *
     * If the pool is not configured or is full, xrootd_aio_post_task() returns
     * posted=0 and we fall through to the synchronous path below.
     */
    /*
     * Keep kXR_dirlist on the synchronous path for now.  The AIO variant can
     * complete successfully without delivering a response frame to clients,
     * which wedges xrdfs readiness probes in one-worker test deployments.
     */
    if (0 && conf->common.thread_pool != NULL) {
        ngx_thread_task_t    *task;
        xrootd_dirlist_aio_t *t;
        ngx_flag_t            posted;
        u_char               *response_buf;

        response_buf = ngx_palloc(c->pool, XROOTD_DIRLIST_AIO_RESPONSE_MAX);
        if (response_buf == NULL) {
            return NGX_ERROR;
        }

        task = ngx_thread_task_alloc(c->pool, sizeof(xrootd_dirlist_aio_t));
        if (task == NULL) {
            return NGX_ERROR;
        }

        t = task->ctx;
        t->c            = c;
        t->ctx          = ctx;
        t->conf         = conf;
        t->streamid[0]  = ctx->cur_streamid[0];
        t->streamid[1]  = ctx->cur_streamid[1];
        t->want_stat    = want_stat;
        t->want_cksum   = want_cksum;
        t->response     = response_buf;
        t->response_cap = XROOTD_DIRLIST_AIO_RESPONSE_MAX;
        t->response_len = 0;
        t->io_errno     = 0;
        t->err_msg[0]   = '\0';
        ngx_cpystrn((u_char *) t->resolved,
                    (u_char *) resolved, sizeof(t->resolved));
        ngx_cpystrn((u_char *) t->cksum_algo,
                    (u_char *) cksum_algo, sizeof(t->cksum_algo));

        task->handler         = xrootd_dirlist_aio_thread;
        task->event.handler   = xrootd_dirlist_aio_done;
        task->event.data      = task;

        if (xrootd_aio_post_task(ctx, c, conf->common.thread_pool, task,
                "xrootd: dirlist thread pool full, running synchronously",
                &posted) != NGX_OK)
        {
            return NGX_ERROR;
        }

        if (posted) {
            return NGX_OK;
        }

        /* Pool queue was full — fall through to the synchronous path. */
    }

/* ------------------------------------------------------------------ */
/* Section: Directory Open & Iteration                                 */
/* ------------------------------------------------------------------ */

    dfd = xrootd_open_confined(c->log, &conf->common.root, resolved,
                               O_RDONLY | O_DIRECTORY, 0);
    if (dfd < 0) {
        int err = errno;

        if (err == ENOTDIR) {
            xrootd_log_access(ctx, c, "DIRLIST", resolved, "-",
                              0, kXR_NotFile, "path is not a directory", 0);
            XROOTD_OP_ERR(ctx, XROOTD_OP_DIRLIST);
            return xrootd_send_error(ctx, c, kXR_NotFile,
                                     "path is not a directory");
        }
        if (err == ENOENT) {
            xrootd_log_access(ctx, c, "DIRLIST", resolved, "-",
                              0, kXR_NotFound, "directory not found", 0);
            XROOTD_OP_ERR(ctx, XROOTD_OP_DIRLIST);
            return xrootd_send_error(ctx, c, kXR_NotFound,
                                     "directory not found");
        }
        xrootd_log_access(ctx, c, "DIRLIST", resolved, "-",
                          0, kXR_IOError, strerror(err), 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_DIRLIST);
        return xrootd_send_error(ctx, c, kXR_IOError, strerror(err));
    }

    dp = fdopendir(dfd);
    if (dp == NULL) {
        int err = errno;

        close(dfd);
        xrootd_log_access(ctx, c, "DIRLIST", resolved, "-",
                          0, kXR_IOError, strerror(err), 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_DIRLIST);
        return xrootd_send_error(ctx, c, kXR_IOError, strerror(err));
    }

    /* Guard against pool exhaustion from a flood of dirlist calls. */
    if (ctx->pool_bytes_used + XRD_RESPONSE_HDR_LEN + chunk_cap
            > XROOTD_MAX_CONN_POOL_BYTES)
    {
        closedir(dp);
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "xrootd: dirlist pool limit reached (%uz bytes), "
                      "closing connection", ctx->pool_bytes_used);
        return xrootd_send_error(ctx, c, kXR_NoMemory,
                                 "connection pool limit exceeded");
    }
    chunk = ngx_palloc(c->pool, XRD_RESPONSE_HDR_LEN + chunk_cap);
    if (chunk == NULL) {
        closedir(dp);
        return NGX_ERROR;
    }
    ctx->pool_bytes_used += XRD_RESPONSE_HDR_LEN + chunk_cap;

    {
        u_char *data = chunk + XRD_RESPONSE_HDR_LEN;

        if (want_stat) {
            static const char dstat_leadin[] = ".\n0 0 0 0\n";

            ngx_memcpy(data, dstat_leadin, 10);
            chunk_pos = 10;
        }

/* ------------------------------------------------------------------ */
/* Section: Chunked Response Framing                                   */
/* ------------------------------------------------------------------ */

        while ((de = readdir(dp)) != NULL) {
            const char *name = de->d_name;
            size_t      nlen = strlen(name);
            char        safe_name[256];
            size_t      need = nlen + 1;
            struct stat entry_st;
            ngx_flag_t  have_stat = 0;
            char        cksum_token[EVP_MAX_MD_SIZE * 2 + 64];
            char        entry_path[PATH_MAX];

            cksum_token[0] = '\0';

            if (name[0] == '.' && (name[1] == '\0' ||
                (name[1] == '.' && name[2] == '\0')))
            {
                continue;
            }

            if (xrootd_dirlist_name_is_unsafe(name)) {
                xrootd_sanitize_log_string(name, safe_name, sizeof(safe_name));
                ngx_log_error(NGX_LOG_WARN, c->log, 0,
                              "xrootd: dirlist skipping entry with control bytes \"%s\"",
                              safe_name);
                continue;
            }

            if (want_stat) {
                if (fstatat(dirfd(dp), name, &entry_st, AT_SYMLINK_NOFOLLOW) != 0) {
                    if (errno != ENOENT) {
                        xrootd_sanitize_log_string(name, safe_name,
                                                   sizeof(safe_name));
                        ngx_log_error(NGX_LOG_WARN, c->log, errno,
                                      "xrootd: dirlist stat failed for \"%s\"",
                                      safe_name);
                    }
                    continue;
                }

                have_stat = 1;
                if (want_cksum) {
                    xrootd_dirlist_make_dcksm_stat_body(&entry_st, statbuf,
                                                        sizeof(statbuf));
                } else {
                    xrootd_make_stat_body(&entry_st, 0, 0, statbuf,
                                          sizeof(statbuf));
                }
                need += strlen(statbuf) + 1;
            }

            if (want_cksum && have_stat) {
                int n;

                n = snprintf(entry_path, sizeof(entry_path), "%s/%s",
                             resolved, name);
                if (n < 0 || (size_t) n >= sizeof(entry_path)) {
                    snprintf(cksum_token, sizeof(cksum_token),
                             "%s:none", cksum_algo);
                } else {
                    xrootd_dirlist_checksum_token(c->log, dirfd(dp), name,
                                                  entry_path, &entry_st,
                                                  cksum_algo, cksum_token,
                                                  sizeof(cksum_token));
                }
                need += strlen(cksum_token) + sizeof(" [  ]") - 1;
            }

            if (chunk_pos + need > chunk_cap) {
                xrootd_build_resp_hdr(ctx->cur_streamid, kXR_oksofar,
                                      (uint32_t) chunk_pos,
                                      (ServerResponseHdr *) chunk);

                rc = xrootd_queue_response(ctx, c, chunk,
                                           XRD_RESPONSE_HDR_LEN + chunk_pos);
                if (rc != NGX_OK) {
                    closedir(dp);
                    return rc;
                }

                chunk_pos = 0;
            }

            ngx_memcpy(data + chunk_pos, name, nlen);
            chunk_pos += nlen;
            data[chunk_pos++] = '\n';

            if (want_stat && have_stat) {
                size_t slen;

                slen = strlen(statbuf);
                ngx_memcpy(data + chunk_pos, statbuf, slen);
                chunk_pos += slen;

                if (want_cksum) {
                    int n;

                    n = snprintf((char *) data + chunk_pos,
                                 chunk_cap - chunk_pos,
                                 " [ %s ]", cksum_token);
                    if (n > 0) {
                        chunk_pos += (size_t) n;
                    }
                }

                data[chunk_pos++] = '\n';
            }
        }

/* ------------------------------------------------------------------ */
/* Section: Final Flush & Completion                                   */
/* ------------------------------------------------------------------ */

        closedir(dp);

        {
            size_t final_len;

            if (chunk_pos == 0) {
                final_len = 0;
            } else {
                data[chunk_pos - 1] = '\0';
                final_len = chunk_pos;
            }

            xrootd_build_resp_hdr(ctx->cur_streamid, kXR_ok,
                                  (uint32_t) final_len,
                                  (ServerResponseHdr *) chunk);

            ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                           "xrootd: kXR_dirlist final chunk %uz bytes", chunk_pos);

            xrootd_log_access(ctx, c, "DIRLIST", resolved,
                              want_cksum ? "dcksm" : (want_stat ? "stat" : "-"),
                              1, 0, NULL, 0);
            XROOTD_OP_OK(ctx, XROOTD_OP_DIRLIST);

            return xrootd_queue_response(ctx, c, chunk,
                                         XRD_RESPONSE_HDR_LEN + final_len);
        }
    }
}
