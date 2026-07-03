/*
 * Directory listing handler — implements the kXR_dirlist operation.
 * Clients request a directory listing and receive entries as newline-delimited
 * text, optionally with per-entry stat information and checksum tokens.
 * The response is sent in 64KB chunks using kXR_oksofar continuation frames,
 * ending with a single kXR_ok frame to signal completion.
 */

#include "core/ngx_brix_module.h"
#include "core/aio/aio.h"
#include "protocols/root/path/op_path.h"
#include "net/manager/registry.h"
#include "protocols/root/protocol/dirlist_fmt.h"   /* shared dstat lead-in sentinel */
#include "fs/vfs/vfs.h"                 /* directory listing via the VFS seam */
#include "dcksm.h"

#include <spawn.h>
#include <sys/wait.h>
#include "core/compat/alloc_guard.h"

extern char **environ;

/*
 * brix_dirlist_name_is_unsafe — detect control characters in a directory
 * entry name that would corrupt the newline-delimited kXR_dirlist wire format.
 *
 * The XRootD dirlist response separates entries with '\n'.  A filename
 * containing '\n' (or any other byte < 0x20) would be misinterpreted as a
 * record separator by the client.  Such filenames are skipped silently.
 *
 * Returns 1 (unsafe, skip this entry), 0 (safe to include).
 */
static ngx_flag_t
brix_dirlist_name_is_unsafe(const char *name)
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
 * brix_handle_dirlist — handle kXR_dirlist: enumerate a directory and send
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
/* §14 (phase-64): the fork/exec `xrdfs <origin> ls` namespace forward for a
 * legacy cache_origin GSI cache is RETIRED with the cache_origin config model —
 * a tier cache lists through the composed backend driver's opendir/readdir. */

ngx_int_t
brix_handle_dirlist(brix_ctx_t *ctx, ngx_connection_t *c,
                      ngx_stream_brix_srv_conf_t *conf)
{
    xrdw_dirlist_req_t    req;
    u_char                options;
    char                  full_path[PATH_MAX];
    char                  reqpath[BRIX_MAX_PATH + 1];
    brix_vfs_ctx_t      vctx;
    brix_vfs_dir_t     *dh;
    ngx_str_t             entry_name;
    brix_vfs_stat_t     entry_vst;
    ngx_flag_t            want_stat;
    u_char               *chunk;
    size_t                chunk_cap = 65536;
    size_t                chunk_pos = 0;
    char                  statbuf[256];
    char                  cksum_algo[32];
    char                  bad_algo[32];
    ngx_int_t             rc;
    ngx_flag_t            want_cksum;


    xrdw_dirlist_req_unpack(((ClientRequestHdr *) ctx->hdr_buf)->body, &req);
    options = req.options;
    want_cksum = (options & kXR_dcksm) ? 1 : 0;
    want_stat = (options & (kXR_dstat | kXR_dcksm)) ? 1 : 0;

    if (ctx->payload == NULL || ctx->cur_dlen == 0) {
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_DIRLIST, "DIRLIST", "-", "-",
                          kXR_ArgMissing, "no path given");
    }

    if (want_cksum
        && brix_dirlist_checksum_algorithm(ctx->payload, ctx->cur_dlen,
                                             cksum_algo, sizeof(cksum_algo),
                                             bad_algo, sizeof(bad_algo))
           != NGX_OK)
    {
        char errmsg[128];

        snprintf(errmsg, sizeof(errmsg), "%s checksum not supported.",
                 bad_algo[0] ? bad_algo : "requested");
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_DIRLIST, "DIRLIST", "-", "dcksm",
                          kXR_ServerError, errmsg);
    }

    if (!want_cksum) {
        ngx_cpystrn((u_char *) cksum_algo, (u_char *) "adler32",
                    sizeof(cksum_algo));
    }

    if (!brix_extract_path(c->log, ctx->payload, ctx->cur_dlen,
                             reqpath, sizeof(reqpath), 1)) {
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_DIRLIST, "DIRLIST", "-", "-",
                          kXR_ArgInvalid, "invalid path payload");
    }

    /* Reject any ".." component (the reference does not normalize ".."); dirlist
     * resolves through the kernel RESOLVE_BENEATH which would collapse it. */
    if (brix_reject_dotdot_path(ctx, c, BRIX_OP_DIRLIST, "DIRLIST",
                                  reqpath)) {
        return ctx->write_rc;
    }

    /* Static manager_map: explicit prefix→backend redirect (mirrors open/stat),
     * so a static-map redirector serves dirlist too (go-hep ls = stat + dirlist). */
    if (conf->manager_map != NULL) {
        const brix_manager_map_t *m =
            brix_find_manager_map(reqpath, conf->manager_map);
        if (m != NULL) {
            BRIX_RETURN_REDIR(ctx, c, BRIX_OP_DIRLIST, "DIRLIST", reqpath,
                                "manager_map",
                                (const char *) m->host.data, m->port);
        }
    }

    /* Manager mode: redirect dirlist to a registered data server. */
    if (conf->manager_mode) {
        char     redir_host[256];
        uint16_t redir_port;

        if (brix_srv_select(reqpath, 0, redir_host,
                              sizeof(redir_host), &redir_port)) {
            BRIX_RETURN_REDIR(ctx, c, BRIX_OP_DIRLIST, "DIRLIST", reqpath,
                                "registry", redir_host, redir_port);
        }
        BRIX_OP_ERR(ctx, BRIX_OP_DIRLIST);
        return brix_send_error(ctx, c, kXR_Overloaded,
                                 "no data server available");
    }

    brix_beneath_full_path(conf->common.root_canon, reqpath,
                             full_path, sizeof(full_path));

    if (brix_auth_gate(ctx, c, BRIX_OP_DIRLIST, "DIRLIST",
                          reqpath, full_path, conf,
                          BRIX_AUTH_LOOKUP, 0) != NGX_OK) {
        return ctx->write_rc;
    }

    /*
     * Synchronous dirlist via the VFS seam: brix_vfs_opendir is
     * impersonation-aware (broker fdopendir as the mapped user) and
     * brix_vfs_readdir yields each name with an optional no-follow lstat. (The
     * thread-pool AIO variant in aio/dirlist.c is currently disabled — it could
     * complete without delivering a response frame, wedging xrdfs probes — so the
     * request path stays synchronous.)
     */
    {
        int err = 0;

        brix_vfs_ctx_init(&vctx, c->pool, c->log, BRIX_PROTO_ROOT,
            conf->common.root_canon, NULL, 0 /* allow_write */, 0 /* is_tls */,
            NULL, full_path);
        dh = brix_vfs_opendir(&vctx, &err);
        if (dh == NULL) {
            if (err == ENOTDIR) {
                BRIX_RETURN_ERR(ctx, c, BRIX_OP_DIRLIST, "DIRLIST", reqpath,
                                  "-", kXR_NotFile, "path is not a directory");
            }
            if (err == ENOENT) {
                BRIX_RETURN_ERR(ctx, c, BRIX_OP_DIRLIST, "DIRLIST", reqpath,
                                  "-", kXR_NotFound, "directory not found");
            }
            BRIX_RETURN_ERR(ctx, c, BRIX_OP_DIRLIST, "DIRLIST", reqpath,
                              "-", kXR_IOError, strerror(err));
        }
    }

    /* Guard against pool exhaustion from a flood of dirlist calls. */
    if (ctx->pool_bytes_used + XRD_RESPONSE_HDR_LEN + chunk_cap
            > BRIX_MAX_CONN_POOL_BYTES)
    {
        brix_vfs_closedir(dh, c->log);
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "brix: dirlist pool limit reached (%uz bytes), "
                      "closing connection", ctx->pool_bytes_used);
        return brix_send_error(ctx, c, kXR_NoMemory,
                                 "connection pool limit exceeded");
    }
    chunk = ngx_palloc(c->pool, XRD_RESPONSE_HDR_LEN + chunk_cap);
    if (chunk == NULL) {
        brix_vfs_closedir(dh, c->log);
        return NGX_ERROR;
    }
    ctx->pool_bytes_used += XRD_RESPONSE_HDR_LEN + chunk_cap;

    {
        u_char *data = chunk + XRD_RESPONSE_HDR_LEN;

        if (want_stat) {
            ngx_memcpy(data, BRIX_DSTAT_LEADIN, BRIX_DSTAT_LEADIN_LEN);
            chunk_pos = BRIX_DSTAT_LEADIN_LEN;
        }


        while (brix_vfs_readdir(dh, &entry_name,
                                  want_stat ? &entry_vst : NULL) == NGX_OK) {
            const char *name = (char *) entry_name.data;
            size_t      nlen = entry_name.len;
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

            /* Hide this gateway's internal control artifacts (e.g. the
             * checkpoint recovery lock) — a stock XRootD export shows no such
             * files; mirror that. */
            if (ngx_strncmp(name, ".nginx-xrootd",
                            sizeof(".nginx-xrootd") - 1) == 0)
            {
                continue;
            }

            if (brix_dirlist_name_is_unsafe(name)) {
                brix_sanitize_log_string(name, safe_name, sizeof(safe_name));
                ngx_log_error(NGX_LOG_WARN, c->log, 0,
                              "brix: dirlist skipping entry with control bytes \"%s\"",
                              safe_name);
                continue;
            }

            if (want_stat) {
                /* readdir already did the no-follow lstat (and skipped any entry
                 * whose stat failed), so entry_vst is valid here. */
                ngx_memzero(&entry_st, sizeof(entry_st));
                entry_st.st_mode   = (mode_t) entry_vst.mode;
                entry_st.st_size   = entry_vst.size;
                entry_st.st_mtime  = entry_vst.mtime;
                entry_st.st_ctime  = entry_vst.ctime;
                entry_st.st_ino    = entry_vst.ino;
                entry_st.st_dev    = entry_vst.dev;
                entry_st.st_uid    = entry_vst.uid;
                entry_st.st_gid    = entry_vst.gid;
                entry_st.st_blocks = entry_vst.blocks;

                have_stat = 1;
                if (want_cksum) {
                    brix_dirlist_make_dcksm_stat_body(&entry_st, statbuf,
                                                        sizeof(statbuf));
                } else {
                    brix_make_stat_body(&entry_st, 0, 0, statbuf,
                                          sizeof(statbuf));
                }
                need += strlen(statbuf) + 1;
            }

            if (want_cksum && have_stat) {
                int n;

                n = snprintf(entry_path, sizeof(entry_path), "%s/%s",
                             full_path, name);
                if (n < 0 || (size_t) n >= sizeof(entry_path)) {
                    snprintf(cksum_token, sizeof(cksum_token),
                             "%s:none", cksum_algo);
                } else {
                    brix_dirlist_checksum_token(c->log,
                                                  brix_vfs_dir_fd(dh), name,
                                                  entry_path, &entry_st,
                                                  cksum_algo, cksum_token,
                                                  sizeof(cksum_token));
                }
                need += strlen(cksum_token) + sizeof(" [  ]") - 1;
            }

            if (chunk_pos + need > chunk_cap) {
                brix_build_resp_hdr(ctx->cur_streamid, kXR_oksofar,
                                      (uint32_t) chunk_pos,
                                      (ServerResponseHdr *) chunk);

                rc = brix_queue_response(ctx, c, chunk,
                                           XRD_RESPONSE_HDR_LEN + chunk_pos);
                if (rc != NGX_OK) {
                    brix_vfs_closedir(dh, c->log);
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


        brix_vfs_closedir(dh, c->log);

        {
            size_t final_len;

            if (chunk_pos == 0) {
                final_len = 0;
            } else {
                data[chunk_pos - 1] = '\0';
                final_len = chunk_pos;
            }

            brix_build_resp_hdr(ctx->cur_streamid, kXR_ok,
                                  (uint32_t) final_len,
                                  (ServerResponseHdr *) chunk);

            ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                           "brix: kXR_dirlist final chunk %uz bytes", chunk_pos);

            brix_log_access(ctx, c, "DIRLIST", reqpath,
                              want_cksum ? "dcksm" : (want_stat ? "stat" : "-"),
                              1, 0, NULL, 0);
            BRIX_OP_OK(ctx, BRIX_OP_DIRLIST);

            return brix_queue_response(ctx, c, chunk,
                                         XRD_RESPONSE_HDR_LEN + final_len);
        }
    }
}
