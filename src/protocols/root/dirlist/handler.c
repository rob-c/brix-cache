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
#include "fs/path/reserved_names.h"     /* brix_is_internal_name — hide sidecars */
#include "dcksm.h"

#include <spawn.h>
#include <sys/wait.h>
#include "core/compat/alloc_guard.h"

extern char **environ;

/*
 * brix_dirlist_walk_t — per-request dirlist state threaded through the
 * decode → redirect → open → stream pipeline below.
 *
 * Groups the decoded request options, resolved paths, the open VFS directory
 * handle, and the 64KB chunk accumulator so each pipeline stage receives one
 * explicit state pointer instead of a parameter fan-out.
 */
typedef struct {
    u_char             options;                     /* raw kXR_dirlist options */
    ngx_flag_t         want_stat;                   /* kXR_dstat or kXR_dcksm */
    ngx_flag_t         want_cksum;                  /* kXR_dcksm */
    char               cksum_algo[32];              /* negotiated cksum algo */
    char               reqpath[BRIX_MAX_PATH + 1];  /* client-supplied path */
    char               full_path[PATH_MAX];         /* confined absolute path */
    brix_vfs_dir_t    *dh;                          /* open directory handle */
    u_char            *chunk;                       /* hdr + data accumulator */
    size_t             chunk_cap;                   /* data capacity (64KB) */
    size_t             chunk_pos;                   /* bytes accumulated */
} brix_dirlist_walk_t;

/*
 * brix_dirlist_entry_fmt_t — formatted per-entry output produced by
 * brix_dirlist_entry_meta and consumed by brix_dirlist_append_entry.
 *
 * Carries the rendered stat line, the optional checksum token, whether stat
 * data is valid for this entry, and the total wire bytes the entry needs so
 * the streaming loop can decide when to flush a kXR_oksofar chunk.
 */
typedef struct {
    char        statbuf[256];                        /* rendered stat line */
    char        cksum_token[EVP_MAX_MD_SIZE * 2 + 64]; /* "algo:hex" token */
    ngx_flag_t  have_stat;                           /* statbuf is valid */
    size_t      need;                                /* wire bytes required */
} brix_dirlist_entry_fmt_t;

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
 * brix_dirlist_parse_request — decode the ClientDirlistRequest into walk
 * state: option flags, checksum algorithm, and the validated request path.
 *
 * Rejects a missing path, an unsupported dcksm algorithm, an unparseable
 * path payload, and any ".." component (the reference does not normalize
 * ".."; dirlist resolves through the kernel RESOLVE_BENEATH which would
 * collapse it).
 *
 * Returns 1 to continue; 0 when a response was already sent (*rc set).
 */
static int
brix_dirlist_parse_request(brix_ctx_t *ctx, ngx_connection_t *c,
    brix_dirlist_walk_t *walk, ngx_int_t *rc)
{
    xrdw_dirlist_req_t  req;
    char                bad_algo[32];

    xrdw_dirlist_req_unpack(((ClientRequestHdr *) ctx->recv.hdr_buf)->body,
                            &req);
    walk->options = req.options;
    walk->want_cksum = (walk->options & kXR_dcksm) ? 1 : 0;
    walk->want_stat = (walk->options & (kXR_dstat | kXR_dcksm)) ? 1 : 0;

    if (ctx->recv.payload == NULL || ctx->recv.cur_dlen == 0) {
        BRIX_BAIL_ERR(ctx, c, BRIX_OP_DIRLIST, "DIRLIST", "-", "-",
                        kXR_ArgMissing, "no path given", rc);
    }

    if (walk->want_cksum
        && brix_dirlist_checksum_algorithm(ctx->recv.payload,
                                             ctx->recv.cur_dlen,
                                             walk->cksum_algo,
                                             sizeof(walk->cksum_algo),
                                             bad_algo, sizeof(bad_algo))
           != NGX_OK)
    {
        char errmsg[128];

        snprintf(errmsg, sizeof(errmsg), "%s checksum not supported.",
                 bad_algo[0] ? bad_algo : "requested");
        BRIX_BAIL_ERR(ctx, c, BRIX_OP_DIRLIST, "DIRLIST", "-", "dcksm",
                        kXR_ServerError, errmsg, rc);
    }

    if (!walk->want_cksum) {
        ngx_cpystrn((u_char *) walk->cksum_algo, (u_char *) "adler32",
                    sizeof(walk->cksum_algo));
    }

    if (!brix_extract_path(c->log, ctx->recv.payload, ctx->recv.cur_dlen,
                             walk->reqpath, sizeof(walk->reqpath), 1)) {
        BRIX_BAIL_ERR(ctx, c, BRIX_OP_DIRLIST, "DIRLIST", "-", "-",
                        kXR_ArgInvalid, "invalid path payload", rc);
    }

    if (brix_reject_dotdot_path(ctx, c, BRIX_OP_DIRLIST, "DIRLIST",
                                  walk->reqpath)) {
        *rc = ctx->write_rc;
        return 0;
    }

    return 1;
}

/*
 * brix_dirlist_check_redirect — apply the two cluster redirect modes before
 * touching local storage.
 *
 * Static manager_map: explicit prefix→backend redirect (mirrors open/stat),
 * so a static-map redirector serves dirlist too (go-hep ls = stat + dirlist).
 * Manager mode: redirect dirlist to a registered data server, or fail with
 * kXR_Overloaded when none is available.
 *
 * Returns 1 to continue serving locally; 0 when a response was already sent
 * (*rc set).
 */
static int
brix_dirlist_check_redirect(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, brix_dirlist_walk_t *walk,
    ngx_int_t *rc)
{
    if (conf->manager_map != NULL) {
        const brix_manager_map_t *m =
            brix_find_manager_map(walk->reqpath, conf->manager_map);
        if (m != NULL) {
            brix_log_access(ctx, c, "DIRLIST", walk->reqpath, "manager_map",
                              1, kXR_ok, NULL, 0);
            BRIX_OP_OK(ctx, BRIX_OP_DIRLIST);
            *rc = brix_send_redirect(ctx, c, (const char *) m->host.data,
                                       m->port);
            return 0;
        }
    }

    if (conf->manager_mode) {
        char     redir_host[256];
        uint16_t redir_port;

        if (brix_srv_select(walk->reqpath, 0, redir_host,
                              sizeof(redir_host), &redir_port)) {
            brix_log_access(ctx, c, "DIRLIST", walk->reqpath, "registry",
                              1, kXR_ok, NULL, 0);
            BRIX_OP_OK(ctx, BRIX_OP_DIRLIST);
            *rc = brix_send_redirect(ctx, c, redir_host, redir_port);
            return 0;
        }
        BRIX_OP_ERR(ctx, BRIX_OP_DIRLIST);
        *rc = brix_send_error(ctx, c, kXR_Overloaded,
                                "no data server available");
        return 0;
    }

    return 1;
}

/*
 * brix_dirlist_open_dir — confine the request path, run the authorization
 * gate, and open the directory through the VFS seam.
 *
 * Synchronous dirlist via the VFS seam: brix_vfs_opendir is
 * impersonation-aware (broker fdopendir as the mapped user) and
 * brix_vfs_readdir yields each name with an optional no-follow lstat. (The
 * thread-pool AIO variant in aio/dirlist.c is currently disabled — it could
 * complete without delivering a response frame, wedging xrdfs probes — so the
 * request path stays synchronous.)
 *
 * Returns 1 with walk->dh open; 0 when a response was already sent (*rc set).
 */
static int
brix_dirlist_open_dir(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, brix_dirlist_walk_t *walk,
    ngx_int_t *rc)
{
    brix_vfs_ctx_t  vctx;
    int             err = 0;

    brix_beneath_full_path(conf->common.root_canon, walk->reqpath,
                             walk->full_path, sizeof(walk->full_path));

    if (brix_auth_gate(ctx, c, BRIX_OP_DIRLIST, "DIRLIST",
                          walk->reqpath, walk->full_path, conf,
                          BRIX_AUTH_LOOKUP, 0) != NGX_OK) {
        *rc = ctx->write_rc;
        return 0;
    }

    brix_vfs_ctx_init(&vctx, c->pool, c->log, BRIX_PROTO_ROOT,
        conf->common.root_canon, NULL, 0 /* allow_write */, 0 /* is_tls */,
        ctx->identity, walk->full_path);
    brix_vfs_ctx_bind_backend_cred(&vctx,
        &conf->common.storage_credential_dir,
        conf->common.storage_credential_fallback);
    brix_root_vfs_bind_deleg(ctx, conf, &vctx);
    walk->dh = brix_vfs_opendir(&vctx, &err);
    if (walk->dh == NULL) {
        if (err == ENOTDIR) {
            BRIX_BAIL_ERR(ctx, c, BRIX_OP_DIRLIST, "DIRLIST", walk->reqpath,
                            "-", kXR_NotFile, "path is not a directory", rc);
        }
        if (err == ENOENT) {
            BRIX_BAIL_ERR(ctx, c, BRIX_OP_DIRLIST, "DIRLIST", walk->reqpath,
                            "-", kXR_NotFound, "directory not found", rc);
        }
        BRIX_BAIL_ERR(ctx, c, BRIX_OP_DIRLIST, "DIRLIST", walk->reqpath,
                        "-", kXR_IOError, strerror(err), rc);
    }

    return 1;
}

/*
 * brix_dirlist_alloc_chunk — allocate the header + 64KB chunk accumulator
 * and seed the optional dstat lead-in sentinel.
 *
 * Guards against pool exhaustion from a flood of dirlist calls before
 * charging the connection pool accounting; closes the directory handle on
 * any failure so the caller can return immediately.
 *
 * Returns 1 with walk->chunk ready; 0 when a response was already sent or
 * allocation failed (*rc set).
 */
static int
brix_dirlist_alloc_chunk(brix_ctx_t *ctx, ngx_connection_t *c,
    brix_dirlist_walk_t *walk, ngx_int_t *rc)
{
    if (ctx->login.pool_bytes_used + XRD_RESPONSE_HDR_LEN + walk->chunk_cap
            > BRIX_MAX_CONN_POOL_BYTES)
    {
        brix_vfs_closedir(walk->dh, c->log);
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "brix: dirlist pool limit reached (%uz bytes), "
                      "closing connection", ctx->login.pool_bytes_used);
        *rc = brix_send_error(ctx, c, kXR_NoMemory,
                                "connection pool limit exceeded");
        return 0;
    }
    walk->chunk = ngx_palloc(c->pool, XRD_RESPONSE_HDR_LEN + walk->chunk_cap);
    if (walk->chunk == NULL) {
        brix_vfs_closedir(walk->dh, c->log);
        *rc = NGX_ERROR;
        return 0;
    }
    ctx->login.pool_bytes_used += XRD_RESPONSE_HDR_LEN + walk->chunk_cap;

    if (walk->want_stat) {
        ngx_memcpy(walk->chunk + XRD_RESPONSE_HDR_LEN,
                   BRIX_DSTAT_LEADIN, BRIX_DSTAT_LEADIN_LEN);
        walk->chunk_pos = BRIX_DSTAT_LEADIN_LEN;
    }

    return 1;
}

/*
 * brix_dirlist_entry_skip — decide whether a directory entry must be
 * excluded from the listing.
 *
 * Skips "." and "..", this gateway's internal control artifacts (e.g. the
 * checkpoint recovery lock — a stock XRootD export shows no such files;
 * mirror that), internal metadata/staging artifacts (cache sidecars, stage
 * markers, in-flight upload temps — never enumerable to a client), and names
 * with control bytes that would corrupt the wire format (logged at WARN).
 *
 * Returns 1 (skip this entry), 0 (include it).
 */
static ngx_flag_t
brix_dirlist_entry_skip(ngx_log_t *log, const char *name)
{
    char safe_name[256];

    if (name[0] == '.' && (name[1] == '\0' ||
        (name[1] == '.' && name[2] == '\0')))
    {
        return 1;
    }

    if (ngx_strncmp(name, ".nginx-xrootd",
                    sizeof(".nginx-xrootd") - 1) == 0)
    {
        return 1;
    }

    if (brix_is_internal_name(name)) {
        return 1;
    }

    if (brix_dirlist_name_is_unsafe(name)) {
        brix_sanitize_log_string(name, safe_name, sizeof(safe_name));
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "brix: dirlist skipping entry with control bytes \"%s\"",
                      safe_name);
        return 1;
    }

    return 0;
}

/*
 * brix_dirlist_entry_meta — render the optional stat line and checksum
 * token for one entry, accumulating the wire bytes it needs into fmt->need.
 *
 * readdir already did the no-follow lstat (and skipped any entry whose stat
 * failed), so vst is valid whenever want_stat is set.  The dcksm variant
 * uses the dcksm stat-body format; the checksum token falls back to
 * "algo:none" when the entry path would overflow PATH_MAX.
 *
 * fmt->need must be pre-seeded with the bare name length + '\n'.
 */
static void
brix_dirlist_entry_meta(ngx_log_t *log, brix_dirlist_walk_t *walk,
    const char *name, const brix_vfs_stat_t *vst,
    brix_dirlist_entry_fmt_t *fmt)
{
    struct stat entry_st;
    char        entry_path[PATH_MAX];

    fmt->cksum_token[0] = '\0';
    fmt->have_stat = 0;

    if (walk->want_stat) {
        ngx_memzero(&entry_st, sizeof(entry_st));
        entry_st.st_mode   = (mode_t) vst->mode;
        entry_st.st_size   = vst->size;
        entry_st.st_mtime  = vst->mtime;
        entry_st.st_ctime  = vst->ctime;
        entry_st.st_ino    = vst->ino;
        entry_st.st_dev    = vst->dev;
        entry_st.st_uid    = vst->uid;
        entry_st.st_gid    = vst->gid;
        entry_st.st_blocks = vst->blocks;

        fmt->have_stat = 1;
        if (walk->want_cksum) {
            brix_dirlist_make_dcksm_stat_body(&entry_st, fmt->statbuf,
                                                sizeof(fmt->statbuf));
        } else {
            brix_make_stat_body(&entry_st, 0, 0, fmt->statbuf,
                                  sizeof(fmt->statbuf));
        }
        fmt->need += strlen(fmt->statbuf) + 1;
    }

    if (walk->want_cksum && fmt->have_stat) {
        int n;

        n = snprintf(entry_path, sizeof(entry_path), "%s/%s",
                     walk->full_path, name);
        if (n < 0 || (size_t) n >= sizeof(entry_path)) {
            snprintf(fmt->cksum_token, sizeof(fmt->cksum_token),
                     "%s:none", walk->cksum_algo);
        } else {
            brix_dirlist_checksum_token(log,
                                          brix_vfs_dir_fd(walk->dh), name,
                                          entry_path, &entry_st,
                                          walk->cksum_algo, fmt->cksum_token,
                                          sizeof(fmt->cksum_token));
        }
        fmt->need += strlen(fmt->cksum_token) + sizeof(" [  ]") - 1;
    }
}

/*
 * brix_dirlist_flush_chunk — frame the accumulated chunk as a kXR_oksofar
 * continuation and queue it, resetting the accumulator for the next chunk.
 *
 * Returns the brix_queue_response result (NGX_OK on success).
 */
static ngx_int_t
brix_dirlist_flush_chunk(brix_ctx_t *ctx, ngx_connection_t *c,
    brix_dirlist_walk_t *walk)
{
    ngx_int_t rc;

    brix_build_resp_hdr(ctx->recv.cur_streamid, kXR_oksofar,
                          (uint32_t) walk->chunk_pos,
                          (ServerResponseHdr *) walk->chunk);

    rc = brix_queue_response(ctx, c, walk->chunk,
                               XRD_RESPONSE_HDR_LEN + walk->chunk_pos);
    if (rc != NGX_OK) {
        return rc;
    }

    walk->chunk_pos = 0;
    return NGX_OK;
}

/*
 * brix_dirlist_append_entry — copy one formatted entry into the chunk
 * accumulator: name '\n' [statline [" [ token ]"] '\n'].
 *
 * The caller has already guaranteed fmt->need bytes of headroom by flushing
 * a full chunk beforehand, so the copies cannot overflow chunk_cap.
 */
static void
brix_dirlist_append_entry(brix_dirlist_walk_t *walk, const char *name,
    size_t nlen, const brix_dirlist_entry_fmt_t *fmt)
{
    u_char *data = walk->chunk + XRD_RESPONSE_HDR_LEN;

    ngx_memcpy(data + walk->chunk_pos, name, nlen);
    walk->chunk_pos += nlen;
    data[walk->chunk_pos++] = '\n';

    if (walk->want_stat && fmt->have_stat) {
        size_t slen;

        slen = strlen(fmt->statbuf);
        ngx_memcpy(data + walk->chunk_pos, fmt->statbuf, slen);
        walk->chunk_pos += slen;

        if (walk->want_cksum) {
            int n;

            n = snprintf((char *) data + walk->chunk_pos,
                         walk->chunk_cap - walk->chunk_pos,
                         " [ %s ]", fmt->cksum_token);
            if (n > 0) {
                walk->chunk_pos += (size_t) n;
            }
        }

        data[walk->chunk_pos++] = '\n';
    }
}

/*
 * brix_dirlist_send_final — frame the last accumulated chunk as kXR_ok to
 * signal end-of-listing, log the access, and bump the success metric.
 *
 * The trailing '\n' of the final entry is replaced by a NUL terminator (an
 * empty listing sends a zero-length body).
 *
 * Returns the brix_queue_response result.
 */
static ngx_int_t
brix_dirlist_send_final(brix_ctx_t *ctx, ngx_connection_t *c,
    brix_dirlist_walk_t *walk)
{
    u_char *data = walk->chunk + XRD_RESPONSE_HDR_LEN;
    size_t  final_len;

    if (walk->chunk_pos == 0) {
        final_len = 0;
    } else {
        data[walk->chunk_pos - 1] = '\0';
        final_len = walk->chunk_pos;
    }

    brix_build_resp_hdr(ctx->recv.cur_streamid, kXR_ok,
                          (uint32_t) final_len,
                          (ServerResponseHdr *) walk->chunk);

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "brix: kXR_dirlist final chunk %uz bytes",
                   walk->chunk_pos);

    brix_log_access(ctx, c, "DIRLIST", walk->reqpath,
                      walk->want_cksum ? "dcksm"
                                       : (walk->want_stat ? "stat" : "-"),
                      1, 0, NULL, 0);
    BRIX_OP_OK(ctx, BRIX_OP_DIRLIST);

    return brix_queue_response(ctx, c, walk->chunk,
                                 XRD_RESPONSE_HDR_LEN + final_len);
}

/*
 * brix_dirlist_stream_entries — the chunked streaming loop: enumerate the
 * open directory, format each visible entry, flush full 64KB chunks as
 * kXR_oksofar frames, and finish with the kXR_ok final frame.
 *
 * Owns walk->dh from here on: the handle is closed on every exit path
 * (queue failure mid-stream or normal end-of-directory).
 *
 * Returns the final queue result (NGX_OK on success).
 */
static ngx_int_t
brix_dirlist_stream_entries(brix_ctx_t *ctx, ngx_connection_t *c,
    brix_dirlist_walk_t *walk)
{
    ngx_str_t         entry_name;
    brix_vfs_stat_t entry_vst;
    ngx_int_t         rc;

    while (brix_vfs_readdir(walk->dh, &entry_name,
                              walk->want_stat ? &entry_vst : NULL) == NGX_OK) {
        const char                *name = (char *) entry_name.data;
        size_t                     nlen = entry_name.len;
        brix_dirlist_entry_fmt_t fmt;

        if (brix_dirlist_entry_skip(c->log, name)) {
            continue;
        }

        fmt.need = nlen + 1;
        brix_dirlist_entry_meta(c->log, walk, name, &entry_vst, &fmt);

        if (walk->chunk_pos + fmt.need > walk->chunk_cap) {
            rc = brix_dirlist_flush_chunk(ctx, c, walk);
            if (rc != NGX_OK) {
                brix_vfs_closedir(walk->dh, c->log);
                return rc;
            }
        }

        brix_dirlist_append_entry(walk, name, nlen, &fmt);
    }

    brix_vfs_closedir(walk->dh, c->log);

    return brix_dirlist_send_final(ctx, c, walk);
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
 *
 * Pipeline: parse request → cluster redirect check → authz + VFS opendir →
 * chunk allocation → chunked entry streaming (helpers above, state in
 * brix_dirlist_walk_t).
 */
/* §14 (phase-64): the fork/exec `xrdfs <origin> ls` namespace forward for a
 * legacy cache_origin GSI cache is RETIRED with the cache_origin config model —
 * a tier cache lists through the composed backend driver's opendir/readdir. */

ngx_int_t
brix_handle_dirlist(brix_ctx_t *ctx, ngx_connection_t *c,
                      ngx_stream_brix_srv_conf_t *conf)
{
    brix_dirlist_walk_t walk;
    ngx_int_t             rc;

    ngx_memzero(&walk, sizeof(walk));
    walk.chunk_cap = 65536;

    if (!brix_dirlist_parse_request(ctx, c, &walk, &rc)) {
        return rc;
    }

    if (!brix_dirlist_check_redirect(ctx, c, conf, &walk, &rc)) {
        return rc;
    }

    if (!brix_dirlist_open_dir(ctx, c, conf, &walk, &rc)) {
        return rc;
    }

    if (!brix_dirlist_alloc_chunk(ctx, c, &walk, &rc)) {
        return rc;
    }

    return brix_dirlist_stream_entries(ctx, c, &walk);
}
