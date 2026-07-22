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
#include "dirlist_handler_internal.h"

#include <spawn.h>
#include <sys/wait.h>
#include "core/compat/alloc_guard.h"

extern char **environ;

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
