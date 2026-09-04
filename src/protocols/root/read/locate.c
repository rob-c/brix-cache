/*
 * locate.c — kXR_locate (3027) opcode handler: resolve a path to a serving endpoint.
 *
 * WHAT: Implements brix_handle_locate(), the protocol handler for kXR_locate.
 *       For a given client path it answers "which server should you talk to?" by
 *       returning either a kXR_redirect to another host (manager/CMS modes) or a
 *       kXR_ok carrying an "Sx<host>:<port>" location token (data-server mode),
 *       where the leading S marks a server and the access char ('w' if
 *       conf->common.allow_write, else 'r') advertises read/write capability.
 *       Also handles the "*" wildcard form (locate the local server itself).
 *
 * WHY:  kXR_locate underpins XRootD's redirection/clustering model: clients query
 *       a manager to discover the data server holding a file before opening it.
 *       This handler centralises that discovery across the module's deployment
 *       modes (standalone data server, static manager map, dynamic registry,
 *       and CMS-backed cluster) so callers get a single consistent answer.
 *
 * HOW:  The orchestrator is a flat sequence of resolve -> query -> format steps.
 *       Per-request state (ctx, connection, conf, the confined path buffer and the
 *       wildcard flag) is bundled in a file-local locate_ctx_t threaded through the
 *       steps. Each query step is a static helper returning a "handled" flag: 1
 *       when it produced the terminal result (stored through *out_rc), 0 to fall
 *       through to the next step. Parse and confine the request path
 *       (locate_resolve_reqpath). In manager_mode (non-wildcard) try, in order:
 *       the collapse-redir cache, the live server registry, then an async
 *       kYR_locate to the CMS parent (locate_try_manager). Falling through,
 *       consult the static manager_map (locate_try_manager_map), then in
 *       data-server mode authorize + stat the file (locate_check_data_server).
 *       Finally format the local "Sx..." location from c->local_sockaddr
 *       (locate_format_local) and reply with brix_send_ok.
 */

#include "core/ngx_brix_module.h"
#include "net/upstream/upstream.h"
#include "protocols/root/path/op_path.h"
#include "fs/vfs/vfs.h"                 /* existence probe via the backend seam */
#include "core/negcache/negcache.h"    /* E-4: locate-harvest backoff */
#include "net/manager/registry.h"
#include "net/manager/pending.h"
#include "net/cms/cms_internal.h"
#include "locate_internal.h"           /* locate_ctx_t + locate_try_manager */

#include <arpa/inet.h>

/*
 * locate_resolve_reqpath — parse, confine and validate the requested path.
 *
 * WHAT: Unpacks the locate request, extracts the confined path into lc->reqpath,
 *       sets lc->is_wildcard for the "*" self-locate form, and rejects missing/
 *       invalid/".."/too-deep paths by emitting the terminal error reply.
 * WHY:  Every code path downstream assumes a validated, confined path (or the
 *       wildcard). Centralising validation keeps the orchestrator flat and the
 *       security ordering (reject before any lookup) explicit.
 * HOW:  Returns 1 when it produced a terminal result (stored through *out_rc) and
 *       the orchestrator must return; returns 0 when lc->reqpath / lc->is_wildcard
 *       are populated and processing should continue. Error replies at the edge —
 *       identical wire behaviour to the inline original.
 */
static int
locate_resolve_reqpath(locate_ctx_t *lc, ngx_int_t *out_rc)
{
    brix_ctx_t        *ctx = lc->ctx;
    ngx_connection_t  *c = lc->c;
    xrdw_locate_req_t  req;

    /* §2.18: kXR_prefname (0x0100) = the client wants the server's DNS hostname
     * in the location token rather than its IP literal (e.g. so a GSI host-cert
     * CN matches, or the name re-resolves through a different route). Honoured in
     * locate_format_local; clear ⇒ the IP literal, byte-identical to before.
     * §2.7: kXR_refresh (0x0080) = the client wants the caches bypassed AND
     * flushed — honoured in locate_try_manager. */
    xrdw_locate_req_unpack(((ClientRequestHdr *) ctx->recv.hdr_buf)->body, &req);
    lc->prefname = (req.options & kXR_prefname) != 0;
    lc->refresh = (req.options & kXR_refresh) != 0;
    /* §1.8: kXR_nowait (0x2000) — the client refuses to be parked; when the
     * answer needs a cluster probe it gets kXR_wait immediately instead
     * (honoured in locate_try_dynamic). */
    lc->nowait = (req.options & kXR_nowait) != 0;

    if (ctx->recv.cur_dlen == 0 || ctx->recv.payload == NULL) {
        BRIX_OP_ERR(ctx, BRIX_OP_LOCATE);
        *out_rc = brix_send_error(ctx, c, kXR_ArgMissing, "no path given");
        return 1;
    }

    if (!brix_extract_path(c->log, ctx->recv.payload, ctx->recv.cur_dlen,
                             lc->reqpath, lc->reqpath_sz, 1))
    {
        BRIX_OP_ERR(ctx, BRIX_OP_LOCATE);
        *out_rc = brix_send_error(ctx, c, kXR_ArgInvalid,
                                    "invalid path payload");
        return 1;
    }

    /* A locate path may be PREFIXED with a star -- XrdCl's "locate a server for
     * a possibly-nonexistent (new) file" form.  Every `xrdfs ls`/read/write does
     * a Locate first and sends star-then-path (e.g. `ls /` sends star then a
     * slash).  The reference server strips the marker and answers with a data
     * server even when the path does not yet exist.  Strip it here and remember
     * to tolerate a stat miss (locate_check_data_server).  A BARE star is the
     * distinct self/all wildcard (is_wildcard) and is left intact so its
     * reqpath stays a lone star. */
    if (lc->reqpath[0] == '*' && lc->reqpath[1] != '\0') {
        lc->tolerate_missing = 1;
        ngx_memmove(lc->reqpath, lc->reqpath + 1,
                    ngx_strlen(lc->reqpath + 1) + 1);
    }

    lc->is_wildcard = (lc->reqpath[0] == '*' && lc->reqpath[1] == '\0');

    /* Reject any ".." component (the reference does not normalize ".."); locate
     * resolves through the kernel RESOLVE_BENEATH which would collapse it.
     * The "*" wildcard locate carries no path to traverse. */
    if (!lc->is_wildcard
        && brix_reject_dotdot_path(ctx, c, BRIX_OP_LOCATE, "LOCATE",
                                     lc->reqpath)) {
        *out_rc = ctx->write_rc;
        return 1;
    }

    if (!lc->is_wildcard && brix_count_path_depth(lc->reqpath) != NGX_OK) {
        BRIX_OP_ERR(ctx, BRIX_OP_LOCATE);
        *out_rc = brix_send_error(ctx, c, kXR_ArgInvalid,
                                    "path exceeds maximum depth");
        return 1;
    }

    return 0;
}

/*
 * locate_try_manager_map — resolve a path via the static manager_map.
 *
 * WHAT: For a non-wildcard path with a configured static map, looks up the
 *       longest matching prefix and, on a hit, redirects to its host:port.
 * WHY:  The static map is the config-driven redirect table used without (or
 *       alongside) a live registry — a deterministic fallback after dynamic
 *       discovery misses.
 * HOW:  Returns 1 with the redirect reply stored through *out_rc on a hit;
 *       returns 0 to continue to the data-server path. No behaviour change.
 */
static int
locate_try_manager_map(locate_ctx_t *lc, ngx_int_t *out_rc)
{
    brix_ctx_t                  *ctx = lc->ctx;
    ngx_connection_t            *c = lc->c;
    ngx_stream_brix_srv_conf_t  *conf = lc->conf;
    const brix_manager_map_t    *m;

    if (lc->is_wildcard || conf->manager_map == NULL) {
        return 0;
    }

    m = brix_find_manager_map(lc->reqpath, conf->manager_map);
    if (m == NULL) {
        return 0;
    }

    brix_log_access(ctx, c, "LOCATE", lc->reqpath, "redirect", 1, 0, NULL, 0);
    BRIX_OP_OK(ctx, BRIX_OP_LOCATE);
    *out_rc = brix_send_redirect(ctx, c, (const char *) m->host.data, m->port);
    return 1;
}

/*
 * locate_check_data_server — authorize and probe existence in data-server mode.
 *
 * WHAT: For a non-wildcard path, enforces read access via brix_auth_gate BEFORE
 *       probing existence, then stats the file beneath conf->rootfd; on a miss it
 *       redirects to a configured upstream or replies kXR_NotFound.
 * WHY:  Authorizing first yields an identical kXR_NotAuthorized whether or not the
 *       path exists — no namespace-existence oracle (mirrors statx.c ordering).
 * HOW:  Returns 1 when it produced a terminal result (auth denial, upstream
 *       redirect, or notFound) stored through *out_rc; returns 0 when the file
 *       exists and the caller should format the local location reply.
 */
static int
locate_check_data_server(locate_ctx_t *lc, ngx_int_t *out_rc)
{
    brix_ctx_t                  *ctx = lc->ctx;
    ngx_connection_t            *c = lc->c;
    ngx_stream_brix_srv_conf_t  *conf = lc->conf;
    char                         full_path[PATH_MAX];
    brix_vfs_ctx_t               vctx;
    brix_vfs_stat_t              vst;

    if (lc->is_wildcard) {
        return 0;
    }

    /* SECURITY: authorize BEFORE probing existence so a denied principal gets an
     * identical kXR_NotAuthorized whether or not the path exists — no namespace-
     * existence oracle (mirrors the statx.c ordering). The gate keys off the
     * identity + logical path, independent of on-disk existence. */
    brix_beneath_full_path(conf->common.root_canon, lc->reqpath,
                             full_path, sizeof(full_path));
    if (brix_auth_gate(ctx, c, BRIX_OP_LOCATE, "LOCATE", lc->reqpath, full_path,
                         conf, BRIX_AUTH_READ, 0) != NGX_OK) {
        *out_rc = ctx->write_rc;
        return 1;
    }

    /* Probe existence through the VFS seam, not a bare rootfd stat: a root://
     * (driver-backed) export holds its files on the origin, so brix_stat_beneath
     * on the empty local export always missed and locate answered NotFound for
     * files that exist. brix_vfs_statf reaches the backend (and, via the keystone
     * kXR_stat, resolves directories too). */
    brix_root_vfs_ctx_init(ctx, c, conf, &vctx, full_path);
    if (brix_vfs_statf(&vctx, &vst) != NGX_OK) {
        if (conf->upstream_host.len > 0) {
            brix_log_access(ctx, c, "LOCATE", lc->reqpath, "upstream",
                              1, 0, NULL, 0);
            BRIX_OP_OK(ctx, BRIX_OP_LOCATE);
            *out_rc = brix_upstream_start(ctx, c, conf);
            return 1;
        }

        /* '*'-prefixed (create/new-file) locate: a standalone data server
         * answers with itself even when the file does not yet exist — the
         * client is about to create it (this is also what makes `xrdfs ls`
         * proceed to dirlist).  Fall through to the local-location reply. */
        if (lc->tolerate_missing) {
            return 0;
        }

        /* E-4: throttle a locate-harvest loop — a principal already over its
         * miss budget is answered with kXR_wait rather than another NotFound. */
        if (conf->negcache.threshold > 0) {
            unsigned w = brix_negcache_note_miss(ctx, conf->negcache.threshold,
                                                 conf->negcache.window_ms,
                                                 conf->negcache.backoff_s);
            if (w > 0) {
                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                    "xrootd negcache: kXR_wait %ud for LOCATE miss %s",
                    w, lc->reqpath);
                BRIX_OP_ERR(ctx, BRIX_OP_LOCATE);
                *out_rc = brix_send_wait(ctx, c, w);
                return 1;
            }
        }

        brix_log_access(ctx, c, "LOCATE", lc->reqpath, "-",
                          0, kXR_NotFound, "file not found", 0);
        BRIX_OP_ERR(ctx, BRIX_OP_LOCATE);
        *out_rc = brix_send_error(ctx, c, kXR_NotFound, "file not found");
        return 1;
    }

    return 0;
}

/*
 * locate_format_local — format the local "Sx<host>:<port>" location token.
 *
 * WHAT: Writes the data-server location string into loc_buf: "Sc<ipv4>:<port>",
 *       "Sc[<ipv6>]:<port>", or the "Sclocalhost" fallback, where c is the access
 *       char ('w' if allow_write else 'r'). When prefname is set (§2.18
 *       kXR_prefname) the host is the server's DNS name (gethostname(2), cached
 *       for the life of the process — the same identity cms/send.c registers
 *       under) rather than the IP literal.
 * WHY:  This is the kXR_ok body a data server returns for its own file — the
 *       leading 'S' marks a server; the access char advertises read/write.
 * HOW:  Pure formatting over conf and c->local_sockaddr (one cached gethostname
 *       for the prefname path). Returns the snprintf length; the caller frames it
 *       as len+1 for brix_send_ok, exactly as the original inline code.
 */
static int
locate_format_local(ngx_stream_brix_srv_conf_t *conf, ngx_connection_t *c,
                    int prefname, char *loc_buf, size_t loc_sz)
{
    char                 access_char;
    struct sockaddr_in  *sin;
    struct sockaddr_in6 *sin6;
    uint16_t             port;

    access_char = conf->common.allow_write ? 'w' : 'r';

    /* §2.18 kXR_prefname: emit the server's DNS hostname instead of the IP.
     * gethostname(2) is cached process-wide — it is the same node identity
     * cms/send.c registers upward. The port still comes from the bound socket
     * (falling back to the configured listen port when unknown). */
    if (prefname) {
        static char        hostname[256];
        static ngx_atomic_t resolved;   /* 0 → unset, 1 → hostname[] valid */

        if (!resolved) {
            if (gethostname(hostname, sizeof(hostname)) != 0) {
                hostname[0] = '\0';
            }
            hostname[sizeof(hostname) - 1] = '\0';
            resolved = 1;
        }
        if (hostname[0] != '\0') {
            port = 0;
            if (c->local_sockaddr != NULL
                && c->local_sockaddr->sa_family == AF_INET)
            {
                port = ntohs(((struct sockaddr_in *) c->local_sockaddr)->sin_port);
            } else if (c->local_sockaddr != NULL
                && c->local_sockaddr->sa_family == AF_INET6)
            {
                port = ntohs(((struct sockaddr_in6 *) c->local_sockaddr)->sin6_port);
            }
            if (port == 0) {
                port = (uint16_t) conf->listen_port;
            }
            return snprintf(loc_buf, loc_sz, "S%c%s:%d",
                            access_char, hostname, (int) port);
        }
        /* gethostname failed — fall through to the IP-literal form. */
    }

    if (c->local_sockaddr != NULL
        && c->local_sockaddr->sa_family == AF_INET)
    {
        char ipbuf[INET_ADDRSTRLEN];
        sin = (struct sockaddr_in *) c->local_sockaddr;
        port = ntohs(sin->sin_port);
        inet_ntop(AF_INET, &sin->sin_addr, ipbuf, sizeof(ipbuf));
        return snprintf(loc_buf, loc_sz, "S%c%s:%d",
                        access_char, ipbuf, (int) port);
    }

    if (c->local_sockaddr != NULL
        && c->local_sockaddr->sa_family == AF_INET6)
    {
        char ipbuf[INET6_ADDRSTRLEN];
        sin6 = (struct sockaddr_in6 *) c->local_sockaddr;
        port = ntohs(sin6->sin6_port);
        inet_ntop(AF_INET6, &sin6->sin6_addr, ipbuf, sizeof(ipbuf));
        return snprintf(loc_buf, loc_sz, "S%c[%s]:%d",
                        access_char, ipbuf, (int) port);
    }

    return snprintf(loc_buf, loc_sz, "S%clocalhost", access_char);
}

ngx_int_t
brix_handle_locate(brix_ctx_t *ctx, ngx_connection_t *c,
                     ngx_stream_brix_srv_conf_t *conf)
{
    char         reqpath_buf[BRIX_MAX_PATH + 1];
    char         loc_buf[256];
    int          loc_len;
    ngx_int_t    out_rc = NGX_OK;
    locate_ctx_t lc = {
        .ctx = ctx,
        .c = c,
        .conf = conf,
        .reqpath = reqpath_buf,
        .reqpath_sz = sizeof(reqpath_buf),
        .is_wildcard = 0
    };

    if (locate_resolve_reqpath(&lc, &out_rc)) {
        return out_rc;
    }

    if (locate_try_manager(&lc, &out_rc)) {
        return out_rc;
    }

    if (locate_try_manager_map(&lc, &out_rc)) {
        return out_rc;
    }

    if (locate_check_data_server(&lc, &out_rc)) {
        return out_rc;
    }

    loc_len = locate_format_local(conf, c, lc.prefname, loc_buf, sizeof(loc_buf));

    brix_log_access(ctx, c, "LOCATE", reqpath_buf, loc_buf, 1, 0, NULL, 0);
    BRIX_OP_OK(ctx, BRIX_OP_LOCATE);

    return brix_send_ok(ctx, c, loc_buf, (uint32_t) (loc_len + 1));
}
