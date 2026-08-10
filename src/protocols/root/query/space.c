#include "query_internal.h"
#include "core/compat/fs_usage.h"
#include "protocols/root/protocol/qspace.h"   /* shared oss.* space-report grammar (emit side) */
#include "fs/vfs/vfs.h"                        /* §4.6: driver-reported space seam */

#include <errno.h>

/*
 * kXR_Qspace (3015) and kXR_QFSinfo (3017): filesystem capacity reports.
 *
 * WHAT: Responds to client queries about local filesystem disk capacity using
 *       statvfs(2). Two opcode variants produce different response formats:
 *       Qspace uses "oss.*" key-value pairs; QFSinfo uses the reference server's
 *       compact numeric format used by locate/redirect logic.
 *
 * WHY: XRootD clients (xrdcp, xrdfs) need filesystem capacity information to
 *      decide whether a server has sufficient space for writes. Qspace provides
 *      detailed byte-level reports; QFSinfo provides the compact format that
 *      client redirect logic uses to select writable servers in CMS cluster mode.
 *
 * HOW: Both handlers call the shared query_space_probe() — driver space view
 *      (pblock quota / sd_xroot origin forward via brix_vfs_space) with a
 *      local-statvfs fallback → on failure return kXR_IOError → on success
 *      format the response per opcode variant and send via brix_send_ok(). Both
 *      log access events at INFO level. Always returns NGX_OK from the handler
 *      (kXR status encoded in wire response).
 */

/*
 * brix_query_space — handle kXR_Qspace (3015) filesystem capacity query.
 *
 * WHAT: Returns filesystem total, available (free), max free, and used bytes
 *       in the "oss.*" key-value format expected by xrdcp and XRootD clients.
 *       oss.maxf equals oss.free since no hard quota is enforced. oss.quota=-1
 *       indicates unlimited quota.
 *
 * WHY: Clients use this response to display disk usage information and decide
 *      whether a server has enough space for incoming writes. The oss.* format
 *      matches the reference xrootd server's Qspace response exactly.
 *
 * HOW: Call brix_fs_usage_stat(root, &fsu) → if NGX_OK fails, log access event
 *      (error), increment error metric, send kXR_IOError → if success, snprintf
 *      resp as "oss.cgroup=default&oss.space=%llu&oss.free=%llu&oss.maxf=%llu&
 *      oss.used=%llu&oss.quota=-1" with fsu values, log access event (success),
 *      increment OK metric, send via brix_send_ok().
 *
 * Parameters:
 *   ctx — xrootd connection context containing parsed request header and payload
 *   c   — nginx connection for logging
 *   conf — server configuration containing root filesystem path
 */

/*
 * brix_query_space_probe — resolve filesystem capacity for a Qspace/QFSinfo
 * report (non-static: the §3.3 oss_quota write-admission gate reuses it).
 *
 * §4.6: prefer the backend driver's own space view — a quota-aware catalog
 * backend (pblock) reports its logical quota, and a remote root:// origin
 * (sd_xroot) forwards the origin's kXR_Qspace — over the raw statvfs(2) of the
 * proxy's local cache disk. A backend with no space slot (plain POSIX) declines
 * and we fall back to the local statvfs, byte-for-byte the prior behaviour.
 *
 * Returns NGX_OK with the total, freeb and used out-params populated, or
 * NGX_ERROR when even the
 * statvfs fallback failed (errno left set; caller emits kXR_IOError). Shared by
 * both the Qspace and QFSinfo handlers so the two reports never disagree about
 * which store's free space a proxy is advertising.
 */
ngx_int_t
brix_query_space_probe(ngx_connection_t *c, ngx_stream_brix_srv_conf_t *conf,
    unsigned long long *total, unsigned long long *freeb,
    unsigned long long *used)
{
    brix_vfs_ctx_t   vctx;
    brix_sd_space_t  sp;
    brix_fs_usage_t  fsu;

    brix_vfs_ctx_init(&vctx, c->pool, c->log, BRIX_PROTO_ROOT,
        conf->common.root_canon, NULL, conf->common.allow_write,
        0 /* is_tls */, NULL, conf->common.root_canon);
    if (brix_vfs_space(&vctx, &sp) == NGX_OK) {
        *total = (unsigned long long) sp.total_bytes;
        *freeb = (unsigned long long) sp.free_bytes;
        *used  = (unsigned long long) sp.used_bytes;
        return NGX_OK;
    }

    if (brix_fs_usage_stat((const char *) conf->common.root.data, &fsu)
        != NGX_OK) {
        return NGX_ERROR;
    }
    *total = (unsigned long long) fsu.total_bytes;
    *freeb = (unsigned long long) fsu.available_bytes;
    *used  = (unsigned long long) fsu.used_bytes;
    return NGX_OK;
}

ngx_int_t
brix_query_space(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf)
{
    char               resp[256];
    unsigned long long total, freeb, used;

    /* The reference do_Qspace runs rpCheck() on the path argument first and
     * rejects a relative path — one that does not begin with '/', which
     * includes the empty path — with kXR_NotAuthorized "...relative path '...'
     * is disallowed." (XrdXrootdProtocol::rpEmsg).  We confine via
     * RESOLVE_BENEATH rather than lexical rpCheck, but still honour this guard
     * so an empty/relative Qspace argument is rejected identically. */
    if (ctx->recv.cur_dlen == 0 || ctx->recv.payload == NULL
        || ((const char *) ctx->recv.payload)[0] != '/') {
        BRIX_OP_ERR(ctx, BRIX_OP_QUERY_SPACE);
        return brix_send_error(ctx, c, kXR_NotAuthorized,
                                 "query relative path '' is disallowed.");
    }

    /* §4.6: driver space view (pblock quota / sd_xroot origin forward) with a
     * local-statvfs fallback — see query_space_probe. */
    if (brix_query_space_probe(c, conf, &total, &freeb, &used) != NGX_OK) {
        brix_log_access(ctx, c, "QUERY", (char *) conf->common.root.data,
                          "space", 0, kXR_IOError, strerror(errno), 0);
        BRIX_OP_ERR(ctx, BRIX_OP_QUERY_SPACE);
        return brix_send_error(ctx, c, kXR_IOError, "statvfs failed");
    }

    /* oss.* grammar is shared with the client's parser (protocol/qspace.h);
     * maxf == free (BriX enforces no hard quota). oss.cgroup carries the server's
     * configured space-group name (brix_oss_cgroup; §3.2, default "default");
     * oss.quota advertises brix_oss_quota (§3.1) — the site's configured space
     * quota for accounting clients, or -1 (unlimited) when unset. Advertisement
     * only: like oss.cgroup, BriX does not itself enforce it. */
    brix_qspace_format(resp, sizeof(resp),
                         (const char *) conf->oss_cgroup.data,
                         total, freeb, freeb, used,
                         (long long) conf->oss_quota);

    brix_log_access(ctx, c, "QUERY", (char *) conf->common.root.data,
                      "space", 1, 0, NULL, 0);
    BRIX_OP_OK(ctx, BRIX_OP_QUERY_SPACE);
    return brix_send_ok(ctx, c, resp, (uint32_t) (strlen(resp) + 1));
}
/* WHY: kXR_Qspace returns filesystem capacity in the "oss.*" key-value format used by xrdcp and XRootD clients to display disk usage. Reports total bytes, available (free) bytes, max free (same as available since no hard quota), and used bytes — matching the reference server's statvfs-based response. Returns kXR_IOError on statvfs failure. */
/* HOW: Calls brix_fs_usage_stat(conf->common.root.data, &fsu) via compat/fs_usage.h to populate fsu with total_bytes/available_bytes/used_bytes from statvfs — if NGX_OK fails logs access event (error), increments BRIX_OP_QUERY_SPACE error metric, sends kXR_IOError response. On success: snprintf(resp) formats "oss.cgroup=default&oss.space=%llu&oss.free=%llu&oss.maxf=%llu&oss.used=%llu&oss.quota=-1" with fsu values; logs access event (success), increments OK metric, sends brix_send_ok(resp). */

/*
 * brix_query_fsinfo — handle kXR_QFSinfo (3017) filesystem capacity query.

 * WHAT: Returns writable flag, free space in MB, and utilization percentage in the
 *       compact numeric format used by XRootD client locate/redirect logic.
 *       Format: wVal freeMB util sVal freeMB util — two identical reports for
 *       writable and staging flags so clients see a single uniform filesystem.

 * WHY: kXR_QFSinfo is the response format that XRootD client redirect logic uses to
 *      determine whether a server can accept writes based on disk space. The compact
 *      numeric format matches the reference xrootd server's QFSinfo output exactly.
 *      Used by CMS cluster manager and kXR_locate to select writable servers.

 * HOW: Call brix_query_space_probe(c, conf, &total, &freeb, &used) — driver space view
 *      (pblock quota / sd_xroot origin forward) with a local-statvfs fallback → if
 *      it fails increment error metric and send kXR_IOError → on success: compute
 *      util=(used*100)/total (0 if total==0), convert free bytes to MB via >>20,
 *      clamp free_mb to 0x7fffffff if overflow (>31 bits). snprintf resp as
 *      "1 %lld %d 1 %lld %d" with writable=1, freeMB, util%, staging=1, same freeMB,
 *      same util%. Log access event (success), increment OK metric, send via
 *      brix_send_ok().

 * Parameters:
 *   ctx — xrootd connection context containing parsed request header and payload
 *   c   — nginx connection for logging
 *   conf — server configuration containing root filesystem path
 */
ngx_int_t
brix_query_fsinfo(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf)
{
    char               resp[256];
    unsigned long long total, freeb, used;
    int                util;
    long long          free_mb;

    /* §4.6: same driver-space seam as Qspace — a proxy/quota backend advertises
     * the origin's (or its quota's) free space for CMS/locate writable-server
     * selection, not the proxy's own cache disk. */
    if (brix_query_space_probe(c, conf, &total, &freeb, &used) != NGX_OK) {
        BRIX_OP_ERR(ctx, BRIX_OP_QUERY_FSINFO);
        return brix_send_error(ctx, c, kXR_IOError, "statvfs failed");
    }

    util = (total > 0) ? (int) ((used * 100) / total) : 0;
    free_mb = (long long) (freeb >> 20);
    if ((free_mb >> 31)) {
        free_mb = 0x7fffffff;
    }

    /*
     * Format: wVal freeMB util sVal freeMB util
     * wVal = 1 (writable), sVal = 1 (staging supported).
     */
    snprintf(resp, sizeof(resp), "%d %lld %d %d %lld %d",
             1, free_mb, util, 1, free_mb, util);

    brix_log_access(ctx, c, "QUERY", (char *) conf->common.root.data,
                      "fsinfo", 1, 0, NULL, 0);
    BRIX_OP_OK(ctx, BRIX_OP_QUERY_FSINFO);
    return brix_send_ok(ctx, c, resp, (uint32_t) (strlen(resp) + 1));
}
/* WHY: kXR_QFSinfo returns filesystem capacity in the reference-compatible "wVal freeMB util sVal freeMB util" format used by XRootD client locate/redirect logic. wVal=1 indicates writable, sVal=1 indicates staging supported; both report identical free_mb and utilization percentage so clients see a single uniform filesystem. Used by kXR_locate to determine whether a server can accept writes based on disk space. */
/* HOW: Calls query_space_probe (driver-space seam with local-statvfs fallback) — if fails increments BRIX_OP_QUERY_FSINFO error metric and sends kXR_IOError response. On success: computes util=(used*100)/total (0 if total==0), converts free bytes to MB via >>20, clamps free_mb to 0x7fffffff if overflow (>31 bits). snprintf(resp) formats "1 %lld %d 1 %lld %d" with writable=1, freeMB, util%, staging=1, same freeMB, same util%. Logs access event (success), increments OK metric, sends brix_send_ok(resp). */
