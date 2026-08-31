#include "query_internal.h"
#include "core/ident.h"

#include <stdarg.h>
#include <sys/statvfs.h>
#include <fcntl.h>       /* O_RDONLY for the xattr-query read gate */
#include <unistd.h>      /* close() */
#include "auth/impersonate/impersonate.h"   /* brix_imp_client_active */

/*
 * WHAT: kXR_QStats, kXR_Qxattr, kXR_QFinfo, kXR_QFSinfo, kXR_Qvisa, kXR_Qopaque, kXR_Qopaquf, kXR_Qopaqug — metadata and plugin-style query handlers.
 *       QStats returns XML-formatted server statistics (connections, bytes, uptime); Qxattr lists extended attributes on a file path;
 *       QFinfo returns "0" as placeholder; QFSinfo delegates to space handler; Qvisa/opaques return FSctl/fctl unsupported responses
 *       matching reference XRootD behavior since nginx-xrootd does not embed the XrdOfs plugin layer.
 *
 * WHY:  These queries provide server observability (stats), filesystem metadata (xattr, finfo), and extension hooks (visa/opaques) that clients use
 *       to discover server capabilities and file properties. QStats XML matches reference format for monitoring dashboards; xattr returns oss.* key-value
 *       pairs including file type, size, timestamps, and user.U.* extended attributes for HEP data provenance tracking. Opaque queries return unsupported
 *       to maintain protocol compatibility with clients that send FSctl/fctl requests expecting a consistent response shape.
 *
 * HOW:  Three shared static helpers handle common patterns: arg_missing() logs + sends kXR_ArgMissing error; fsctl_unsupported()/fctl_unsupported()
 *       log + send kXR_Unsupported for plugin operations. payload_equals() compares wire payload against expected text with null-termination handling.
 * Public APIs follow security chain (extract_path → resolve_path → authdb → vo_acl) where applicable, then delegate to stat/listxattr/getxattr syscalls
 * or return placeholder/unsupported responses. QStats reads metrics struct + local socket address for port extraction; xattr builds oss.* key-value string
 * with listxattr iteration filtering user.U.* prefixes.
 */

static ngx_int_t
brix_query_arg_missing(brix_ctx_t *ctx, ngx_connection_t *c,
    const char *tag, ngx_uint_t op)
{
    BRIX_RETURN_ERR(ctx, c, op, "QUERY", "-", tag,
                      kXR_ArgMissing, "Required query argument not present");
}

static ngx_int_t
brix_query_fsctl_unsupported(brix_ctx_t *ctx, ngx_connection_t *c,
    const char *path, const char *tag, ngx_uint_t op)
{
    BRIX_RETURN_ERR(ctx, c, op, "QUERY", path ? path : "-", tag,
                      kXR_Unsupported, "FSctl operation not supported");
}

static ngx_int_t
brix_query_fctl_unsupported(brix_ctx_t *ctx, ngx_connection_t *c,
    const char *path, const char *tag, ngx_uint_t op)
{
    BRIX_RETURN_ERR(ctx, c, op, "QUERY", path ? path : "-", tag,
                      kXR_Unsupported, "fctl operation not supported");
}

static ngx_flag_t
brix_query_payload_equals(brix_ctx_t *ctx, const char *text)
{
    size_t len, text_len;

    if (ctx->recv.payload == NULL) {
        return 0;
    }

    len = ctx->recv.cur_dlen;
    if (len > 0 && ctx->recv.payload[len - 1] == '\0') {
        len--;
    }

    text_len = strlen(text);
    return (len == text_len
            && ngx_memcmp(ctx->recv.payload, text, text_len) == 0);
}

/* ---- Bounded append for the stats document (qconfig-style) ---- */
static void
stats_append(char *resp, size_t cap, size_t *pos, const char *fmt, ...)
{
    va_list ap;
    int     n;

    if (*pos >= cap) {
        return;
    }
    va_start(ap, fmt);
    n = vsnprintf(resp + *pos, cap - *pos, fmt, ap);
    va_end(ap);
    if (n > 0) {
        *pos += ((size_t) n < cap - *pos) ? (size_t) n : cap - *pos - 1;
    }
}

/* ---- Which sections did the QStats arg select? ----
 *
 * WHAT: Returns the stock selector bitmask for the request payload: letters
 *       a=all b=buff d=poll i=info l=link p=protocol s=sched u=proc (verified
 *       live against 5.6.9); unknown letters contribute nothing; an absent /
 *       empty payload behaves like 'a' (the pre-existing BriX behavior, which
 *       the suites pin).
 *
 * WHY: §1.13 — stock clients ask for subsets (mpxstats polls 'p' etc.); BriX
 *      used to ignore the argument entirely and always answer everything.
 *
 * HOW: One pass over the payload letters setting bits; 'a' sets all.
 */
#define BRIX_QSTATS_INFO   0x01
#define BRIX_QSTATS_LINK   0x02
#define BRIX_QSTATS_PROTO  0x04
#define BRIX_QSTATS_ALL    0x07

static unsigned
stats_selector(const brix_ctx_t *ctx)
{
    unsigned    mask = 0;
    uint32_t    i;
    const char *p = (const char *) ctx->recv.payload;

    if (p == NULL || ctx->recv.cur_dlen == 0) {
        return BRIX_QSTATS_ALL;
    }
    for (i = 0; i < ctx->recv.cur_dlen && p[i] != '\0'; i++) {
        switch (p[i]) {
        case 'a': mask |= BRIX_QSTATS_ALL;   break;
        case 'i': mask |= BRIX_QSTATS_INFO;  break;
        case 'l': mask |= BRIX_QSTATS_LINK;  break;
        case 'p': mask |= BRIX_QSTATS_PROTO; break;
        default:  break;   /* stock: unknown letters contribute nothing */
        }
    }
    return mask;
}

/* brix_query_stats — kXR_QStats: the stock-shaped XML <statistics> document.
 *
 * WHAT: Emits the reference wrapper (tod/ver/src/tos/pgm/ins/pid/site
 *       attributes, byte-shape verified live against stock 5.6.9) and the
 *       sections BriX can fill honestly — info, link, xrootd(ops from the
 *       per-op metric slots), oss(v=2, statvfs of the export), sgen — gated
 *       by the stock selector letters. Sections whose letters BriX has no
 *       data for (buff/poll/sched/proc) are simply absent, exactly like an
 *       unknown letter on stock.
 *
 * WHY: §1.13 — the old abbreviated document broke XML-parsing consumers:
 *      wrong root attributes (spurious id=, missing tod/src/pid) and no ops
 *      section. Counters that do not exist are emitted as 0 rather than
 *      invented; ver/pgm keep the honest BriX identity.
 *
 * HOW: 1. Resolve selector mask + identity fields (hostname from ngx_cycle,
 *         port from metrics or the local sockaddr, tos latched on first use).
 *      2. Append the wrapper, then each selected section from the metric
 *         slots (misc/err aggregate the unmapped op slots so totals stay
 *         truthful). 3. oss + sgen ride the 'a' selection only, like stock.
 */

/* Resolve the local listen port for the stats src= field: the metrics slot
 * first, else the connection's local sockaddr (v4/v6). 0 when unknown. */
static int
stats_resolve_port(brix_ctx_t *ctx, ngx_connection_t *c)
{
    int port = ctx->metrics ? (int) ctx->metrics->port : 0;

    if (port == 0 && c->local_sockaddr != NULL) {
        if (c->local_sockaddr->sa_family == AF_INET) {
            port = (int) ntohs(((struct sockaddr_in *)
                                c->local_sockaddr)->sin_port);
        } else if (c->local_sockaddr->sa_family == AF_INET6) {
            port = (int) ntohs(((struct sockaddr_in6 *)
                                c->local_sockaddr)->sin6_port);
        }
    }
    return port;
}

ngx_int_t
brix_query_stats(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf)
{
    static time_t tos_latch = 0;   /* worker start proxy: first-stats time */
    char     resp[4096];
    size_t   pos = 0;
    unsigned sel = stats_selector(ctx);
    int      port = stats_resolve_port(ctx, c);
    time_t   now = time(NULL);
    long     ok_open = 0, err_sum = 0, misc = 0;
    int      i;

    if (tos_latch == 0) {
        tos_latch = now;
    }

    /* site="" is the summary-monitoring site label federation dashboards read;
     * populate it from brix_sitename (the advertise.sitename slot), matching
     * stock's all.sitename. Emitted raw like the adjacent hostname — an operator
     * sitename is a plain identifier, not attacker input. Empty when unset. */
    stats_append(resp, sizeof(resp), &pos,
        "<statistics tod=\"%ld\" ver=\"" BRIX_SERVER_VERSION "\""
        " src=\"%.*s:%d\" tos=\"%ld\" pgm=\"" BRIX_SERVER_NAME "\""
        " ins=\"brix\" pid=\"%d\" site=\"%.*s\">",
        (long) now, (int) ngx_cycle->hostname.len, ngx_cycle->hostname.data,
        port, (long) tos_latch, (int) ngx_pid,
        (int) conf->advertise.sitename.len, conf->advertise.sitename.data);

    if (sel & BRIX_QSTATS_INFO) {
        stats_append(resp, sizeof(resp), &pos,
            "<stats id=\"info\"><host>%.*s</host><port>%d</port>"
            "<name>" BRIX_SERVER_NAME "</name></stats>",
            (int) ngx_cycle->hostname.len, ngx_cycle->hostname.data, port);
    }

    if ((sel & BRIX_QSTATS_LINK) && ctx->metrics) {
        /* Stock tag order: num maxn tot in out ctime tmo stall sfps.  maxn
         * (max ever concurrent) is not tracked — the live count is the best
         * lower bound we can attest. */
        stats_append(resp, sizeof(resp), &pos,
            "<stats id=\"link\"><num>%ld</num><maxn>%ld</maxn>"
            "<tot>%ld</tot><in>%ld</in><out>%ld</out>"
            "<ctime>0</ctime><tmo>0</tmo><stall>0</stall>"
            "<sfps>0</sfps></stats>",
            (long) ctx->metrics->connections_active,
            (long) ctx->metrics->connections_active,
            (long) ctx->metrics->connections_total,
            (long) ctx->metrics->bytes_rx_total,
            (long) ctx->metrics->bytes_tx_total);
    }

    if ((sel & BRIX_QSTATS_PROTO) && ctx->metrics) {
        for (i = 0; i < BRIX_NOPS; i++) {
            err_sum += (long) ctx->metrics->op_err[i];
            misc    += (long) ctx->metrics->op_ok[i];
        }
        ok_open = (long) ctx->metrics->op_ok[BRIX_OP_OPEN_RD]
                  + (long) ctx->metrics->op_ok[BRIX_OP_OPEN_WR];
        /* misc = every completed op not named in the ops block, so the block
         * totals stay truthful. */
        misc -= ok_open
                + (long) ctx->metrics->op_ok[BRIX_OP_READ]
                + (long) ctx->metrics->op_ok[BRIX_OP_PGREAD]
                + (long) ctx->metrics->op_ok[BRIX_OP_READV]
                + (long) ctx->metrics->op_ok[BRIX_OP_WRITEV]
                + (long) ctx->metrics->op_ok[BRIX_OP_WRITE]
                + (long) ctx->metrics->op_ok[BRIX_OP_SYNC]
                + (long) ctx->metrics->op_ok[BRIX_OP_LOGIN];
        if (misc < 0) {
            misc = 0;
        }
        stats_append(resp, sizeof(resp), &pos,
            "<stats id=\"xrootd\"><num>%ld</num>"
            "<ops><open>%ld</open><rf>0</rf>"
            "<rd>%ld</rd><pr>%ld</pr><rv>%ld</rv><rs>0</rs>"
            "<wv>%ld</wv><ws>0</ws><wr>%ld</wr><sync>%ld</sync>"
            "<getf>0</getf><putf>0</putf><misc>%ld</misc></ops>"
            "<sig><ok>0</ok><bad>0</bad><ign>0</ign></sig>"
            "<aio><num>0</num><max>0</max><rej>0</rej></aio>"
            "<err>%ld</err><rdr>0</rdr><dly>0</dly>"
            "<lgn><num>%ld</num><af>0</af><au>0</au><ua>0</ua></lgn>"
            "</stats>",
            (long) ctx->metrics->connections_total, ok_open,
            (long) ctx->metrics->op_ok[BRIX_OP_READ],
            (long) ctx->metrics->op_ok[BRIX_OP_PGREAD],
            (long) ctx->metrics->op_ok[BRIX_OP_READV],
            (long) ctx->metrics->op_ok[BRIX_OP_WRITEV],
            (long) ctx->metrics->op_ok[BRIX_OP_WRITE],
            (long) ctx->metrics->op_ok[BRIX_OP_SYNC],
            misc, err_sum,
            (long) ctx->metrics->op_ok[BRIX_OP_LOGIN]);
    }

    /* oss + sgen ride the full document only, mirroring stock's 'a'. */
    if ((sel & BRIX_QSTATS_ALL) == BRIX_QSTATS_ALL) {
        struct statvfs vfs;

        stats_append(resp, sizeof(resp), &pos,
            "<stats id=\"ofs\"><role>%s</role></stats>",
            conf->manager_mode ? "manager" : "server");
        if (conf->common.root_canon[0] != '\0'
            && statvfs(conf->common.root_canon, &vfs) == 0)
        {
            stats_append(resp, sizeof(resp), &pos,
                "<stats id=\"oss\" v=\"2\"><paths>1"
                "<stats id=\"0\"><lp>\"/\"</lp><rp>\"%s\"</rp>"
                "<tot>%llu</tot><free>%llu</free>"
                "<ino>%llu</ino><ifr>%llu</ifr></stats></paths>"
                "<space>0</space></stats>",
                conf->common.root_canon,
                (unsigned long long) (vfs.f_blocks * (vfs.f_frsize / 1024)),
                (unsigned long long) (vfs.f_bavail * (vfs.f_frsize / 1024)),
                (unsigned long long) vfs.f_files,
                (unsigned long long) vfs.f_favail);
        }
        stats_append(resp, sizeof(resp), &pos,
            "<stats id=\"sgen\"><as>1</as><et>0</et><toe>%ld</toe></stats>",
            (long) now);
    }

    stats_append(resp, sizeof(resp), &pos, "</statistics>");

    brix_log_access(ctx, c, "QUERY", "-", "stats", 1, 0, NULL, 0);
    BRIX_OP_OK(ctx, BRIX_OP_QUERY_STATS);
    return brix_send_ok(ctx, c, resp, (uint32_t) (pos + 1));
}

/* Prologue for kXR_Qxattr: extract the request path, resolve it beneath the
 * export root, run the read auth gate, and VFS-probe the target (following
 * symlinks). Fills pathbuf, full_path and the vctx/vst it probes into. Returns NGX_OK to proceed, or
 * the send rc / ctx->write_rc that the caller must return on any failure. */
static ngx_int_t
xattr_resolve_and_probe(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, char *pathbuf, char *full_path,
    brix_vfs_ctx_t *vctx, brix_vfs_stat_t *vst)
{
    if (ctx->recv.cur_dlen == 0 || ctx->recv.payload == NULL) {
        BRIX_OP_ERR(ctx, BRIX_OP_QUERY_XATTR);
        return brix_send_error(ctx, c, kXR_ArgMissing, "xattr: path required");
    }
    if (!brix_extract_path(c->log, ctx->recv.payload, ctx->recv.cur_dlen,
                             pathbuf, BRIX_MAX_PATH + 1, 1)) {
        BRIX_OP_ERR(ctx, BRIX_OP_QUERY_XATTR);
        return brix_send_error(ctx, c, kXR_ArgInvalid, "invalid path");
    }
    /* phase74-fp: pathbuf is the request path, full_path the output buf. */
    brix_beneath_full_path(conf->common.root_canon, pathbuf,  /* NOLINT(readability-suspicious-call-argument) */
                              full_path, PATH_MAX);
    if (brix_auth_gate(ctx, c, BRIX_OP_QUERY_XATTR, "QUERY",
                         pathbuf, full_path, conf,
                         BRIX_AUTH_READ, 0) != NGX_OK) {
        return ctx->write_rc;
    }
    /* Stat + xattr list/get all flow through the VFS (one ctx, confined to the
     * export root). probe (follow) replaces the raw stat; OP_STAT is suppressed
     * (probe) so only the enclosing QUERY op is accounted. */
    brix_vfs_ctx_init(vctx, c->pool, c->log, BRIX_PROTO_ROOT,
        conf->common.root_canon, NULL,
        brix_vfs_policy_from_write_enable(conf->common.allow_write),
        0 /* is_tls */, NULL, full_path);
    if (brix_vfs_probe(vctx, 0 /* follow */, vst) != NGX_OK) {
        BRIX_OP_ERR(ctx, BRIX_OP_QUERY_XATTR);
        return brix_send_error(ctx, c, brix_kxr_from_errno(errno),
                                 strerror(errno));
    }
    return NGX_OK;
}

/* brix_query_xattr — kXR_Qxattr: list a path's extended attributes through the
 * full security chain (extract → resolve → authdb → VO ACL → stat), returning the
 * oss.* key-values plus any user.U.*-prefixed xattrs. */
ngx_int_t
brix_query_xattr(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf)
{
    char              pathbuf[BRIX_MAX_PATH + 1];
    char              full_path[PATH_MAX];
    char              resp[4096];
    int               pos = 0;
    char              raw_list[4096];
    ssize_t           list_sz;
    brix_vfs_ctx_t  vctx;
    brix_vfs_stat_t vst;
    char              ftype;
    char              facc;

    {
        ngx_int_t prc = xattr_resolve_and_probe(ctx, c, conf, pathbuf,
                                                full_path, &vctx, &vst);
        if (prc != NGX_OK) {
            return prc;
        }
    }

    /* SECURITY: a stat/probe succeeds for anyone who can merely TRAVERSE to the
     * file (POSIX), so the probe alone would expose oss.used (size) + the user.U.*
     * xattrs of a peer's UNREADABLE 0600 file to a cross-tenant caller who can
     * reach its 0755 parent — a metadata oracle.  UNDER IMPERSONATION only (the
     * cross-tenant case), require actual READ access as the mapped user via the
     * broker, the same gate query-checksum enforces.  Gating on
     * brix_imp_client_active() leaves the single-identity (non-map) path byte-for-
     * byte unchanged — no new open() for a server that has one filesystem view. */
    if (vst.is_regular && brix_imp_client_active()) {
        int rfd = brix_vfs_open_fd(c->log, conf->common.root_canon, full_path,
                                     O_RDONLY, 0);
        if (rfd < 0) {
            BRIX_OP_ERR(ctx, BRIX_OP_QUERY_XATTR);
            return brix_send_error(ctx, c, brix_kxr_from_errno(errno),
                                     strerror(errno));
        }
        close(rfd);
    }

    if (vst.is_regular) {
        ftype = 'f';
    } else if (vst.is_directory) {
        ftype = 'd';
    } else {
        ftype = 'o';
    }

    facc = (vst.mode & S_IWUSR) ? 'w' : 'r';

    pos = snprintf(resp, sizeof(resp) - 1,
                   "oss.cgroup=default&oss.type=%c&oss.used=%lld"
                   "&oss.mt=%ld&oss.ct=%ld&oss.at=%ld"
                   "&oss.u=*&oss.g=*&oss.fs=%c",
                   ftype, (long long) vst.size,
                   (long) vst.mtime, (long) vst.ctime, (long) vst.atime,
                   facc);

    list_sz = brix_vfs_listxattr(&vctx, raw_list, sizeof(raw_list));
    if (list_sz > 0) {
        char *lp = raw_list;
        char *lend = raw_list + list_sz;

        while (lp < lend && pos < (int) sizeof(resp) - 256) {
            size_t nlen = strlen(lp);

            if (strncmp(lp, "user.U.", 7) == 0 && nlen > 7) {
                char    val[1024];
                ssize_t vlen;

                vlen = brix_vfs_getxattr(&vctx, lp, val, sizeof(val) - 1);
                if (vlen >= 0) {
                    val[vlen] = '\0';
                    pos += snprintf(resp + pos, sizeof(resp) - pos - 1,
                                    "&%s=%.*s", lp + 5, (int) vlen, val);
                }
            }

            lp += nlen + 1;
        }
    }

    brix_log_access(ctx, c, "QUERY", pathbuf, "xattr", 1, 0, NULL, 0);
    BRIX_OP_OK(ctx, BRIX_OP_QUERY_XATTR);

    return brix_send_ok(ctx, c, resp, (uint32_t) (pos + 1));
}

/* brix_query_finfo — kXR_QFinfo: returns "0" placeholder (matches reference
 * XRootD, which serves this via the XrdOfs plugin layer nginx-xrootd lacks). */
ngx_int_t
brix_query_finfo(brix_ctx_t *ctx, ngx_connection_t *c)
{
    brix_log_access(ctx, c, "QUERY", "-", "finfo", 1, 0, NULL, 0);
    BRIX_OP_OK(ctx, BRIX_OP_QUERY_FINFO);
    return brix_send_ok(ctx, c, "0", 2);
}

/* brix_query_visa — kXR_Qvisa: validate the fhandle, then return FSctl-
 * unsupported (matches reference XRootD without the XrdOfs plugin layer). */
ngx_int_t
brix_query_visa(brix_ctx_t *ctx, ngx_connection_t *c,
    const xrdw_query_req_t *req)
{
    int       idx;
    ngx_int_t rc;

    idx = (int) (unsigned char) req->fhandle[0];
    if (!brix_validate_file_handle(ctx, c, idx, "QUERY",
                                     BRIX_OP_QUERY_VISA, &rc)) {
        return rc;
    }

    return brix_query_fctl_unsupported(ctx, c, ctx->files[idx].path,
                                         "visa", BRIX_OP_QUERY_VISA);
}

/* brix_query_opaque — kXR_Qopaque: validate payload presence, then return
 * FSctl-unsupported (matches reference XRootD without the XrdOfs plugin layer). */
ngx_int_t
brix_query_opaque(brix_ctx_t *ctx, ngx_connection_t *c)
{
    if (ctx->recv.payload == NULL || ctx->recv.cur_dlen == 0) {
        return brix_query_arg_missing(ctx, c, "opaque",
                                        BRIX_OP_QUERY_OPAQUE);
    }

    return brix_query_fsctl_unsupported(ctx, c, "-", "opaque",
                                          BRIX_OP_QUERY_OPAQUE);
}

/* brix_query_opaquf — kXR_Qopaquf: run the security chain (extract →
 * resolve_noexist → authdb → VO ACL), then return fctl-unsupported (reference parity). */
ngx_int_t
brix_query_opaquf(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf)
{
    char pathbuf[BRIX_MAX_PATH + 1];
    char full_path[PATH_MAX];

    if (ctx->recv.payload == NULL || ctx->recv.cur_dlen == 0) {
        return brix_query_arg_missing(ctx, c, "opaquf",
                                        BRIX_OP_QUERY_OPAQUF);
    }

    if (!brix_extract_path(c->log, ctx->recv.payload, ctx->recv.cur_dlen,
                             pathbuf, sizeof(pathbuf), 1)) {
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_QUERY_OPAQUF, "QUERY", "-",
                          "opaquf", kXR_ArgInvalid, "invalid path");
    }

    /* phase74-fp: pathbuf is the request path, full_path the output buf. */
    brix_beneath_full_path(conf->common.root_canon, pathbuf,  /* NOLINT(readability-suspicious-call-argument) */
                              full_path, sizeof(full_path));

    if (brix_auth_gate(ctx, c, BRIX_OP_QUERY_OPAQUF, "QUERY",
                         pathbuf, full_path, conf,
                         BRIX_AUTH_READ, 0) != NGX_OK) {
        return ctx->write_rc;
    }

    return brix_query_fsctl_unsupported(ctx, c, pathbuf, "opaquf",
                                          BRIX_OP_QUERY_OPAQUF);
}

/* brix_query_opaqug — kXR_Qopaqug: validate the fhandle and detect TPC
 * cancellation ("ofs.tpc cancel", else kXR_FSError), then return fctl-unsupported. */
ngx_int_t
brix_query_opaqug(brix_ctx_t *ctx, ngx_connection_t *c,
    const xrdw_query_req_t *req)
{
    int       idx;
    ngx_int_t rc;

    idx = (int) (unsigned char) req->fhandle[0];
    if (!brix_validate_file_handle(ctx, c, idx, "QUERY",
                                     BRIX_OP_QUERY_OPAQUG, &rc)) {
        return rc;
    }

    if (brix_query_payload_equals(ctx, "ofs.tpc cancel")) {
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_QUERY_OPAQUG, "QUERY",
                          ctx->files[idx].path, "opaqug",
                          kXR_FSError, "tpc operation not found");
    }

    return brix_query_fctl_unsupported(ctx, c, ctx->files[idx].path,
                                         "opaqug", BRIX_OP_QUERY_OPAQUG);

}
