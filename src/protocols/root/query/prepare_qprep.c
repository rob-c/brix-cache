#include "query_internal.h"
#include "prepare_internal.h"
#include "fs/path/beneath.h"
#include "fs/xfer/stage_request_registry.h"
#include "core/compat/alloc_guard.h"

#include <errno.h>
#include <sys/stat.h>

/*
 * prepare_qprep.c — kXR_QPrep staging-status query handler (split from
 * prepare.c so each file owns one wire verb and stays under the size cap).
 *
 * WHAT: answers "is each of these paths resident?" for paths named in a prior
 *       kXR_prepare (or inline in the query).  Emits one "<status> <path>" line
 *       per file: 'A' resident, 'M' missing/unauthorized, or a live FRM queue
 *       state ('q' queued, 's' staging, 'f' failed) when the durable queue has a
 *       record for a not-yet-resident file.
 * WHY:  clients poll QPrep to learn when a staged/recalled file has landed,
 *       across reconnects; the FRM queue-state passthrough lets a poll follow a
 *       real recall to completion instead of flapping on a bare 'M'.
 * HOW:  capture the request-id (first payload line), pick the path list (inline
 *       lines after the id, else the stored prepare list), then for each path
 *       run the SAME auth chain as prepare before reporting residency.  A path
 *       that fails any auth tier reports 'M' — identical to xrootd reference
 *       behaviour and never an authorization oracle.
 */

/* Phase 35: map a durable queue status to the QPrep per-path status letter.
 * 'A' available/online, 'q' queued, 's' staging, 'f' failed, 'M' missing. */
static char
qprep_status_letter(brix_stage_req_status_t s)
{
    switch (s) {
    case BRIX_STAGE_REQ_QUEUED: return 'q';
    case BRIX_STAGE_REQ_ACTIVE: return 's';
    case BRIX_STAGE_REQ_DONE:   return 'A';
    case BRIX_STAGE_REQ_FAILED: return 'f';
    default:                      return 'M';
    }
}

/*
 * Authorize the path through the same three tiers prepare uses (authdb VO/ACL,
 * VO identity ACL, token scope).  Boolean: a denial is silent (the caller maps
 * it to 'M'), so this never sends a wire response.
 */
static ngx_flag_t
qprep_path_authorized(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const char *pathbuf, const char *full_path)
{
    return brix_authz_check(ctx, c, conf, pathbuf, full_path, "PREPARE",
                              BRIX_AUTH_READ, BRIX_AOP_STAGE) == NGX_OK
        && brix_check_vo_acl_identity(c->log, full_path, conf->vo_rules,
                                        ctx->identity) == NGX_OK
        && brix_check_token_scope(ctx, pathbuf, 0) == NGX_OK;
}

/*
 * Residency status letter for one already-extracted logical path.  Unauthorized
 * or non-resident with no live queue record → 'M'; resident regular file → 'A';
 * otherwise the FRM queue state when a durable record exists.
 */
static char
qprep_status_for_path(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const char *pathbuf, const char *full_path)
{
    struct stat st;

    if (!qprep_path_authorized(ctx, c, conf, pathbuf, full_path)) {
        return 'M';
    }

    if (brix_stat_beneath(conf->rootfd, pathbuf, &st) == 0 && S_ISREG(st.st_mode)) {
        return 'A';                                   /* resident on disk */
    }

    if (conf->frm.enable && brix_stage_registry_singleton() != NULL) {
        brix_stage_registry_t *reg = brix_stage_registry_singleton();
        brix_stage_request_t   qrec;
        char                     frq[BRIX_STAGE_REQID_LEN];

        if (brix_stage_request_find_by_path(reg, full_path, frq, sizeof(frq),
                                              c->log) == NGX_OK
            && brix_stage_request_get(reg, frq, &qrec, c->log) == NGX_OK)
        {
            return qprep_status_letter(qrec.status);
        }
    }

    return 'M';
}

/*
 * Capture the request-id from the first payload line (trimmed of trailing
 * CR/NUL) into `reqid`, and return the pointer just past that line (the start of
 * the inline path list, if any).  `reqid` is left "" when absent/oversized.
 */
static const u_char *
qprep_capture_reqid(const u_char *p, const u_char *end, char *reqid,
    size_t reqid_sz)
{
    const u_char *rid = p;
    size_t        reqid_len;

    while (p < end && *p != '\n') {
        p++;
    }
    reqid_len = (size_t) (p - rid);
    while (reqid_len > 0 && (rid[reqid_len - 1] == '\r' || rid[reqid_len - 1] == '\0')) {
        reqid_len--;
    }
    if (reqid_len > 0 && reqid_len < reqid_sz) {
        ngx_memcpy(reqid, rid, reqid_len);
        reqid[reqid_len] = '\0';
    } else {
        reqid[0] = '\0';
    }

    if (p < end) {
        p++;  /* consume '\n' */
    }
    return p;
}

/*
 * Choose the path list to report on: inline lines after the reqid, else the
 * session's stored prepare list.  Returns NGX_DECLINED with src and src_len set
 * when a list is available (proceed); otherwise it has already sent the terminal
 * response (an ok with no body, or — for a named id we never issued — a
 * kXR_ArgInvalid reject like reference do_Prepare(isQuery)) and returns that rc.
 */
static ngx_int_t
qprep_resolve_src(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const u_char *p, const u_char *end,
    const char *reqid, const u_char **src, size_t *src_len)
{
    if (p < end) {
        *src     = p;
        *src_len = (size_t) (end - p);
        return NGX_DECLINED;
    }

    if (ctx->prepare.paths != NULL && ctx->prepare.paths_len > 0) {
        *src     = ctx->prepare.paths;
        *src_len = ctx->prepare.paths_len;
        return NGX_DECLINED;
    }

    if (reqid[0] != '\0') {
        brix_stage_request_t rec;
        int known = (conf->frm.enable
                     && brix_stage_registry_singleton() != NULL
                     && brix_stage_request_get(
                            brix_stage_registry_singleton(), reqid, &rec,
                            c->log) == NGX_OK);
        if (!known) {
            return brix_prepare_send_fail(ctx, c, reqid, kXR_ArgInvalid,
                "Prepare requestid owned by an unknown server");
        }
    }
    return brix_send_ok(ctx, c, NULL, 0);
}

/*
 * Emit one "<status> <path>\n" record per non-empty path line in [src, src_len)
 * into resp (capacity resp_cap), skipping malformed paths and truncating on
 * overflow.  Returns the number of bytes written (0 = nothing emitted).
 */
static size_t
qprep_emit_all(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const u_char *src, size_t src_len,
    u_char *resp, size_t resp_cap)
{
    const u_char *p   = src;
    const u_char *end = src + src_len;
    u_char       *rp  = resp;

    while (p < end) {
        const u_char *line;
        size_t        line_len;
        char          pathbuf[BRIX_MAX_PATH + 1];
        char          full_path[PATH_MAX];
        char          status_ch;

        line = p;
        while (p < end && *p != '\n') {
            p++;
        }
        line_len = (size_t) (p - line);
        if (p < end) {
            p++;
        }
        while (line_len > 0
               && (line[line_len - 1] == '\r' || line[line_len - 1] == '\0'))
        {
            line_len--;
        }
        if (line_len == 0) {
            continue;
        }

        if (!brix_extract_path(c->log, line, line_len, pathbuf,
                                 sizeof(pathbuf), 1)) {
            continue;  /* skip malformed paths */
        }

        /* Both non-existent and unauthorized paths report 'M', consistent with
         * xrootd reference behavior; a live FRM queue record reports q/s/f. */
        /* phase74-fp: pathbuf is the request path, full_path the output buf. */
        brix_beneath_full_path(conf->common.root_canon, pathbuf,  /* NOLINT(readability-suspicious-call-argument) */
                                 full_path, sizeof(full_path));
        status_ch = qprep_status_for_path(ctx, c, conf, pathbuf, full_path);

        *rp++ = (u_char) status_ch;
        *rp++ = ' ';

        /* Copy logical path into response. */
        if ((size_t) (rp - resp) + line_len + 1 >= resp_cap) {
            break;  /* safety: truncate on overflow */
        }
        ngx_memcpy(rp, pathbuf, strlen(pathbuf));
        rp += strlen(pathbuf);
        *rp++ = '\n';
    }

    return (size_t) (rp - resp);
}

/*
 * kXR_QPrep handler.
 *
 * Payload format (newline-separated):
 *   line 0: request ID (from kXR_prepare response)
 *   line 1+: optional paths to check (may be omitted; use stored path list)
 *
 * Response: one "A <path>" / "M <path>" (or q/s/f) line per file, NUL-terminated.
 */
ngx_int_t
brix_query_prep_status(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf)
{
    const u_char *src = NULL;
    size_t        src_len = 0;
    const u_char *p;
    const u_char *end;
    u_char       *resp;
    size_t        resp_cap;
    size_t        nout;
    char          reqid[BRIX_STAGE_REQID_LEN];
    ngx_int_t     rc;

    if (ctx->recv.payload == NULL || ctx->recv.cur_dlen == 0) {
        return brix_send_ok(ctx, c, NULL, 0);
    }

    p   = ctx->recv.payload;
    end = ctx->recv.payload + ctx->recv.cur_dlen;

    /* The first payload line is the prepare request-id.  Capture it so an id we
     * have no record of can be rejected the way reference do_Prepare(isQuery)
     * does. */
    p = qprep_capture_reqid(p, end, reqid, sizeof(reqid));

    rc = qprep_resolve_src(ctx, c, conf, p, end, reqid, &src, &src_len);
    if (rc != NGX_DECLINED) {
        return rc;   /* no path list — response (ok/reject) already sent */
    }

    /* Allocate response buffer: worst case "A " + path + "\n" per line. */
    resp_cap = src_len * 2 + 64;
    BRIX_PALLOC_OR_RETURN(resp, c->pool, resp_cap,
        brix_send_error(ctx, c, kXR_NoMemory, "out of memory"));

    nout = qprep_emit_all(ctx, c, conf, src, src_len, resp, resp_cap);
    if (nout == 0) {
        return brix_send_ok(ctx, c, NULL, 0);
    }

    resp[nout] = '\0';
    brix_log_access(ctx, c, "QPREP", "-", "-", 1, kXR_ok, NULL, 0);
    return brix_send_ok(ctx, c, resp, (uint32_t) (nout + 1));
}
