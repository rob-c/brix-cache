#include "query_internal.h"
#include "prepare_internal.h"
#include "fs/path/beneath.h"
#include "fs/xfer/stage_request_registry.h"

#include <errno.h>
#include <sys/stat.h>
#include <time.h>
#include "core/compat/alloc_guard.h"

#define BRIX_PREPARE_OWNER_KEY_MAX  64

/*
 * WHAT: kXR_prepare — local-storage staging hint. (kXR_QPrep status query lives
 *       in prepare_qprep.c.)
 *       prepare accepts newline-separated path lists, validates each against auth/ACLs/filesystem existence,
 *       optionally invokes a configured staging command (e.g., xrdcp to tape), returns request ID for later status queries.
 *       QPrep queries staging status of prior prepare paths — returns "A <path>" (available) or "M <path>" (missing).
 *
 * WHY:  Staging workflows require clients to submit file lists before actual transfer, enabling servers to initiate
 *       tape nearline retrieval or other pre-transfer operations. prepare stores request ID + path list for QPrep status
 *       queries. Disk-only servers return immediate results since files are either present or absent. Cancel/evict options
 *       allow clients to abort pending staging operations without penalty.
 *
 * HOW:  brix_handle_prepare() parses ClientPrepareRequest — extracts optionX via ntohs, checks kXR_wmode+allow_write,
 *       cancel/evict as noops, payload presence. Pre-allocates stage_paths/stage_bufs if collect_stage (kXR_stage + prepare_command). Parses
 *       newline-separated paths: extract_path → has_forbidden_component() → resolve_path → authdb(vo_acl token_scope) → stat(S_ISDIR check).
 * Fills out_resolved for staging collection. Stores saved payload in ctx->prepare.paths, sets reqid="0", invokes staging command best-effort,
 * returns "0" as response. brix_query_prep_status() parses payload skipping reqid line — uses inline paths or falls back to stored
 * prepare_paths. Allocates resp buffer src_len*2+64, resolves each path + auth chain + stat(S_ISREG) → writes 'A'/'M' prefix per path,
 * NUL-terminates and sends response.
 */

static ngx_flag_t
brix_prepare_has_forbidden_component(const char *path)
{
    const char *p = path;

    while (*p != '\0') {
        const char *seg;
        size_t      len;

        while (*p == '/') {
            p++;
        }

        seg = p;
        while (*p != '\0' && *p != '/') {
            p++;
        }

        len = (size_t) (p - seg);
        if ((len == 1 && seg[0] == '.')
            || (len == 2 && seg[0] == '.' && seg[1] == '.'))
        {
            return 1;
        }
    }

    return 0;
}
/* WHY: kXR_prepare rejects paths containing dot (.) or double-dot (..) components to prevent directory traversal into parent exports. Used as a fast pre-check before full path resolution — avoids expensive resolve_path() calls on obviously invalid paths. */
/* HOW: Scans path character-by-character, skipping leading '/' separators; extracts each segment between slashes via seg→p pointer arithmetic. For each segment checks len==1 && seg[0]=='.' or len==2 && seg[0]=='.' && seg[1]=='.' — if match returns 1 (forbidden). Returns 0 if no forbidden components found after full scan. Static helper used exclusively by brix_prepare_check_path(). */

/*
 * WHAT: Return the stable owner string used for FRM stream prepare records and
 * cancel checks. Authenticated callers use their canonical identity DN/token
 * subject; anonymous callers get a per-login owner key derived from sessid.
 * WHY: FRM cancel authorization compares stored requester strings. Leaving
 * anonymous records owner-less lets any later anonymous session cancel another
 * session's stage request by guessing its reqid.
 * HOW: Borrow the identity string when present. Otherwise render
 * "anon-session:" plus the 16-byte session id as lowercase hex into caller
 * storage and return that buffer. */
static const char *
brix_prepare_owner_key(brix_ctx_t *ctx, char *anon_key, size_t anon_key_sz)
{
    static const char hex[] = "0123456789abcdef";
    static const char prefix[] = "anon-session:";
    const char       *dn;
    size_t            pos;
    ngx_uint_t        i;

    if (ctx == NULL) {
        return NULL;
    }

    dn = brix_identity_dn_cstr(ctx->identity);
    if (dn != NULL && dn[0] != '\0') {
        return dn;
    }

    if (anon_key == NULL || anon_key_sz < sizeof(prefix) + 32) {
        return NULL;
    }

    ngx_memcpy(anon_key, prefix, sizeof(prefix) - 1);
    pos = sizeof(prefix) - 1;
    for (i = 0; i < 16; i++) {
        u_char b = ctx->login.sessid[i];
        anon_key[pos++] = hex[b >> 4];
        anon_key[pos++] = hex[b & 0x0f];
    }
    anon_key[pos] = '\0';
    return anon_key;
}

ngx_int_t
brix_prepare_send_fail(brix_ctx_t *ctx, ngx_connection_t *c,
    const char *path, uint16_t errcode, const char *errmsg)
{
    brix_log_access(ctx, c, "PREPARE", path != NULL ? path : "-",
                      "-", 0, errcode, errmsg, 0);

    return brix_send_error(ctx, c, errcode, errmsg);
}
/* WHY: kXR_prepare responses use a unified error format — log access event then send wire response. This helper centralizes the logging + response pattern so callers don't duplicate both steps. Returns brix_send_error() result directly for callers that need the raw nginx_int_t return code. */
/* HOW: Logs access event via brix_log_access(ctx, c, "PREPARE", path or "-", "-", 0, errcode, errmsg, 0) — then calls brix_send_error(ctx, c, errcode, errmsg) and returns its result. Static helper used by check_path and handle_prepare for error responses. */

static ngx_int_t
brix_prepare_check_fail(brix_ctx_t *ctx, ngx_connection_t *c,
    const char *path, uint16_t errcode, const char *errmsg)
{
    ngx_int_t rc;

    rc = brix_prepare_send_fail(ctx, c, path, errcode, errmsg);
    return (rc == NGX_OK) ? NGX_DONE : rc;
}
/* WHY: kXR_prepare check_path callers need NGX_DONE (continue processing) vs NGX_ERROR (abort). This helper converts the brix_send_error() result into the appropriate return code — NGX_OK from send_error becomes NGX_DONE for graceful continuation, other results pass through as abort codes. Used by check_path to distinguish between "error logged but continue" and "fatal error" returns. */
/* HOW: Calls brix_prepare_send_fail(ctx, c, path, errcode, errmsg) — if result == NGX_OK returns NGX_DONE (graceful continuation), otherwise returns the raw result code unchanged. Static helper used exclusively by check_path(). */

/*
 * WHAT: run the three prepare authorization tiers (authdb VO/ACL, VO identity
 *       ACL, token scope) on one resolved path.
 * WHY:  the existing-file and noerrs-absent branches of check_path must apply
 *       the SAME gate on the SAME paths (verdict parity between "exists" and
 *       "absent") — factoring it here removes the duplication AND guarantees the
 *       two branches can never drift apart.  Authorization is a property of the
 *       identity + logical path, not of on-disk existence.
 * HOW:  each tier that denies sends its specific error via check_fail and its rc
 *       (NGX_DONE/error) is returned; NGX_OK only when all three pass.
 */
static ngx_int_t
prepare_path_authz(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const char *pathbuf, const char *full_path)
{
    if (brix_authz_check(ctx, c, conf, pathbuf, full_path, "PREPARE",
                           BRIX_AUTH_READ, BRIX_AOP_STAGE) != NGX_OK) {
        return brix_prepare_check_fail(ctx, c, full_path, kXR_NotAuthorized,
                                         "not authorized");
    }
    if (brix_check_vo_acl_identity(c->log, full_path, conf->vo_rules,
                                     ctx->identity) != NGX_OK) {
        return brix_prepare_check_fail(ctx, c, full_path, kXR_NotAuthorized,
                                         "VO not authorized");
    }
    if (brix_check_token_scope(ctx, pathbuf, 0) != NGX_OK) {
        return brix_prepare_check_fail(ctx, c, pathbuf, kXR_NotAuthorized,
                                         "token scope denied");
    }
    return NGX_OK;
}

/*
 * Map a confined-stat failure (non-noerrs, or non-ENOENT errno) to the wire
 * error: ENOENT/ENOTDIR → kXR_NotFound, EACCES/EPERM → kXR_NotAuthorized, any
 * other errno → kXR_IOError.  Returns the check_fail rc (NGX_DONE/error).
 */
static ngx_int_t
prepare_stat_error(brix_ctx_t *ctx, ngx_connection_t *c,
    const char *pathbuf, const char *full_path)
{
    if (errno == ENOENT || errno == ENOTDIR) {
        return brix_prepare_check_fail(ctx, c, pathbuf, kXR_NotFound,
                                         "file not found");
    }
    if (errno == EACCES || errno == EPERM) {
        return brix_prepare_check_fail(ctx, c, full_path, kXR_NotAuthorized,
                                         "not authorized");
    }
    return brix_prepare_check_fail(ctx, c, full_path, kXR_IOError,
                                     "prepare stat failed");
}

static ngx_int_t
brix_prepare_check_path(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const u_char *line, size_t line_len,
    ngx_flag_t noerrs, ngx_uint_t *missing,
    char *out_resolved)   /* PATH_MAX buffer filled with absolute path on
                             auth-pass paths; '\0' if path cannot be resolved.
                             Pass NULL when staging collection is not needed. */
{
    char         pathbuf[BRIX_MAX_PATH + 1];
    char         full_path[PATH_MAX];
    struct stat  st;

    if (line_len > BRIX_MAX_PATH) {
        return brix_prepare_check_fail(ctx, c, "-", kXR_ArgTooLong,
                                         "prepare path too long");
    }

    if (!brix_extract_path(c->log, line, line_len, pathbuf,
                             sizeof(pathbuf), 1)) {
        return brix_prepare_check_fail(ctx, c, "-", kXR_ArgInvalid,
                                         "invalid prepare path");
    }

    if (brix_prepare_has_forbidden_component(pathbuf)) {
        return brix_prepare_check_fail(ctx, c, pathbuf, kXR_ArgInvalid,
                                         "invalid prepare path");
    }

    /* phase74-fp: pathbuf is the request path, full_path the output buf. */
    brix_beneath_full_path(conf->common.root_canon, pathbuf,  /* NOLINT(readability-suspicious-call-argument) */
                             full_path, sizeof(full_path));

    /*
     * CONTRACT: the same "file is absent" condition (ENOENT/ENOTDIR from the
     * confined stat) has two outcomes selected by the kXR_noerrs flag:
     *   - noerrs set  → not an error. The path is counted in *missing and the
     *     request still succeeds, so a client can prepare/stage files that do
     *     not exist on disk yet (tape nearline recall, not-yet-cached objects).
     *   - noerrs clear → kXR_NotFound, failing the request on the first miss.
     * EACCES/EPERM and any other errno always fail regardless of noerrs.
     */
    if (brix_stat_beneath(conf->rootfd, pathbuf, &st) != 0) {
        if ((errno == ENOENT || errno == ENOTDIR) && noerrs) {
            (*missing)++;
            /* SECURITY: authorization is a property of the IDENTITY + LOGICAL
             * PATH, not of on-disk existence. A prepare/stage of a not-yet-
             * materialised object (tape nearline recall, not-yet-cached) must
             * still prove the caller may READ/STAGE this namespace path —
             * otherwise an unauthorized principal drives recalls or enumerates
             * the namespace via prepare, and later serves the recalled bytes from
             * the shared cache. Run the SAME three tiers, on the SAME paths, as
             * the existing-file branch below (verdict parity between "exists" and
             * "absent"); only then supply the staging path. */
            {
                ngx_int_t arc = prepare_path_authz(ctx, c, conf, pathbuf,
                                                     full_path);
                if (arc != NGX_OK) {
                    return arc;
                }
            }
            /* For staging: supply absolute path even if file doesn't exist yet
             * (tape nearline / not-yet-created). */
            if (out_resolved != NULL) {
                ngx_cpystrn((u_char *) out_resolved, (u_char *) full_path,
                            PATH_MAX);
            }
            return NGX_OK;
        }
        return prepare_stat_error(ctx, c, pathbuf, full_path);
    }

    {
        ngx_int_t arc = prepare_path_authz(ctx, c, conf, pathbuf, full_path);
        if (arc != NGX_OK) {
            return arc;
        }
    }

    /* Copy the absolute export path for the staging command; only authorized
     * paths reach here so the staging hook can trust the value. */
    if (out_resolved != NULL) {
        ngx_cpystrn((u_char *) out_resolved, (u_char *) full_path, PATH_MAX);
    }

    if (S_ISDIR(st.st_mode)) {
        if (noerrs) {
            (*missing)++;
            return NGX_OK;
        }
        return brix_prepare_check_fail(ctx, c, pathbuf, kXR_isDirectory,
                                         "prepare target is a directory");
    }

    return NGX_OK;
}

/* Phase 35: kXR_prepare + kXR_cancel — delete the named request from the durable
 * queue. The reqid is the first payload line. Idempotent: an unknown reqid still
 * returns kXR_ok (no enumeration oracle). */
static ngx_int_t
brix_prepare_handle_cancel(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf)
{
    char                     reqid[BRIX_STAGE_REQID_LEN];
    char                     owner_key[BRIX_PREPARE_OWNER_KEY_MAX];
    brix_stage_registry_t *reg = brix_stage_registry_singleton();
    const u_char            *p, *end;
    size_t                   n;

    if (ctx->recv.payload == NULL || ctx->recv.cur_dlen == 0) {
        return brix_prepare_send_fail(ctx, c, "-", kXR_ArgMissing,
                                        "prepare requestid not specified");
    }
    p   = ctx->recv.payload;
    end = ctx->recv.payload + ctx->recv.cur_dlen;
    while (p < end && *p != '\n' && *p != '\r' && *p != '\0') {
        p++;
    }
    n = (size_t) (p - ctx->recv.payload);
    if (n == 0 || n >= sizeof(reqid)) {
        return brix_prepare_send_fail(ctx, c, "-", kXR_ArgMissing,
                                        "prepare requestid not specified");
    }
    ngx_memcpy(reqid, ctx->recv.payload, n);
    reqid[n] = '\0';

    /* FRM-1: a request may only be cancelled by the owner that created it.
     * Anonymous stream callers are scoped to their login session id, so another
     * anonymous session cannot cancel by guessing a durable reqid. */
    if (brix_stage_request_owner_check(reg, reqid,
                                brix_prepare_owner_key(ctx, owner_key,
                                                         sizeof(owner_key)),
                                c->log) != NGX_OK)
    {
        brix_log_access(ctx, c, "PREPARE", reqid, "cancel-denied", 0,
                          kXR_NotAuthorized, NULL, 0);
        return brix_prepare_send_fail(ctx, c, reqid, kXR_NotAuthorized,
                                        "not the owner of this request");
    }

    (void) brix_stage_request_delete(reg, reqid, c->log);      /* idempotent */
    brix_log_access(ctx, c, "PREPARE", reqid, "cancel", 1, kXR_ok, NULL, 0);
    return brix_send_ok(ctx, c, NULL, 0);
}

/*
 * Shared state for the kXR_prepare path-scan pipeline (alloc → scan → emit).
 * Passed by pointer so the three phases read/accumulate the same counters and
 * staging buffers without a long positional argument list.  group_reqid points
 * at a caller-owned BRIX_STAGE_REQID_LEN buffer.
 */
typedef struct {
    ngx_stream_brix_srv_conf_t *conf;
    uint16_t     options;          /* req.options snapshot */
    ngx_flag_t   need_resolved;    /* fill out_resolved (legacy cmd OR enqueue) */
    ngx_flag_t   do_enqueue;       /* enqueue into the durable FRM queue        */
    ngx_flag_t   collect_stage;    /* collect paths for brix_prepare_command    */
    const char **stage_paths;      /* pool array, stage_max entries             */
    char        *stage_bufs;       /* pool array, stage_max * PATH_MAX          */
    ngx_uint_t   stage_max;
    ngx_uint_t   stage_count;      /* accumulated resolved paths                */
    ngx_uint_t   paths;            /* non-empty lines seen                       */
    ngx_uint_t   missing;          /* absent-but-authorized paths (noerrs)      */
    char        *group_reqid;      /* first durable reqid = client handle        */
} prepare_scan_t;

/*
 * Pre-allocate the staging collection arrays when a resolved path list is
 * needed.  Cap at BRIX_PREPARE_CMD_MAX_PATHS (typically dlen/2 paths, but
 * bounded to avoid excessive allocation).  No-op when need_resolved is clear.
 */
static ngx_int_t
prepare_alloc_stage_arrays(ngx_connection_t *c, prepare_scan_t *sc, size_t dlen)
{
    if (!sc->need_resolved) {
        return NGX_OK;
    }

    sc->stage_max = dlen / 2 + 1;
    if (sc->stage_max > BRIX_PREPARE_CMD_MAX_PATHS) {
        sc->stage_max = BRIX_PREPARE_CMD_MAX_PATHS;
    }

    sc->stage_paths = ngx_palloc(c->pool, sizeof(const char *) * sc->stage_max);
    sc->stage_bufs  = ngx_palloc(c->pool, (size_t) sc->stage_max * PATH_MAX);
    if (sc->stage_paths == NULL || sc->stage_bufs == NULL) {
        return NGX_ERROR;
    }
    return NGX_OK;
}

/*
 * Accept one authorized, resolved path: durably enqueue it (FRM) and/or collect
 * it for the legacy staging command.  The first durable reqid becomes the client
 * handle.  The caller advances stage_count after this returns.
 */
static void
prepare_enqueue_resolved(brix_ctx_t *ctx, ngx_connection_t *c,
    prepare_scan_t *sc, char *out_resolved)
{
    if (sc->do_enqueue) {
        brix_stage_request_view_t v;
        char        rq[BRIX_STAGE_REQID_LEN];
        ngx_int_t   arc;
        /* Record the canonical identity DN/token subject, or a scoped
         * anonymous-session key, so the cancel-owner check has the same
         * owner string. */
        char        owner_key[BRIX_PREPARE_OWNER_KEY_MAX];
        const char *rdn = brix_prepare_owner_key(ctx, owner_key,
                                                   sizeof(owner_key));

        ngx_memzero(&v, sizeof(v));
        v.lfn          = out_resolved;
        v.requester_dn = (rdn != NULL && rdn[0] != '\0') ? rdn : NULL;
        v.tod_expire   = (int64_t) time(NULL)
                       + (int64_t) (sc->conf->frm.stage_ttl / 1000);

        arc = brix_stage_request_add(brix_stage_registry_singleton(),
                                       &v, rq, sizeof(rq), c->log);
        if (arc == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                          "brix: stage request add failed for \"%s\"",
                          out_resolved);
        } else if (sc->group_reqid[0] == '\0') {
            /* The first request id is the handle returned to the client. */
            ngx_cpystrn((u_char *) sc->group_reqid, (u_char *) rq,
                        BRIX_STAGE_REQID_LEN);
        }
        /* NOTE (engine-integration step): driving the recall — the former
         * frm_stage_kick() — moves to brix_stage_submit(RECALL) + the engine
         * scheduler; the composable sd_frm backend also faults the recall on
         * read, so the request is durably recorded here. */
    }
    if (sc->collect_stage) {
        sc->stage_paths[sc->stage_count] = out_resolved;
    }
}

/*
 * Parse the newline-separated payload, validate + authorize each path via
 * brix_prepare_check_path, and enqueue/collect the ones that pass.  Returns
 * NGX_OK when the whole list scanned; NGX_DONE or an error rc when a path failed
 * (check_path already sent the response) — the caller maps NGX_DONE to NGX_OK.
 */
static ngx_int_t
prepare_scan_paths(brix_ctx_t *ctx, ngx_connection_t *c, prepare_scan_t *sc)
{
    const u_char *p   = ctx->recv.payload;
    const u_char *end = ctx->recv.payload + ctx->recv.cur_dlen;

    while (p < end) {
        const u_char *line;
        size_t        line_len;
        ngx_int_t     rc;
        char         *out_resolved;

        line = p;
        while (p < end && *p != '\n') {
            p++;
        }

        line_len = (size_t) (p - line);
        if (p < end && *p == '\n') {
            p++;
        }

        while (line_len > 0
               && (line[line_len - 1] == '\r'
                   || line[line_len - 1] == '\0'))
        {
            line_len--;
        }

        if (line_len == 0) {
            continue;
        }

        sc->paths++;

        /* Point out_resolved at the next slot in the staging buffer (when the
         * legacy command OR the durable queue needs the resolved path) so
         * brix_prepare_check_path fills it in-place. */
        if (sc->need_resolved && sc->stage_count < sc->stage_max) {
            out_resolved = sc->stage_bufs + sc->stage_count * PATH_MAX;
            out_resolved[0] = '\0';
        } else {
            out_resolved = NULL;
        }

        rc = brix_prepare_check_path(ctx, c, sc->conf, line, line_len,
                                       (sc->options & kXR_noerrs) != 0,
                                       &sc->missing, out_resolved);
        if (rc != NGX_OK) {
            return rc;   /* NGX_DONE (response sent) or a hard error */
        }

        if (out_resolved != NULL && out_resolved[0] != '\0') {
            prepare_enqueue_resolved(ctx, c, sc, out_resolved);
            sc->stage_count++;
        }
    }

    return NGX_OK;
}

/*
 * kXR_stage tail: persist the path list for later kXR_QPrep queries, launch the
 * legacy staging command if configured, and (kXR_notify) fold an asyncms
 * "complete" notification into the ok response when nothing is still missing.
 * Returns the queued-response rc.
 */
static ngx_int_t
prepare_emit_stage(brix_ctx_t *ctx, ngx_connection_t *c, prepare_scan_t *sc)
{
    u_char     *saved;
    const char *resp_reqid;
    size_t      resp_reqid_len;

    /* The request handle: the durable reqid when enqueued, else legacy "0". */
    resp_reqid     = (sc->do_enqueue && sc->group_reqid[0] != '\0')
                   ? sc->group_reqid : "0";
    resp_reqid_len = ngx_strlen(resp_reqid);

    saved = ngx_alloc((size_t) ctx->recv.cur_dlen + 1, c->log);
    if (saved == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(saved, ctx->recv.payload, ctx->recv.cur_dlen);
    saved[ctx->recv.cur_dlen] = '\0';

    if (ctx->prepare.paths != NULL) {
        ngx_free(ctx->prepare.paths);
    }

    ngx_cpystrn((u_char *) ctx->prepare.reqid, (u_char *) resp_reqid,
                sizeof(ctx->prepare.reqid));
    ctx->prepare.paths     = saved;
    ctx->prepare.paths_len = ctx->recv.cur_dlen;

    /* Invoke the staging command if configured and paths were collected. */
    if (sc->collect_stage && sc->stage_count > 0) {
        if (brix_prepare_invoke_command(c->log, sc->conf,
                                          sc->stage_paths, sc->stage_count,
                                          (sc->options & kXR_coloc) != 0)
            != NGX_OK)
        {
            ngx_log_error(NGX_LOG_ERR, c->log, ngx_errno,
                          "brix: prepare_command launch failed");
            /* Best-effort: continue and return ok to the client. */
        }
    } else if (sc->collect_stage && sc->stage_count == 0) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "brix: kXR_stage set but no resolvable paths"
                      " for prepare_command");
    }

    /* kXR_notify: send kXR_attn + kXR_asyncms notification when all requested
     * files are already on disk (missing == 0).  The notification is combined
     * with the kXR_ok response in a single buffer to avoid a double-queue race
     * on EAGAIN write paths.  When missing > 0 some files are still being staged
     * by the background command; we cannot know when they arrive, so the
     * notification is omitted and a warning is logged. */
    if (sc->options & kXR_notify) {
        if (sc->missing == 0) {
            char     notify_msg[96];
            size_t   notify_len;
            size_t   ok_len      = XRD_RESPONSE_HDR_LEN + resp_reqid_len;
            size_t   attn_len;
            size_t   total;
            u_char  *buf;

            notify_len = (size_t) snprintf(notify_msg, sizeof(notify_msg),
                             "prepare reqid=%s complete", resp_reqid);
            if (notify_len >= sizeof(notify_msg)) {
                notify_len = sizeof(notify_msg) - 1;
            }
            attn_len = brix_attn_asyncms_frame_len(notify_len);
            total    = ok_len + attn_len;

            BRIX_PALLOC_OR_RETURN(buf, c->pool, total, NGX_ERROR);

            brix_build_resp_hdr(ctx->recv.cur_streamid, kXR_ok,
                                  (uint32_t) resp_reqid_len,
                                  (ServerResponseHdr *) buf);
            ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN, resp_reqid, resp_reqid_len);
            brix_build_attn_asyncms_frame(buf + ok_len, notify_msg, notify_len);

            ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                "brix: sending kXR_prepare ok + kXR_attn asyncms notify");

            return brix_queue_response(ctx, c, buf, total);

        } else {
            ngx_log_error(NGX_LOG_WARN, c->log, 0,
                "brix: kXR_notify requested but %ui path(s) still being "
                "staged; async completion notification not supported",
                sc->missing);
        }
    }

    return brix_send_ok(ctx, c, (u_char *) resp_reqid,
                          (uint32_t) resp_reqid_len);
}

/*
 * Handle the option flags that short-circuit the path scan: read-only rejection
 * (kXR_wmode), cancel (real FRM cancel, or a logged noop), and evict (logged
 * release intent — actual reclamation is delegated to the MSS / WLCG Tape REST
 * /release).  Returns NGX_DECLINED when none applied (proceed to the scan); any
 * other value is the response rc the caller must return.
 */
static ngx_int_t
prepare_dispatch_special(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const xrdw_prepare_req_t *req,
    uint16_t optionx)
{
    char detail[96];

    if ((req->options & kXR_wmode) && !conf->common.allow_write) {
        return brix_prepare_send_fail(ctx, c, "-", kXR_fsReadOnly,
                                        "this is a read-only server");
    }

    if (req->options & kXR_cancel) {
        /* Real cancel against the durable registry when staging is on. */
        if (conf->frm.enable && brix_stage_registry_singleton() != NULL) {
            return brix_prepare_handle_cancel(ctx, c, conf);
        }
        snprintf(detail, sizeof(detail), "noop cancel opts=0x%02x optx=0x%04x",
                 (unsigned int) req->options, (unsigned int) optionx);
        brix_log_access(ctx, c, "PREPARE", "-", detail, 1, kXR_ok, NULL, 0);
        return brix_send_ok(ctx, c, NULL, 0);
    }

    if (optionx & kXR_evict) {
        snprintf(detail, sizeof(detail), "evict opts=0x%02x optx=0x%04x",
                 (unsigned int) req->options, (unsigned int) optionx);
        brix_log_access(ctx, c, "PREPARE", "-", detail, 1, kXR_ok, NULL, 0);
        return brix_send_ok(ctx, c, NULL, 0);
    }

    return NGX_DECLINED;
}

/* public API: brix_handle_prepare() — kXR_prepare staging hint handler * WHAT: Main handler for prepare requests. Parses ClientPrepareRequest, validates newline-separated path list against auth/ACLs/filesystem existence,
 *       optionally invokes configured staging command via brix_prepare_invoke_command(), stores request ID + paths in ctx->prepare.paths for QPrep queries.
 *       Returns "0" as response on kXR_stage; NULL payload on other options. Cancel/evict return noop ok.
 */
/* WHY: kXR_prepare validates each path in a prepare request against auth, ACLs, and filesystem existence before accepting it for staging. Handles two modes: noerrs (skip errors, count missing paths) for staging collections where files may not exist yet (tape nearline), and strict mode (return error on first failure). Fills out_resolved with canonical path when collecting staging arguments. */
/* HOW: Checks line_len > BRIX_MAX_PATH → fail kXR_ArgTooLong. Extracts path via brix_extract_path() — if fails fail kXR_ArgInvalid. Checks forbidden components (dot/dotdot) via has_forbidden_component() — fail kXR_ArgInvalid. Resolves path via brix_resolve_path(): if noerrs and resolve fails, tries resolve_path_noexist() for out_resolved, increments missing count, returns NGX_OK; otherwise fail kXR_NotFound. Auth chain: check_authdb(BRIX_AUTH_READ) → fail kXR_NotAuthorized; check_vo_acl(vo_rules + vo_list) → fail kXR_NotAuthorized; check_token_scope(pathbuf, 0) → fail kXR_NotAuthorized. Copies resolved path to out_resolved via ngx_cpystrn(). stat(resolved): ENOENT/ENOTDIR with noerrs increments missing, returns NGX_OK; without noerrs fail kXR_NotFound; EACCES/EPERM fail kXR_NotAuthorized; other errno fail kXR_IOError. S_ISDIR: noerrs increments missing; otherwise fail kXR_isDirectory. Returns NGX_OK on full pass or NGX_DONE on error. */

ngx_int_t
brix_handle_prepare(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf)
{
    xrdw_prepare_req_t    req;
    uint16_t              optionx;
    char                  detail[96];
    char                  group_reqid[BRIX_STAGE_REQID_LEN];
    prepare_scan_t        sc;
    ngx_int_t             rc;

    xrdw_prepare_req_unpack(((ClientRequestHdr *) ctx->recv.hdr_buf)->body, &req);
    optionx = req.optionX;

    ngx_memzero(&sc, sizeof(sc));
    sc.conf          = conf;
    sc.options       = req.options;
    sc.collect_stage = (req.options & kXR_stage) && conf->prepare_command.len > 0;
    sc.do_enqueue    = (req.options & kXR_stage) && conf->frm.enable
                       && brix_stage_registry_singleton() != NULL;
    sc.need_resolved = sc.collect_stage || sc.do_enqueue;
    sc.group_reqid   = group_reqid;
    group_reqid[0]   = '\0';

    rc = prepare_dispatch_special(ctx, c, conf, &req, optionx);
    if (rc != NGX_DECLINED) {
        return rc;   /* read-only reject, cancel, or evict — response sent */
    }

    if (ctx->recv.cur_dlen == 0 || ctx->recv.payload == NULL) {
        return brix_prepare_send_fail(ctx, c, "-", kXR_ArgMissing,
                                        "prepare file list is missing");
    }

    if (prepare_alloc_stage_arrays(c, &sc, ctx->recv.cur_dlen) != NGX_OK) {
        return NGX_ERROR;
    }

    rc = prepare_scan_paths(ctx, c, &sc);
    if (rc == NGX_DONE) {
        return NGX_OK;
    }
    if (rc != NGX_OK) {
        return rc;
    }

    if (sc.paths == 0) {
        return brix_prepare_send_fail(ctx, c, "-", kXR_ArgMissing,
                                        "prepare file list is empty");
    }

    snprintf(detail, sizeof(detail),
             "paths=%u missing=%u opts=0x%02x optx=0x%04x%s",
             (unsigned int) sc.paths, (unsigned int) sc.missing,
             (unsigned int) req.options, (unsigned int) optionx,
             (req.options & kXR_coloc) ? " (coloc)" : "");

    brix_log_access(ctx, c, "PREPARE", "-", detail, 1, kXR_ok, NULL, 0);

    /* kXR_stage: save the path list for kXR_QPrep queries, launch the staging
     * command, and (kXR_notify) fold in an asyncms completion notification. */
    if (req.options & kXR_stage) {
        return prepare_emit_stage(ctx, c, &sc);
    }

    return brix_send_ok(ctx, c, NULL, 0);
}
/* WHY: kXR_prepare accepts a newline-separated list of paths from clients, validates each against auth/ACLs/filesystem existence, optionally invokes a staging command (e.g., xrdcp to tape), and returns a request ID for later status queries via kXR_QPrep. Supports cancel/evict options as noops, write mode enforcement, and best-effort staging invocation (continues on launch failure). */
/* HOW: Parses ClientPrepareRequest from ctx->recv.hdr_buf — extracts optionX via ntohs(req->optionX). Checks kXR_stage + prepare_command.len > 0 → collect_stage=1. If kXR_wmode && !allow_write fail kXR_fsReadOnly("read-only server"). If kXR_cancel or kXR_evict in optx: log access, send ok with NULL payload (noop). If ctx->recv.cur_dlen==0 || payload==NULL fail kXR_ArgMissing("file list missing"). Pre-allocates stage_paths/stage_bufs arrays via ngx_palloc if collect_stage — caps at BRIX_PREPARE_CMD_MAX_PATHS. Parses payload line-by-line: extracts line_len trimming trailing \r/\NUL, skips empty lines, increments paths count. For each path points out_resolved at staging buffer slot (if collecting), calls brix_prepare_check_path() with noerrs flag from kXR_noerrs — if NGX_DONE returns NGX_OK; if other error returns rc. Accepts non-empty resolved paths into stage_paths array. If paths==0 fail kXR_ArgMissing("empty list"). Logs detail string "paths=%u missing=%u opts=0x%02x optx=0x%04x". If kXR_stage: allocates saved buffer via ngx_alloc, copies payload, frees old ctx->prepare.paths if any, sets reqid="0", stores paths in ctx->prepare.paths/len; invokes staging command via brix_prepare_invoke_command() (best-effort: logs error on failure but continues); returns ok with "0" as response. Otherwise returns ok with NULL. */
