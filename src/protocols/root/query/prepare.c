#include "query_internal.h"
#include "fs/path/beneath.h"
#include "fs/xfer/stage_request_registry.h"

#include <errno.h>
#include <sys/stat.h>
#include <time.h>
#include "core/compat/alloc_guard.h"

#define BRIX_PREPARE_OWNER_KEY_MAX  64

/* Phase 35: map a durable queue status to the QPrep per-path status letter.
 * 'A' available/online, 'q' queued, 's' staging, 'f' failed, 'M' missing. */
static char
brix_prepare_status_char(brix_stage_req_status_t s)
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
 * WHAT: kXR_prepare / kXR_QPrep — local-storage staging hint and status query.
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

static ngx_int_t
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

    brix_beneath_full_path(conf->common.root_canon, pathbuf,
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
            /* For staging: supply absolute path even if file doesn't exist yet
             * (tape nearline / not-yet-created).  Auth checks are skipped since
             * there is no filesystem object to verify against. */
            if (out_resolved != NULL) {
                ngx_cpystrn((u_char *) out_resolved, (u_char *) full_path,
                            PATH_MAX);
            }
            return NGX_OK;
        }
        if (errno == ENOENT || errno == ENOTDIR) {
            return brix_prepare_check_fail(ctx, c, pathbuf, kXR_NotFound,
                                             "file not found");
        }
        if (errno == EACCES || errno == EPERM) {
            return brix_prepare_check_fail(ctx, c, full_path,
                                             kXR_NotAuthorized, "not authorized");
        }
        return brix_prepare_check_fail(ctx, c, full_path, kXR_IOError,
                                         "prepare stat failed");
    }

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
    const u_char         *p;
    const u_char         *end;
    ngx_uint_t            paths = 0;
    ngx_uint_t            missing = 0;
    uint16_t              optionx;
    char                  detail[96];

    /* Staging command path collection.  Only allocated when kXR_stage is set
     * and brix_prepare_command is configured. */
    ngx_flag_t   collect_stage;
    ngx_flag_t   do_enqueue;        /* Phase 35: enqueue into the durable queue */
    ngx_flag_t   need_resolved;     /* fill out_resolved (legacy OR enqueue)     */
    const char **stage_paths = NULL;
    char        *stage_bufs  = NULL;
    ngx_uint_t   stage_count = 0;
    ngx_uint_t   stage_max   = 0;
    char         group_reqid[BRIX_STAGE_REQID_LEN];

    xrdw_prepare_req_unpack(((ClientRequestHdr *) ctx->recv.hdr_buf)->body, &req);
    optionx = req.optionX;

    collect_stage = (req.options & kXR_stage) && conf->prepare_command.len > 0;
    do_enqueue    = (req.options & kXR_stage) && conf->frm.enable
                    && brix_stage_registry_singleton() != NULL;
    need_resolved = collect_stage || do_enqueue;
    group_reqid[0] = '\0';

    if ((req.options & kXR_wmode) && !conf->common.allow_write) {
        return brix_prepare_send_fail(ctx, c, "-", kXR_fsReadOnly,
                                        "this is a read-only server");
    }

    if (req.options & kXR_cancel) {
        /* Phase 35: real cancel against the durable registry when staging is on. */
        if (conf->frm.enable && brix_stage_registry_singleton() != NULL) {
            return brix_prepare_handle_cancel(ctx, c, conf);
        }
        snprintf(detail, sizeof(detail), "noop cancel opts=0x%02x optx=0x%04x",
                 (unsigned int) req.options, (unsigned int) optionx);
        brix_log_access(ctx, c, "PREPARE", "-", detail, 1, kXR_ok, NULL, 0);
        return brix_send_ok(ctx, c, NULL, 0);
    }

    if (optionx & kXR_evict) {
        /* Evict releases the disk pin: the staged copy may be purged. The actual
         * disk reclamation is delegated to the MSS (Category-2, Phase 4); here we
         * record the release intent. The authoritative per-path release path with
         * full resolve+scope is the WLCG Tape REST /release endpoint. */
        /* (evict metric re-homes to the stage metrics in Task 5) */
        snprintf(detail, sizeof(detail), "evict opts=0x%02x optx=0x%04x",
                 (unsigned int) req.options, (unsigned int) optionx);
        brix_log_access(ctx, c, "PREPARE", "-", detail, 1, kXR_ok, NULL, 0);
        return brix_send_ok(ctx, c, NULL, 0);
    }

    if (ctx->recv.cur_dlen == 0 || ctx->recv.payload == NULL) {
        return brix_prepare_send_fail(ctx, c, "-", kXR_ArgMissing,
                                        "prepare file list is missing");
    }

    /* Pre-allocate staging collection arrays.  Cap at BRIX_PREPARE_CMD_MAX_PATHS
     * (typically payload / 2 paths, but bounded to avoid excessive allocation). */
    if (need_resolved) {
        stage_max = ctx->recv.cur_dlen / 2 + 1;
        if (stage_max > BRIX_PREPARE_CMD_MAX_PATHS) {
            stage_max = BRIX_PREPARE_CMD_MAX_PATHS;
        }

        stage_paths = ngx_palloc(c->pool,
                                 sizeof(const char *) * stage_max);
        stage_bufs  = ngx_palloc(c->pool,
                                 (size_t) stage_max * PATH_MAX);
        if (stage_paths == NULL || stage_bufs == NULL) {
            return NGX_ERROR;
        }
    }

    p = ctx->recv.payload;
    end = ctx->recv.payload + ctx->recv.cur_dlen;

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

        paths++;

        /* Point out_resolved at the next slot in the staging buffer (when the
         * legacy command OR the durable queue needs the resolved path) so
         * brix_prepare_check_path fills it in-place. */
        if (need_resolved && stage_count < stage_max) {
            out_resolved = stage_bufs + stage_count * PATH_MAX;
            out_resolved[0] = '\0';
        } else {
            out_resolved = NULL;
        }

        rc = brix_prepare_check_path(ctx, c, conf, line, line_len,
                                       (req.options & kXR_noerrs) != 0,
                                       &missing, out_resolved);
        if (rc == NGX_DONE) {
            return NGX_OK;
        }
        if (rc != NGX_OK) {
            return rc;
        }

        /* Accept the resolved path: enqueue it durably (FRM) and/or collect it
         * for the legacy staging command. */
        if (out_resolved != NULL && out_resolved[0] != '\0') {
            if (do_enqueue) {
                brix_stage_request_view_t v;
                char           rq[BRIX_STAGE_REQID_LEN];
                ngx_int_t      arc;
                /* Record the canonical identity DN/token subject, or a scoped
                 * anonymous-session key, so the cancel-owner check has the same
                 * owner string. */
                char           owner_key[BRIX_PREPARE_OWNER_KEY_MAX];
                const char    *rdn = brix_prepare_owner_key(ctx, owner_key,
                                                              sizeof(owner_key));

                ngx_memzero(&v, sizeof(v));
                v.lfn        = out_resolved;
                v.requester_dn = (rdn != NULL && rdn[0] != '\0') ? rdn : NULL;
                v.tod_expire = (int64_t) time(NULL)
                             + (int64_t) (conf->frm.stage_ttl / 1000);

                arc = brix_stage_request_add(brix_stage_registry_singleton(),
                                               &v, rq, sizeof(rq), c->log);
                if (arc == NGX_ERROR) {
                    ngx_log_error(NGX_LOG_ERR, c->log, 0,
                                  "brix: stage request add failed for \"%s\"",
                                  out_resolved);
                } else if (group_reqid[0] == '\0') {
                    /* The first request id is the handle returned to the client. */
                    ngx_cpystrn((u_char *) group_reqid, (u_char *) rq,
                                sizeof(group_reqid));
                }
                /* NOTE (engine-integration step): driving the recall — the former
                 * frm_stage_kick() — moves to brix_stage_submit(RECALL) + the
                 * engine scheduler; the composable sd_frm backend also faults the
                 * recall on read, so the request is durably recorded here. */
            }
            if (collect_stage) {
                stage_paths[stage_count] = out_resolved;
            }
            stage_count++;
        }
    }

    if (paths == 0) {
        return brix_prepare_send_fail(ctx, c, "-", kXR_ArgMissing,
                                        "prepare file list is empty");
    }

    snprintf(detail, sizeof(detail),
             "paths=%u missing=%u opts=0x%02x optx=0x%04x%s",
             (unsigned int) paths, (unsigned int) missing,
             (unsigned int) req.options, (unsigned int) optionx,
             (req.options & kXR_coloc) ? " (coloc)" : "");

    brix_log_access(ctx, c, "PREPARE", "-", detail, 1, kXR_ok, NULL, 0);

    /* kXR_stage: save the path list for kXR_QPrep status queries, return
     * request ID "0", and optionally invoke the configured staging command. */
    if (req.options & kXR_stage) {
        u_char     *saved;
        const char *resp_reqid;
        size_t      resp_reqid_len;

        /* The request handle: the durable reqid when enqueued, else legacy "0". */
        resp_reqid     = (do_enqueue && group_reqid[0] != '\0')
                       ? group_reqid : "0";
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
        if (collect_stage && stage_count > 0) {
            if (brix_prepare_invoke_command(c->log, conf,
                                              stage_paths, stage_count,
                                              (req.options & kXR_coloc) != 0)
                != NGX_OK)
            {
                ngx_log_error(NGX_LOG_ERR, c->log, ngx_errno,
                              "brix: prepare_command launch failed");
                /* Best-effort: continue and return ok to the client. */
            }
        } else if (collect_stage && stage_count == 0) {
            ngx_log_error(NGX_LOG_WARN, c->log, 0,
                          "brix: kXR_stage set but no resolvable paths"
                          " for prepare_command");
        }

        /* kXR_notify: send kXR_attn + kXR_asyncms notification when all
         * requested files are already on disk (missing == 0).  The notification
         * is combined with the kXR_ok response in a single buffer to avoid
         * a double-queue race on EAGAIN write paths.
         *
         * When missing > 0 some files are still being staged by the background
         * command; we cannot know when they arrive, so the notification is
         * omitted and a warning is logged.  Future work could add a completion
         * pipe from the staging command to deliver the notification later. */
        if (req.options & kXR_notify) {
            if (missing == 0) {
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
                ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN, resp_reqid,
                           resp_reqid_len);
                brix_build_attn_asyncms_frame(buf + ok_len,
                                                notify_msg, notify_len);

                ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                    "brix: sending kXR_prepare ok + kXR_attn asyncms notify");

                return brix_queue_response(ctx, c, buf, total);

            } else {
                ngx_log_error(NGX_LOG_WARN, c->log, 0,
                    "brix: kXR_notify requested but %ui path(s) still being "
                    "staged; async completion notification not supported",
                    missing);
            }
        }

        return brix_send_ok(ctx, c, (u_char *) resp_reqid,
                              (uint32_t) resp_reqid_len);
    }

    return brix_send_ok(ctx, c, NULL, 0);
}
/* WHY: kXR_prepare accepts a newline-separated list of paths from clients, validates each against auth/ACLs/filesystem existence, optionally invokes a staging command (e.g., xrdcp to tape), and returns a request ID for later status queries via kXR_QPrep. Supports cancel/evict options as noops, write mode enforcement, and best-effort staging invocation (continues on launch failure). */
/* HOW: Parses ClientPrepareRequest from ctx->recv.hdr_buf — extracts optionX via ntohs(req->optionX). Checks kXR_stage + prepare_command.len > 0 → collect_stage=1. If kXR_wmode && !allow_write fail kXR_fsReadOnly("read-only server"). If kXR_cancel or kXR_evict in optx: log access, send ok with NULL payload (noop). If ctx->recv.cur_dlen==0 || payload==NULL fail kXR_ArgMissing("file list missing"). Pre-allocates stage_paths/stage_bufs arrays via ngx_palloc if collect_stage — caps at BRIX_PREPARE_CMD_MAX_PATHS. Parses payload line-by-line: extracts line_len trimming trailing \r/\NUL, skips empty lines, increments paths count. For each path points out_resolved at staging buffer slot (if collecting), calls brix_prepare_check_path() with noerrs flag from kXR_noerrs — if NGX_DONE returns NGX_OK; if other error returns rc. Accepts non-empty resolved paths into stage_paths array. If paths==0 fail kXR_ArgMissing("empty list"). Logs detail string "paths=%u missing=%u opts=0x%02x optx=0x%04x". If kXR_stage: allocates saved buffer via ngx_alloc, copies payload, frees old ctx->prepare.paths if any, sets reqid="0", stores paths in ctx->prepare.paths/len; invokes staging command via brix_prepare_invoke_command() (best-effort: logs error on failure but continues); returns ok with "0" as response. Otherwise returns ok with NULL. */

/*
 * kXR_QPrep handler.
 *
 * Payload format (newline-separated):
 *   line 0: request ID (from kXR_prepare response)
 *   line 1+: optional paths to check (may be omitted; use stored path list)
 *
 * This server is disk-only — files are immediately staged or absent.
 * Response: one "A <path>" or "M <path>" line per file, NUL-terminated.
 */
ngx_int_t
brix_query_prep_status(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf)
{
    const u_char *src;
    size_t        src_len;
    const u_char *p;
    const u_char *end;
    u_char       *resp;
    u_char       *rp;
    size_t        resp_cap;
    char          reqid[BRIX_STAGE_REQID_LEN];
    size_t        reqid_len = 0;

    if (ctx->recv.payload == NULL || ctx->recv.cur_dlen == 0) {
        return brix_send_ok(ctx, c, NULL, 0);
    }

    p   = ctx->recv.payload;
    end = ctx->recv.payload + ctx->recv.cur_dlen;

    /* The first payload line is the prepare request-id.  Capture it (trimmed of
     * trailing CR/NUL) so an id we have no record of can be rejected the way the
     * reference do_Prepare(isQuery) does. */
    {
        const u_char *rid = p;
        while (p < end && *p != '\n') {
            p++;
        }
        reqid_len = (size_t) (p - rid);
        while (reqid_len > 0
               && (rid[reqid_len - 1] == '\r' || rid[reqid_len - 1] == '\0')) {
            reqid_len--;
        }
        if (reqid_len > 0 && reqid_len < sizeof(reqid)) {
            ngx_memcpy(reqid, rid, reqid_len);
            reqid[reqid_len] = '\0';
        } else {
            reqid[0] = '\0';
        }
    }
    if (p < end) {
        p++;  /* consume '\n' */
    }

    /* Determine which path list to use: inline paths (after reqid) or stored. */
    if (p < end) {
        src     = p;
        src_len = (size_t) (end - p);
    } else if (ctx->prepare.paths != NULL
               && ctx->prepare.paths_len > 0) {
        src     = ctx->prepare.paths;
        src_len = ctx->prepare.paths_len;
    } else {
        /* No inline paths and nothing stored for this session.  If the client
         * named a request-id we have no record of — FRM disabled, or the durable
         * queue has no such record — reject it exactly like the reference
         * do_Prepare(isQuery): "Prepare requestid owned by an unknown server".
         * Resilience polling is unaffected: it carries inline paths (handled
         * above), and an id we issued resolves via stored paths or an FRM
         * record. */
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

    /* Allocate response buffer: worst case "A " + path + "\n" per line. */
    resp_cap = src_len * 2 + 64;
    BRIX_PALLOC_OR_RETURN(resp, c->pool, resp_cap, brix_send_error(ctx, c, kXR_NoMemory, "out of memory"));
    rp = resp;

    p   = src;
    end = src + src_len;

    while (p < end) {
        const u_char *line;
        size_t        line_len;
        char          pathbuf[BRIX_MAX_PATH + 1];
        char          full_path[PATH_MAX];
        struct stat   st;

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

        /* Check availability; both non-existent and unauthorized paths are
         * treated as missing, consistent with xrootd reference behavior.
         * Phase 35: when FRM is enabled, a file that is not yet resident but
         * has a live queue record reports its queue state (q/s/f) instead of M,
         * so a client polls a real recall to completion across reconnects. */
        brix_beneath_full_path(conf->common.root_canon, pathbuf,
                                 full_path, sizeof(full_path));
        {
            char status_ch = 'M';

            if (brix_authz_check(ctx, c, conf, pathbuf, full_path, "PREPARE",
                                   BRIX_AUTH_READ, BRIX_AOP_STAGE) == NGX_OK
                && brix_check_vo_acl_identity(c->log, full_path,
                                                conf->vo_rules,
                                                ctx->identity) == NGX_OK
                && brix_check_token_scope(ctx, pathbuf, 0) == NGX_OK)
            {
                if (brix_stat_beneath(conf->rootfd, pathbuf, &st) == 0
                    && S_ISREG(st.st_mode))
                {
                    status_ch = 'A';                /* resident on disk */
                } else if (conf->frm.enable
                           && brix_stage_registry_singleton() != NULL) {
                    brix_stage_registry_t *reg =
                        brix_stage_registry_singleton();
                    brix_stage_request_t   qrec;
                    char                     frq[BRIX_STAGE_REQID_LEN];
                    if (brix_stage_request_find_by_path(reg, full_path, frq,
                                                          sizeof(frq), c->log)
                            == NGX_OK
                        && brix_stage_request_get(reg, frq, &qrec, c->log)
                            == NGX_OK)
                    {
                        status_ch = brix_prepare_status_char(qrec.status);
                    }
                }
            }
            *rp++ = (u_char) status_ch;
        }
        *rp++ = ' ';

        /* Copy logical path into response. */
        if ((size_t) (rp - resp) + line_len + 1 >= resp_cap) {
            break;  /* safety: truncate on overflow */
        }
        ngx_memcpy(rp, pathbuf, strlen(pathbuf));
        rp += strlen(pathbuf);
        *rp++ = '\n';
    }

    if (rp == resp) {
        return brix_send_ok(ctx, c, NULL, 0);
    }

    *rp = '\0';
    brix_log_access(ctx, c, "QPREP", "-", "-", 1, kXR_ok, NULL, 0);
    return brix_send_ok(ctx, c, resp, (uint32_t) (rp - resp + 1));
}
/* WHY: kXR_QPrep queries the staging status of paths from a prior kXR_prepare request — clients use it to verify whether files are available on disk ("A") or missing ("M"). Supports inline path lists in the query payload or falls back to stored prepare_paths from the original request. Disk-only servers return immediate results since files are either present or absent. */
/* HOW: Parses ctx->recv.payload — if empty returns ok NULL. Skips first line as reqid (ignored). If remaining lines exist uses them as inline paths; otherwise falls back to ctx->prepare.paths/stored list from prior kXR_prepare. Allocates response buffer resp_cap=src_len*2+64 via ngx_palloc — on OOM fail kXR_NoMemory. Parses each path line trimming trailing \r/\NUL, skips empty lines. For each path: extracts via brix_extract_path() (skip if malformed), resolves via brix_resolve_path(), checks authdb(BRIX_AUTH_READ) + vo_acl + token_scope + stat(S_ISREG) — if all pass writes 'A ' to response; otherwise writes 'M '. Copies logical pathbuf into response, truncates on buffer overflow. If no output (rp==resp) returns ok NULL; otherwise NUL-terminates resp, logs access event, sends brix_send_ok(resp). */

/* public API: brix_query_prep_status() — kXR_QPrep staging status query handler * WHAT: Queries staging availability of paths from prior prepare request. Returns "A <path>" for files present on disk, "M <path>" for missing/unauthorized.
 *       Uses inline path list in payload or falls back to stored ctx->prepare.paths. Allocates resp buffer src_len*2+64 via ngx_palloc, resolves each path
 *       + authdb(vo_acl token_scope) + stat(S_ISREG) → writes 'A'/'M' prefix per path, NUL-terminates and sends response.
 */
