#include "server.h"
#include "router.h"                       /* table-driven opcode routing */
#include "rrdata.h"                       /* Pup decode + statfs reply encode */
#include "net/manager/registry.h"          /* aggregate space for statfs reply */
#include "cns.h"                          /* §6 CNS inventory + event codec */
#include "observability/metrics/metrics_macros.h"   /* Phase 51 (A1): resilience counters */
#include "observability/sesslog/sesslog_ngx.h"
#include "core/compat/log_diag.h"

static void
cms_srv_set_end_hint(brix_cms_srv_ctx_t *ctx, brix_sess_end_t why)
{
    if (ctx == NULL || ctx->sess_end_hint_set) {
        return;
    }

    ctx->sess_end_hint = why;
    ctx->sess_end_hint_set = 1;
}

static brix_sess_end_t
cms_srv_end_reason(brix_cms_srv_ctx_t *ctx, ngx_connection_t *c)
{
    if (ngx_exiting || ngx_terminate) {
        return BRIX_SESS_END_SHUTDOWN;
    }

    if (ctx != NULL && ctx->sess_end_hint_set) {
        return ctx->sess_end_hint;
    }

    if (c != NULL) {
        if ((c->read != NULL && c->read->timedout)
            || (c->write != NULL && c->write->timedout))
        {
            return BRIX_SESS_END_TIMEOUT;
        }
        if (c->error) {
            return BRIX_SESS_END_ERROR;
        }
    }

    return BRIX_SESS_END_CLIENT;
}

static const char *
cms_srv_target_path(brix_cms_srv_ctx_t *ctx, char *dst, size_t dst_size)
{
    u_char *p;
    u_char *end;

    if (ctx == NULL || dst == NULL || dst_size == 0) {
        return "-";
    }

    end = (u_char *) dst + dst_size;
    p = ngx_snprintf((u_char *) dst, dst_size, "%s:%d",
                     ctx->host, (int) ctx->port);
    if (p < end) {
        *p = '\0';
    } else {
        dst[dst_size - 1] = '\0';
    }

    return dst;
}

static void
cms_srv_log_auth_fail(brix_cms_srv_ctx_t *ctx, const char *err)
{
    if (ctx == NULL) {
        return;
    }

    brix_sess_auth(ctx->sess, 0, BRIX_SESS_AM_HOST, "-", "-", err);
}

static void
cms_srv_log_registration(brix_cms_srv_ctx_t *ctx)
{
    char        target[BRIX_SESSLOG_PATH_MAX];
    const char *path;

    if (ctx == NULL || ctx->sess_attempt_logged) {
        return;
    }

    path = cms_srv_target_path(ctx, target, sizeof(target));
    brix_sess_auth_once(ctx->sess, BRIX_SESS_AM_HOST, ctx->host, "-");
    brix_sess_attempt(ctx->sess, path, BRIX_SESS_MODE_META);
    ctx->sess_attempt_logged = 1;
    brix_sess_result(ctx->sess, 1, path, BRIX_SESS_MODE_META, NULL);
}

/* brix_cms_srv_close — tear down a CMS data-server connection: drop the ping
 * timer, unregister host/port from the server registry if logged_in (so locate
 * queries stop routing clients to a dead server), NULL ctx->c, and close. */

void
brix_cms_srv_close(brix_cms_srv_ctx_t *ctx)
{
    ngx_connection_t  *c;

    c = ctx->c;
    if (c == NULL) {
        return;
    }

    if (ctx->ping_timer.timer_set) {
        ngx_del_timer(&ctx->ping_timer);
    }

    /* WS3: cancel the login/idle read deadline before tearing the socket down. */
    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    /* WS4 + A3: release the admission-cap slots (global + per-IP) exactly once. */
    if (ctx->counted) {
        brix_cms_srv_conn_dec();
        brix_cms_srv_ip_dec(ctx->host);
        ctx->counted = 0;
    }

    if (ctx->logged_in) {
        /* Blacklist for 30 s so in-flight locate responses don't route to a
         * server that just went away.  brix_srv_register() clears the flag
         * the moment the server successfully reconnects and re-heartbeats. */
        brix_srv_blacklist(ctx->host, ctx->port,
                           NGX_BRIX_CMS_SRV_DROP_BLACKLIST_MS);
        BRIX_DIAG(NGX_LOG_NOTICE, c->log, 0,
            "xrootd[cms]: data server %s:%d disconnected (blacklisted 30s)",
            "the data server dropped its CMS connection — it crashed, was "
            "restarted, or lost network to the manager",
            "if it does not re-register within seconds, check that server's "
            "health and connectivity; clients are routed away from it "
            "meanwhile",
            ctx->host, (int) ctx->port);
    }

    brix_sess_end(ctx->sess, cms_srv_end_reason(ctx, c));
    ctx->sess = NULL;

    ctx->c = NULL;
    ngx_close_connection(c);
}

/*
 * cms_srv_fail_close — record why the session ended, then tear it down.
 * Shared epilogue for every fatal per-frame/per-read error so each handler
 * stays single-purpose; after this returns ctx->c is NULL and the caller must
 * not touch the connection again.
 */
static void
cms_srv_fail_close(brix_cms_srv_ctx_t *ctx, brix_sess_end_t why)
{
    cms_srv_set_end_hint(ctx, why);
    brix_cms_srv_close(ctx);
}

/* TLV walk helpers */

/*
 * The LOGIN/LOAD/AVAIL payloads use a simple type-tagged encoding:
 *   CMS_PT_SHORT (0x80) + big-endian uint16
 *   CMS_PT_INT   (0xa0) + big-endian uint32
 *
 * Walk *p forward by one tagged value, returning the decoded uint32.
 * Advances *p past the tag+value bytes.  Returns 0 and sets *p=end on error.
 */
static uint32_t
tlv_read_next(const u_char **p, const u_char *end)
{
    if (*p >= end) {
        *p = end;
        return 0;
    }

    if (**p == CMS_PT_SHORT) {
        if (end - *p < 3) { *p = end; return 0; }
        uint32_t v = ngx_brix_cms_get16(*p + 1);
        *p += 3;
        return v;
    }

    if (**p == CMS_PT_INT) {
        if (end - *p < 5) { *p = end; return 0; }
        uint32_t v = ngx_brix_cms_get32(*p + 1);
        *p += 5;
        return v;
    }

    /* Unknown tag — treat as end of parseable data. */
    *p = end;
    return 0;
}

/*
 * Read one XrdOucPup string from *p: a 2-byte big-endian length followed by
 * <len> raw bytes (the length includes the trailing NUL).  Sets *out / *out_len
 * to the data span and advances *p.  Returns 1 on success, 0 (and *p=end) on a
 * short/overrun buffer.  Strings carry NO type tag — the high bit of the first
 * length byte is clear for any reasonable length, which is how the real Parser
 * tells a string apart from a PT_short/PT_int scalar.
 */
static int
cms_srv_read_string(const u_char **p, const u_char *end,
    const u_char **out, size_t *out_len)
{
    uint16_t  len;

    if (end - *p < 2) { *p = end; return 0; }
    len = ngx_brix_cms_get16(*p);
    *p += 2;
    if ((size_t) (end - *p) < len) { *p = end; return 0; }
    *out = *p;
    *out_len = len;
    *p += len;
    return 1;
}

/* LOGIN payload parser */

/*
 * Parse the CMS LOGIN frame payload in the real XrdCms CmsLoginData wire format
 * (XrdOucPup), the same one a real cmsd and our own cms/send.c now emit:
 *
 *   PT_SHORT Version    PT_INT Mode      PT_INT HoldTime
 *   PT_INT   tSpace     PT_INT fSpace ←free_mb   PT_INT mSpace
 *   PT_SHORT fsNum      PT_SHORT fsUtil ←util_pct PT_SHORT dPort ←port
 *   PT_SHORT sPort      [Fence]
 *   string SID          string Paths     string ifList   string envCGI
 *
 * The Paths string is a newline-separated list of "<type> <namespace-path>"
 * entries (type 'r'/'w', e.g. "w /\nw /atlas").  We strip the type prefix and
 * store the bare namespace paths colon-delimited ("/:/atlas") — the form the
 * registry's srv_path_matches() expects.
 */

/*
 * cms_srv_login_scalars — decode the fixed PT_SHORT/PT_INT scalar prologue of
 * the LOGIN payload (Version..sPort), capturing free_mb/util_pct/port on ctx.
 * Splitting the scalar block from the string/paths negotiation keeps each
 * piece independently checkable.  Advances *p past the block; tlv_read_next()
 * self-terminates on a short buffer so missing fields decode as 0.
 */
static void
cms_srv_login_scalars(brix_cms_srv_ctx_t *ctx,
    const u_char **p, const u_char *end)
{
    /* version */   (void) tlv_read_next(p, end);
    /* mode    */   (void) tlv_read_next(p, end);
    /* holdtime */  (void) tlv_read_next(p, end);
    /* tSpace  */   (void) tlv_read_next(p, end);
    ctx->free_mb  = tlv_read_next(p, end);     /* fSpace  */
    /* mSpace  */   (void) tlv_read_next(p, end);
    /* fsNum   */   (void) tlv_read_next(p, end);
    ctx->util_pct = tlv_read_next(p, end);     /* fsUtil  */
    ctx->port     = (uint16_t) tlv_read_next(p, end); /* dPort */
    /* sPort   */   (void) tlv_read_next(p, end);
}

/*
 * cms_srv_login_seg_path — reduce one "<type> <path>" Paths segment to the
 * bare path: drop the leading type token up to and including the first run of
 * spaces (a segment without a space is taken verbatim), then trim trailing
 * blanks.  Adjusts *tok / *tok_len in place; *tok_len may become 0.
 */
static void
cms_srv_login_seg_path(const u_char **tok, size_t *tok_len)
{
    size_t  sp = 0;

    /* split off the leading "<type> " prefix, if any */
    while (sp < *tok_len && (*tok)[sp] != ' ') {
        sp++;
    }
    if (sp < *tok_len) {              /* found a space → path follows it */
        sp++;
        while (sp < *tok_len && (*tok)[sp] == ' ') {
            sp++;
        }
        *tok += sp;
        *tok_len -= sp;
    }

    while (*tok_len > 0
           && ((*tok)[*tok_len - 1] == ' ' || (*tok)[*tok_len - 1] == '\t'))
    {
        (*tok_len)--;
    }
}

/*
 * cms_srv_login_next_path — scan the newline-separated Paths string for the
 * next segment starting at *i, skipping blank/NUL padding, and hand back the
 * bare path span via cms_srv_login_seg_path().  Advances *i past the segment.
 * Returns 1 with *tok / *tok_len set (len may be 0), 0 when exhausted.
 */
static int
cms_srv_login_next_path(const u_char *paths, size_t paths_len, size_t *i,
    const u_char **tok, size_t *tok_len)
{
    size_t  seg_end;

    while (*i < paths_len
           && (paths[*i] == '\n' || paths[*i] == ' '
               || paths[*i] == '\t' || paths[*i] == '\0'))
    {
        (*i)++;
    }
    if (*i >= paths_len) {
        return 0;
    }

    /* find end of this segment (newline / NUL terminated) */
    seg_end = *i;
    while (seg_end < paths_len
           && paths[seg_end] != '\n' && paths[seg_end] != '\0')
    {
        seg_end++;
    }

    *tok = paths + *i;
    *tok_len = seg_end - *i;
    cms_srv_login_seg_path(tok, tok_len);

    *i = seg_end;
    return 1;
}

/*
 * cms_srv_login_append_path — append one bare path to the colon-delimited
 * ctx->paths buffer, truncating at the buffer boundary exactly like the
 * original inline copy loop.  Empty tokens (type-only segments) are dropped.
 */
static void
cms_srv_login_append_path(brix_cms_srv_ctx_t *ctx, u_char **dst,
    u_char *dst_end, const u_char *tok, size_t tok_len)
{
    size_t  cp;

    if (tok_len == 0) {
        return;
    }

    if (*dst != (u_char *) ctx->paths && *dst < dst_end) {
        *(*dst)++ = ':';
    }
    cp = (size_t) (dst_end - *dst);
    if (cp > tok_len) {
        cp = tok_len;
    }
    ngx_memcpy(*dst, tok, cp);
    *dst += cp;
}

static int
cms_srv_parse_login(brix_cms_srv_ctx_t *ctx,
    const u_char *payload, size_t payload_len)
{
    const u_char  *p   = payload;
    const u_char  *end = payload + payload_len;
    const u_char  *sid;
    const u_char  *paths;
    const u_char  *tok;
    size_t         sid_len;
    size_t         paths_len;
    size_t         tok_len;
    u_char        *dst;
    u_char        *dst_end;
    size_t         i;

    cms_srv_login_scalars(ctx, &p, end);

    /* SID (ignored) then Paths (extracted). ifList/envCGI ignored. */
    (void) cms_srv_read_string(&p, end, &sid, &sid_len);
    if (!cms_srv_read_string(&p, end, &paths, &paths_len)) {
        paths = NULL;
        paths_len = 0;
    }

    /*
     * Convert "<type> <path>\n<type> <path>..." -> colon-delimited bare paths.
     * Each newline segment is "<type> <path>"; the path follows the first
     * space.  A segment without a space is taken verbatim as the path.
     */
    dst     = (u_char *) ctx->paths;
    dst_end = dst + sizeof(ctx->paths) - 1;
    i = 0;
    while (dst < dst_end
           && cms_srv_login_next_path(paths, paths_len, &i, &tok, &tok_len))
    {
        cms_srv_login_append_path(ctx, &dst, dst_end, tok, tok_len);
    }
    *dst = '\0';

    /* Default XRootD port if the data server didn't advertise one. */
    if (ctx->port == 0) {
        ctx->port = BRIX_DEFAULT_PORT;
    }

    return 1;
}

/* LOAD/AVAIL payload parsers */

/*
 * LOAD payload (from cms/send.c):
 *   PT_SHORT  count=6      (3 bytes)
 *   <6 raw bytes>          (cpu load values, ignored)
 *   PT_INT    free_mb      (5 bytes)  ← extracted
 */
static uint32_t
cms_srv_parse_load_free_mb(const u_char *payload, size_t payload_len)
{
    const u_char  *p   = payload;
    const u_char  *end = payload + payload_len;

    /* count field */
    (void) tlv_read_next(&p, end);

    /* skip 6 raw CPU bytes */
    if (end - p >= 6) {
        p += 6;
    } else {
        return 0;
    }

    return tlv_read_next(&p, end);
}

/*
 * AVAIL payload (from cms/send.c):
 *   PT_INT    free_mb      (5 bytes)  ← extracted
 *   PT_INT    util_pct     (5 bytes)  ← extracted
 *
 * Used for both CMS_RR_AVAIL and CMS_RR_SPACE.
 */
static void
cms_srv_parse_avail(const u_char *payload, size_t payload_len,
    uint32_t *free_mb, uint32_t *util_pct)
{
    const u_char  *p   = payload;
    const u_char  *end = payload + payload_len;

    *free_mb  = tlv_read_next(&p, end);
    *util_pct = tlv_read_next(&p, end);
}

/* Ping timer */

static void
brix_cms_srv_ping_timer(ngx_event_t *ev)
{
    brix_cms_srv_ctx_t  *ctx = ev->data;

    if (brix_cms_srv_send_ping(ctx) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, ev->log, 0,
                      "brix: CMS server: ping to %s failed, closing",
                      ctx->host);
        cms_srv_set_end_hint(ctx, BRIX_SESS_END_ERROR);
        brix_cms_srv_close(ctx);
        return;
    }

    ngx_add_timer(&ctx->ping_timer, ctx->interval_ms);
}

/* Frame dispatcher */

/*
 * cms_srv_complete_login — register the data server and arm heartbeats.
 *
 * Called once the LOGIN frame has been parsed AND (when sss is configured) the
 * kYR_xauth credential has been verified.  Splitting this out lets the sss path
 * defer registration until authentication succeeds without duplicating the
 * register/log/timer sequence.
 */
static void
cms_srv_complete_login(brix_cms_srv_ctx_t *ctx)
{
    brix_srv_register(ctx->host, ctx->port, ctx->paths,
                         ctx->free_mb, ctx->util_pct);
    ctx->logged_in = 1;
    cms_srv_log_registration(ctx);

    /* Arm the periodic ping now that the data server is logged in. */
    ctx->ping_timer.handler = brix_cms_srv_ping_timer;
    ngx_add_timer(&ctx->ping_timer, ctx->interval_ms);

    /*
     * WS3: switch the read deadline from the LOGIN handshake bound to the
     * post-login idle watchdog.  Re-armed on every received frame in
     * brix_cms_srv_read; if the node goes silent for idle_timeout_ms it is
     * closed + unregistered + blacklisted (reaps a black-holed node the ping
     * send cannot detect).  0 = disabled.
     */
    if (ctx->idle_timeout_ms > 0 && ctx->c != NULL) {
        ngx_add_timer(ctx->c->read, ctx->idle_timeout_ms);
    } else if (ctx->c != NULL && ctx->c->read->timer_set) {
        ngx_del_timer(ctx->c->read);   /* idle watchdog disabled — drop login timer */
    }

    /* ctx->c is non-NULL for a frame being processed (a close nulls it and
     * returns), but match the ctx->c guards above for consistency. */
    if (ctx->c != NULL) {
        ngx_log_error(NGX_LOG_NOTICE, ctx->c->log, 0,
                      "brix: CMS server: registered %s:%d paths=[%s] "
                      "free_mb=%uD util_pct=%uD",
                      ctx->host, (int) ctx->port, ctx->paths,
                      ctx->free_mb, ctx->util_pct);
    }
}

/* Per-opcode frame handlers.  All share one signature so the dispatcher can be
 * a data-driven route table (mirrors recv.c's client-side shape); handlers
 * that need no payload/streamid simply ignore those arguments.  A handler that
 * closes the connection leaves ctx->c NULL — the read loop checks that. */

typedef void (*cms_srv_frame_pt)(brix_cms_srv_ctx_t *ctx, uint32_t streamid,
    const u_char *payload, size_t payload_len);

/*
 * cms_srv_frame_login — LOGIN: parse the CmsLoginData payload; on parse
 * failure log + close.  W1a — if sss cluster auth is required, do NOT register
 * yet.  Mirror the real cmsd manager (XrdCmsLogin::Admit): after the LOGIN
 * frame arrives, send our security parms and wait for the node's kYR_xauth
 * credential before admitting it into the registry.
 */
static void
cms_srv_frame_login(brix_cms_srv_ctx_t *ctx, uint32_t streamid,
    const u_char *payload, size_t payload_len)
{
    if (!cms_srv_parse_login(ctx, payload, payload_len)) {
        ngx_log_error(NGX_LOG_WARN, ctx->c->log, 0,
                      "brix: CMS server: malformed LOGIN from %s",
                      ctx->host);
        cms_srv_log_auth_fail(ctx, "invalid");
        cms_srv_fail_close(ctx, BRIX_SESS_END_ERROR);
        return;
    }

    if (ctx->auth_state == CMS_AUTH_REQUESTED) {
        static const u_char sss_parms[] = "&P=sss";
        if (brix_cms_srv_send_xauth(ctx, sss_parms,
                                      sizeof(sss_parms)) != NGX_OK)
        {
            cms_srv_fail_close(ctx, BRIX_SESS_END_ERROR);
            return;
        }
        ctx->auth_state = CMS_AUTH_CHALLENGED;
        return;
    }

    cms_srv_complete_login(ctx);
}

/*
 * cms_srv_frame_xauth — kYR_xauth: verify the node's sss credential and admit
 * it.  Only meaningful while we are waiting for a credential; anything else
 * (or a bad signature) is an auth failure and closes the connection.
 */
static void
cms_srv_frame_xauth(brix_cms_srv_ctx_t *ctx, uint32_t streamid,
    const u_char *payload, size_t payload_len)
{
    if (ctx->auth_state != CMS_AUTH_CHALLENGED) {
        ngx_log_error(NGX_LOG_NOTICE, ctx->c->log, 0,
                      "brix: CMS server: unexpected kYR_xauth from %s",
                      ctx->host);
        cms_srv_log_auth_fail(ctx, "invalid");
        cms_srv_fail_close(ctx, BRIX_SESS_END_ERROR);
        return;
    }
    if (brix_cms_srv_verify_xauth(ctx, payload, payload_len) != NGX_OK) {
        cms_srv_log_auth_fail(ctx, "bad-signature");
        cms_srv_fail_close(ctx, BRIX_SESS_END_ERROR);
        return;
    }
    ctx->auth_state = CMS_AUTH_DONE;
    cms_srv_complete_login(ctx);
}

/*
 * cms_srv_frame_load — LOAD: refresh the node's free-space figure in the
 * registry (util_pct unchanged — LOAD carries no utilisation).  Pre-login
 * frames are ignored.
 */
static void
cms_srv_frame_load(brix_cms_srv_ctx_t *ctx, uint32_t streamid,
    const u_char *payload, size_t payload_len)
{
    uint32_t  free_mb;

    if (!ctx->logged_in) {
        return;
    }
    free_mb = cms_srv_parse_load_free_mb(payload, payload_len);
    brix_srv_update_load(ctx->host, ctx->port, free_mb, ctx->util_pct);
    ctx->free_mb = free_mb;
}

/*
 * cms_srv_frame_avail — AVAIL/SPACE: refresh both free-space and utilisation
 * in the registry (the two opcodes share this payload shape).  Pre-login
 * frames are ignored.
 */
static void
cms_srv_frame_avail(brix_cms_srv_ctx_t *ctx, uint32_t streamid,
    const u_char *payload, size_t payload_len)
{
    uint32_t  free_mb, util_pct;

    if (!ctx->logged_in) {
        return;
    }
    cms_srv_parse_avail(payload, payload_len, &free_mb, &util_pct);
    brix_srv_update_load(ctx->host, ctx->port, free_mb, util_pct);
    ctx->free_mb  = free_mb;
    ctx->util_pct = util_pct;
}

/*
 * cms_srv_frame_pong — PONG: heartbeat reply to our ping; log only.
 */
static void
cms_srv_frame_pong(brix_cms_srv_ctx_t *ctx, uint32_t streamid,
    const u_char *payload, size_t payload_len)
{
    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, ctx->c->log, 0,
                   "brix: CMS server: pong from %s", ctx->host);
}

/*
 * cms_srv_frame_ping — symmetric liveness (do_Ping): a node (or peer) probing
 * us gets a header-only kYR_pong.  No auth/state needed — pure liveness.
 */
static void
cms_srv_frame_ping(brix_cms_srv_ctx_t *ctx, uint32_t streamid,
    const u_char *payload, size_t payload_len)
{
    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, ctx->c->log, 0,
                   "brix: CMS server: ping from %s -> pong", ctx->host);
    if (brix_cms_srv_send_pong(ctx) != NGX_OK) {
        cms_srv_fail_close(ctx, BRIX_SESS_END_ERROR);
    }
}

/*
 * cms_srv_frame_disc — graceful disconnect (do_Disc as manager): echo a
 * kYR_disc back, then close — which unregisters the node from the registry.
 */
static void
cms_srv_frame_disc(brix_cms_srv_ctx_t *ctx, uint32_t streamid,
    const u_char *payload, size_t payload_len)
{
    ngx_log_error(NGX_LOG_NOTICE, ctx->c->log, 0,
                  "brix: CMS server: %s requested disconnect", ctx->host);
    (void) brix_cms_srv_send_disc(ctx);
    cms_srv_fail_close(ctx, BRIX_SESS_END_CLIENT);
}

/*
 * cms_srv_frame_update — state-refresh request (do_Update): resend our state
 * as a kYR_status frame so the peer keeps us active and eligible.
 */
static void
cms_srv_frame_update(brix_cms_srv_ctx_t *ctx, uint32_t streamid,
    const u_char *payload, size_t payload_len)
{
    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, ctx->c->log, 0,
                   "brix: CMS server: update from %s -> status", ctx->host);
    if (brix_cms_srv_send_status(ctx, CMS_ST_RESUME | CMS_ST_NOSTAGE)
        != NGX_OK)
    {
        cms_srv_fail_close(ctx, BRIX_SESS_END_ERROR);
    }
}

/*
 * cms_srv_frame_statfs — space query for a path (do_StatFS): answer kYR_data
 * with aggregate cluster space for the servers that hold the path.  We report
 * a single tier (staging == writable) since we model one storage class.
 */
static void
cms_srv_frame_statfs(brix_cms_srv_ctx_t *ctx, uint32_t streamid,
    const u_char *payload, size_t payload_len)
{
    brix_cms_rrdata_t         d;
    brix_cms_statfs_fields_t  space;
    u_char                      out[64];
    uint32_t                    free_mb = 0, util = 0, num;
    int                         olen;

    if (!ctx->logged_in
        || brix_cms_rrdata_parse(CMS_RR_STATFS, payload, payload_len, &d)
           != 0
        || d.path == NULL)
    {
        return;                          /* malformed / pre-auth: ignore */
    }

    num = (uint32_t) brix_srv_count_matching((const char *) d.path);
    brix_srv_aggregate_space(&free_mb, &util);
    space.w_num  = num;  space.w_free = free_mb;  space.w_util = util;
    space.s_num  = num;  space.s_free = free_mb;  space.s_util = util;
    olen = brix_cms_statfs_encode(&space, out, sizeof(out));
    if (olen > 0) {
        (void) brix_cms_srv_send_data(ctx, streamid, out, (size_t) olen);
    }
}

/*
 * cms_srv_frame_gone — a data server signals that it no longer holds a
 * specific path.  Remove that path token from its registry entry without
 * touching the rest of the registration (the server still holds other paths).
 */
static void
cms_srv_frame_gone(brix_cms_srv_ctx_t *ctx, uint32_t streamid,
    const u_char *payload, size_t payload_len)
{
    char    path[BRIX_SRV_MAX_PATHS];
    size_t  copy;

    if (!ctx->logged_in || payload_len == 0) {
        return;
    }

    copy = payload_len < sizeof(path) - 1
           ? payload_len : sizeof(path) - 1;
    ngx_memcpy(path, payload, copy);
    path[copy] = '\0';
    brix_srv_unregister_path(ctx->host, ctx->port, path);
    ngx_log_debug3(NGX_LOG_DEBUG_STREAM, ctx->c->log, 0,
                   "brix: CMS server: kYR_gone path=%s from %s:%d",
                   path, ctx->host, (int) ctx->port);
}

/*
 * cms_srv_frame_cns — §6 Composite Cluster Name Space: a data server reports a
 * namespace mutation.  Apply it into the manager inventory (collect mode only).
 */
static void
cms_srv_frame_cns(brix_cms_srv_ctx_t *ctx, uint32_t streamid,
    const u_char *payload, size_t payload_len)
{
    uint8_t   op;
    uint64_t  size, mtime;
    char      path[BRIX_CNS_PATH_MAX + 1];
    uint32_t  server_id;
    const u_char *h = (const u_char *) ctx->host;
    size_t    i;

    if (!ctx->logged_in || !brix_cns_collecting()) {
        return;
    }

    if (brix_cns_event_decode(payload, payload_len, &op, &size, &mtime,
                                path, sizeof(path)) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_WARN, ctx->c->log, 0,
                      "brix: CMS server: malformed CNS event from %s",
                      ctx->host);
        return;
    }
    server_id = (uint32_t) ctx->port;        /* host hash + port = origin id */
    for (i = 0; h[i] != '\0'; i++) {
        server_id = server_id * 33 + h[i];
    }
    (void) brix_cns_apply(op, path, size, mtime, server_id);
    ngx_log_debug3(NGX_LOG_DEBUG_STREAM, ctx->c->log, 0,
                   "brix: CNS event op=%ud path=%s from %s",
                   (unsigned) op, path, ctx->host);
}

/*
 * cms_srv_frame_unknown — default: consult the manager routing table so the
 * log distinguishes a valid manager opcode we have not wired yet (e.g.
 * usage/stats/statfs) from a truly unroutable code.  Either way we drop it —
 * matching cmsd's tolerance of frames it does not act on.
 */
static void
cms_srv_frame_unknown(brix_cms_srv_ctx_t *ctx, u_char code)
{
    const brix_cms_route_t *r =
        brix_cms_route_lookup(XRDCMS_ROLE_MANAGER, code);
    if (r != NULL) {
        ngx_log_debug2(NGX_LOG_DEBUG_STREAM, ctx->c->log, 0,
                       "brix: CMS server: unhandled opcode '%s' from %s",
                       r->name, ctx->host);
    } else {
        ngx_log_debug2(NGX_LOG_DEBUG_STREAM, ctx->c->log, 0,
                       "brix: CMS server: unknown rrCode=%ui from %s",
                       (ngx_uint_t) code, ctx->host);
    }
}

/* Opcode → handler route table.  AVAIL and SPACE share a payload shape and a
 * handler; the NULL sentinel terminates the scan (unmatched codes fall through
 * to cms_srv_frame_unknown). */
static const struct {
    u_char            code;
    cms_srv_frame_pt  handler;
} cms_srv_frame_routes[] = {
    { CMS_RR_LOGIN,  cms_srv_frame_login  },
    { CMS_RR_XAUTH,  cms_srv_frame_xauth  },
    { CMS_RR_LOAD,   cms_srv_frame_load   },
    { CMS_RR_AVAIL,  cms_srv_frame_avail  },
    { CMS_RR_SPACE,  cms_srv_frame_avail  },
    { CMS_RR_PONG,   cms_srv_frame_pong   },
    { CMS_RR_PING,   cms_srv_frame_ping   },
    { CMS_RR_DISC,   cms_srv_frame_disc   },
    { CMS_RR_UPDATE, cms_srv_frame_update },
    { CMS_RR_STATFS, cms_srv_frame_statfs },
    { CMS_RR_GONE,   cms_srv_frame_gone   },
    { CMS_RR_CNS,    cms_srv_frame_cns    },
    { 0,             NULL                 },
};

/*
 * cms_srv_process_frame — route one complete frame by opcode through the
 * table above.  A handler that tears the connection down leaves ctx->c NULL;
 * the read loop checks that after every dispatch.
 */
static void
cms_srv_process_frame(brix_cms_srv_ctx_t *ctx, u_char code, uint32_t streamid,
    const u_char *payload, size_t payload_len)
{
    ngx_uint_t  i;

    for (i = 0; cms_srv_frame_routes[i].handler != NULL; i++) {
        if (cms_srv_frame_routes[i].code == code) {
            cms_srv_frame_routes[i].handler(ctx, streamid,
                                            payload, payload_len);
            return;
        }
    }

    cms_srv_frame_unknown(ctx, code);
}

/* Read handler */

/* brix_cms_srv_write — CMS server write event handler: a pure timeout guard.
 * All writes are synchronous via send_ping() (driven by the ping timer), so this
 * only closes the connection (brix_cms_srv_close) on a timeout. */

void
brix_cms_srv_write(ngx_event_t *ev)
{
    /* We send synchronously via send_ping; nothing to flush here. */
    ngx_connection_t      *c   = ev->data;
    brix_cms_srv_ctx_t  *ctx = c->data;

    if (ev->timedout) {
        cms_srv_set_end_hint(ctx, BRIX_SESS_END_TIMEOUT);
        brix_cms_srv_close(ctx);
    }
}

/* brix_cms_srv_read — read event handler for connected data-server clients
 * (server-side counterpart to recv.c): accumulate bytes to a complete header, read
 * the dlen payload, and dispatch each frame (LOGIN→register, LOAD/AVAIL→update load,
 * PONG→log, GONE→unregister) via cms_srv_process_frame(); disconnect on
 * timeout/error or a frame over NGX_BRIX_CMS_MAX_FRAME. */

/*
 * cms_srv_read_timeout — the c->read timer fired.  A1: distinguish the
 * LOGIN-handshake deadline from the post-login idle watchdog (both fire the
 * read handler via the same timer), count the right resilience metric, and
 * close the connection.
 */
static void
cms_srv_read_timeout(brix_cms_srv_ctx_t *ctx)
{
    if (ctx->logged_in) {
        BRIX_RESIL_METRIC_INC(cms_idle_closes_total);
    } else {
        BRIX_RESIL_METRIC_INC(cms_login_timeouts_total);
    }
    cms_srv_fail_close(ctx, BRIX_SESS_END_TIMEOUT);
}

/*
 * cms_srv_read_accumulate — one recv() step of the frame accumulator: pull
 * bytes into ctx->inbuf, and once the fixed header is complete extend
 * ctx->in_need to the full frame length (rejecting frames over
 * NGX_BRIX_CMS_MAX_FRAME).  Splitting accumulation from dispatch keeps the
 * framing state machine in one place.  Returns NGX_AGAIN (socket drained),
 * NGX_DONE (progress made, frame still incomplete — call again), NGX_OK (a
 * complete frame sits in ctx->inbuf), or NGX_ERROR (peer EOF / recv error /
 * oversized frame — the connection has been closed).
 */
static ngx_int_t
cms_srv_read_accumulate(brix_cms_srv_ctx_t *ctx, ngx_connection_t *c)
{
    ssize_t   n;
    uint16_t  dlen;

    n = c->recv(c, ctx->inbuf + ctx->in_pos,
                ctx->in_need - ctx->in_pos);

    if (n == NGX_AGAIN) {
        return NGX_AGAIN;
    }

    if (n == NGX_ERROR || n == 0) {
        cms_srv_fail_close(ctx, n == 0 ? BRIX_SESS_END_CLIENT
                                       : BRIX_SESS_END_ERROR);
        return NGX_ERROR;
    }

    ctx->in_pos += (size_t) n;

    if (ctx->in_pos < ctx->in_need) {
        return NGX_DONE;
    }

    /* Completed reading the header — extend to full frame if needed. */
    if (ctx->in_need == NGX_BRIX_CMS_HDR_LEN) {
        dlen = ngx_brix_cms_get16(ctx->inbuf + 6);

        if ((size_t) dlen + NGX_BRIX_CMS_HDR_LEN
            > NGX_BRIX_CMS_MAX_FRAME)
        {
            ngx_log_error(NGX_LOG_WARN, c->log, 0,
                          "brix: CMS server: frame too large (%ui) "
                          "from %s", (ngx_uint_t) dlen, ctx->host);
            cms_srv_fail_close(ctx, BRIX_SESS_END_ERROR);
            return NGX_ERROR;
        }

        ctx->in_need = NGX_BRIX_CMS_HDR_LEN + dlen;
        if (ctx->in_pos < ctx->in_need) {
            return NGX_DONE;
        }
    }

    return NGX_OK;
}

/*
 * cms_srv_dispatch_frame — hand the complete frame in ctx->inbuf to the
 * opcode router, then reset the accumulator for the next header and re-arm
 * the idle watchdog.  WS3: a complete frame proves the node is alive — reset
 * the post-login idle watchdog.  Pre-login the absolute LOGIN deadline armed
 * at accept is deliberately NOT reset here, so a slowloris that completes one
 * frame cannot extend its handshake window.  Returns NGX_ERROR if the frame
 * handler closed the connection (ctx->c is NULL), NGX_OK otherwise.
 */
static ngx_int_t
cms_srv_dispatch_frame(brix_cms_srv_ctx_t *ctx)
{
    u_char    code;
    uint16_t  dlen;

    code = ctx->inbuf[4];
    dlen = ngx_brix_cms_get16(ctx->inbuf + 6);
    cms_srv_process_frame(ctx, code, ngx_brix_cms_get32(ctx->inbuf),
                          ctx->inbuf + NGX_BRIX_CMS_HDR_LEN, dlen);

    /* ctx->c may be NULL if the frame handler closed the connection. */
    if (ctx->c == NULL) {
        return NGX_ERROR;
    }

    ctx->in_pos  = 0;
    ctx->in_need = NGX_BRIX_CMS_HDR_LEN;

    if (ctx->logged_in && ctx->idle_timeout_ms > 0) {
        ngx_add_timer(ctx->c->read, ctx->idle_timeout_ms);
    }

    return NGX_OK;
}

/*
 * cms_srv_read_yield — A2 fairness: after a bounded number of frames, re-arm
 * the read event and resume via a posted read event, so a flooding data node
 * cannot monopolise the event loop.  Closes the connection if the event
 * cannot be re-armed; either way the caller returns.
 */
static void
cms_srv_read_yield(brix_cms_srv_ctx_t *ctx, ngx_connection_t *c)
{
    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        cms_srv_fail_close(ctx, BRIX_SESS_END_ERROR);
        return;
    }
    BRIX_RESIL_METRIC_INC(cms_frame_yields_total);
    ngx_post_event(c->read, &ngx_posted_events);
}

void
brix_cms_srv_read(ngx_event_t *ev)
{
    ngx_connection_t      *c;
    brix_cms_srv_ctx_t  *ctx;
    ngx_int_t              rc;
    ngx_uint_t             processed = 0;

    c   = ev->data;
    ctx = c->data;

    if (ev->timedout) {
        cms_srv_read_timeout(ctx);
        return;
    }

    for ( ;; ) {
        rc = cms_srv_read_accumulate(ctx, c);

        if (rc == NGX_AGAIN) {
            break;
        }
        if (rc == NGX_ERROR) {
            return;
        }
        if (rc == NGX_DONE) {
            continue;
        }

        /* Full frame received — dispatch. */
        if (cms_srv_dispatch_frame(ctx) != NGX_OK) {
            return;
        }

        if (++processed >= NGX_BRIX_CMS_MAX_FRAMES_PER_WAKEUP) {
            cms_srv_read_yield(ctx, c);
            return;
        }
    }

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        cms_srv_fail_close(ctx, BRIX_SESS_END_ERROR);
    }
}
