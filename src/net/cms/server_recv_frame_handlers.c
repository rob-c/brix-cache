/*
 * cms/server_recv_frame_handlers.c — CMS server per-opcode frame handlers.
 *
 * WHAT: The per-opcode handlers for an accepted CMS data-server connection
 * (LOGIN, kYR_xauth, LOAD, AVAIL/SPACE, PONG, PING, DISC, UPDATE, STATFS,
 * STATUS, USAGE, STATS, GONE, HAVE, kYR_error fold, and CNS).  All share the
 * cms_srv_frame_pt signature so the route table in server_recv_frame.c can
 * dispatch them by opcode.
 *
 * WHY: Split out of server_recv_frame.c (file-size split) to keep the wire
 * dispatch table + read-loop routing (server_recv_frame.c) separate from the
 * bulk of "what each opcode does".  Each handler reaches the lifecycle helpers,
 * the payload parsers, and cms_srv_complete_login through
 * server_recv_internal.h; the handlers themselves are declared there and are
 * therefore non-static.
 *
 * HOW: A handler that tears the connection down leaves ctx->c NULL for the read
 * loop to observe.  The auth handlers (login/xauth) hand off to
 * cms_srv_complete_login (defined in server_recv_frame.c) once the node is
 * admitted.
 */

#include "server.h"
#include "server_recv_internal.h"
#include "rrdata.h"                       /* Pup decode + statfs reply encode */
#include "net/manager/registry.h"          /* aggregate space for statfs reply */
#include "net/manager/loc_cache.h"         /* W3: dynamic file-location cache */
#include "recv_internal.h"                 /* W3: pending-locate client wake */
#include "cns.h"                          /* §6 CNS inventory + event codec */
#include "fanout.h"                       /* W8: fold forwarded-op kYR_error */

/* Per-opcode frame handlers.  All share one signature so the dispatcher in
 * server_recv_frame.c can be a data-driven route table (mirrors recv.c's
 * client-side shape); handlers that need no payload/streamid simply ignore
 * those arguments.  A handler that closes the connection leaves ctx->c NULL —
 * the read loop checks that. */

/*
 * cms_srv_frame_login — LOGIN: parse the CmsLoginData payload; on parse
 * failure log + close.  W1a — if sss cluster auth is required, do NOT register
 * yet.  Mirror the real cmsd manager (XrdCmsLogin::Admit): after the LOGIN
 * frame arrives, send our security parms and wait for the node's kYR_xauth
 * credential before admitting it into the registry.
 */
void
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
void
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
 * registry (util_pct unchanged — LOAD carries no utilisation) and record its
 * machine-load percentage from the theLoad bytes (Phase-89 W4, feeds
 * load-weighted selection).  Pre-login frames are ignored.
 */
void
cms_srv_frame_load(brix_cms_srv_ctx_t *ctx, uint32_t streamid,
    const u_char *payload, size_t payload_len)
{
    uint32_t  free_mb;

    if (!ctx->logged_in) {
        return;
    }
    free_mb = cms_srv_parse_load_free_mb(payload, payload_len);
    brix_srv_update_load(ctx->host, ctx->port, free_mb, ctx->util_pct);
    brix_srv_set_machine_load(ctx->host, ctx->port,
        cms_srv_parse_load_machine_pct(payload, payload_len));
    ctx->free_mb = free_mb;
}

/*
 * cms_srv_frame_avail — AVAIL/SPACE: refresh both free-space and utilisation
 * in the registry (the two opcodes share this payload shape).  Pre-login
 * frames are ignored.
 */
void
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
void
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
void
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
void
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
void
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
void
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
 * cms_srv_frame_status — kYR_status from a node: the phase-89 W9 state
 * machine.  Modifier bits (read from the frame header at ctx->inbuf[5], the
 * dispatch table forwards only code/streamid/payload):
 *   suspend → stop selecting the node (drain until it resumes; bounded at
 *             24 h so a node that dies suspended eventually ages out via the
 *             normal stale-entry path instead of pinning a slot forever);
 *   resume  → immediately selectable again (clears the suspend drain);
 *   reset   → forget cached metrics/fault state, node re-announces
 *             (brix_srv_reset contract);
 *   stage/nostage → record staging availability for stage-aware selection.
 * Unknown/empty modifiers are a no-op, matching stock cmsd; pre-login status
 * frames are ignored.
 */
void
cms_srv_frame_status(brix_cms_srv_ctx_t *ctx, uint32_t streamid,
    const u_char *payload, size_t payload_len)
{
    u_char  mod = ctx->inbuf[5];

    if (!ctx->logged_in) {
        return;                          /* pre-auth: ignore */
    }

    if (mod & CMS_ST_SUSPEND) {
        brix_srv_blacklist(ctx->host, ctx->port, 24 * 60 * 60 * 1000);
        ngx_log_error(NGX_LOG_NOTICE, ctx->c->log, 0,
                      "brix: CMS server: %s:%d suspended",
                      ctx->host, (int) ctx->port);
    } else if (mod & CMS_ST_RESUME) {
        (void) brix_srv_undrain(ctx->host, ctx->port);
        ngx_log_error(NGX_LOG_NOTICE, ctx->c->log, 0,
                      "brix: CMS server: %s:%d resumed",
                      ctx->host, (int) ctx->port);
    }

    if (mod & CMS_ST_RESET) {
        (void) brix_srv_reset(ctx->host, ctx->port);
        ngx_log_error(NGX_LOG_NOTICE, ctx->c->log, 0,
                      "brix: CMS server: %s:%d state reset",
                      ctx->host, (int) ctx->port);
    }

    if (mod & CMS_ST_STAGE) {
        brix_srv_set_stage(ctx->host, ctx->port, 1);
    } else if (mod & CMS_ST_NOSTAGE) {
        brix_srv_set_stage(ctx->host, ctx->port, 0);
    }
}

/*
 * cms_srv_frame_usage — load/usage query (do_Usage): answer kYR_load with our
 * 6-byte load vector + aggregate free MB, echoing the streamid.  The five
 * non-dsk bytes come from the Phase-89 W4 machine meter (state lives on the
 * srv conf — one meter per CMS server block, sampling the shared machine);
 * dsk carries the aggregate utilisation percentage.
 */
void
cms_srv_frame_usage(brix_cms_srv_ctx_t *ctx, uint32_t streamid,
    const u_char *payload, size_t payload_len)
{
    u_char    load6[6] = { 0 };
    uint32_t  free_mb = 0, util = 0;

    if (!ctx->logged_in) {
        return;                          /* pre-auth: ignore */
    }
    brix_cms_meter_sample(&ctx->conf->meter, (uint64_t) ngx_current_msec,
                          load6);
    brix_srv_aggregate_space(&free_mb, &util);
    load6[5] = (u_char) (util > 100 ? 100 : util);
    (void) brix_cms_srv_send_load(ctx, streamid, load6, free_mb);
}

/*
 * cms_srv_frame_stats — statistics query (do_Stats), size form: answer
 * kYR_data with a raw 4-byte big-endian length = the buffer a full stats
 * reply would need.  Stock cmsd's kYR_size modifier asks exactly this so the
 * caller can allocate before requesting the text form; we answer the size
 * form for every modifier until a text renderer exists (the dispatch table
 * does not forward the modifier byte), which callers handle as "allocate,
 * then re-ask" — the honest subset of do_Stats.
 */
void
cms_srv_frame_stats(brix_cms_srv_ctx_t *ctx, uint32_t streamid,
    const u_char *payload, size_t payload_len)
{
    u_char    out[4];
    uint32_t  need;

    if (!ctx->logged_in) {
        return;                          /* pre-auth: ignore */
    }

    /* An allocation advertisement, not a promise of exact length: a flat
     * upper bound covering the stock statistics document shape (<statistics>
     * shell + per-node <subscriber> rows) at the registry's configured slot
     * ceiling, so a future text form always fits the advertised buffer. */
    need = 4096;

    out[0] = (u_char) (need >> 24);
    out[1] = (u_char) (need >> 16);
    out[2] = (u_char) (need >> 8);
    out[3] = (u_char) need;
    (void) brix_cms_srv_send_data(ctx, streamid, out, sizeof(out));
}

/*
 * cms_srv_frame_gone — a data server signals that it no longer holds a
 * specific path.  Remove that path token from its registry entry without
 * touching the rest of the registration (the server still holds other paths).
 */
void
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
 * cms_srv_frame_have — Phase-89 W3: a node asserts it holds a path (kYR_have,
 * raw NUL-terminated path), answering one of our kYR_state fan-out probes.
 *
 * SECURITY GATE: a node may only assert `have` for paths under its own
 * login-Paths prefixes.  Anything else (including an unsolicited HAVE from a
 * hostile/buggy node) is logged and dropped — never cached, never woken on.
 * A currently-blacklisted/draining node is likewise refused, so the dynamic
 * location plane cannot bypass the operator blacklist (W6′) or a drain.
 *
 * On acceptance: record node → path in the SHM loc cache, then wake the
 * parked client whose pending-locate entry the echoed streamid keys (first
 * HAVE wins — later answers find no pending entry and are cache-only).
 */
void
cms_srv_frame_have(brix_cms_srv_ctx_t *ctx, uint32_t streamid,
    const u_char *payload, size_t payload_len)
{
    char    path[BRIX_LOC_CACHE_PATH_MAX];
    size_t  plen;

    if (!ctx->logged_in || payload_len == 0 || ctx->c == NULL) {
        return;
    }

    /* Bound + shape the path: NUL-terminated, absolute, no ".." traversal.
     * The node side stats before answering, but this side must not trust the
     * peer's parser — same reject-not-guess posture as the state ingest. */
    plen = ngx_strnlen((u_char *) payload, payload_len);
    if (plen == 0 || plen >= sizeof(path) || payload[0] != '/') {
        return;
    }
    ngx_memcpy(path, payload, plen);
    path[plen] = '\0';
    if (strstr(path, "..") != NULL) {
        return;
    }

    if (!brix_srv_paths_cover(ctx->paths, path)) {
        ngx_log_error(NGX_LOG_WARN, ctx->c->log, 0,
                      "brix: CMS server: %s:%d asserted have for \"%s\" "
                      "outside its exported paths [%s] — dropped",
                      ctx->host, (int) ctx->port, path, ctx->paths);
        return;
    }

    if (brix_srv_is_blacklisted(ctx->host, ctx->port)) {
        ngx_log_error(NGX_LOG_INFO, ctx->c->log, 0,
                      "brix: CMS server: ignoring have for \"%s\" from "
                      "drained node %s:%d", path, ctx->host, (int) ctx->port);
        return;
    }

    brix_loc_cache_insert(path, ctx->host, ctx->port);
    (void) brix_cms_wake_pending_session(ctx->c->log, streamid,
                                           ctx->host, ctx->port);
}

/*
 * cms_srv_frame_error — Phase-89 W8: a node answered a forwarded namespace op
 * with kYR_error ([4B big-endian ecode][text + NUL], echoing the fan-out
 * streamid).  Fold it into the fan-out aggregation slot; success stays silent
 * (the deadline window in fanout.c is the success signal).  Payload text is
 * peer-controlled — it is bounded here and sanitized before it can reach the
 * client reply.
 */
void
cms_srv_frame_error(brix_cms_srv_ctx_t *ctx, uint32_t streamid,
    const u_char *payload, size_t payload_len)
{
    uint32_t  ecode;
    char      text[128];
    size_t    tlen;

    if (!ctx->logged_in || ctx->c == NULL) {
        return;
    }

    ecode = 0;
    text[0] = '\0';
    if (payload_len >= 4) {
        ecode = ((uint32_t) payload[0] << 24) | ((uint32_t) payload[1] << 16)
                | ((uint32_t) payload[2] << 8) | (uint32_t) payload[3];
        tlen = ngx_strnlen((u_char *) payload + 4, payload_len - 4);
        if (tlen >= sizeof(text)) {
            tlen = sizeof(text) - 1;
        }
        ngx_memcpy(text, payload + 4, tlen);
        text[tlen] = '\0';
    }

    brix_cms_fanout_note_error(streamid, ecode, text, ctx->c->log);
}

/*
 * cms_srv_frame_cns — §6 Composite Cluster Name Space: a data server reports a
 * namespace mutation.  Apply it into the manager inventory (collect mode only).
 */
void
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
