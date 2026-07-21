/*
 * cms/server_recv_frame.c — CMS server-side opcode handlers + dispatch table.
 *
 * WHAT: The per-opcode frame handlers for an accepted CMS data-server
 * connection (LOGIN, kYR_xauth, LOAD, AVAIL/SPACE, PONG, PING, DISC, UPDATE,
 * STATFS, USAGE, STATS, STATUS, GONE, CNS, and the unknown-opcode fallback), the
 * login-completion
 * step, the periodic ping timer, and the data-driven opcode → handler route
 * table consumed by cms_srv_process_frame().
 *
 * WHY: Split out of the former monolithic server_recv.c (Phase-79 file-size
 * split).  Grouping "what each opcode does" behind a single dispatch table keeps
 * the wire-framing state machine (server_recv.c) and the pure decoders
 * (server_recv_parse.c) each single-purpose.  Handlers reach the lifecycle
 * helpers and the payload parsers through server_recv_internal.h; only
 * cms_srv_process_frame is exported (declared there and thus non-static).
 *
 * HOW: Each handler shares one signature so the route table can dispatch by
 * opcode; a handler that tears the connection down leaves ctx->c NULL for the
 * read loop to observe.  cms_srv_process_frame scans the table, falling through
 * to cms_srv_frame_unknown for codes we do not act on.
 */

#include "server.h"
#include "server_recv_internal.h"
#include "router.h"                       /* table-driven opcode routing */
#include "rrdata.h"                       /* Pup decode + statfs reply encode */
#include "net/manager/registry.h"          /* aggregate space for statfs reply */
#include "net/manager/loc_cache.h"         /* W3: dynamic file-location cache */
#include "recv_internal.h"                 /* W3: pending-locate client wake */
#include "cns.h"                          /* §6 CNS inventory + event codec */
#include "fanout.h"                       /* W8: fold forwarded-op kYR_error */

/* Ping timer */

/*
 * cms_srv_blfile_tick — enforce the operator blacklist file (Phase-89 W6′).
 *
 * Piggybacked on the per-connection ping cadence (and called with force=1
 * right after a registration) instead of a dedicated timer: the file only
 * matters while data servers are registered, and registered servers are
 * exactly the ones with a live ping timer.  The poll self-rate-limits its
 * stat() to 1/s, so many nodes sharing one srv block stay cheap.  The
 * blacklist duration is 3x the ping interval — always longer than the gap to
 * the next re-assert, so a file-listed server stays down (over undrain and
 * over the register-time blacklist clear) until the line is removed.
 */
static void
cms_srv_blfile_tick(brix_cms_srv_ctx_t *ctx, ngx_uint_t force,
    ngx_log_t *log)
{
    brix_cms_blfile_poll(&ctx->conf->blfile, &ctx->conf->blacklist_file,
                           ctx->interval_ms * 3, force, log);
}

static void
brix_cms_srv_ping_timer(ngx_event_t *ev)
{
    brix_cms_srv_ctx_t  *ctx = ev->data;

    cms_srv_blfile_tick(ctx, 0, ev->log);

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
    if (ctx->vnid[0] != '\0') {
        brix_srv_set_vnid(ctx->host, ctx->port, ctx->vnid);
    }
    ctx->logged_in = 1;
    cms_srv_log_registration(ctx);

    /* W3: join this worker's fan-out set — locate misses can now probe this
     * node with kYR_state.  Removed again in brix_cms_srv_close. */
    brix_cms_srv_node_add(ctx);

    /* W6′: brix_srv_register just cleared any prior blacklist — re-assert
     * the file immediately so a listed node is never selectable, not even
     * for one poll period. */
    if (ctx->c != NULL) {
        cms_srv_blfile_tick(ctx, 1, ctx->c->log);
    }

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
 * registry (util_pct unchanged — LOAD carries no utilisation) and record its
 * machine-load percentage from the theLoad bytes (Phase-89 W4, feeds
 * load-weighted selection).  Pre-login frames are ignored.
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
    brix_srv_set_machine_load(ctx->host, ctx->port,
        cms_srv_parse_load_machine_pct(payload, payload_len));
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
static void
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
static void
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
static void
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
static void
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
static void
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
    { CMS_RR_USAGE,  cms_srv_frame_usage  },
    { CMS_RR_STATS,  cms_srv_frame_stats  },
    { CMS_RR_STATUS, cms_srv_frame_status },
    { CMS_RR_GONE,   cms_srv_frame_gone   },
    { CMS_RR_HAVE,   cms_srv_frame_have   },
    { CMS_RSP_ERROR, cms_srv_frame_error  },   /* W8 fan-out reply fold */
    { CMS_RR_CNS,    cms_srv_frame_cns    },
    { 0,             NULL                 },
};

/*
 * cms_srv_process_frame — route one complete frame by opcode through the
 * table above.  A handler that tears the connection down leaves ctx->c NULL;
 * the read loop checks that after every dispatch.
 */
void
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
