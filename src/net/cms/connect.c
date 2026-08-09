#include "cms_internal.h"
#include "state_relay.h"   /* Phase-61 W7: flush parked kYR_state relays */
#include "action_log.h"                          /* cmsd-action NOTICE lines */
#include "protocols/root/connection/netopt.h"   /* Phase 50: TCP dead-peer opts (WS5) */
#include "core/compat/log_diag.h"
#include "core/compat/lifecycle_timing.h"   /* monotonic clock for settle timing */
#include "observability/sesslog/sesslog_ngx.h"
#include "observability/metrics/metrics_macros.h"  /* A3: federation-join counters */

#include <ngx_event_connect.h>
#include <netinet/in.h>

void
ngx_brix_cms_set_end_hint(ngx_brix_cms_ctx_t *ctx, brix_sess_end_t why)
{
    if (ctx == NULL || ctx->sess_end_hint_set) {
        return;
    }

    ctx->sess_end_hint = why;
    ctx->sess_end_hint_set = 1;
}

static brix_sess_end_t
ngx_brix_cms_end_reason(ngx_brix_cms_ctx_t *ctx, ngx_connection_t *c)
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

    return BRIX_SESS_END_ERROR;
}

static const char *
ngx_brix_cms_manager_cstr(ngx_brix_cms_ctx_t *ctx, char *dst,
    size_t dst_size)
{
    size_t n;

    if (ctx == NULL || dst == NULL || dst_size == 0
        || ctx->mgr_name.data == NULL)
    {
        return "-";
    }

    n = ctx->mgr_name.len;
    if (n >= dst_size) {
        n = dst_size - 1;
    }
    if (n > 0) {
        ngx_memcpy(dst, ctx->mgr_name.data, n);
    }
    dst[n] = '\0';

    return dst;
}

static void
ngx_brix_cms_sess_begin(ngx_brix_cms_ctx_t *ctx)
{
    if (ctx == NULL || ctx->sess != NULL) {
        return;
    }

    ctx->sess = brix_sess_begin(ctx->conf->session_log,
                                ctx->conf->access_log_fd,
                                BRIX_SESS_PROTO_CMS,
                                BRIX_SESS_DIR_OUT,
                                (const char *) ctx->mgr_name.data,
                                ctx->mgr_name.len,
                                BRIX_SESS_AM_HOST, NULL);
}

static void
ngx_brix_cms_log_registration(ngx_brix_cms_ctx_t *ctx)
{
    char        manager[BRIX_SESSLOG_PATH_MAX];
    const char *target;

    if (ctx == NULL || ctx->sess_attempt_logged) {
        return;
    }

    target = ngx_brix_cms_manager_cstr(ctx, manager, sizeof(manager));
    brix_sess_auth_once(ctx->sess, BRIX_SESS_AM_HOST, target, "-");
    brix_sess_attempt(ctx->sess, target, BRIX_SESS_MODE_META);
    ctx->sess_attempt_logged = 1;
    brix_sess_result(ctx->sess, 1, target, BRIX_SESS_MODE_META, NULL);
}

/* ngx_brix_cms_arm_read_deadline — (re)arm c->read with conf->cms.read_timeout
 * (WS1) so a black-holed/half-open manager is detected; ngx_add_timer replaces any
 * pending timer, so each call measures from now. On expiry the recv handler's
 * ev->timedout branch disconnects and retries. */

void
ngx_brix_cms_arm_read_deadline(ngx_brix_cms_ctx_t *ctx)
{
    ngx_connection_t  *c;

    c = ctx->connection;
    if (c == NULL || ctx->conf->cms.read_timeout == 0 || ngx_exiting) {
        return;
    }

    ngx_add_timer(c->read, ctx->conf->cms.read_timeout);
}

/* ngx_brix_cms_schedule — arm or replace the CMS heartbeat timer to fire after
 * `delay` ms (any pending timer is removed first); used across the connect
 * lifecycle for retry and periodic heartbeat. */

void
ngx_brix_cms_schedule(ngx_brix_cms_ctx_t *ctx, ngx_msec_t delay)
{
    if (ctx->timer.timer_set) {
        ngx_del_timer(&ctx->timer);
    }

    ngx_add_timer(&ctx->timer, delay);
}

/* ngx_brix_cms_schedule_retry — schedule the next reconnect after a failure.
 *
 * Two regimes, chosen automatically so every caller (connect.c and recv.c) gets the
 * right behaviour without having to know which failure path it is on:
 *
 *   - COLD-START FAST-RETRY: a node that has NEVER yet logged in is racing its
 *     manager's listen socket (most acutely when the whole mesh boots together on
 *     one host).  Retry on the short fixed fast-retry interval for a bounded window
 *     so the mesh settles in tens of ms instead of seconds.  Quiet (debug) — a brief
 *     race is expected, not WARN-worthy.
 *   - EXPONENTIAL BACKOFF: once the fast-retry window expires, or once this node has
 *     ever logged in (so a failure is a real outage, not a cold start), fall back to
 *     the doubling+jitter backoff.  The genuinely-unreachable diagnostic is surfaced
 *     here, sparsely.
 *
 * Gating fast-retry on pre-first-login + a bounded window is what guarantees it can
 * never become a busy-spin (cf. the self-rearming-0ms-timer footgun).
 */

void
ngx_brix_cms_schedule_retry(ngx_brix_cms_ctx_t *ctx)
{
    ngx_msec_t  delay;
    ngx_msec_t  max_backoff;
    ngx_msec_t  now;

    /* Never schedule a reconnect once the worker is draining — a pending retry
     * timer would otherwise keep the exiting worker alive to the shutdown
     * timeout for no purpose. */
    if (ngx_exiting) {
        return;
    }

    /* §2.9: while retargeted by a login kYR_try, three consecutive failed
     * connects to the redirect target fall the link back to the CONFIGURED
     * manager — a dead supervisor must not orphan the node. */
    if (ctx->retargeted && !ctx->logged_in) {
        if (++ctx->retarget_fails >= 3) {
            ngx_log_error(NGX_LOG_NOTICE, ctx->cycle->log, 0,
                "brix: CMS retarget %V unreachable — reverting to "
                "configured manager %V", &ctx->mgr_name, &ctx->orig_name);
            ctx->mgr_addr = ctx->orig_addr;
            ctx->mgr_name = ctx->orig_name;
            ctx->retargeted = 0;
            ctx->retarget_depth = 0;
            ctx->retarget_fails = 0;
        }
    }

    /* Cold-start fast-retry window. */
    if (!ctx->ever_logged_in && ctx->fast_window > 0) {
        now = ngx_current_msec;

        /* Start the window on the first failure of this cold start. */
        if (ctx->fast_deadline == 0) {
            ctx->fast_deadline = now + ctx->fast_window;
        }

        if ((ngx_msec_int_t) (ctx->fast_deadline - now) > 0) {
            ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ctx->cycle->log, 0,
                           "brix: CMS fast-retry to %V (attempt %ui)",
                           &ctx->mgr_name, ctx->connect_attempts);
            ngx_brix_cms_schedule(ctx, ctx->fast_retry);
            return;
        }

        /* Window expired: the manager is genuinely unreachable for a same-host
         * cold start — surface the actionable diagnostic, then fall through to the
         * sparse exponential backoff below. */
        BRIX_DIAG_WARN(ctx->cycle->log, 0,
            "xrootd[cms]: cannot reach cluster manager %V",
            "the cmsd is down, the address/port is wrong, or a firewall blocks "
            "the connection",
            "confirm cmsd is listening and that brix_cms_manager matches its "
            "host:port; this node stays OUT of the cluster until it connects",
            &ctx->mgr_name);
    }

    /* Cap max backoff at 10× the heartbeat interval so a short cms_interval
     * (e.g. 2s for tests) also gives short reconnect windows. */
    max_backoff = (ngx_msec_t) ctx->conf->cms.interval * 10000;
    if (max_backoff > NGX_BRIX_CMS_BACKOFF_MAX) {
        max_backoff = NGX_BRIX_CMS_BACKOFF_MAX;
    }

    delay = ctx->backoff;
    if (ctx->backoff < max_backoff) {
        ctx->backoff *= 2;
        if (ctx->backoff > max_backoff) {
            ctx->backoff = max_backoff;
        }
    }

    /*
     * Phase 39 (WS7): add up to +25% random jitter so many workers/nodes that lost
     * the manager at the same instant do not reconnect in lockstep (a thundering
     * herd that would re-overload a recovering manager).  ngx_random() is nginx's
     * PRNG; jitter only ever lengthens the delay, never shortens it.
     */
    if (delay > 0) {
        delay += (ngx_msec_t) (ngx_random() % (delay / 4 + 1));
    }

    ngx_brix_cms_schedule(ctx, delay);
}

/* ngx_brix_cms_disconnect — close the TCP connection, drop its timers, NULL
 * ctx->connection, clear logged_in, and reset inbuf for the next reconnect; called
 * on I/O errors or timeouts. */

void
ngx_brix_cms_disconnect(ngx_brix_cms_ctx_t *ctx)
{
    ngx_connection_t  *c;

    c = ctx->connection;
    if (c == NULL) {
        return;
    }

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    brix_sess_end(ctx->sess, ngx_brix_cms_end_reason(ctx, c));
    ctx->sess = NULL;
    ctx->sess_attempt_logged = 0;
    ctx->sess_end_hint_set = 0;

    ngx_close_connection(c);

    if (ctx->logged_in) {
        /* This link leaves the cluster now — drop the gauge exactly once per
         * login/teardown pair (the flag is cleared immediately below). */
        BRIX_RESIL_METRIC_DEC(cms_registered_links);

    } else {
        /*
         * Torn down before LOGIN ever went out: this dial never became a link,
         * so it is a failed join attempt.  Counted HERE rather than at each
         * failure site because a refused dial can surface on any of three of
         * them — connect deadline, login write, or (on loopback, the common
         * one) the read side reporting ECONNREFUSED — and every one of them
         * funnels through this teardown exactly once.
         */
        BRIX_RESIL_METRIC_INC(cms_connect_failures_total);
    }

    ctx->connection = NULL;
    ctx->logged_in = 0;
    ctx->in_pos = 0;
    ctx->in_need = NGX_BRIX_CMS_HDR_LEN;

    /* Phase-61 W7: flush any kYR_state relays parked on this upward leg —
     * a late child kYR_have must not be echoed into a dead/reused conn. */
    brix_cms_state_relay_drop_ctx(ctx);
}

static void
ngx_brix_cms_write_handler(ngx_event_t *ev)
{
    ngx_connection_t       *c;
    ngx_brix_cms_ctx_t   *ctx;

    c = ev->data;
    ctx = c->data;

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->write->log, 0,
                   "brix: CMS write handler called timedout=%d "
                   "logged_in=%d c=%p",
                   (int) ev->timedout,
                   ctx ? (int) ctx->logged_in : -1, c);

    if (ev->timedout) {
        /* A connect/first-write that never completed.  Route through the connect
         * retry policy: pre-first-login it may fast-retry (bounded window), else it
         * backs off — never the multi-second backoff for a same-host cold start. */
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                       "brix: CMS connect/write timed out");
        ngx_brix_cms_set_end_hint(ctx, BRIX_SESS_END_TIMEOUT);
        ngx_brix_cms_disconnect(ctx);
        ngx_brix_cms_schedule_retry(ctx);
        return;
    }

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    if (!ctx->logged_in) {
        if (ngx_brix_cms_send_login(ctx) != NGX_OK) {
            /* The TCP connect was refused/half-open (on loopback, ECONNREFUSED
             * surfaces here as a writable-with-error event, not at connect()).
             * This is exactly the same-host "manager not listening yet" case → the
             * fast-retry policy, not the multi-second backoff. */
            ngx_brix_cms_set_end_hint(ctx, BRIX_SESS_END_ERROR);
            ngx_brix_cms_disconnect(ctx);
            ngx_brix_cms_schedule_retry(ctx);
            return;
        }

        ctx->logged_in = 1;
        ctx->retarget_fails = 0;   /* §2.9: the retarget (if any) worked */
        BRIX_RESIL_METRIC_INC(cms_logins_total);
        BRIX_RESIL_METRIC_INC(cms_registered_links);
        ctx->backoff = ngx_min((ngx_msec_t) ctx->conf->cms.interval * 1000,
                               (ngx_msec_t) NGX_BRIX_CMS_BACKOFF_INITIAL);

        ngx_log_error(NGX_LOG_NOTICE, ev->log, 0,
                      "brix: CMS login sent to %V",
                      &ctx->mgr_name);
        brix_cms_log_action(ev->log, "login",
                            (const char *) ctx->mgr_name.data,
                            "out", NULL, 1,
                            ctx->conf->manager_mode
                                ? "sub-manager registering up (Manager bit)"
                                : "leaf/client registering up");

        /* First successful login of this boot: leave fast-retry mode (any future
         * reconnect is a real outage → backoff) and report the settle time. */
        if (!ctx->ever_logged_in) {
            ctx->ever_logged_in = 1;
            ctx->fast_deadline  = 0;
            ngx_log_error(NGX_LOG_NOTICE, ev->log, 0,
                          "brix: CMS registered with %V after %uL ms "
                          "(%ui connect attempt(s), %s)",
                          &ctx->mgr_name,
                          (brix_phase_now_ns() - ctx->start_ns) / 1000000ull,
                          ctx->connect_attempts,
                          ctx->is_loopback ? "loopback" : "remote");
        }

        /*
         * Announce traffic state (Resume|noStage) immediately after login so a
         * real cmsd manager marks this disk-only node active and eligible for
         * selection; without it the manager keeps us suspended and never
         * redirects clients here.
         */
        if (ngx_brix_cms_send_status(ctx) != NGX_OK) {
            ngx_brix_cms_set_end_hint(ctx, BRIX_SESS_END_ERROR);
            ngx_brix_cms_disconnect(ctx);
            ngx_brix_cms_schedule_retry(ctx);
            return;
        }
        ngx_brix_cms_log_registration(ctx);

        /*
         * WS1: arm the manager-silence deadline ONCE, at the login transition.
         * It is deliberately NOT re-armed on our own heartbeat sends (that would
         * let our outbound traffic mask a manager that has gone silent); recv.c
         * resets it only when a frame actually arrives FROM the manager.  So it
         * measures time since the last manager activity and, on expiry, the recv
         * handler reconnects us to a healthy manager.
         */
        ngx_brix_cms_arm_read_deadline(ctx);
    }

    if (ngx_brix_cms_send_load(ctx) != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, ev->log, 0,
                      "brix: CMS write handler: send_load failed");
        brix_cms_log_action(ev->log, "load",
                            (const char *) ctx->mgr_name.data,
                            "out", NULL, 0, "send_load failed");
        ngx_brix_cms_set_end_hint(ctx, BRIX_SESS_END_ERROR);
        ngx_brix_cms_disconnect(ctx);
        ngx_brix_cms_schedule_retry(ctx);
        return;
    }

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        ngx_brix_cms_set_end_hint(ctx, BRIX_SESS_END_ERROR);
        ngx_brix_cms_disconnect(ctx);
        ngx_brix_cms_schedule_retry(ctx);
        return;
    }

    ngx_brix_cms_schedule(ctx, (ngx_msec_t) ctx->conf->cms.interval * 1000);

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                   "brix: CMS write handler: heartbeat sent");
}

/* ngx_brix_cms_connect — start a TCP connect to the CMS manager via
 * ngx_event_connect_peer, install the read/write handlers, and arm the connect
 * timeout (NGX_BRIX_CMS_CONNECT_TIMEOUT = 5s); called from the timer when
 * ctx->connection == NULL. */

static void
ngx_brix_cms_connect(ngx_brix_cms_ctx_t *ctx)
{
    ngx_int_t          rc;
    ngx_connection_t  *c;

    ctx->connect_attempts++;

    ngx_memzero(&ctx->peer, sizeof(ctx->peer));
    ctx->peer.sockaddr = ctx->mgr_addr->sockaddr;
    ctx->peer.socklen = ctx->mgr_addr->socklen;
    ctx->peer.name = &ctx->mgr_addr->name;
    ctx->peer.get = ngx_event_get_peer;
    ctx->peer.log = ctx->cycle->log;
    ctx->peer.log_error = NGX_ERROR_ERR;

    rc = ngx_event_connect_peer(&ctx->peer);
    if (rc == NGX_ERROR || rc == NGX_DECLINED || ctx->peer.connection == NULL) {
        BRIX_DIAG_WARN(ctx->cycle->log, 0,
            "xrootd[cms]: cannot reach cluster manager %V",
            "the cmsd is down, the address/port is wrong, or a firewall "
            "blocks the connection",
            "confirm cmsd is listening and that brix_cms_manager matches "
            "its host:port; this node will keep retrying and stays OUT of the "
            "cluster until it connects",
            &ctx->mgr_name);
        BRIX_RESIL_METRIC_INC(cms_connect_failures_total);
        ngx_brix_cms_schedule_retry(ctx);
        return;
    }

    c = ctx->peer.connection;
    ctx->connection = c;
    ctx->logged_in = 0;
    ctx->in_pos = 0;
    ctx->in_need = NGX_BRIX_CMS_HDR_LEN;

    c->data = ctx;
    c->read->handler = ngx_brix_cms_read_handler;
    c->write->handler = ngx_brix_cms_write_handler;
    ngx_brix_cms_sess_begin(ctx);

    /*
     * WS5: OS-level dead-peer reaping on the manager socket, so a silently-
     * dropped manager is torn down by the kernel even between event-loop
     * deadlines.  Best-effort; failures are non-fatal.
     */
    brix_apply_tcp_deadpeer_opts(c->fd, ctx->conf->cms.tcp_keepalive,
                                   ctx->conf->cms.tcp_user_timeout);

    if (rc == NGX_AGAIN) {
        /*
         * WS2: bound the connect + first-write readiness window with
         * cms_send_timeout (operator-tunable); the write handler's ev->timedout
         * path reconnects with backoff.  Falls back to the fixed connect timeout
         * if the knob is disabled (0).
         */
        ngx_msec_t connect_tmo = ctx->conf->cms.send_timeout > 0
                                 ? ctx->conf->cms.send_timeout
                                 : NGX_BRIX_CMS_CONNECT_TIMEOUT;
        ngx_add_timer(c->write, connect_tmo);
        return;
    }

    ngx_brix_cms_write_handler(c->write);
}

/* ngx_brix_cms_timer — the CMS timer handler: when connected, send a load
 * heartbeat every cms_interval seconds (disconnect + backoff on failure); when
 * ctx->connection == NULL, trigger a reconnect. */

void
ngx_brix_cms_timer(ngx_event_t *ev)
{
    ngx_brix_cms_ctx_t  *ctx;

    ctx = ev->data;

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                   "brix: CMS timer fired connection=%p logged_in=%d",
                   ctx->connection,
                   ctx->connection ? (int) ctx->logged_in : -1);

    /* Worker shutting down: drop the manager link immediately (so the manager
     * sees us leave at once) and do not reschedule the heartbeat. */
    if (ngx_exiting) {
        ngx_brix_cms_disconnect(ctx);
        return;
    }

    if (ctx->connection == NULL) {
        ngx_brix_cms_connect(ctx);
        return;
    }

    if (ngx_brix_cms_send_load(ctx) != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, ev->log, 0,
                      "brix: CMS load heartbeat failed");
        brix_cms_log_action(ev->log, "load",
                            (const char *) ctx->mgr_name.data,
                            "out", NULL, 0, "heartbeat send failed");
        ngx_brix_cms_set_end_hint(ctx, BRIX_SESS_END_ERROR);
        ngx_brix_cms_disconnect(ctx);
        ngx_brix_cms_schedule_retry(ctx);
        return;
    }

    brix_cms_log_action(ev->log, "load",
                        (const char *) ctx->mgr_name.data,
                        "out", NULL, 1,
                        ctx->conf->manager_mode ? "aggregate space heartbeat"
                                                : "free-space heartbeat");

    ngx_brix_cms_schedule(ctx, (ngx_msec_t) ctx->conf->cms.interval * 1000);
}

