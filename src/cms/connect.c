#include "cms_internal.h"
#include "../connection/netopt.h"   /* Phase 50: TCP dead-peer opts (WS5) */
#include "../compat/log_diag.h"
#include "../compat/lifecycle_timing.h"   /* monotonic clock for settle timing */

#include <ngx_event_connect.h>
#include <netinet/in.h>

/* cms_addr_is_loopback — classify the resolved manager address as on-host
 * (127.0.0.0/8 or ::1).  A loopback manager is reached with no network latency, so
 * it gets the most aggressive cold-start settle profile. */
static ngx_uint_t
cms_addr_is_loopback(struct sockaddr *sa)
{
    if (sa == NULL) {
        return 0;
    }

    if (sa->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *) sa;
        return (ntohl(sin->sin_addr.s_addr) & 0xFF000000u) == 0x7F000000u;
    }

#if (NGX_HAVE_INET6)
    if (sa->sa_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) sa;
        return IN6_IS_ADDR_LOOPBACK(&sin6->sin6_addr) ? 1 : 0;
    }
#endif

    return 0;
}

/* ngx_xrootd_cms_arm_read_deadline — (re)arm c->read with conf->cms_read_timeout
 * (WS1) so a black-holed/half-open manager is detected; ngx_add_timer replaces any
 * pending timer, so each call measures from now. On expiry the recv handler's
 * ev->timedout branch disconnects and retries. */

void
ngx_xrootd_cms_arm_read_deadline(ngx_xrootd_cms_ctx_t *ctx)
{
    ngx_connection_t  *c;

    c = ctx->connection;
    if (c == NULL || ctx->conf->cms_read_timeout == 0 || ngx_exiting) {
        return;
    }

    ngx_add_timer(c->read, ctx->conf->cms_read_timeout);
}

/* ngx_xrootd_cms_schedule — arm or replace the CMS heartbeat timer to fire after
 * `delay` ms (any pending timer is removed first); used across the connect
 * lifecycle for retry and periodic heartbeat. */

void
ngx_xrootd_cms_schedule(ngx_xrootd_cms_ctx_t *ctx, ngx_msec_t delay)
{
    if (ctx->timer.timer_set) {
        ngx_del_timer(&ctx->timer);
    }

    ngx_add_timer(&ctx->timer, delay);
}

/* ngx_xrootd_cms_schedule_retry — schedule the next reconnect after a failure.
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
ngx_xrootd_cms_schedule_retry(ngx_xrootd_cms_ctx_t *ctx)
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

    /* Cold-start fast-retry window. */
    if (!ctx->ever_logged_in && ctx->fast_window > 0) {
        now = ngx_current_msec;

        /* Start the window on the first failure of this cold start. */
        if (ctx->fast_deadline == 0) {
            ctx->fast_deadline = now + ctx->fast_window;
        }

        if ((ngx_msec_int_t) (ctx->fast_deadline - now) > 0) {
            ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ctx->cycle->log, 0,
                           "xrootd: CMS fast-retry to %V (attempt %ui)",
                           &ctx->conf->cms_manager, ctx->connect_attempts);
            ngx_xrootd_cms_schedule(ctx, ctx->fast_retry);
            return;
        }

        /* Window expired: the manager is genuinely unreachable for a same-host
         * cold start — surface the actionable diagnostic, then fall through to the
         * sparse exponential backoff below. */
        XROOTD_DIAG_WARN(ctx->cycle->log, 0,
            "xrootd[cms]: cannot reach cluster manager %V",
            "the cmsd is down, the address/port is wrong, or a firewall blocks "
            "the connection",
            "confirm cmsd is listening and that xrootd_cms_manager matches its "
            "host:port; this node stays OUT of the cluster until it connects",
            &ctx->conf->cms_manager);
    }

    /* Cap max backoff at 10× the heartbeat interval so a short cms_interval
     * (e.g. 2s for tests) also gives short reconnect windows. */
    max_backoff = (ngx_msec_t) ctx->conf->cms_interval * 10000;
    if (max_backoff > NGX_XROOTD_CMS_BACKOFF_MAX) {
        max_backoff = NGX_XROOTD_CMS_BACKOFF_MAX;
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

    ngx_xrootd_cms_schedule(ctx, delay);
}

/* ngx_xrootd_cms_disconnect — close the TCP connection, drop its timers, NULL
 * ctx->connection, clear logged_in, and reset inbuf for the next reconnect; called
 * on I/O errors or timeouts. */

void
ngx_xrootd_cms_disconnect(ngx_xrootd_cms_ctx_t *ctx)
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

    ngx_close_connection(c);

    ctx->connection = NULL;
    ctx->logged_in = 0;
    ctx->in_pos = 0;
    ctx->in_need = NGX_XROOTD_CMS_HDR_LEN;
}

static void
ngx_xrootd_cms_write_handler(ngx_event_t *ev)
{
    ngx_connection_t       *c;
    ngx_xrootd_cms_ctx_t   *ctx;

    c = ev->data;
    ctx = c->data;

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->write->log, 0,
                   "xrootd: CMS write handler called timedout=%d "
                   "logged_in=%d c=%p",
                   (int) ev->timedout,
                   ctx ? (int) ctx->logged_in : -1, c);

    if (ev->timedout) {
        /* A connect/first-write that never completed.  Route through the connect
         * retry policy: pre-first-login it may fast-retry (bounded window), else it
         * backs off — never the multi-second backoff for a same-host cold start. */
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                       "xrootd: CMS connect/write timed out");
        ngx_xrootd_cms_disconnect(ctx);
        ngx_xrootd_cms_schedule_retry(ctx);
        return;
    }

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    if (!ctx->logged_in) {
        if (ngx_xrootd_cms_send_login(ctx) != NGX_OK) {
            /* The TCP connect was refused/half-open (on loopback, ECONNREFUSED
             * surfaces here as a writable-with-error event, not at connect()).
             * This is exactly the same-host "manager not listening yet" case → the
             * fast-retry policy, not the multi-second backoff. */
            ngx_xrootd_cms_disconnect(ctx);
            ngx_xrootd_cms_schedule_retry(ctx);
            return;
        }

        ctx->logged_in = 1;
        ctx->backoff = ngx_min((ngx_msec_t) ctx->conf->cms_interval * 1000,
                               (ngx_msec_t) NGX_XROOTD_CMS_BACKOFF_INITIAL);

        ngx_log_error(NGX_LOG_NOTICE, ev->log, 0,
                      "xrootd: CMS login sent to %V",
                      &ctx->conf->cms_manager);

        /* First successful login of this boot: leave fast-retry mode (any future
         * reconnect is a real outage → backoff) and report the settle time. */
        if (!ctx->ever_logged_in) {
            ctx->ever_logged_in = 1;
            ctx->fast_deadline  = 0;
            ngx_log_error(NGX_LOG_NOTICE, ev->log, 0,
                          "xrootd: CMS registered with %V after %uL ms "
                          "(%ui connect attempt(s), %s)",
                          &ctx->conf->cms_manager,
                          (xrootd_phase_now_ns() - ctx->start_ns) / 1000000ull,
                          ctx->connect_attempts,
                          ctx->is_loopback ? "loopback" : "remote");
        }

        /*
         * Announce traffic state (Resume|noStage) immediately after login so a
         * real cmsd manager marks this disk-only node active and eligible for
         * selection; without it the manager keeps us suspended and never
         * redirects clients here.
         */
        if (ngx_xrootd_cms_send_status(ctx) != NGX_OK) {
            ngx_xrootd_cms_disconnect(ctx);
            ngx_xrootd_cms_schedule_retry(ctx);
            return;
        }

        /*
         * WS1: arm the manager-silence deadline ONCE, at the login transition.
         * It is deliberately NOT re-armed on our own heartbeat sends (that would
         * let our outbound traffic mask a manager that has gone silent); recv.c
         * resets it only when a frame actually arrives FROM the manager.  So it
         * measures time since the last manager activity and, on expiry, the recv
         * handler reconnects us to a healthy manager.
         */
        ngx_xrootd_cms_arm_read_deadline(ctx);
    }

    if (ngx_xrootd_cms_send_load(ctx) != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, ev->log, 0,
                      "xrootd: CMS write handler: send_load failed");
        ngx_xrootd_cms_disconnect(ctx);
        ngx_xrootd_cms_schedule_retry(ctx);
        return;
    }

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        ngx_xrootd_cms_disconnect(ctx);
        ngx_xrootd_cms_schedule_retry(ctx);
        return;
    }

    ngx_xrootd_cms_schedule(ctx, (ngx_msec_t) ctx->conf->cms_interval * 1000);

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                   "xrootd: CMS write handler: heartbeat sent");
}

/* ngx_xrootd_cms_connect — start a TCP connect to the CMS manager via
 * ngx_event_connect_peer, install the read/write handlers, and arm the connect
 * timeout (NGX_XROOTD_CMS_CONNECT_TIMEOUT = 5s); called from the timer when
 * ctx->connection == NULL. */

static void
ngx_xrootd_cms_connect(ngx_xrootd_cms_ctx_t *ctx)
{
    ngx_int_t          rc;
    ngx_connection_t  *c;

    ctx->connect_attempts++;

    ngx_memzero(&ctx->peer, sizeof(ctx->peer));
    ctx->peer.sockaddr = ctx->conf->cms_addr->sockaddr;
    ctx->peer.socklen = ctx->conf->cms_addr->socklen;
    ctx->peer.name = &ctx->conf->cms_addr->name;
    ctx->peer.get = ngx_event_get_peer;
    ctx->peer.log = ctx->cycle->log;
    ctx->peer.log_error = NGX_ERROR_ERR;

    rc = ngx_event_connect_peer(&ctx->peer);
    if (rc == NGX_ERROR || rc == NGX_DECLINED || ctx->peer.connection == NULL) {
        XROOTD_DIAG_WARN(ctx->cycle->log, 0,
            "xrootd[cms]: cannot reach cluster manager %V",
            "the cmsd is down, the address/port is wrong, or a firewall "
            "blocks the connection",
            "confirm cmsd is listening and that xrootd_cms_manager matches "
            "its host:port; this node will keep retrying and stays OUT of the "
            "cluster until it connects",
            &ctx->conf->cms_manager);
        ngx_xrootd_cms_schedule_retry(ctx);
        return;
    }

    c = ctx->peer.connection;
    ctx->connection = c;
    ctx->logged_in = 0;
    ctx->in_pos = 0;
    ctx->in_need = NGX_XROOTD_CMS_HDR_LEN;

    c->data = ctx;
    c->read->handler = ngx_xrootd_cms_read_handler;
    c->write->handler = ngx_xrootd_cms_write_handler;

    /*
     * WS5: OS-level dead-peer reaping on the manager socket, so a silently-
     * dropped manager is torn down by the kernel even between event-loop
     * deadlines.  Best-effort; failures are non-fatal.
     */
    xrootd_apply_tcp_deadpeer_opts(c->fd, ctx->conf->cms_tcp_keepalive,
                                   ctx->conf->cms_tcp_user_timeout);

    if (rc == NGX_AGAIN) {
        /*
         * WS2: bound the connect + first-write readiness window with
         * cms_send_timeout (operator-tunable); the write handler's ev->timedout
         * path reconnects with backoff.  Falls back to the fixed connect timeout
         * if the knob is disabled (0).
         */
        ngx_msec_t connect_tmo = ctx->conf->cms_send_timeout > 0
                                 ? ctx->conf->cms_send_timeout
                                 : NGX_XROOTD_CMS_CONNECT_TIMEOUT;
        ngx_add_timer(c->write, connect_tmo);
        return;
    }

    ngx_xrootd_cms_write_handler(c->write);
}

/* ngx_xrootd_cms_timer — the CMS timer handler: when connected, send a load
 * heartbeat every cms_interval seconds (disconnect + backoff on failure); when
 * ctx->connection == NULL, trigger a reconnect. */

static void
ngx_xrootd_cms_timer(ngx_event_t *ev)
{
    ngx_xrootd_cms_ctx_t  *ctx;

    ctx = ev->data;

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                   "xrootd: CMS timer fired connection=%p logged_in=%d",
                   ctx->connection,
                   ctx->connection ? (int) ctx->logged_in : -1);

    /* Worker shutting down: drop the manager link immediately (so the manager
     * sees us leave at once) and do not reschedule the heartbeat. */
    if (ngx_exiting) {
        ngx_xrootd_cms_disconnect(ctx);
        return;
    }

    if (ctx->connection == NULL) {
        ngx_xrootd_cms_connect(ctx);
        return;
    }

    if (ngx_xrootd_cms_send_load(ctx) != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, ev->log, 0,
                      "xrootd: CMS load heartbeat failed");
        ngx_xrootd_cms_disconnect(ctx);
        ngx_xrootd_cms_schedule_retry(ctx);
        return;
    }

    ngx_xrootd_cms_schedule(ctx, (ngx_msec_t) ctx->conf->cms_interval * 1000);
}

/* ngx_xrootd_cms_start — worker-init entry point (from config/process.c): allocate
 * the CMS context, seed the reconnect backoff from cms_interval (capped at
 * NGX_XROOTD_CMS_BACKOFF_INITIAL), and schedule the first connect after
 * NGX_XROOTD_CMS_INITIAL_DELAY (1s). Each worker keeps its own connection. */

void
ngx_xrootd_cms_start(ngx_cycle_t *cycle, ngx_stream_xrootd_srv_conf_t *conf)
{
    ngx_xrootd_cms_ctx_t  *ctx;

    if (conf->cms_addr == NULL || conf->cms_ctx != NULL) {
        return;
    }

    ctx = ngx_pcalloc(cycle->pool, sizeof(ngx_xrootd_cms_ctx_t));
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                      "xrootd: CMS heartbeat allocation failed");
        return;
    }

    ctx->cycle = cycle;
    ctx->conf = conf;
    ctx->backoff = ngx_min((ngx_msec_t) conf->cms_interval * 1000,
                           (ngx_msec_t) NGX_XROOTD_CMS_BACKOFF_INITIAL);
    ctx->in_need = NGX_XROOTD_CMS_HDR_LEN;
    ctx->start_ns = xrootd_phase_now_ns();

    /*
     * Resolve the cold-start settle profile once.  A loopback manager (same host)
     * is reached with no network latency, so it gets the most aggressive defaults;
     * an explicit directive overrides the locality default.  The fast-retry interval
     * is floored so a misconfigured "0" can never become a busy connect-storm.
     */
    ctx->is_loopback = cms_addr_is_loopback(conf->cms_addr->sockaddr);

    ctx->fast_retry = (conf->cms_connect_retry != NGX_CONF_UNSET_MSEC)
                      ? conf->cms_connect_retry
                      : (ctx->is_loopback ? NGX_XROOTD_CMS_FASTRETRY_LOOPBACK
                                          : NGX_XROOTD_CMS_FASTRETRY_REMOTE);
    if (ctx->fast_retry < NGX_XROOTD_CMS_FASTRETRY_FLOOR) {
        ctx->fast_retry = NGX_XROOTD_CMS_FASTRETRY_FLOOR;
    }
    ctx->fast_window = ctx->is_loopback ? NGX_XROOTD_CMS_FASTWIN_LOOPBACK
                                        : NGX_XROOTD_CMS_FASTWIN_REMOTE;

    ctx->timer.handler = ngx_xrootd_cms_timer;
    ctx->timer.data = ctx;
    ctx->timer.log = cycle->log;
    /*
     * The heartbeat re-arms itself every cms_interval (connect.c:194,298).  Mark
     * it cancelable so a draining worker (ngx_exiting after `nginx -s reload`)
     * exits as soon as its connections close, instead of being held alive to the
     * shutdown timeout by the next pending heartbeat.  The cluster keepalive is
     * best-effort; dropping a final tick at teardown is harmless (the reconnect
     * path is already ngx_exiting-guarded).  Matches the io_uring panic timer.
     */
    ctx->timer.cancelable = 1;

    conf->cms_ctx = ctx;

    {
        /* First-connect delay: directive override, else the locality default
         * (0 for loopback — connect immediately; the fast-retry handles a miss). */
        ngx_msec_t init_delay = (conf->cms_initial_delay != NGX_CONF_UNSET_MSEC)
            ? conf->cms_initial_delay
            : (ctx->is_loopback ? NGX_XROOTD_CMS_INITDELAY_LOOPBACK
                                : NGX_XROOTD_CMS_INITDELAY_REMOTE);
        ngx_xrootd_cms_schedule(ctx, init_delay);
    }

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                  "xrootd: CMS heartbeat starting for manager %V",
                  &conf->cms_manager);
}
