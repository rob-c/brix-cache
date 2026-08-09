/*
 * cms/altds.c — §2.12: alternate-data-server liveness monitor (cms.altds).
 *
 * WHAT: A periodic nonblocking TCP connect probe of the co-located foreign
 * data server (127.0.0.1:<brix_cms_altds port>).  On DOWN, every logged-in
 * manager link gets kYR_status(suspend) so the mesh stops selecting this
 * node; on recovery, kYR_status(resume).  The advertisement half of §2.12
 * (dPort = altds port in the login) lives in send.c.
 *
 * WHY: The CMS half of this node fronts a foreign data server it does not
 * host in-process; a dead foreign DS with a live heartbeat would keep
 * attracting redirects into connection refusals.  Stock cmsd monitors its
 * altds the same way.
 *
 * HOW: One timer per CMS-client worker (worker 0).  Each tick opens a
 * nonblocking socket, connects to loopback:<port>, and classifies: immediate
 * success / EINPROGRESS-with-writable-within-timeout = UP, refusal/timeout =
 * DOWN.  The wait is event-driven (ngx_get_connection on the probe fd); a
 * 2s cap bounds a black-holed probe.  Only state TRANSITIONS emit status
 * frames — steady state is silent.
 */

#include "cms_internal.h"
#include "altds.h"
#include "frame_io.h"     /* brix_cms_send_frame — status broadcast */
#include "action_log.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#define BRIX_ALTDS_PROBE_TIMEOUT_MS  2000

typedef struct {
    ngx_cycle_t                  *cycle;
    ngx_stream_brix_srv_conf_t *conf;
    ngx_event_t                   tick;      /* periodic probe timer */
    ngx_connection_t             *probe;     /* in-flight probe socket */
    unsigned                      down:1;    /* last verdict (0 at boot = up) */
    unsigned                      started:1;
} brix_cms_altds_t;

static brix_cms_altds_t  brix_cms_altds;

/*
 * altds_broadcast — send kYR_status to every logged-in manager link.
 *
 * WHAT: suspend=1 sends CMS_ST_SUSPEND, else CMS_ST_RESUME|CMS_ST_NOSTAGE
 *       (the same resume shape login uses).  Send failures are left to the
 *       heartbeat machinery — a broken link reconnects and re-announces.
 * WHY:  The verdict must reach ALL redundant managers, not the rotation pick.
 * HOW:  Walk conf->cms.ctxs like the CNS fan-out does.
 */
static void
altds_broadcast(brix_cms_altds_t *ad, int suspend)
{
    ngx_uint_t            i;
    ngx_brix_cms_ctx_t *ctx;
    u_char                mod = suspend ? CMS_ST_SUSPEND
                                        : (CMS_ST_RESUME | CMS_ST_NOSTAGE);

    for (i = 0; i < ad->conf->cms.nctxs; i++) {
        ctx = ad->conf->cms.ctxs[i];
        if (ctx == NULL || ctx->connection == NULL || !ctx->logged_in) {
            continue;
        }
        (void) brix_cms_send_frame(ctx->connection, 0, CMS_RR_STATUS, mod,
                                     NULL, 0);
    }
}

/*
 * altds_verdict — fold one probe outcome into the up/down state machine.
 *
 * WHAT: Emits the suspend/resume broadcast ONLY on a transition and logs it.
 * WHY:  Steady-state chatter would spam every manager each interval.
 * HOW:  Compare with ad->down; update; broadcast on change.
 */
static void
altds_verdict(brix_cms_altds_t *ad, int alive)
{
    if (alive == !ad->down) {
        return;   /* no transition */
    }
    ad->down = !alive;

    ngx_log_error(NGX_LOG_NOTICE, ad->cycle->log, 0,
        "brix: cms altds 127.0.0.1:%i is %s — %s",
        (int) ad->conf->cms.altds_port,
        alive ? "back" : "down",
        alive ? "resuming this node in the cluster"
              : "suspending this node in the cluster");
    brix_cms_log_action(ad->cycle->log, "altds",
                        (const char *) ad->conf->cms.manager.data, "out",
                        NULL, alive,
                        alive ? "foreign data server recovered -> resume"
                              : "foreign data server unreachable -> suspend");
    altds_broadcast(ad, !alive);
}

/* altds_probe_close — release the in-flight probe connection (idempotent). */
static void
altds_probe_close(brix_cms_altds_t *ad)
{
    if (ad->probe != NULL) {
        ngx_close_connection(ad->probe);
        ad->probe = NULL;
    }
}

/*
 * altds_probe_event — the pending connect resolved (writable) or timed out.
 *
 * WHAT: Reads SO_ERROR for the verdict on writability; ev->timedout is DOWN.
 * WHY:  A nonblocking connect signals completion via writability; SO_ERROR
 *       distinguishes success from a delayed refusal.
 * HOW:  Classify, close the probe, fold the verdict.
 */
static void
altds_probe_event(ngx_event_t *ev)
{
    ngx_connection_t *c = ev->data;
    brix_cms_altds_t *ad = c->data;
    int                 err = 0;
    socklen_t           errlen = sizeof(err);
    int                 alive = 0;

    if (!ev->timedout) {
        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, &err, &errlen) == 0
            && err == 0)
        {
            alive = 1;
        }
    }
    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }
    altds_probe_close(ad);
    altds_verdict(ad, alive);
}

/*
 * altds_tick — periodic probe: nonblocking TCP connect to the foreign DS.
 *
 * WHAT: Immediate success/refusal classifies synchronously; EINPROGRESS
 *       parks the fd in the event loop with a bounded wait.
 * WHY:  The probe must never block the worker — the CMS heartbeat shares it.
 * HOW:  socket + O_NONBLOCK + connect to loopback:<port>; wrap pending fds
 *       in ngx_get_connection with altds_probe_event on write-ready.
 */
static void
altds_tick(ngx_event_t *ev)
{
    brix_cms_altds_t   *ad = ev->data;
    struct sockaddr_in  sin;
    ngx_connection_t   *c;
    int                 fd, rc;

    if (!ngx_exiting) {
        ngx_add_timer(&ad->tick, ad->conf->cms.altds_interval);
    }
    if (ad->probe != NULL) {
        return;   /* previous probe still pending — its timeout will verdict */
    }

    fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        return;   /* fd pressure: skip this tick, keep the last verdict */
    }

    ngx_memzero(&sin, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons((uint16_t) ad->conf->cms.altds_port);
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    rc = connect(fd, (struct sockaddr *) &sin, sizeof(sin));
    if (rc == 0) {
        close(fd);
        altds_verdict(ad, 1);
        return;
    }
    if (errno != EINPROGRESS) {
        close(fd);
        altds_verdict(ad, 0);
        return;
    }

    c = ngx_get_connection(fd, ad->cycle->log);
    if (c == NULL) {
        close(fd);
        return;
    }
    c->data = ad;
    c->read->handler  = altds_probe_event;
    c->write->handler = altds_probe_event;
    if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
        ngx_close_connection(c);
        return;
    }
    ad->probe = c;
    ngx_add_timer(c->write, BRIX_ALTDS_PROBE_TIMEOUT_MS);
}

void
brix_cms_altds_start(ngx_cycle_t *cycle, ngx_stream_brix_srv_conf_t *conf)
{
    brix_cms_altds_t *ad = &brix_cms_altds;

    if (conf->cms.altds_port <= 0 || !conf->cms.altds_monitor
        || ad->started)
    {
        return;
    }

    ad->cycle = cycle;
    ad->conf = conf;
    ad->started = 1;
    ad->tick.handler = altds_tick;
    ad->tick.data = ad;
    ad->tick.log = cycle->log;
    ad->tick.cancelable = 1;

    ngx_add_timer(&ad->tick, conf->cms.altds_interval);

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                  "brix: cms altds monitor started for 127.0.0.1:%i "
                  "(every %Mms)",
                  (int) conf->cms.altds_port, conf->cms.altds_interval);
}
