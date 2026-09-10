/*
 * peer_name.c — accept-time wait for the peer's reverse-DNS name (phase-116).
 *
 * WHAT: When this listener's policy consults the peer's hostname (XrdAcc `h`
 *       rules via brix_acc_resolve_hosts, a protbind host template, or
 *       `brix_auth host`), look the PTR up ONCE at accept, off the event loop,
 *       and only then start the protocol pump.  Listeners that never consult
 *       the name pay three flag tests.
 * WHY:  The consumers (auth gate, protbind, host auth) run in the middle of
 *       kXR_login/kXR_auth handling, where they can only probe a cache — the
 *       blocking getnameinfo() they used to call stalled the worker (the
 *       Phase 51 breaker merely bounded it).  Waiting at accept keeps every
 *       later brix_acc_resolve_peer() probe a hit.  The wait is bounded by the
 *       resolver's own timeout*attempts; a peer that connects and says nothing
 *       is bounded the same way it always was once the pump arms its timers.
 * HOW:  brix_conn_peer_name_wait(): a cached probe first (hit → pump now);
 *       otherwise a brix_dns_rev_req_t on c->pool with a pool cleanup that
 *       cancels an in-flight lookup, idle event handlers so a stray read event
 *       cannot re-enter the stream content phase while nothing is armed, and a
 *       completion handler that calls the pump.  The pump is passed in so
 *       handler.c keeps ownership of its static conn_pump().
 */
#include "core/ngx_brix_module.h"
#include "protocols/root/connection/peer_name.h"
#include "auth/protbind/protbind.h"
#include "tpc/common/identity_matrix.h"  /* F18 host-rule PTR need */
#include "net/dns/dns.h"

typedef struct {
    brix_dns_rev_req_t   req;
    ngx_connection_t    *c;
    brix_conn_pump_pt    pump;
    unsigned             inline_call:1;   /* inside brix_dns_reverse() */
    unsigned             done:1;
} conn_peer_name_wait_t;


static ngx_flag_t
conn_peer_name_needed(const ngx_stream_brix_srv_conf_t *sconf)
{
    return sconf->common.acc.resolve_hosts > 0
           || sconf->auth == BRIX_AUTH_HOST
           || brix_protbind_needs_hostname(sconf->protbind)
           /* 2.0 F18: `brix_tpc_allow_identity host <pattern>` is a fourth
            * host-template consumer.  Without the wait its rule would be
            * evaluated against a name that had not landed yet and deny every
            * TPC — a confinement control must fail closed, but not by accident
            * of timing. */
           || brix_tpc_matrix_needs_hostname(sconf->common.tpc_allow_identity);
}


static void
conn_peer_name_idle(ngx_event_t *ev)
{
    (void) ev;           /* the wait owns the connection until the pump runs */
}


static void
conn_peer_name_cleanup(void *data)
{
    conn_peer_name_wait_t  *w = data;

    if (!w->done) {
        brix_dns_reverse_cancel(&w->req);
        w->done = 1;
    }
}


static void
conn_peer_name_done(brix_dns_rev_req_t *req)
{
    conn_peer_name_wait_t  *w = req->data;

    w->done = 1;
    if (w->inline_call) {
        return;                  /* brix_conn_peer_name_wait() pumps itself */
    }
    w->pump(w->c);
}


ngx_int_t
brix_conn_peer_name_wait(ngx_stream_session_t *s, ngx_connection_t *c,
    brix_conn_pump_pt pump)
{
    ngx_stream_brix_srv_conf_t  *sconf;
    conn_peer_name_wait_t       *w;
    ngx_pool_cleanup_t          *cln;
    char                         name[BRIX_DNS_REVERSE_NAME_LEN];

    sconf = ngx_stream_get_module_srv_conf(s, ngx_stream_brix_module);
    if (!conn_peer_name_needed(sconf) || c->sockaddr == NULL
        || c->socklen > sizeof(struct sockaddr_storage)
        || brix_dns_reverse_cached(c->sockaddr, c->socklen, name,
                                   sizeof(name)) != NGX_AGAIN)
    {
        return NGX_OK;
    }

    w = ngx_pcalloc(c->pool, sizeof(*w));
    cln = (w != NULL) ? ngx_pool_cleanup_add(c->pool, 0) : NULL;
    if (cln == NULL) {
        return NGX_OK;                        /* no memory: decide numerically */
    }
    cln->handler = conn_peer_name_cleanup;
    cln->data = w;

    ngx_memcpy(&w->req.ss, c->sockaddr, c->socklen);
    w->req.len = c->socklen;
    w->req.policy = sconf->common.dns.policy;
    w->req.log = c->log;
    w->req.handler = conn_peer_name_done;
    w->req.data = w;
    w->c = c;
    w->pump = pump;

    c->read->handler = conn_peer_name_idle;
    c->write->handler = conn_peer_name_idle;

    w->inline_call = 1;
    if (brix_dns_reverse(&w->req) != NGX_OK) {
        w->done = 1;
        return NGX_OK;                        /* not started: decide numerically */
    }
    w->inline_call = 0;

    return w->done ? NGX_OK : NGX_AGAIN;
}
