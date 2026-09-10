/*
 * http_peer_name.c — PREACCESS-phase wait for the peer's reverse-DNS name
 * (phase-116).
 *
 * WHAT: For locations whose policy consults the peer's hostname (XrdAcc `h`
 *       rules via brix_acc_resolve_hosts, or a protbind host template), hold
 *       the request in NGX_HTTP_PREACCESS_PHASE until the PTR answer is in the
 *       reverse cache; every later brix_acc_resolve_peer() probe is then a
 *       hit.  Locations that never consult the name pay two flag tests.
 * WHY:  The WebDAV/S3 handlers and the protbind access check run on the event
 *       loop, where the blocking getnameinfo() they used to call stalled the
 *       worker.  limit_req shows the nginx-native way to pause a request in a
 *       phase: return NGX_AGAIN without advancing r->phase_handler and call
 *       ngx_http_core_run_phases() when the wait is over.
 * HOW:  brix_http_peer_name_postconfiguration() pushes the handler onto the
 *       PREACCESS phase (the common module owns the whole HTTP plane's hook).
 *       The handler probes brix_dns_reverse_cached(); on NGX_AGAIN it starts a
 *       brix_dns_rev_req_t on r->pool (a pool cleanup cancels an in-flight
 *       lookup if the client goes away first), parks the request behind
 *       ngx_http_test_reading so a client abort is noticed, and resumes the
 *       phase engine from the completion handler.  A request waits at most
 *       once (a flag on the common module's request ctx): a second pass — a
 *       resolver failure the cache could not record — falls through and the
 *       consumers decide numerically.
 */
#include "core/http/http_peer_name.h"
#include "tpc/common/identity_matrix.h"  /* F18 host-rule PTR need */
#include "core/http/http_variables.h"          /* brix_http_monitor_get */
#include "core/config/http_common.h"
#include "auth/protbind/protbind.h"
#include "observability/metrics/io_monitor.h"
#include "net/dns/dns.h"

typedef struct {
    brix_dns_rev_req_t    req;
    ngx_http_request_t   *r;
    unsigned              inline_call:1;   /* inside brix_dns_reverse() */
    unsigned              done:1;
} http_peer_name_wait_t;


static ngx_flag_t
http_peer_name_needed(const ngx_http_brix_common_conf_t *ccf)
{
    return ccf->common.acc.resolve_hosts > 0
           || brix_protbind_needs_hostname(ccf->common.protbind)
           /* 2.0 F18: the TPC identity matrix's `allow ... host <pattern>`
            * reads the same PTR answer (see peer_name.c on the root plane). */
           || brix_tpc_matrix_needs_hostname(ccf->common.tpc_allow_identity);
}


static void
http_peer_name_cleanup(void *data)
{
    http_peer_name_wait_t  *w = data;

    if (!w->done) {
        brix_dns_reverse_cancel(&w->req);
        w->done = 1;
    }
}


static void
http_peer_name_done(brix_dns_rev_req_t *req)
{
    http_peer_name_wait_t  *w = req->data;
    ngx_http_request_t     *r = w->r;

    w->done = 1;
    if (w->inline_call) {
        return;                       /* http_peer_name_start() falls through */
    }
    r->read_event_handler = ngx_http_block_reading;
    r->write_event_handler = ngx_http_core_run_phases;
    ngx_http_core_run_phases(r);
}


/* NGX_AGAIN = parked until http_peer_name_done(); NGX_DECLINED = decide now */
static ngx_int_t
http_peer_name_start(ngx_http_request_t *r, const brix_dns_policy_t *policy)
{
    http_peer_name_wait_t  *w;
    ngx_pool_cleanup_t     *cln;
    ngx_connection_t       *c = r->connection;

    w = ngx_pcalloc(r->pool, sizeof(*w));
    cln = (w != NULL) ? ngx_pool_cleanup_add(r->pool, 0) : NULL;
    if (cln == NULL) {
        return NGX_DECLINED;
    }
    cln->handler = http_peer_name_cleanup;
    cln->data = w;

    ngx_memcpy(&w->req.ss, c->sockaddr, c->socklen);
    w->req.len = c->socklen;
    w->req.policy = policy;
    w->req.log = c->log;
    w->req.handler = http_peer_name_done;
    w->req.data = w;
    w->r = r;

    w->inline_call = 1;
    if (brix_dns_reverse(&w->req) != NGX_OK) {
        w->done = 1;
        return NGX_DECLINED;
    }
    w->inline_call = 0;
    if (w->done) {
        return NGX_DECLINED;
    }

    r->read_event_handler = ngx_http_test_reading;
    r->write_event_handler = ngx_http_request_empty_handler;
    return NGX_AGAIN;
}


static ngx_int_t
http_peer_name_handler(ngx_http_request_t *r)
{
    ngx_http_brix_common_conf_t  *ccf;
    ngx_connection_t             *c = r->connection;
    brix_io_monitor_t            *m;
    char                          name[BRIX_DNS_REVERSE_NAME_LEN];

    ccf = ngx_http_get_module_loc_conf(r, ngx_http_brix_common_module);
    if (ccf == NULL || !http_peer_name_needed(ccf) || c->sockaddr == NULL
        || c->socklen > sizeof(struct sockaddr_storage)
        || brix_dns_reverse_cached(c->sockaddr, c->socklen, name,
                                   sizeof(name)) != NGX_AGAIN)
    {
        return NGX_DECLINED;
    }

    m = brix_http_monitor_get(r);
    if (m == NULL || m->peer_name_waited) {
        return NGX_DECLINED;
    }
    m->peer_name_waited = 1;

    return http_peer_name_start(r, ccf->common.dns.policy);
}


ngx_int_t
brix_http_peer_name_postconfiguration(ngx_conf_t *cf)
{
    ngx_http_core_main_conf_t  *cmcf;
    ngx_http_handler_pt        *h;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = http_peer_name_handler;
    return NGX_OK;
}
