/*
 * cms_select.c — the one place a manager turns "data server X was selected for
 * this request" into an answer for the client (phase-115 W2.1).
 *
 * WHAT: brix_cms_answer_selected() emits kXR_redirect — the stock cmsd/xrootd
 *       behaviour and the default — or, under `brix_cms_response proxy`, pins
 *       the session to the selected server and relays the in-flight request
 *       through the transparent proxy (src/net/proxy) so the client never
 *       leaves the gateway.
 * WHY:  NAT'd / firewalled sites and stable-endpoint deployments cannot expose
 *       every data server to clients; a single chokepoint keeps the
 *       redirect-vs-proxy policy out of the six selection sites (open, locate,
 *       stat, dirlist, query-checksum, mutations) and the CMS wake path.
 * HOW:  policy check → brix_send_redirect; else brix_proxy_dispatch_to() with
 *       the selected host:port as the pinned upstream.  The host has already
 *       passed the registry store choke point (brix_net_host_chars_valid) or
 *       the wake path's identical check, so nothing is re-parsed here.  The
 *       proxy's own fail budget (BRIX_PROXY_MAX_CONN_FAILS) bounds a dead
 *       selection: the client gets kXR_error, never a hang.
 */
#include "protocols/root/response/response.h"
#include "protocols/root/read/locate.h"
#include "proxy.h"

ngx_int_t
brix_cms_answer_selected(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const char *host, uint16_t port)
{
    if (conf->cms.response != BRIX_CMS_RESPONSE_PROXY) {
        return brix_send_redirect(ctx, c, host, port);
    }

    /* A proxying gateway is, to its clients, a data server: kXR_locate names
     * the gateway itself.  Forwarding it would leak the selected node's
     * address and the client's next open would bypass the gateway. */
    if (ctx->recv.cur_reqid == kXR_locate) {
        ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "brix: cms select: locate answered as self "
                       "(selected %s:%ud)", host, (unsigned) port);
        return brix_locate_answer_self(ctx, c, conf);
    }

    ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "brix: cms select: proxying session to %s:%ud",
                   host, (unsigned) port);
    return brix_proxy_dispatch_to(ctx, c, conf, host, port);
}
