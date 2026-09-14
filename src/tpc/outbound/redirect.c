/* File: redirect.c — native TPC multihop: follow a source's kXR_redirect
 * WHAT: tpc_redirect_note() records the target a source named in a kXR_redirect
 *       reply to the pull's kXR_open (host, port, capability opaque);
 *       tpc_redirect_follow() decides whether the pull thread may dial it — hop
 *       budget, self-loop, and the same egress allowlist the first hop passed —
 *       and swaps it in as the next leg's source.
 *
 * WHY (release-2.0 F7): a real HEP source is often a manager/redirector (cmsd,
 *      EOS MGM, dCache door) that answers the open with "go to data server X".
 *      Before F7 the pull treated that reply as an open failure, so every native
 *      root:// TPC into a clustered source died at the first hop. The follow is
 *      bounded (brix_tpc_max_hops) and policy-checked on EVERY hop so a hostile
 *      or mis-configured source cannot steer the gateway at an internal host the
 *      operator never allowed (the request-forgery class the egress guard exists
 *      for) — the redirect target passes brix_tpc_source_guard here and the
 *      address-level SSRF check (I-DNS-3) again in tpc_connect().
 *
 * HOW: the shared frame_hdr.h decoder splits the ServerRedirectBody; the follow
 *      counts hops against conf->tpc_max_hops, refuses a target equal to the
 *      current source (a two-node ping-pong is still caught by the hop cap), runs
 *      the allowlist, then copies redir_host/redir_port into src_host/src_port.
 *      Runs on the pull thread: only the pull task and its immutable conf are
 *      touched (a refusal is counted on the event loop by done.c via
 *      t->redirect_refused). */
#include "tpc/engine/tpc_internal.h"
#include "protocols/root/protocol/frame_hdr.h"   /* xrd_redirect_body_decode */
#include "tpc/common/egress_guard.h"             /* brix_tpc_source_guard_check */

#include <string.h>
#include <strings.h>


/* WHAT: the port a host:port pair connects to when the wire said 0. */
static unsigned
tpc_redirect_effective_port(uint16_t port)
{
    return (port != 0) ? (unsigned) port : TPC_DEFAULT_PORT;
}

int
tpc_redirect_note(brix_tpc_pull_t *t, const u_char *body, uint32_t dlen)
{
    int port = 0;

    if (xrd_redirect_body_decode(body, dlen, t->redir_host,
                                 sizeof(t->redir_host), &port,
                                 t->redir_opaque, sizeof(t->redir_opaque)) != 0
        || t->redir_host[0] == '\0')
    {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC source redirect body malformed");
        t->xrd_error = kXR_ServerError;
        return -1;
    }
    /* XRootD lets a redirector send port 0 ("the default"); a negative port
     * selects the URL-list form this pull does not speak. */
    if (port < 0 || port > BRIX_MAX_PORT) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC source redirect to %s carries invalid port %d",
                 t->redir_host, port);
        t->xrd_error = kXR_ServerError;
        return -1;
    }
    t->redir_port        = (uint16_t) port;
    t->redirect_pending  = 1;
    return 0;
}

/* WHAT: the hop-budget gate. */
static int
tpc_redirect_check_hops(brix_tpc_pull_t *t)
{
    ngx_uint_t cap = (t->conf != NULL) ? t->conf->tpc_max_hops : 0;

    if (t->hops < cap) {
        return 0;
    }
    snprintf(t->err_msg, sizeof(t->err_msg),
             "TPC source %.128s:%u redirected to %.128s:%u but "
             "brix_tpc_max_hops is %lu",
             t->src_host, tpc_redirect_effective_port(t->src_port),
             t->redir_host, tpc_redirect_effective_port(t->redir_port),
             (unsigned long) cap);
    t->xrd_error = kXR_NotAuthorized;
    return -1;
}

/* WHAT: the egress-policy gate — the redirect target must pass the same source
 * allowlist the client's original tpc.src passed on the event loop. */
static int
tpc_redirect_check_policy(brix_tpc_pull_t *t)
{
    char guard_err[256];

    if (t->conf == NULL) {
        return 0;
    }
    if (brix_tpc_source_guard_check(t->conf->common.tpc_source_guard,
                                    t->conf->common.tpc_source_allow,
                                    t->redir_host, guard_err,
                                    sizeof(guard_err)) == 0)
    {
        return 0;
    }
    t->redirect_refused = 1;
    snprintf(t->err_msg, sizeof(t->err_msg),
             "TPC redirect to %.128s refused: %.200s", t->redir_host,
             guard_err);
    t->xrd_error = kXR_NotAuthorized;
    return -1;
}

int
tpc_redirect_follow(brix_tpc_pull_t *t, ngx_log_t *log)
{
    unsigned cur_port = tpc_redirect_effective_port(t->src_port);
    unsigned new_port = tpc_redirect_effective_port(t->redir_port);

    if (!t->redirect_pending) {
        return -1;
    }
    t->redirect_pending = 0;

    if (tpc_redirect_check_hops(t) != 0) {
        return -1;
    }
    if (strcasecmp(t->redir_host, t->src_host) == 0 && new_port == cur_port) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC source redirect loops back to itself (%s:%u)",
                 t->src_host, cur_port);
        t->xrd_error = kXR_ServerError;
        return -1;
    }
    if (tpc_redirect_check_policy(t) != 0) {
        return -1;
    }

    t->hops++;
    ngx_log_error(NGX_LOG_INFO, log, 0,
                  "brix: TPC hop %ui: %s:%ud -> %s:%ud for %s",
                  t->hops, t->src_host, cur_port, t->redir_host, new_port,
                  t->src_path);

    ngx_cpystrn((u_char *) t->src_host, (u_char *) t->redir_host,
                sizeof(t->src_host));
    t->src_port      = t->redir_port;
    t->sessid_known  = 0;             /* a new host means a new session */
    return 0;
}
