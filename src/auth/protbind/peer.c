/*
 * peer.c — root:// binding for the protbind engine, and the shared
 * per-connection peer-hostname cache every host-template policy reads.
 *
 * WHAT: Supplies the peer identity the pure engine needs for a stream session:
 *       the reverse-resolved peer hostname (copied at most once per
 *       connection) and the peer IP already recorded at accept time, then calls
 *       brix_protbind_resolve().
 *
 * WHY:  policy.c and match.c must stay free of brix_ctx_t so the HTTP frontend
 *       can reuse them, but SOMETHING has to own the one impure step — reading
 *       the peer's PTR answer out of the phase-116 reverse cache — and the
 *       per-connection copy that keeps it to one probe.  Two subsystems match
 *       host templates against that name (protbind rules here, XrdAcc
 *       `h <host>`/`h .domain` records in ../authz/auth_gate.c), so the copy
 *       lives here once and both read it; otherwise a session with both
 *       features on would probe twice.
 *
 * HOW:  brix_protbind_peer_host_cached() fills the ctx->login.acc_host slot
 *       through brix_acc_resolve_peer() — a never-blocking probe of the reverse
 *       cache the accept path (../../protocols/root/connection/peer_name.c)
 *       already filled off the event loop — and every later call returns the
 *       cached string.  A still-pending answer is retried on the next call
 *       instead of being cached as "no name".  brix_protbind_peer_host() adds
 *       the protbind-specific short-circuit: when every template is a bare "*"
 *       no lookup is needed at all.
 */

#include "core/ngx_brix_module.h"
#include "auth/authz/acc/acc.h"   /* brix_acc_resolve_peer (phase-116 cache probe) */
#include "net/dns/dns.h"          /* BRIX_DNS_REVERSE_NAME_LEN */
#include "protbind.h"

/* ---- Reverse-resolved peer hostname, copied once per connection ----
 *
 * WHAT: Returns the peer's FQDN, or NULL when it has no PTR record, the answer
 *       is still pending, or the name could not be copied.  The result is
 *       borrowed from the connection pool and lives for the whole session.
 *
 * WHY:  The lookup itself ran at accept, off the event loop; this is a cache
 *       read, and a session pays for the pool copy at most once no matter how
 *       many host-template policies consult the name — the kXR_auth path alone
 *       re-evaluates protbind on every round.  Caching a "no PTR" result too
 *       (via the done flag) is deliberate: a peer with no PTR record must not
 *       trigger a fresh probe per request.  A pending answer is the one result
 *       NOT cached, so the next round can pick the name up.
 *
 * HOW:  1. Return the cached pointer once the answer has settled.
 *       2. Probe the reverse cache under this listener's DNS policy.
 *       3. On OK/DECLINED mark the cache settled; on OK copy the name into the
 *          connection pool.
 */
const char *
brix_protbind_peer_host_cached(struct brix_ctx_s *ctx, ngx_connection_t *c)
{
    ngx_stream_brix_srv_conf_t  *sconf;
    char                         host_buf[BRIX_DNS_REVERSE_NAME_LEN];
    ngx_int_t                    rc;

    if (ctx->login.acc_host_done) {
        return ctx->login.acc_host;
    }

    sconf = (ctx->session != NULL)
            ? ngx_stream_get_module_srv_conf(ctx->session, ngx_stream_brix_module)
            : NULL;
    rc = brix_acc_resolve_peer(sconf != NULL ? sconf->common.dns.policy : NULL,
                               c->sockaddr, c->socklen,
                               host_buf, sizeof(host_buf));
    if (rc == NGX_AGAIN) {
        return NULL;                        /* not settled: ask again next round */
    }

    ctx->login.acc_host_done = 1;
    if (rc == NGX_OK) {
        size_t   name_len = ngx_strlen(host_buf);
        char    *owned = ngx_pnalloc(c->pool, name_len + 1);

        if (owned != NULL) {
            ngx_memcpy(owned, host_buf, name_len + 1);
            ctx->login.acc_host = owned;
        }
    }

    return ctx->login.acc_host;
}

/* ---- Peer hostname for protbind template matching ----
 *
 * WHAT: Returns the cached peer hostname, or NULL when no configured template
 *       could consult it.
 *
 * WHY:  The dominant configuration is a single `brix_protbind * <protos>`
 *       line, which is decidable from the wildcard alone.  Asking that question
 *       before touching the resolver keeps the common case free of DNS entirely
 *       — and, just as importantly, keeps protbind from populating the shared
 *       cache for sessions that never needed it.
 *
 * HOW:  Short-circuit on a wildcard-only ruleset, else read the shared cache.
 */
const char *
brix_protbind_peer_host(struct brix_ctx_s *ctx, ngx_connection_t *c,
    ngx_array_t *rules)
{
    if (!brix_protbind_needs_hostname(rules)) {
        return NULL;
    }

    return brix_protbind_peer_host_cached(ctx, c);
}

/* ---- Resolve the effective protocol set for a root:// session ----
 *
 * WHAT: Fills *out with the ordered protocols this session may authenticate
 *       with, given the listener's brix_auth mode and its protbind rules.
 *
 * WHY:  Both kXR_login (which advertises the set as the "&P=" sec token) and
 *       kXR_auth (which enforces membership before running a scheme) need the
 *       same verdict.  Recomputing it from the connection rather than caching a
 *       set on brix_ctx_t keeps the per-connection struct unchanged and costs
 *       only a handful of string compares, the DNS lookup being cached.
 *
 * HOW:  1. Build the base set from the brix_auth mode.
 *       2. Supply the (lazily resolved) hostname and the recorded peer IP.
 *       3. Delegate the decision to the shared resolver.
 */
void
brix_protbind_resolve_ctx(struct brix_ctx_s *ctx, ngx_connection_t *c,
    ngx_array_t *rules, ngx_uint_t base_auth, brix_protbind_set_t *out)
{
    brix_protbind_set_t   base;
    const char           *peer_ip;

    brix_protbind_base_set(base_auth, &base);

    peer_ip = (ctx->login.peer_ip[0] != '\0') ? ctx->login.peer_ip : NULL;

    brix_protbind_resolve(rules, &base,
                          brix_protbind_peer_host(ctx, c, rules),
                          peer_ip, out);
}
