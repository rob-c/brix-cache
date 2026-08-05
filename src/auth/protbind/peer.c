/*
 * peer.c — root:// binding for the protbind engine, and the shared
 * per-connection peer-hostname cache every host-template policy reads.
 *
 * WHAT: Supplies the peer identity the pure engine needs for a stream session:
 *       the reverse-resolved peer hostname (resolved at most once per
 *       connection) and the peer IP already recorded at accept time, then calls
 *       brix_protbind_resolve().
 *
 * WHY:  policy.c and match.c must stay free of brix_ctx_t so the HTTP frontend
 *       can reuse them, but SOMETHING has to own the one impure step — a
 *       blocking PTR lookup — and the cache that keeps it to one call per
 *       connection.  Two subsystems match host templates against that name
 *       (protbind rules here, XrdAcc `h <host>`/`h .domain` records in
 *       ../authz/auth_gate.c), so the cache lives here once and both read it;
 *       otherwise a session with both features on would resolve twice.
 *
 * HOW:  brix_protbind_peer_host_cached() fills the ctx->login.acc_host slot
 *       through brix_acc_resolve_peer() — the circuit-breaker-bounded
 *       getnameinfo path — and every later call returns the cached string.
 *       brix_protbind_peer_host() adds the protbind-specific short-circuit:
 *       when every template is a bare "*" no lookup is needed at all.
 */

#include "core/ngx_brix_module.h"
#include "auth/authz/acc/acc.h"   /* brix_acc_resolve_peer (breaker-bounded) */
#include "protbind.h"

/* getnameinfo() writes an FQDN; 256 covers the 255-byte DNS name limit + NUL. */
#define BRIX_PROTBIND_HOST_MAX  256

/* ---- Reverse-resolve the peer hostname, once per connection ----
 *
 * WHAT: Returns the peer's FQDN, or NULL when it has no PTR record, the DNS
 *       circuit breaker is open, or the name could not be cached.  The result
 *       is borrowed from the connection pool and lives for the whole session.
 *
 * WHY:  Reverse DNS blocks the event loop, so a session must pay for it at most
 *       once no matter how many host-template policies consult the name — the
 *       kXR_auth path alone re-evaluates protbind on every round.  Caching a
 *       NULL result too (via the done flag) is deliberate: a peer with no PTR
 *       record must not trigger a fresh lookup per request.
 *
 * HOW:  1. On the first call, mark the cache resolved and attempt the lookup.
 *       2. Copy any resulting name into the connection pool.
 *       3. Return the cached pointer (NULL when resolution failed).
 */
const char *
brix_protbind_peer_host_cached(struct brix_ctx_s *ctx, ngx_connection_t *c)
{
    char         host_buf[BRIX_PROTBIND_HOST_MAX];
    const char  *resolved;

    if (!ctx->login.acc_host_done) {
        ctx->login.acc_host_done = 1;

        resolved = brix_acc_resolve_peer(c->sockaddr, c->socklen,
                                         host_buf, sizeof(host_buf));
        if (resolved != NULL) {
            size_t   name_len = ngx_strlen(resolved);
            char    *owned = ngx_pnalloc(c->pool, name_len + 1);

            if (owned != NULL) {
                ngx_memcpy(owned, resolved, name_len + 1);
                ctx->login.acc_host = owned;
            }
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
