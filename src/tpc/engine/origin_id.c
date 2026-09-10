/* File: origin_id.c — the tpc.org identity of a TPC destination's client
 *
 * WHAT: Builds "user.pid@host" — the string the XRootD source pairs against
 * its rendezvous grant (XrdOfsTPC::genOrg → XrdNetAddr::Name, a raw strcmp in
 * XrdOfsTPCInfo::Match).  The host is the client's PTR name, else the
 * bracketed numeric literal XrdNetAddr prints for a name-less peer.  Two
 * halves: brix_tpc_origin_build() on the event loop at kXR_open (cached PTR
 * or the numeric fallback, with a PTR fill started), and
 * brix_tpc_origin_thread_fill() on the pull thread (blocking PTR through the
 * DNS driver when the loop-side build was still pending).
 *
 * WHY: I-DNS-1 — the old build called getnameinfo(NI_NAMEREQD) on the event
 * loop for every TPC open: a worker-wide stall for the resolver's full timeout
 * budget whenever the client's reverse zone was slow or absent.  The name still
 * has to be right, or the source never redeems the grant and the pull-open
 * hangs on kXR_waitresp until it TTL-expires, so the thread finishes what the
 * loop could not wait for.
 *
 * HOW: Every XRootD server is IPv6 dual-stack and sees an IPv4 client as the
 * IPv4-MAPPED address ::ffff:a.b.c.d, reverse-resolves that, and falls back to
 * its bracketed literal ("[::ffff:127.0.0.1]" for a non-DNS loopback client).
 * The numeric fallback therefore maps IPv4 into that form and prints it with
 * inet_ntop (byte-identical to XrdNetAddr), while the PTR lookup keys on the
 * peer address as-is: glibc asks the same in-addr.arpa question for the mapped
 * form, and the plain key shares the cache entry with the host-rule and
 * authorization lookups.
 * */

#include "tpc_internal.h"
#include "net/dns/dns.h"

#include <netinet/in.h>   /* sockaddr_in6 — the IPv4-mapped form XrdNetAddr prints */
#include <arpa/inet.h>    /* inet_ntop — XrdNetAddr::Format-identical text */
#include <stdio.h>
#include <string.h>


static void
tpc_origin_identity(const brix_ctx_t *ctx, char *user, size_t user_sz,
    uint32_t *pid)
{
    ngx_cpystrn((u_char *) user,
                (u_char *) (ctx->login.user[0] != '\0' ? ctx->login.user
                                                       : "xrd"),
                user_sz);
    *pid = ctx->login.pid != 0 ? ctx->login.pid : (uint32_t) ngx_pid;
}


/* "user.pid@" then the host, truncated rather than dropped (tpc_org is 256
 * bytes; a 255-byte PTR name would not fit behind the prefix). */
static void
tpc_origin_format(const char *user, uint32_t pid, const char *host,
    char *dst, size_t dst_size)
{
    int  prefix_len;

    prefix_len = snprintf(dst, dst_size, "%s.%u@", user, (unsigned) pid);
    if (prefix_len < 0 || (size_t) prefix_len >= dst_size) {
        dst[0] = '\0';
        return;
    }
    ngx_cpystrn((u_char *) dst + prefix_len, (u_char *) host,
                dst_size - (size_t) prefix_len);
}


/* The host XrdNetAddr::Name prints for a peer without a PTR: the bracketed
 * literal of the IPv6 (or IPv4-mapped) address, else the accept-time address
 * text, else "unknown". */
static void
tpc_origin_numeric_host(const struct sockaddr *sa, const ngx_str_t *addr_text,
    char *host, size_t sz)
{
    struct sockaddr_in6  v6;
    char                 numeric[INET6_ADDRSTRLEN];

    host[0] = '\0';

    if (sa != NULL && sa->sa_family == AF_INET) {
        const struct sockaddr_in  *s4 = (const struct sockaddr_in *) sa;

        ngx_memzero(&v6, sizeof(v6));
        v6.sin6_family = AF_INET6;
        v6.sin6_addr.s6_addr[10] = 0xff;
        v6.sin6_addr.s6_addr[11] = 0xff;
        ngx_memcpy(&v6.sin6_addr.s6_addr[12], &s4->sin_addr, 4);
        sa = (const struct sockaddr *) &v6;
    }
    if (sa != NULL && sa->sa_family == AF_INET6) {
        const struct sockaddr_in6  *s6 = (const struct sockaddr_in6 *) sa;

        if (inet_ntop(AF_INET6, &s6->sin6_addr, numeric, sizeof(numeric))
            != NULL)
        {
            (void) snprintf(host, sz, "[%s]", numeric);
        }
    }
    if (host[0] == '\0' && addr_text != NULL && addr_text->len > 0) {
        ngx_cpystrn((u_char *) host, addr_text->data,
                    ngx_min(addr_text->len + 1, sz));
    }
    if (host[0] == '\0') {
        ngx_cpystrn((u_char *) host, (u_char *) "unknown", sz);
    }
}


unsigned
brix_tpc_origin_build(brix_ctx_t *ctx, ngx_connection_t *c,
    const brix_dns_policy_t *policy, char *dst, size_t dst_size)
{
    char       host[BRIX_DNS_REVERSE_NAME_LEN];
    char       user[sizeof(ctx->login.user)];
    uint32_t   pid;
    ngx_int_t  rc = NGX_DECLINED;
    unsigned   pending = 0;

    tpc_origin_identity(ctx, user, sizeof(user), &pid);

    if (c->sockaddr != NULL) {
        rc = brix_dns_reverse_cached(c->sockaddr, c->socklen, host,
                                     sizeof(host));
        if (rc == NGX_AGAIN) {
            brix_dns_reverse_prefetch(policy, c->sockaddr, c->socklen);
            pending = 1;
        }
    }
    if (rc != NGX_OK) {
        tpc_origin_numeric_host(c->sockaddr, &c->addr_text, host,
                                sizeof(host));
    }
    tpc_origin_format(user, pid, host, dst, dst_size);
    return pending;
}


void
brix_tpc_origin_snapshot_peer(brix_tpc_pull_t *t, const brix_ctx_t *ctx,
    const ngx_connection_t *c)
{
    t->peer_len = 0;
    if (c->sockaddr != NULL && c->socklen <= sizeof(t->peer_ss)) {
        ngx_memcpy(&t->peer_ss, c->sockaddr, c->socklen);
        t->peer_len = c->socklen;
    }
    tpc_origin_identity(ctx, t->org_user, sizeof(t->org_user), &t->org_pid);
}


void
brix_tpc_origin_thread_fill(brix_tpc_pull_t *t)
{
    char  name[BRIX_DNS_REVERSE_NAME_LEN];

    if (!t->tpc_org_unresolved) {
        return;
    }
    t->tpc_org_unresolved = 0;
    if (t->peer_len == 0) {
        return;
    }
    if (brix_dns_reverse_sync(t->conf->common.dns.policy,
                              (const struct sockaddr *) &t->peer_ss,
                              t->peer_len, name, sizeof(name)) != NGX_OK)
    {
        return;                 /* keep the numeric literal the loop built */
    }
    tpc_origin_format(t->org_user, t->org_pid, name, t->tpc_org,
                      sizeof(t->tpc_org));
}
