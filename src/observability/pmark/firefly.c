/*
 * firefly.c — SciTags "firefly" UDP flow reporting.
 *
 * WHAT: The out-of-band SciTags mechanism: for each marked flow emit a
 *   RFC5424-syslog-wrapped JSON "firefly" document (start / ongoing / end) to the
 *   configured collector(s) and, optionally, to the client origin.  Byte-for-byte
 *   compatible with XRootD's XrdNetPMarkFF (template at XrdNetPMarkFF.cc:60-99).
 *   This file owns the per-flow lifecycle entry points (flow_begin / flow_end /
 *   flow_echo) and the per-worker UDP sender.
 *
 * WHY: Firefly is the interop path — it is what site flowd collectors and the
 *   SciTags dashboards consume.  It is also the begin/end site where the in-band
 *   IPv6 flow label is applied (flowlabel.c), so one call marks a flow both ways.
 *
 * HOW: Codes are resolved via mapping.c; the datagram is built with libc snprintf
 *   (only the parsed integers + numeric IPs reach it — never raw client bytes);
 *   delivery is a non-blocking, fire-and-forget sendto on a per-worker UDP socket
 *   (one AF_INET + one AF_INET6, created lazily).  Everything is fail-open: a
 *   send error is dropped, never surfaced, and never blocks the data plane.
 */

#include "pmark.h"
#include "observability/metrics/metrics.h"
#include "observability/metrics/metrics_macros.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include "core/compat/alloc_guard.h"

/* Per-worker UDP sender sockets (one per family), created on first use.  Process
 * globals: each worker gets its own copy after fork; closed at process exit. */
static ngx_socket_t  pmark_fd4 = (ngx_socket_t) -1;
static ngx_socket_t  pmark_fd6 = (ngx_socket_t) -1;


static ngx_socket_t
pmark_worker_socket(int family)
{
    ngx_socket_t *slot = (family == AF_INET6) ? &pmark_fd6 : &pmark_fd4;
    ngx_socket_t  fd;

    if (*slot != (ngx_socket_t) -1) {
        return *slot;
    }
    fd = ngx_socket(family, SOCK_DGRAM, 0);
    if (fd == (ngx_socket_t) -1) {
        return (ngx_socket_t) -1;
    }
    if (ngx_nonblocking(fd) == -1) {
        ngx_close_socket(fd);
        return (ngx_socket_t) -1;
    }
    *slot = fd;
    return fd;
}


/* Build the firefly datagram into buf; returns its length (0 on failure). */
static size_t
pmark_build(brix_pmark_flow_t *f, const char *state, int with_end,
    u_char *buf, size_t buflen)
{
    brix_pmark_sockstats_t  st;
    char       now[48], endt[80];
    uint64_t   recv, sent;
    ngx_str_t  host;
    int        n;

    host = ngx_cycle->hostname;

    brix_pmark_sockstats((int) f->fd, &st);
    /* "supplier is source": for a PUT the client supplies the data, so report
     * bytes from the supplier's perspective (swap acked/received). */
    if (f->is_put) { recv = st.bytes_sent; sent = st.bytes_recv; }
    else           { recv = st.bytes_recv; sent = st.bytes_sent; }

    brix_pmark_iso8601_now(now, sizeof(now));

    endt[0] = '\0';
    if (with_end) {
        char e[48];
        brix_pmark_iso8601_now(e, sizeof(e));
        (void) snprintf(endt, sizeof(endt), ",\"end-time\":\"%s\"", e);
    }

    n = snprintf((char *) buf, buflen,
        "<134>1 - %.*s xrootd - firefly-json - "
        "{\"version\":1,"
        "\"flow-lifecycle\":{\"state\":\"%s\",\"current-time\":\"%s\","
        "\"start-time\":\"%s\"%s},"
        "\"usage\":{\"received\":%llu,\"sent\":%llu},"
        "\"netlink\":{\"rtt\":%u.%03u},"
        "\"context\":{\"experiment-id\":%u,\"activity-id\":%u,"
        "\"application\":\"%s\"},"
        "\"flow-id\":{\"afi\":\"ipv%c\",\"src-ip\":\"%s\",\"dst-ip\":\"%s\","
        "\"protocol\":\"tcp\",\"src-port\":%d,\"dst-port\":%d}}",
        (int) host.len, (const char *) host.data,
        state, now, f->start_iso, endt,
        (unsigned long long) recv, (unsigned long long) sent,
        (unsigned) (st.rtt_us / 1000), (unsigned) (st.rtt_us % 1000),
        (unsigned) f->exp, (unsigned) f->act, f->app,
        f->afi, f->src_ip, f->dst_ip, f->src_port, f->dst_port);

    if (n < 0) {
        return 0;
    }
    return ((size_t) n < buflen) ? (size_t) n : buflen;
}


/* Fire one datagram to every configured collector + optional origin. */
static void
pmark_emit(brix_pmark_flow_t *f, const char *state, int with_end,
    ngx_log_t *log)
{
    u_char               buf[1280];
    size_t               n;
    brix_pmark_conf_t *pm = f->pm;
    ngx_uint_t           i;

    n = pmark_build(f, state, with_end, buf, sizeof(buf));
    if (n == 0) {
        return;
    }

    if (pm->dest_sa) {
        brix_pmark_dest_t *d = pm->dest_sa->elts;
        for (i = 0; i < pm->dest_sa->nelts; i++) {
            ngx_socket_t fd = pmark_worker_socket(d[i].family);
            if (fd == (ngx_socket_t) -1) {
                continue;
            }
            if (sendto(fd, buf, n, 0, (struct sockaddr *) &d[i].ss, d[i].len)
                < 0)
            {
                BRIX_PMARK_METRIC_INC(pmark_firefly_dropped_total);
                ngx_log_debug1(NGX_LOG_DEBUG_CORE, log, ngx_errno,
                    "pmark: firefly sendto failed (state=%s)", state);
            } else {
                BRIX_PMARK_METRIC_INC(pmark_firefly_sent_total);
            }
        }
    }

    /* Report to the client origin (its IP at the firefly port). */
    if (f->want_origin && f->peer_len) {
        struct sockaddr_storage o;
        ngx_socket_t            fd;

        ngx_memcpy(&o, &f->peer_ss, f->peer_len);
        if (o.ss_family == AF_INET) {
            ((struct sockaddr_in *) &o)->sin_port = htons(BRIX_PMARK_FF_PORT);
        } else if (o.ss_family == AF_INET6) {
            ((struct sockaddr_in6 *) &o)->sin6_port =
                htons(BRIX_PMARK_FF_PORT);
        }
        fd = pmark_worker_socket(o.ss_family);
        if (fd != (ngx_socket_t) -1) {
            (void) sendto(fd, buf, n, 0, (struct sockaddr *) &o, f->peer_len);
        }
    }
}


brix_pmark_flow_t *
brix_pmark_flow_begin(brix_pmark_conf_t *pm, ngx_pool_t *pool,
    ngx_connection_t *c, int is_write, const char *vo_csv, const char *user,
    const char *path, const char *cgi, ngx_log_t *log)
{
    brix_pmark_flow_t *f;
    ngx_uint_t           exp, act;
    char                 pip[64], sip[64];
    int                  pport, sport;
    char                 pafi, safi;
    size_t               an;

    if (pm == NULL || !pm->enable || c == NULL) {
        return NULL;
    }
    if (brix_pmark_runtime_ensure(pm, ngx_cycle->pool, log) != NGX_OK) {
        return NULL;
    }
    brix_pmark_flow_id_t flow_id = {
        .vo_csv = vo_csv, .user = user, .path = path, .cgi = cgi,
    };
    if (brix_pmark_map_codes(pm, &flow_id, &exp, &act) != NGX_OK) {
        BRIX_PMARK_METRIC_INC(pmark_map_unresolved_total);
        return NULL;                 /* nothing maps → not marked */
    }

    BRIX_PCALLOC_OR_RETURN(f, pool, sizeof(*f), NULL);
    f->pm          = pm;
    f->exp         = exp;
    f->act         = act;
    f->fd          = c->fd;
    f->is_put      = is_write ? 1 : 0;
    f->want_origin = pm->firefly_origin ? 1 : 0;

    an = pm->appname.len < sizeof(f->app) - 1
       ? pm->appname.len : sizeof(f->app) - 1;
    if (an) {
        ngx_memcpy(f->app, pm->appname.data, an);
    }
    f->app[an] = '\0';

    brix_pmark_iso8601_now(f->start_iso, sizeof(f->start_iso));

    /* Endpoints: 0 = peer (client), 1 = local (server). */
    brix_pmark_endpoint((int) c->fd, 0, pip, sizeof(pip), &pport, &pafi);
    brix_pmark_endpoint((int) c->fd, 1, sip, sizeof(sip), &sport, &safi);
    f->afi = pafi;
    if (f->is_put) {                 /* client supplies → client is src */
        ngx_memcpy(f->src_ip, pip, sizeof(f->src_ip));
        ngx_memcpy(f->dst_ip, sip, sizeof(f->dst_ip));
        f->src_port = pport;
        f->dst_port = sport;
    } else {                         /* server supplies → server is src */
        ngx_memcpy(f->src_ip, sip, sizeof(f->src_ip));
        ngx_memcpy(f->dst_ip, pip, sizeof(f->dst_ip));
        f->src_port = sport;
        f->dst_port = pport;
    }

    /* Capture the client peer sockaddr for origin firefly reports. */
    f->peer_len = sizeof(f->peer_ss);
    if (getpeername((int) c->fd, (struct sockaddr *) &f->peer_ss, &f->peer_len)
        != 0)
    {
        f->peer_len = 0;
    }

    /* In-band IPv6 flow label (no-op on IPv4/mapped/disabled — see flowlabel.c). */
    if (pm->flowlabel) {
        (void) brix_pmark_flowlabel_apply(c, (int) c->fd, exp, act, log);
    }

    /* Out-of-band firefly start. */
    if (pm->firefly) {
        pmark_emit(f, "start", 0, log);
        f->firefly_started = 1;
    }

    BRIX_PMARK_METRIC_INC(pmark_flows_started_total);
    return f;
}


void
brix_pmark_flow_end(brix_pmark_flow_t *flow, ngx_log_t *log)
{
    if (flow == NULL || flow->pm == NULL) {
        return;
    }
    if (flow->firefly_started && flow->pm->firefly) {
        pmark_emit(flow, "end", 1, log);
        BRIX_PMARK_METRIC_INC(pmark_flows_ended_total);
    }
}


void
brix_pmark_flow_echo(brix_pmark_flow_t *flow, ngx_log_t *log)
{
    if (flow == NULL || flow->pm == NULL) {
        return;
    }
    if (flow->firefly_started && flow->pm->firefly) {
        pmark_emit(flow, "ongoing", 0, log);
    }
}


void
brix_pmark_flow_cleanup(void *data)
{
    brix_pmark_flow_end((brix_pmark_flow_t *) data, ngx_cycle->log);
}


void
brix_pmark_firefly_oneshot(brix_pmark_conf_t *pm, int fd, ngx_uint_t exp,
    ngx_uint_t act, int peer_is_src, const char *app, ngx_log_t *log)
{
    brix_pmark_flow_t  f;
    char                 pip[64], sip[64];
    int                  pport, sport;
    char                 pafi, safi;
    size_t               an;

    if (pm == NULL || !pm->firefly || fd < 0) {
        return;
    }

    ngx_memzero(&f, sizeof(f));
    f.pm  = pm;
    f.exp = exp;
    f.act = act;
    f.fd  = fd;
    f.is_put = peer_is_src ? 1 : 0;
    f.firefly_started = 1;

    if (app != NULL) {
        an = ngx_strlen(app);
        if (an >= sizeof(f.app)) { an = sizeof(f.app) - 1; }
        ngx_memcpy(f.app, app, an);
        f.app[an] = '\0';
    }

    brix_pmark_iso8601_now(f.start_iso, sizeof(f.start_iso));
    brix_pmark_endpoint(fd, 0, pip, sizeof(pip), &pport, &pafi);
    brix_pmark_endpoint(fd, 1, sip, sizeof(sip), &sport, &safi);
    f.afi = pafi;
    if (f.is_put) {                  /* peer is source */
        ngx_memcpy(f.src_ip, pip, sizeof(f.src_ip)); f.src_port = pport;
        ngx_memcpy(f.dst_ip, sip, sizeof(f.dst_ip)); f.dst_port = sport;
    } else {                         /* local is source */
        ngx_memcpy(f.src_ip, sip, sizeof(f.src_ip)); f.src_port = sport;
        ngx_memcpy(f.dst_ip, pip, sizeof(f.dst_ip)); f.dst_port = pport;
    }

    /* Outbound sockets are short-lived to us (curl owns the connection); emit a
     * start + end pair at close, when the socket is connected and TCP_INFO is
     * available. */
    pmark_emit(&f, "start", 0, log);
    pmark_emit(&f, "end", 1, log);
    BRIX_PMARK_METRIC_INC(pmark_flows_started_total);
    BRIX_PMARK_METRIC_INC(pmark_flows_ended_total);
}


void
brix_pmark_http_mark(brix_pmark_conf_t *pm, ngx_pool_t *pool,
    ngx_connection_t *c, int is_write, const char *vo_csv, const char *user,
    const char *path, const char *cgi)
{
    brix_pmark_flow_t *fl;
    ngx_pool_cleanup_t  *cln;

    fl = brix_pmark_flow_begin(pm, pool, c, is_write, vo_csv, user, path, cgi,
                                 c->log);
    if (fl == NULL) {
        return;
    }
    /* End the flow (firefly "end" + final TCP_INFO) when the request pool is
     * destroyed — which happens while the connection fd is still open. */
    cln = ngx_pool_cleanup_add(pool, 0);
    if (cln != NULL) {
        cln->handler = brix_pmark_flow_cleanup;
        cln->data    = fl;
    }
}
