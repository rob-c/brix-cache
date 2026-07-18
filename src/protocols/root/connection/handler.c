#include "core/ngx_brix_module.h"
#include <netinet/tcp.h>   /* Phase 39: TCP_USER_TIMEOUT / TCP_KEEPIDLE etc. */
#include "netopt.h"        /* Phase 50: shared dead-peer setsockopt helper */
#include "protocols/root/relay/relay.h"   /* transparent pass-through relay engage */
#include "observability/sesslog/sesslog_ngx.h"
#include "core/aio/uring.h"   /* orphan in-flight uring ops on pool teardown */

#if (BRIX_HAVE_LIBURING)
/*
 * Connection-pool cleanup: sever any io_uring op still in flight for this
 * connection the instant its pool is destroyed — no matter WHICH path tore the
 * connection down (our brix_on_disconnect, an nginx-core stream finalize on a
 * read error / RST, a stream-level timeout, or worker exit).  Hooking only
 * brix_on_disconnect missed the core-driven teardown paths, so a late CQE for a
 * freed task posted its completion event into the reused pool memory and
 * crashed the worker in ngx_event_process_posted.  A pool cleanup runs on the
 * one action every path funnels through (ngx_destroy_pool), closing that gap. */
static void
brix_conn_uring_cleanup(void *data)
{
    brix_uring_orphan_owner(data);   /* data == the ngx_connection_t* */
}
#endif

/*
 * WHAT: Register the io_uring orphan cleanup on the connection pool.
 * WHY : It must fire on EVERY teardown path (see brix_conn_uring_cleanup), so
 *       it is armed up front on the one action all paths funnel through.
 * HOW : Best-effort ngx_pool_cleanup_add; a NULL slot (OOM) is non-fatal — the
 *       ring is simply not up for this connection.  Compiled out without liburing.
 */
#if (BRIX_HAVE_LIBURING)
static void
conn_arm_uring_cleanup(ngx_connection_t *c)
{
    ngx_pool_cleanup_t *uring_cln = ngx_pool_cleanup_add(c->pool, 0);

    if (uring_cln != NULL) {
        uring_cln->handler = brix_conn_uring_cleanup;
        uring_cln->data    = c;
    }
}
#endif

/*
 * WHAT: Record the immutable connection-time protocol label, IP version, and
 *       peer IP string on the freshly-allocated ctx.
 * WHY : These are detected once at accept and never change; the hot paths read
 *       them without re-inspecting the socket.
 * HOW : Pure field writes derived from c->sockaddr / c->addr_text; peer IP is
 *       length-clamped and NUL-terminated into the fixed login.peer_ip buffer.
 */
static void
conn_set_immutable_labels(ngx_connection_t *c, brix_ctx_t *ctx)
{
    ngx_memcpy(ctx->protocol_label, "root", sizeof("root"));  /* "root\0" */

    if (c->sockaddr) {
        switch (c->sockaddr->sa_family) {
        case AF_INET6:
            ctx->ip_version = AF_INET6;
            break;
        default:
            ctx->ip_version = AF_INET;
            break;
        }
    } else {
        ctx->ip_version = 0; /* unknown */
    }

    if (c->addr_text.len > 0) {
        size_t n = c->addr_text.len;
        if (n >= sizeof(ctx->login.peer_ip)) {
            n = sizeof(ctx->login.peer_ip) - 1;
        }
        ngx_memcpy(ctx->login.peer_ip, c->addr_text.data, n);
        ctx->login.peer_ip[n] = '\0';
    }
}

/*
 * WHAT: Mark all fd slots free and mint the 16-byte opaque session ID.
 * WHY : fd < 0 is the free-slot sentinel every handle path relies on; the
 *       session ID identifies this connection within the process AND is later
 *       presented back by kXR_bind/kXR_endsess as an unauthenticated bearer
 *       (session.c: a matching sessid inherits the primary's auth state), so it
 *       must be unpredictable — a guessed sessid would let a fresh connection
 *       bind to another client's authenticated session (hyper-hardening D-4).
 * HOW : Loop the fixed slot array, then draw all 16 bytes from the OpenSSL
 *       CSPRNG. The former time|pid|ptr|ngx_random() packing was predictable
 *       (ngx_random() is the non-cryptographic random(3)) and additionally
 *       leaked a live heap pointer past ASLR. RAND_bytes failure means the
 *       process entropy source is dead (TLS would be broken too), so we fail
 *       closed: return NGX_ERROR and let the caller drop the connection rather
 *       than emit a weak, forgeable session ID.
 */
static ngx_int_t
conn_init_slots_and_sessid(ngx_connection_t *c, brix_ctx_t *ctx)
{
    int  i;

    /* Sentinel value: fd < 0 means the slot is free. */
    for (i = 0; i < BRIX_MAX_FILES; i++) {
        ctx->files[i].fd = -1;
        ctx->files[i].shared_handle_slot_hint = -1;  /* Phase 33 C2: no cache yet */
    }

    if (RAND_bytes(ctx->login.sessid, BRIX_SESSION_ID_LEN) != 1) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "brix: RAND_bytes failed minting session id — "
                      "refusing connection (CSPRNG unavailable)");
        return NGX_ERROR;
    }

    return NGX_OK;
}

/*
 * WHAT: Allocate and populate the per-connection brix_ctx_t.
 * WHY : ctx lives for the whole TCP connection; every later phase reads it.
 * HOW : ngx_pcalloc from the connection pool, allocate identity, arm the uring
 *       cleanup, set immutable labels, init fd slots + session ID, and bind the
 *       ctx to the stream module.  Returns NULL after finalizing the session on
 *       any allocation failure so the caller returns immediately.
 */
static brix_ctx_t *
conn_init_ctx(ngx_stream_session_t *s, ngx_connection_t *c)
{
    brix_ctx_t *ctx;

    /* Pool allocation: ctx lives for the duration of the TCP connection. */
    ctx = ngx_pcalloc(c->pool, sizeof(brix_ctx_t));
    if (ctx == NULL) {
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return NULL;
    }

    ctx->session = s;
    ctx->state = XRD_ST_HANDSHAKE;
    ctx->recv.hdr_pos = 0;
    ctx->identity = brix_identity_alloc(c->pool);
    if (ctx->identity == NULL) {
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return NULL;
    }

#if (BRIX_HAVE_LIBURING)
    conn_arm_uring_cleanup(c);
#endif

    conn_set_immutable_labels(c, ctx);
    if (conn_init_slots_and_sessid(c, ctx) != NGX_OK) {
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return NULL;
    }

    ngx_stream_set_ctx(s, ctx, ngx_stream_brix_module);
    return ctx;
}

/*
 * WHAT: Cache the network-fault deadlines and allocate the pipeline rings.
 * WHY : Caching the merged deadlines keeps the hot recv/park paths off the
 *       srv_conf lookup; the rings size the in-flight window that absorbs wire
 *       jitter without stalling the recv->send loop.
 * HOW : Copy the three deadlines, then pcalloc the out/read rings.  pipeline_depth
 *       is set LAST so it stays 0 (teardown loops no-op) until both rings exist.
 *       Returns NGX_ERROR after finalizing on allocation failure, else NGX_OK.
 */
static ngx_int_t
conn_setup_pipeline(ngx_stream_session_t *s, ngx_connection_t *c,
    brix_ctx_t *ctx, ngx_stream_brix_srv_conf_t *mconf)
{
    ngx_uint_t depth = mconf->pipeline_depth;

    /* Phase 39: cache the merged network-fault deadlines so the hot
     * recv/park paths never do a srv_conf lookup.  All default 0 = off. */
    ctx->deadline.read_ms      = mconf->read_timeout;
    ctx->deadline.handshake_ms = mconf->handshake_timeout;
    ctx->deadline.send_ms      = mconf->send_timeout;

    ctx->out.ring = ngx_pcalloc(c->pool, depth * sizeof(brix_resp_slot_t));
    ctx->rd.pool  = ngx_pcalloc(c->pool, depth * sizeof(brix_read_slot_t));
    if (ctx->out.ring == NULL || ctx->rd.pool == NULL) {
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return NGX_ERROR;
    }
    ctx->out.pipeline_depth = depth;
    return NGX_OK;
}

/*
 * WHAT: Map the merged auth mode to its lowercase metric label string.
 * WHY : The per-server metrics row carries a low-cardinality auth label; this
 *       is the single place the enum→string mapping lives.
 * HOW : Pure lookup over the BRIX_AUTH_* modes, defaulting to "anon".
 */
static const char *
conn_metrics_auth_label(ngx_uint_t auth)
{
    switch (auth) {
    case BRIX_AUTH_GSI:   return "gsi";
    case BRIX_AUTH_TOKEN: return "token";
    case BRIX_AUTH_SSS:   return "sss";
    case BRIX_AUTH_UNIX:  return "unix";
    case BRIX_AUTH_KRB5:  return "krb5";
    default:              return "anon";
    }
}

/*
 * WHAT: Record the listener's local port into the metrics row.
 * WHY : The dashboard labels each server row by its listening port.
 * HOW : Read c->local_sockaddr for the IPv4/IPv6 port; leave unchanged if absent.
 */
static void
conn_metrics_set_port(ngx_connection_t *c, ngx_brix_srv_metrics_t *srv)
{
    sa_family_t fam;

    if (c->local_sockaddr == NULL) {
        return;
    }

    fam = c->local_sockaddr->sa_family;
    if (fam == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *) c->local_sockaddr;
        srv->port = ntohs(sin->sin_port);
    } else if (fam == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) c->local_sockaddr;
        srv->port = ntohs(sin6->sin6_port);
    }
}

/*
 * WHAT: Write the per-upstream "host:port" labels into the metrics row.
 * WHY : Proxy upstream labels are emitted once (idempotent at first use) so the
 *       dashboard can name each configured upstream.
 * HOW : Iterate the configured upstream array, clamped to BRIX_PROXY_MAX_UPSTREAMS,
 *       formatting each label with ngx_snprintf.
 */
static void
conn_metrics_set_upstreams(ngx_stream_brix_srv_conf_t *mconf,
    ngx_brix_srv_metrics_t *srv)
{
    brix_proxy_upstream_t *ups;
    ngx_uint_t             nu, ui;

    if (mconf->proxy.upstreams == NULL) {
        return;
    }

    ups = mconf->proxy.upstreams->elts;
    nu  = mconf->proxy.upstreams->nelts;
    if (nu > BRIX_PROXY_MAX_UPSTREAMS) {
        nu = BRIX_PROXY_MAX_UPSTREAMS;
    }
    for (ui = 0; ui < nu; ui++) {
        ngx_snprintf((u_char *) srv->proxy.upstreams[ui].label,
                     BRIX_PROXY_UPSTREAM_LABEL_LEN - 1,
                     "%V:%ui%Z",
                     &ups[ui].host, (ngx_uint_t) ups[ui].port);
    }
}

/*
 * WHAT: Populate the one-time server-level metric labels (auth/port/upstreams).
 * WHY : These labels are immutable per server and written once at first use to
 *       keep the metrics row low-cardinality.
 * HOW : Guarded by !srv->in_use; sets the in_use flag then delegates the auth
 *       label, port, and upstream labels to their focused helpers.
 */
static void
conn_metrics_init_labels(ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *mconf, ngx_brix_srv_metrics_t *srv)
{
    if (srv->in_use) {
        return;
    }

    srv->in_use = 1;
    ngx_cpystrn((u_char *) srv->auth,
                (u_char *) conn_metrics_auth_label(mconf->auth),
                sizeof(srv->auth));

    conn_metrics_set_port(c, srv);
    conn_metrics_set_upstreams(mconf, srv);
}

/*
 * WHAT: Resolve the per-server metrics row for this connection, if any.
 * WHY : Metrics are optional; the row only exists when a slot is bound and the
 *       shared-memory zone is live and initialized.
 * HOW : Validate slot + shm zone (data != NULL and != the sentinel (void *)1),
 *       returning the srv row or NULL.
 */
static ngx_brix_srv_metrics_t *
conn_metrics_row(ngx_stream_brix_srv_conf_t *mconf)
{
    ngx_brix_metrics_t *shm;

    if (mconf->metrics_slot < 0 || ngx_brix_shm_zone == NULL
        || ngx_brix_shm_zone->data == NULL
        || ngx_brix_shm_zone->data == (void *) 1)
    {
        return NULL;
    }

    shm = ngx_brix_shm_zone->data;
    return &shm->servers[mconf->metrics_slot];
}

/*
 * WHAT: Bind the metrics row, publish cache labels, and apply the admission cap.
 * WHY : Metrics must be attached and the pre-identity connection cap enforced
 *       BEFORE active++ so a refused connection never perturbs the gauge.
 * HOW : Resolve the row (no-op if metrics disabled), write cache labels + one-time
 *       server labels, then enforce brix_max_connections; on refusal finalize the
 *       session and return NGX_DONE, else bump the counters and return NGX_OK.
 */
static ngx_int_t
conn_register_metrics(ngx_stream_session_t *s, ngx_connection_t *c,
    brix_ctx_t *ctx, ngx_stream_brix_srv_conf_t *mconf)
{
    ngx_brix_srv_metrics_t *srv = conn_metrics_row(mconf);

    if (srv == NULL) {
        return NGX_OK;
    }

    ctx->metrics = srv;

    srv->cache_enabled = mconf->cache ? 1 : 0;
    srv->cache_eviction_threshold = mconf->cache_eviction_threshold;
    if (mconf->cache && mconf->cache_root.len < sizeof(srv->cache_root)) {
        ngx_memcpy(srv->cache_root, mconf->cache_root.data,
                   mconf->cache_root.len);
        srv->cache_root[mconf->cache_root.len] = '\0';
    } else {
        srv->cache_root[0] = '\0';
    }

    conn_metrics_init_labels(c, mconf, srv);

    /*
     * Phase 39 (WS9): pre-identity admission cap.  Once the listener's
     * active-connection gauge is at brix_max_connections, refuse with a
     * plain TCP close — there is no streamid pre-login for a framed
     * kXR_wait, and combined with brix_handshake_timeout this bounds a
     * half-open / reconnect-storm flood.  Checked BEFORE the active++ so
     * a refused connection never perturbs the gauge.  0 = unlimited.
     */
    if (mconf->max_connections > 0
        && (ngx_uint_t) ngx_atomic_fetch_add(&srv->connections_active, 0)
           >= mconf->max_connections)
    {
        ngx_atomic_fetch_add(&srv->connections_rejected_total, 1);
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "brix: connection refused — listener at "
                      "brix_max_connections (%ui)",
                      mconf->max_connections);
        ngx_stream_finalize_session(s, NGX_STREAM_OK);
        return NGX_DONE;
    }

    ngx_atomic_fetch_add(&srv->connections_total, 1);
    ngx_atomic_fetch_add(&srv->connections_active, 1);
    return NGX_OK;
}

/*
 * WHAT: Apply all per-server configuration to the connection.
 * WHY : Groups the srv_conf-derived setup (deadlines/rings, dead-peer sockopts,
 *       congestion control, metrics + admission) behind one flat sequence.
 * HOW : Look up the srv_conf once, run the pipeline setup and TCP sockopts, then
 *       register metrics.  Returns NGX_ERROR/NGX_DONE (session already finalized)
 *       if any step demands the caller return, else NGX_OK.
 */
static ngx_int_t
conn_apply_srv_conf(ngx_stream_session_t *s, ngx_connection_t *c,
    brix_ctx_t *ctx)
{
    ngx_stream_brix_srv_conf_t *mconf =
        ngx_stream_get_module_srv_conf(s, ngx_stream_brix_module);
    ngx_int_t rc;

    rc = conn_setup_pipeline(s, c, ctx, mconf);
    if (rc != NGX_OK) {
        return rc;
    }

    /*
     * Phase 39 (WS3): OS-level dead-peer reaping, applied once at accept on
     * the control path.  Both default off (leave the kernel defaults), so a
     * stock deployment is byte-for-byte unchanged.  setsockopt failures are
     * deliberately non-fatal — a missing option must never abort a connection.
     */
    brix_apply_tcp_deadpeer_opts(c->fd, mconf->tcp_keepalive,
                                   mconf->tcp_user_timeout);

    /* Per-socket congestion control (e.g. "bbr"); empty = kernel default.
     * Best-effort — a missing algorithm leaves the default, never aborts. */
    brix_apply_tcp_congestion(c->fd, mconf->tcp_congestion);

    return conn_register_metrics(s, c, ctx, mconf);
}

/*
 * WHAT: Engage the transparent relay if this port is configured for it.
 * WHY : A relay port passes frames verbatim to an upstream XRootD server
 *       (tapping cleartext) instead of terminating the protocol locally; it must
 *       engage before any frame is read and then owns the connection.
 * HOW : If a relay_addr is configured, start the relay (finalizing on error) and
 *       return NGX_DONE so the caller returns; otherwise NGX_DECLINED.
 */
static ngx_int_t
conn_try_relay(ngx_stream_session_t *s, ngx_connection_t *c)
{
    ngx_stream_brix_srv_conf_t *rconf =
        ngx_stream_get_module_srv_conf(s, ngx_stream_brix_module);

    if (rconf->relay_addr == NULL) {
        return NGX_DECLINED;
    }

    if (brix_relay_start(s, c, rconf) != NGX_OK) {
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
    }
    return NGX_DONE;
}

/*
 * WHAT: Begin the session-lifecycle log record for this connection.
 * WHY : Every terminating connection emits a CONNECT record keyed to the peer,
 *       protocol, direction, and auth mode.
 * HOW : Look up srv_conf, resolve the peer string (or "-"), and call brix_sess_begin,
 *       storing the returned session handle on ctx.
 */
static void
conn_begin_session(ngx_stream_session_t *s, ngx_connection_t *c, brix_ctx_t *ctx)
{
    ngx_stream_brix_srv_conf_t *sconf =
        ngx_stream_get_module_srv_conf(s, ngx_stream_brix_module);
    const char *peer;
    size_t      peer_len;

    if (c->addr_text.len > 0) {
        peer = (const char *) c->addr_text.data;
        peer_len = c->addr_text.len;
    } else {
        peer = "-";
        peer_len = 1;
    }

    ctx->sess = brix_sess_begin(sconf->session_log,
                                sconf->access_log_fd,
                                BRIX_SESS_PROTO_ROOT,
                                BRIX_SESS_DIR_IN,
                                peer, peer_len,
                                brix_sess_am_from_stream_auth(sconf->auth),
                                NULL);
}

/*
 * WHAT: Arm the read/write event handlers and fire the first recv.
 * WHY : From here the recv/send event pair drives the protocol; the initial
 *       recv kick starts header accumulation.
 * HOW : Point c->read/c->write at the recv/send handlers, then call recv directly.
 */
static void
conn_pump(ngx_connection_t *c)
{
    c->read->handler = ngx_stream_brix_recv;
    c->write->handler = ngx_stream_brix_send;

    ngx_stream_brix_recv(c->read);
}

/*
 * WHAT: Per-connection entry point for the root:// stream protocol.
 * WHY : The front door: build the connection context, apply per-server config,
 *       branch to the transparent relay if configured, then start the protocol.
 * HOW : Flat early-return sequence of focused helpers — any helper that has
 *       already finalized the session signals it via a non-OK / NGX_DONE return,
 *       and this orchestrator returns immediately.  Byte-exact framing and
 *       TLS-pending timing are preserved by keeping each helper's logic verbatim.
 */
void
ngx_stream_brix_handler(ngx_stream_session_t *s)
{
    ngx_connection_t *c = s->connection;
    brix_ctx_t       *ctx;

    ctx = conn_init_ctx(s, c);
    if (ctx == NULL) {
        return;
    }

    if (conn_apply_srv_conf(s, c, ctx) != NGX_OK) {
        return;
    }

    if (conn_try_relay(s, c) == NGX_DONE) {
        return;
    }

    conn_begin_session(s, c, ctx);
    conn_pump(c);
}
