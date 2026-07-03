#include "server.h"
#include "protocols/root/connection/netopt.h"   /* Phase 50: TCP dead-peer opts (WS5) */
#include "core/compat/log_diag.h"
#include "observability/metrics/metrics_macros.h"   /* Phase 51 (A1): resilience counters */

/*
 * Phase 50 (WS4): per-worker live gauge of accepted CMS data-server connections.
 * One process-global counter encapsulated behind accessors; incremented once a
 * connection is admitted (handler) and decremented when it closes (server_recv.c
 * brix_cms_srv_close), gated by ctx->counted so it can never double-count or
 * underflow.  Enforces brix_cms_server_max_connections so a peer inside the
 * (often unset) CIDR allowlist cannot exhaust memory/fds with idle connections.
 */
static ngx_uint_t  brix_cms_srv_conns;

ngx_uint_t
brix_cms_srv_conn_count(void)
{
    return brix_cms_srv_conns;
}

void
brix_cms_srv_conn_inc(void)
{
    brix_cms_srv_conns++;
}

void
brix_cms_srv_conn_dec(void)
{
    if (brix_cms_srv_conns > 0) {
        brix_cms_srv_conns--;
    }
}

/*
 * Phase 51 (A3): per-source-IP connection accounting (per-worker), so one peer
 * cannot consume every slot of the global cap.  A small open-addressing table
 * keyed by the peer IP string; linear-probe.  If the table is full (an abusive
 * fan-out of distinct IPs — itself bounded by the global cap) we fail OPEN: the
 * global cap still bounds the total, we just stop enforcing per-IP for the
 * overflow.  Lock-free: per-worker, event-loop only.
 */
#define BRIX_CMS_IP_SLOTS  4096

typedef struct {
    char        ip[64];     /* peer IP string; '\0' = free slot */
    ngx_uint_t  count;      /* live connections from this IP in this worker */
} brix_cms_ip_slot_t;

static brix_cms_ip_slot_t  brix_cms_ip_table[BRIX_CMS_IP_SLOTS];

static ngx_uint_t
brix_cms_ip_hash(const char *ip)
{
    ngx_uint_t  h = 5381;
    const u_char *p = (const u_char *) ip;

    while (*p) {
        h = ((h << 5) + h) ^ (ngx_uint_t) *p++;   /* djb2-xor */
    }
    return h % BRIX_CMS_IP_SLOTS;
}

/* Find the slot for ip; if create, claim a free slot when absent.  Returns NULL
 * when absent and (not create OR table full). Probes a bounded window. */
static brix_cms_ip_slot_t *
brix_cms_ip_find(const char *ip, int create)
{
    ngx_uint_t  start = brix_cms_ip_hash(ip);
    ngx_uint_t  i;

    for (i = 0; i < BRIX_CMS_IP_SLOTS; i++) {
        brix_cms_ip_slot_t *slot =
            &brix_cms_ip_table[(start + i) % BRIX_CMS_IP_SLOTS];

        if (slot->ip[0] == '\0') {
            if (!create) {
                return NULL;            /* absent */
            }
            ngx_cpystrn((u_char *) slot->ip, (u_char *) ip, sizeof(slot->ip));
            slot->count = 0;
            return slot;
        }
        if (ngx_strcmp(slot->ip, ip) == 0) {
            return slot;                /* found */
        }
    }
    return NULL;                        /* table full */
}

ngx_uint_t
brix_cms_srv_ip_count(const char *ip)
{
    brix_cms_ip_slot_t *slot = brix_cms_ip_find(ip, 0);
    return slot ? slot->count : 0;
}

void
brix_cms_srv_ip_inc(const char *ip)
{
    brix_cms_ip_slot_t *slot = brix_cms_ip_find(ip, 1);
    if (slot != NULL) {
        slot->count++;
    }
}

void
brix_cms_srv_ip_dec(const char *ip)
{
    brix_cms_ip_slot_t *slot = brix_cms_ip_find(ip, 0);
    if (slot != NULL && slot->count > 0) {
        slot->count--;
        if (slot->count == 0) {
            slot->ip[0] = '\0';         /* free the slot */
        }
    }
}

/*
 * server_handler.c — CMS server connection handler
 *
 * WHAT: Accepts TCP connections from the XRootD CMS manager and maintains a
 *       persistent heartbeat session. Each accepted connection is assigned a
 *       read/write handler pair that exchanges periodic load reports.
 *
 * WHY: The CMS manager needs to know which data servers are alive, how much
 *      free space they have, and their utilisation percentage so it can route
 *      client requests (kXR_locate / kXR_redirect) to the best server.
 *
 * HOW: On accept we allocate a cms_srv_ctx_t on the connection pool, set up
 *      ping_timer for periodic heartbeats, assign read/write handlers,
 *      and immediately arm the first read event. The read handler (recv.c)
 *      dispatches incoming frames; the write handler (send.c) fires load
 *      reports at conf->interval_ms intervals.
 */

void
brix_cms_srv_handler(ngx_stream_session_t *s)
/*
 *
 * WHAT: Entry point for CMS server connections accepted by the stream module.
 *       Allocates context, sets up handlers and timer, arms first read.
 *
 * WHY: The CMS manager connects to this port as a data-server client. We need
 *      a per-connection state object (ctx) that tracks the connection pointer,
 *      how many bytes remain in the current frame header, the peer host string,
 *      and the heartbeat timer.
 *
 * HOW: 1. pcalloc ctx on c->pool (auto-cleaned on pool destruction).
 *      2. Initialise ctx fields: c pointer, hdr-in_need = CMS_HDR_LEN,
 *         host from ngx_sock_ntop, interval_ms from conf.
 *      3. Set ping_timer log/data, assign c->data = ctx.
 *      4. Replace default read/write handlers with cms_srv_read/cms_srv_write.
 *      5. Log debug line and arm first read.
 */

{
    ngx_connection_t                  *c;
    brix_cms_srv_ctx_t              *ctx;
    ngx_stream_brix_cms_srv_conf_t  *conf;
    size_t                             len;

    c = s->connection;

    ctx = ngx_pcalloc(c->pool, sizeof(brix_cms_srv_ctx_t));
    if (ctx == NULL) {
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ctx->c       = c;
    ctx->in_need = NGX_BRIX_CMS_HDR_LEN;

    len = ngx_sock_ntop(c->sockaddr, c->socklen,
                        (u_char *) ctx->host, sizeof(ctx->host) - 1, 0);
    ctx->host[len] = '\0';

    conf = ngx_stream_get_module_srv_conf(s, ngx_stream_brix_cms_srv_module);
    ctx->conf        = conf;
    ctx->interval_ms = (ngx_msec_t) conf->interval * 1000;
    if (ctx->interval_ms < 1000) {
        /* Never arm a 0/sub-1s self-rearming ping timer: interval 0 → 0ms timer
         * → epoll_wait(timeout=0) busy-loop pinning the worker. Floor at 1s. */
        ctx->interval_ms = 1000;
    }
    ctx->login_timeout_ms = conf->login_timeout;   /* WS3 */
    ctx->idle_timeout_ms  = conf->idle_timeout;    /* WS3 */

    /*
     * WS4 — admission cap.  Reject before installing any frame handler so an
     * abusive peer (inside the often-unset CIDR allowlist) cannot exhaust
     * memory/fds with idle connections.  0 = unlimited (back-compat).
     */
    if (conf->max_connections > 0
        && brix_cms_srv_conn_count() >= (ngx_uint_t) conf->max_connections)
    {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "xrootd: CMS server: connection from %s refused — "
                      "max_connections (%i) reached",
                      ctx->host, conf->max_connections);
        BRIX_RESIL_METRIC_INC(cms_cap_rejections_total);
        ngx_stream_finalize_session(s, NGX_STREAM_FORBIDDEN);
        return;
    }

    /*
     * A3 — per-source-IP admission cap, so one peer cannot consume every slot of
     * the global cap above.  0 = disabled (back-compat).
     */
    if (conf->max_connections_per_ip > 0
        && brix_cms_srv_ip_count(ctx->host)
           >= (ngx_uint_t) conf->max_connections_per_ip)
    {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "xrootd: CMS server: connection from %s refused — "
                      "max_connections_per_ip (%i) reached",
                      ctx->host, conf->max_connections_per_ip);
        BRIX_RESIL_METRIC_INC(cms_cap_rejections_total);
        ngx_stream_finalize_session(s, NGX_STREAM_FORBIDDEN);
        return;
    }

    /*
     * W1b — accept-time CIDR allowlist gate.  Reject before installing any
     * frame handler so an unauthorised peer never reaches the LOGIN/registry
     * path.  When no allowlist is configured this passes (back-compat).
     */
    if (brix_cms_srv_check_peer(c, conf) != NGX_OK) {
        BRIX_DIAG(NGX_LOG_NOTICE, c->log, 0,
            "xrootd[cms]: rejected data-server registration from %s",
            "the peer's IP is not covered by the brix_cms_server_allow "
            "allowlist (or the allowlist is wrong)",
            "if this is a legitimate data server, add its IP/CIDR to "
            "brix_cms_server_allow; otherwise this is an unauthorised peer "
            "being correctly refused",
            ctx->host);
        ngx_stream_finalize_session(s, NGX_STREAM_FORBIDDEN);
        return;
    }

    /* W1a — require the sss handshake before registration iff a keytab is set. */
    ctx->auth_state = (conf->sss_keys != NULL) ? CMS_AUTH_REQUESTED
                                               : CMS_AUTH_NONE;

    ctx->ping_timer.log  = c->log;
    ctx->ping_timer.data = ctx;

    /* WS4 + A3: admitted — count it globally and per-IP (decremented in
     * brix_cms_srv_close). */
    brix_cms_srv_conn_inc();
    brix_cms_srv_ip_inc(ctx->host);
    ctx->counted = 1;

    c->data = ctx;
    c->read->handler  = brix_cms_srv_read;
    c->write->handler = brix_cms_srv_write;

    /*
     * WS5: OS-level dead-peer reaping on the accepted socket, so a silently-
     * dropped data node is torn down by the kernel.  Best-effort, non-fatal.
     */
    brix_apply_tcp_deadpeer_opts(c->fd, conf->tcp_keepalive,
                                   conf->tcp_user_timeout);

    /*
     * WS3: arm the LOGIN handshake deadline (absolute, from accept).  A peer that
     * never completes LOGIN (+sss xauth) — or trickles a partial header — is
     * closed by the read handler's ev->timedout path instead of squatting a ctx +
     * fd forever (slowloris).  Replaced by the post-login idle watchdog in
     * cms_srv_complete_login.  0 = disabled.
     */
    if (ctx->login_timeout_ms > 0) {
        ngx_add_timer(c->read, ctx->login_timeout_ms);
    }

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: CMS server accepted from %s", ctx->host);

    brix_cms_srv_read(c->read);
}
