/*
 * gsi_upstream_login.c — Phase-4b GSI delegation: threaded blocking login to the
 * upstream AS THE USER + fd handoff into the async relay (Tasks 3+4).
 *
 * WHY: the proven in-process GSI client (the cache origin client) is BLOCKING —
 *   it runs the certreq/cert handshake on a thread-pool worker. The terminating
 *   proxy is event-driven. So for `xrootd_tap_proxy_auth gsi` we offload the whole
 *   connect+GSI-login (presenting the client's DELEGATED proxy) to a thread, then
 *   promote the authenticated fd to the proxy's async forward/relay.
 *
 * HOW: thread body builds a synthetic origin conf (host/port + the delegated proxy
 *   path + the proxy server's CA store) and reuses xrootd_cache_origin_connect +
 *   _bootstrap; on success it transfers the authenticated fd. The completion
 *   handler (event loop) wraps that fd in an ngx_connection_t already at IDLE
 *   (bootstrap done), unlinks the temp credential, and dispatches the saved
 *   request. Lifecycle guarded by client_ctx->destroyed (the worker may finish
 *   after the client vanished). GSI auth is cleartext-data here (tls=0), which is
 *   what the tap observes and what the fd handoff supports.
 */

#include "proxy_internal.h"
#include "gsi_upstream.h"
#include "cache/cache_internal.h"          /* origin connect/bootstrap + fill_t */
#include "core/aio/aio.h"                        /* xrootd_task_bind */
#include "connection/event_sched.h"        /* xrootd_schedule_read_resume */
#include "core/compat/af_policy.h"              /* XROOTD_AF_AUTO */

#include <unistd.h>

typedef struct {
    /* inputs (copied — the thread touches no shared session state) */
    char       host[256];
    uint16_t   port;
    int        family;
    char       deleg_path[256];      /* 0600 temp holding the delegated proxy   */
    X509_STORE *gsi_store;           /* borrowed from conf (verify upstream cert) */
    ngx_log_t *log;

    /* back-references for the completion handler (main thread) */
    xrootd_proxy_ctx_t *proxy;
    ngx_connection_t   *client_conn;

    /* outputs */
    int        result_fd;            /* authenticated fd, or -1 on failure */
} proxy_gsi_login_t;


/* Thread-pool worker: blocking connect + GSI login presenting the delegated proxy.
 * Reuses the cache origin client over a throwaway synthetic conf. On success the
 * authenticated fd is transferred out of `oc` so origin_close does not take it. */
static void
proxy_gsi_login_thread(void *data, ngx_log_t *log)
{
    proxy_gsi_login_t            *g     = data;
    ngx_stream_xrootd_srv_conf_t *synth = calloc(1, sizeof(*synth));
    xrootd_cache_fill_t          *t     = calloc(1, sizeof(*t));
    xrootd_cache_origin_conn_t    oc;

    (void) log;
    g->result_fd = -1;

    if (synth == NULL || t == NULL) {
        free(synth);
        free(t);
        return;
    }

    oc.fd      = -1;
    oc.ssl     = NULL;
    oc.ssl_ctx = NULL;

    synth->cache_origin_host.data   = (u_char *) g->host;
    synth->cache_origin_host.len    = ngx_strlen(g->host);
    synth->cache_origin_port        = g->port;
    synth->cache_origin_tls         = 0;                  /* cleartext GSI auth */
    synth->cache_origin_family      = (ngx_uint_t) g->family;
    synth->cache_origin_x509_proxy.data = (u_char *) g->deleg_path;
    synth->cache_origin_x509_proxy.len  = ngx_strlen(g->deleg_path);
    synth->gsi_store                = g->gsi_store;       /* borrowed; do not free */
    t->conf = synth;

    if (xrootd_cache_origin_connect(t, &oc) == 0
        && xrootd_cache_origin_bootstrap(t, &oc) == 0)
    {
        g->result_fd = oc.fd;        /* transfer ownership */
        oc.fd        = -1;
    }

    xrootd_cache_origin_close(&oc);  /* frees SSL (if any); fd already taken */
    free(synth);
    free(t);
}


/* Build the upstream ngx_connection_t around the authenticated fd (already
 * post-login), wired to the proxy relay handlers, at IDLE. Returns NGX_OK. */
static ngx_int_t
proxy_gsi_promote_fd(xrootd_proxy_ctx_t *proxy, int fd)
{
    ngx_connection_t *client_conn = proxy->client_conn;
    ngx_connection_t *uconn;

    uconn = ngx_get_connection(fd, client_conn->log);
    if (uconn == NULL) {
        return NGX_ERROR;
    }
    uconn->pool = ngx_create_pool(512, client_conn->log);
    if (uconn->pool == NULL) {
        ngx_free_connection(uconn);
        return NGX_ERROR;
    }
    if (ngx_nonblocking(fd) == -1) {
        ngx_destroy_pool(uconn->pool);
        ngx_free_connection(uconn);
        return NGX_ERROR;
    }

    uconn->data          = proxy;
    uconn->recv          = ngx_recv;
    uconn->send          = ngx_send;
    uconn->recv_chain    = ngx_recv_chain;
    uconn->send_chain    = ngx_send_chain;
    uconn->log           = client_conn->log;
    uconn->read->log     = client_conn->log;
    uconn->write->log    = client_conn->log;
    uconn->read->handler  = xrootd_proxy_read_handler;
    uconn->write->handler = xrootd_proxy_write_handler;

    proxy->conn      = uconn;
    proxy->state     = XRD_PX_IDLE;   /* bootstrap already done in the thread */
    proxy->from_pool = 1;             /* => skip the bootstrap path           */

    if (ngx_handle_read_event(uconn->read, 0) != NGX_OK) {
        return NGX_ERROR;
    }
    return NGX_OK;
}


/* Event-loop completion: the thread finished. Unlink the temp credential, then —
 * if the client is still alive — promote the authenticated fd and dispatch. */
static void
proxy_gsi_login_done(ngx_event_t *ev)
{
    ngx_thread_task_t  *task  = ev->data;
    proxy_gsi_login_t  *g     = task->ctx;
    xrootd_proxy_ctx_t *proxy = g->proxy;

    if (g->deleg_path[0] != '\0') {
        (void) unlink(g->deleg_path);   /* vfs-seam-allow: config-domain delegated GSI proxy credential temp (not export storage) */
    }

    /* Client vanished while we were logging in: drop the authed fd and stop. */
    if (proxy->client_ctx == NULL || proxy->client_ctx->destroyed) {
        if (g->result_fd >= 0) {
            ngx_close_socket(g->result_fd);
        }
        return;
    }

    if (g->result_fd < 0) {
        xrootd_proxy_abort(proxy, "proxy: GSI upstream login failed");
        return;
    }

    if (proxy_gsi_promote_fd(proxy, g->result_fd) != NGX_OK) {
        ngx_close_socket(g->result_fd);
        xrootd_proxy_abort(proxy, "proxy: GSI upstream handoff failed");
        return;
    }

    if (proxy->saved_req != NULL) {
        xrootd_proxy_dispatch_pending(proxy);
    } else {
        proxy->client_ctx->state = XRD_ST_REQ_HEADER;
        (void) xrootd_schedule_read_resume(proxy->client_conn);
    }
}


ngx_int_t
xrootd_proxy_gsi_connect_async(xrootd_proxy_ctx_t *proxy,
    ngx_stream_xrootd_srv_conf_t *conf, ngx_str_t *host, uint16_t port)
{
    ngx_connection_t  *c   = proxy->client_conn;
    xrootd_ctx_t      *ctx = proxy->client_ctx;
    ngx_thread_task_t *task;
    proxy_gsi_login_t *g;

    if (conf->common.thread_pool == NULL) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
            "xrootd_tap_proxy_auth gsi: a thread_pool is required");
        return NGX_ERROR;
    }
    if (ctx->gsi_deleg_proxy_pem == NULL || ctx->gsi_deleg_proxy_len == 0) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
            "xrootd tap proxy: no delegated X.509 proxy from the client "
            "(client must delegate; is the client GSI with delegation?)");
        return NGX_ERROR;
    }

    task = ngx_thread_task_alloc(c->pool, sizeof(proxy_gsi_login_t));
    if (task == NULL) {
        return NGX_ERROR;
    }
    g = task->ctx;

    if (xrootd_proxy_gsi_write_pem_temp(ctx->gsi_deleg_proxy_pem,
                                        ctx->gsi_deleg_proxy_len,
                                        g->deleg_path, sizeof(g->deleg_path)) != 0)
    {
        ngx_log_error(NGX_LOG_ERR, c->log, ngx_errno,
            "xrootd tap proxy: cannot persist delegated proxy");
        return NGX_ERROR;
    }

    ngx_cpystrn((u_char *) g->host, host->data, sizeof(g->host));
    g->port        = port;
    g->family      = XROOTD_AF_AUTO;
    g->gsi_store   = conf->gsi_store;   /* the proxy server's CA store (borrowed) */
    g->log         = c->log;
    g->proxy       = proxy;
    g->client_conn = c;
    g->result_fd   = -1;

    xrootd_task_bind(task, proxy_gsi_login_thread, proxy_gsi_login_done);

    if (ngx_thread_task_post(conf->common.thread_pool, task) != NGX_OK) {
        (void) unlink(g->deleg_path);   /* vfs-seam-allow: config-domain delegated GSI proxy credential temp (not export storage) */
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
            "xrootd tap proxy: GSI login thread post failed");
        return NGX_ERROR;
    }

    /* Park the client read loop until the login completes. */
    proxy->client_ctx->state = XRD_ST_PROXY;
    return NGX_OK;
}
