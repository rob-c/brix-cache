#include "core/ngx_brix_module.h"
#include "handoff.h"

/*
 * handoff.c — single-port protocol handoff: a small bidirectional buffered TCP
 * relay from the stream xrootd listener to a local HTTP/WebDAV listener.  See
 * handoff.h for the WHAT/WHY.  No XRootD framing is involved — this is a raw
 * byte pump, used only for connections whose first byte proves they are not an
 * XRootD client (HTTP method letter / TLS 0x16) when brix_http_handoff is set.
 */

#define BRIX_HANDOFF_BUF   (64 * 1024)
#define BRIX_HANDOFF_IDLE  75000   /* ms; drop a relay that stalls both ways */

typedef struct {
    ngx_stream_session_t      *s;
    ngx_connection_t          *client;
    ngx_connection_t          *upstream;
    ngx_peer_connection_t      peer;

    /* client -> upstream pending window [off,end) */
    u_char  *cu;
    size_t   cu_off, cu_end;
    /* upstream -> client pending window [off,end) */
    u_char  *uc;
    size_t   uc_off, uc_end;

    ngx_brix_srv_metrics_t  *metrics;   /* for connections_active-- on close */
    unsigned                   connected:1;
    unsigned                   closed:1;
} brix_handoff_t;


/* ----- config-time directive: brix_http_handoff host:port ----- */

char *
brix_conf_set_http_handoff(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_brix_srv_conf_t *xcf = conf;
    ngx_str_t                    *value;
    ngx_url_t                     url;
    ngx_addr_t                   *addr;

    (void) cmd;
    value = cf->args->elts;

    if (xcf->http_handoff_addr != NULL) {
        return "is duplicate";
    }

    xcf->http_handoff_name = value[1];

    ngx_memzero(&url, sizeof(url));
    url.url = value[1];
    url.default_port = 0;

    if (ngx_parse_url(cf->pool, &url) != NGX_OK || url.no_port
        || url.naddrs == 0 || url.addrs == NULL)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_http_handoff: could not resolve host:port in \"%V\"",
            &value[1]);
        return NGX_CONF_ERROR;
    }

    addr = ngx_pcalloc(cf->pool, sizeof(ngx_addr_t));
    if (addr == NULL) {
        return NGX_CONF_ERROR;
    }
    addr->sockaddr = ngx_pnalloc(cf->pool, url.addrs[0].socklen);
    if (addr->sockaddr == NULL) {
        return NGX_CONF_ERROR;
    }
    ngx_memcpy(addr->sockaddr, url.addrs[0].sockaddr, url.addrs[0].socklen);
    addr->socklen = url.addrs[0].socklen;
    addr->name = url.addrs[0].name;
    xcf->http_handoff_addr = addr;

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
        "xrootd: HTTP handoff target configured: %V", &value[1]);
    return NGX_CONF_OK;
}


/* ----- relay ----- */

static ngx_int_t handoff_peer_get(ngx_peer_connection_t *pc, void *data)
{ (void) pc; (void) data; return NGX_OK; }

static void handoff_peer_free(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t state)
{ (void) pc; (void) data; (void) state; }


/* Tear the relay down once: free the upstream connection (best effort) and
 * finalize the stream session (which closes the client and frees its pool). */
static void
handoff_close(brix_handoff_t *h)
{
    if (h->closed) {
        return;
    }
    h->closed = 1;

    if (h->metrics != NULL) {
        ngx_atomic_fetch_add(&h->metrics->connections_active,
                             (ngx_atomic_int_t) -1);
    }
    if (h->upstream != NULL) {
        ngx_close_connection(h->upstream);
        h->upstream = NULL;
    }
    ngx_stream_finalize_session(h->s, NGX_STREAM_OK);
}


/*
 * Move bytes one direction: drain the pending window [off,end) into `to`, then
 * read more from `from` and loop.  Arms the appropriate event (and an idle
 * timer) when either side would block; returns NGX_ERROR on EOF/error so the
 * caller closes the whole relay.  Pending is always fully flushed before the
 * next read, so a peer's EOF is only seen after its last bytes were delivered.
 */
static ngx_int_t
handoff_pump(ngx_connection_t *from, ngx_connection_t *to,
    u_char *buf, size_t *off, size_t *end)
{
    ssize_t  n;

    for ( ;; ) {
        while (*off < *end) {
            n = to->send(to, buf + *off, *end - *off);
            if (n > 0) {
                *off += (size_t) n;
                continue;
            }
            if (n == NGX_AGAIN) {
                if (ngx_handle_write_event(to->write, 0) != NGX_OK) {
                    return NGX_ERROR;
                }
                ngx_add_timer(to->write, BRIX_HANDOFF_IDLE);
                return NGX_OK;
            }
            return NGX_ERROR;          /* 0 or NGX_ERROR on the write side */
        }
        *off = *end = 0;

        n = from->recv(from, buf, BRIX_HANDOFF_BUF);
        if (n > 0) {
            *end = (size_t) n;
            *off = 0;
            continue;
        }
        if (n == NGX_AGAIN) {
            if (ngx_handle_read_event(from->read, 0) != NGX_OK) {
                return NGX_ERROR;
            }
            ngx_add_timer(from->read, BRIX_HANDOFF_IDLE);
            return NGX_OK;
        }
        return NGX_ERROR;              /* EOF (0) or error: tear the relay down */
    }
}


/* Resolve the relay hub from a CLIENT-side event (client conn data == session). */
static brix_handoff_t *
handoff_from_client(ngx_event_t *ev)
{
    ngx_connection_t     *c   = ev->data;
    ngx_stream_session_t *s   = c->data;
    brix_ctx_t         *ctx = ngx_stream_get_module_ctx(s,
                                    ngx_stream_brix_module);
    return ctx->handoff;
}


/* client readable / upstream writable -> pump client -> upstream */
static void
handoff_cu(brix_handoff_t *h, ngx_event_t *ev)
{
    if (ev->timedout) {
        handoff_close(h);
        return;
    }
    if (handoff_pump(h->client, h->upstream, h->cu, &h->cu_off, &h->cu_end)
        != NGX_OK)
    {
        handoff_close(h);
    }
}

/* upstream readable / client writable -> pump upstream -> client */
static void
handoff_uc(brix_handoff_t *h, ngx_event_t *ev)
{
    if (ev->timedout) {
        handoff_close(h);
        return;
    }
    if (handoff_pump(h->upstream, h->client, h->uc, &h->uc_off, &h->uc_end)
        != NGX_OK)
    {
        handoff_close(h);
    }
}

static void handoff_client_read(ngx_event_t *ev)  /* client -> upstream */
{ handoff_cu(handoff_from_client(ev), ev); }

static void handoff_client_write(ngx_event_t *ev) /* resume upstream -> client */
{ handoff_uc(handoff_from_client(ev), ev); }

static void handoff_upstream_read(ngx_event_t *ev)  /* upstream -> client */
{ ngx_connection_t *u = ev->data; handoff_uc(u->data, ev); }

static void handoff_upstream_write(ngx_event_t *ev) /* resume client -> upstream */
{ ngx_connection_t *u = ev->data; handoff_cu(u->data, ev); }


/* Promote a connected upstream to the running relay: install the four relay
 * handlers and kick both directions once (the client->upstream pump replays the
 * already-read prefix that start() left in the cu window). */
static void
handoff_begin_relay(brix_handoff_t *h)
{
    h->connected = 1;

    h->client->read->handler    = handoff_client_read;
    h->client->write->handler   = handoff_client_write;
    h->upstream->read->handler  = handoff_upstream_read;
    h->upstream->write->handler = handoff_upstream_write;

    /* Drive client->upstream first (flush the prefix), then upstream->client. */
    if (handoff_pump(h->client, h->upstream, h->cu, &h->cu_off, &h->cu_end)
        != NGX_OK)
    {
        handoff_close(h);
        return;
    }
    if (handoff_pump(h->upstream, h->client, h->uc, &h->uc_off, &h->uc_end)
        != NGX_OK)
    {
        handoff_close(h);
    }
}

/* upstream writable while still connecting: connect completed (or timed out). */
static void
handoff_connect_done(ngx_event_t *ev)
{
    ngx_connection_t *u = ev->data;
    brix_handoff_t *h = u->data;
    int               err;
    socklen_t         len = sizeof(err);

    if (ev->timedout) {
        ngx_log_error(NGX_LOG_ERR, h->client->log, NGX_ETIMEDOUT,
                      "xrootd handoff: connect to %V timed out", h->peer.name);
        handoff_close(h);
        return;
    }
    if (getsockopt(u->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len) == -1
        || err != 0)
    {
        ngx_log_error(NGX_LOG_ERR, h->client->log, err,
                      "xrootd handoff: connect to upstream failed");
        handoff_close(h);
        return;
    }
    if (u->write->timer_set) {
        ngx_del_timer(u->write);
    }
    handoff_begin_relay(h);
}


ngx_int_t
brix_http_handoff_start(ngx_stream_session_t *s, ngx_connection_t *c,
    void *srv_conf, u_char *prefix, size_t prefix_len)
{
    ngx_stream_brix_srv_conf_t *conf = srv_conf;
    brix_ctx_t                 *ctx;
    brix_handoff_t             *h;
    ngx_connection_t             *u;
    ngx_int_t                     rc;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_brix_module);

    h = ngx_pcalloc(c->pool, sizeof(brix_handoff_t));
    if (h == NULL) {
        return NGX_ERROR;
    }
    h->cu = ngx_pnalloc(c->pool, BRIX_HANDOFF_BUF);
    h->uc = ngx_pnalloc(c->pool, BRIX_HANDOFF_BUF);
    if (h->cu == NULL || h->uc == NULL) {
        return NGX_ERROR;
    }
    if (prefix_len > BRIX_HANDOFF_BUF) {
        return NGX_ERROR;                 /* a 20-byte hello can't exceed this */
    }

    h->s       = s;
    h->client  = c;
    h->metrics = ctx->metrics;

    /* Seed the client->upstream window with the bytes already read. */
    ngx_memcpy(h->cu, prefix, prefix_len);
    h->cu_off = 0;
    h->cu_end = prefix_len;

    /* The xrootd recv/send handlers and any read/send deadline timer must not
     * fire on this connection again — the relay owns it now. */
    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }
    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }
    ctx->state   = XRD_ST_PROXY;          /* recv loop would yield anyway */
    ctx->handoff = h;

    h->peer.sockaddr  = conf->http_handoff_addr->sockaddr;
    h->peer.socklen   = conf->http_handoff_addr->socklen;
    h->peer.name      = &conf->http_handoff_name;
    h->peer.get       = handoff_peer_get;
    h->peer.free      = handoff_peer_free;
    h->peer.log       = c->log;
    h->peer.log_error = NGX_ERROR_ERR;

    rc = ngx_event_connect_peer(&h->peer);
    if (rc == NGX_ERROR || rc == NGX_BUSY || rc == NGX_DECLINED) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "xrootd handoff: cannot connect to %V", &conf->http_handoff_name);
        return NGX_ERROR;
    }

    u           = h->peer.connection;
    h->upstream = u;
    u->data     = h;
    u->pool     = c->pool;
    u->read->handler  = handoff_upstream_read;
    u->write->handler = handoff_connect_done;

    if (rc == NGX_OK) {
        /* Connected synchronously (loopback) — start relaying immediately. */
        handoff_begin_relay(h);
    } else {
        /* NGX_AGAIN: connect in progress; arm a connect deadline. */
        ngx_add_timer(u->write, BRIX_HANDOFF_IDLE);
    }

    return NGX_OK;
}
