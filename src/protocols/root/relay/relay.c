#include "core/ngx_xrootd_module.h"
#include "relay.h"
#include "relay_guard.h"
#include "net/tap/tap.h"

/*
 * relay.c — transparent pass-through relay: a bidirectional buffered TCP relay
 * from the stream xrootd listener to an upstream XRootD server, with a
 * non-consuming tap that decodes the cleartext frames in flight.  See relay.h
 * for WHAT/WHY.  Modeled on src/handoff/handoff.c — the difference is the
 * upstream is the configured XRootD server, the relay engages before any frame
 * is read, and each freshly-recv'd chunk is fed to a per-direction tap decoder.
 */

#define XROOTD_RELAY_BUF   (64 * 1024)
#define XROOTD_RELAY_IDLE  75000   /* ms; drop a relay that stalls both ways */

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

    /* tap: one decoder per direction, fanning frames out to the audit sink */
    xrootd_tap_ctx_t     tap;
    xrootd_tap_stream_t  cu_dec;   /* client -> upstream = requests  */
    xrootd_tap_stream_t  uc_dec;   /* upstream -> client = responses */

    /* Stable log for the tap audit sink: a copy of the client log with the
     * per-session handler/data cleared. The connection's c->log carries a stream
     * log handler whose data is the xrootd session context, which is torn down
     * out from under the relay — dereferencing it from a later event would crash.
     * This copy keeps the server's error-log destination without that appender. */
    ngx_log_t                  log;

    /* bad-actor guard (xrootd_guard_stream): a second tap sink that classifies
     * each frame and raises a drop flag the pump enforces. */
    xrootd_relay_guard_t       guard;

    ngx_xrootd_srv_metrics_t  *metrics;   /* for connections_active-- on close */
    unsigned                   connected:1;
    unsigned                   closed:1;
} xrootd_relay_t;


/* ----- config-time directive: xrootd_transparent_proxy host:port ----- */

char *
xrootd_conf_set_transparent_proxy(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_xrootd_srv_conf_t *xcf = conf;
    ngx_str_t                    *value;
    ngx_url_t                     url;
    ngx_addr_t                   *addr;

    (void) cmd;
    value = cf->args->elts;

    if (xcf->relay_addr != NULL) {
        return "is duplicate";
    }

    xcf->relay_name = value[1];

    ngx_memzero(&url, sizeof(url));
    url.url = value[1];
    url.default_port = 0;

    if (ngx_parse_url(cf->pool, &url) != NGX_OK || url.no_port
        || url.naddrs == 0 || url.addrs == NULL)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_transparent_proxy: could not resolve host:port in \"%V\"",
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
    xcf->relay_addr = addr;

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
        "xrootd: transparent relay upstream configured: %V", &value[1]);
    return NGX_CONF_OK;
}


/* ----- tap audit sink: one JSON line per decoded frame to error.log ----- */

static void
relay_audit_sink(void *ctx, const xrootd_tap_frame_t *f, xrootd_tap_dir_t dir,
    const uint8_t *payload, size_t payload_len)
{
    ngx_log_t *log = ctx;
    char       line[1280];

    (void) payload;
    (void) payload_len;

    if (xrootd_tap_audit_format(f, dir, line, sizeof(line)) > 0) {
        ngx_log_error(NGX_LOG_INFO, log, 0, "xrootd tap: %s", line);
    }
}


/* ----- relay ----- */

static ngx_int_t relay_peer_get(ngx_peer_connection_t *pc, void *data)
{ (void) pc; (void) data; return NGX_OK; }

static void relay_peer_free(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t state)
{ (void) pc; (void) data; (void) state; }


/* Tear the relay down once: free the upstream connection (best effort) and
 * finalize the stream session (which closes the client and frees its pool). */
static void
relay_close(xrootd_relay_t *r)
{
    if (r->closed) {
        return;
    }
    r->closed = 1;

    if (r->metrics != NULL) {
        ngx_atomic_fetch_add(&r->metrics->connections_active,
                             (ngx_atomic_int_t) -1);
    }
    if (r->upstream != NULL) {
        ngx_close_connection(r->upstream);
        r->upstream = NULL;
    }
    ngx_stream_finalize_session(r->s, NGX_STREAM_OK);
}


/*
 * Move bytes one direction: drain the pending window [off,end) into `to`, then
 * read more from `from` and loop.  Each freshly-read chunk is fed to `dec` (the
 * direction's tap decoder) exactly once — before it is queued for send, never on
 * a re-send after NGX_AGAIN — so the tap observes every byte once, in order.
 * When the guard sink flags a frame in that chunk, the chunk is NOT forwarded
 * and the whole relay comes down (bounce = connection drop).
 * Arms the appropriate event (and an idle timer) when either side would block;
 * returns NGX_ERROR on EOF/error so the caller closes the whole relay.
 */
static ngx_int_t
relay_pump(xrootd_relay_t *r, ngx_connection_t *from, ngx_connection_t *to,
    u_char *buf, size_t *off, size_t *end, xrootd_tap_stream_t *dec)
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
                ngx_add_timer(to->write, XROOTD_RELAY_IDLE);
                return NGX_OK;
            }
            return NGX_ERROR;          /* 0 or NGX_ERROR on the write side */
        }
        *off = *end = 0;

        n = from->recv(from, buf, XROOTD_RELAY_BUF);
        if (n > 0) {
            xrootd_tap_stream_feed(dec, buf, (size_t) n);   /* tap once */
            if (xrootd_relay_guard_should_drop(&r->guard)) {
                return NGX_ERROR;      /* BOUNCE: never forward this chunk */
            }
            *end = (size_t) n;
            *off = 0;
            continue;
        }
        if (n == NGX_AGAIN) {
            if (ngx_handle_read_event(from->read, 0) != NGX_OK) {
                return NGX_ERROR;
            }
            ngx_add_timer(from->read, XROOTD_RELAY_IDLE);
            return NGX_OK;
        }
        return NGX_ERROR;              /* EOF (0) or error: tear the relay down */
    }
}


/* Resolve the relay hub from a CLIENT-side event (client conn data == session). */
static xrootd_relay_t *
relay_from_client(ngx_event_t *ev)
{
    ngx_connection_t     *c   = ev->data;
    ngx_stream_session_t *s   = c->data;
    xrootd_ctx_t         *ctx = ngx_stream_get_module_ctx(s,
                                    ngx_stream_xrootd_module);
    return ctx->relay;
}


/* client readable / upstream writable -> pump client -> upstream (requests) */
static void
relay_cu(xrootd_relay_t *r, ngx_event_t *ev)
{
    if (ev->timedout) {
        relay_close(r);
        return;
    }
    if (relay_pump(r, r->client, r->upstream, r->cu, &r->cu_off, &r->cu_end,
                   &r->cu_dec) != NGX_OK)
    {
        relay_close(r);
    }
}

/* upstream readable / client writable -> pump upstream -> client (responses) */
static void
relay_uc(xrootd_relay_t *r, ngx_event_t *ev)
{
    if (ev->timedout) {
        relay_close(r);
        return;
    }
    if (relay_pump(r, r->upstream, r->client, r->uc, &r->uc_off, &r->uc_end,
                   &r->uc_dec) != NGX_OK)
    {
        relay_close(r);
    }
}

static void relay_client_read(ngx_event_t *ev)  /* client -> upstream */
{ relay_cu(relay_from_client(ev), ev); }

static void relay_client_write(ngx_event_t *ev) /* resume upstream -> client */
{ relay_uc(relay_from_client(ev), ev); }

static void relay_upstream_read(ngx_event_t *ev)  /* upstream -> client */
{ ngx_connection_t *u = ev->data; relay_uc(u->data, ev); }

static void relay_upstream_write(ngx_event_t *ev) /* resume client -> upstream */
{ ngx_connection_t *u = ev->data; relay_cu(u->data, ev); }


/* Promote a connected upstream to the running relay: install the four relay
 * handlers and kick both directions once (the client->upstream pump reads the
 * client's hello fresh — there is no pre-read prefix in transparent mode). */
static void
relay_begin(xrootd_relay_t *r)
{
    r->connected = 1;

    r->client->read->handler    = relay_client_read;
    r->client->write->handler   = relay_client_write;
    r->upstream->read->handler  = relay_upstream_read;
    r->upstream->write->handler = relay_upstream_write;

    if (relay_pump(r, r->client, r->upstream, r->cu, &r->cu_off, &r->cu_end,
                   &r->cu_dec) != NGX_OK)
    {
        relay_close(r);
        return;
    }
    if (relay_pump(r, r->upstream, r->client, r->uc, &r->uc_off, &r->uc_end,
                   &r->uc_dec) != NGX_OK)
    {
        relay_close(r);
    }
}

/* upstream writable while still connecting: connect completed (or timed out). */
static void
relay_connect_done(ngx_event_t *ev)
{
    ngx_connection_t *u = ev->data;
    xrootd_relay_t   *r = u->data;
    int               err;
    socklen_t         len = sizeof(err);

    if (ev->timedout) {
        ngx_log_error(NGX_LOG_ERR, r->client->log, NGX_ETIMEDOUT,
                      "xrootd relay: connect to %V timed out", r->peer.name);
        relay_close(r);
        return;
    }
    if (getsockopt(u->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len) == -1
        || err != 0)
    {
        ngx_log_error(NGX_LOG_ERR, r->client->log, err,
                      "xrootd relay: connect to upstream failed");
        relay_close(r);
        return;
    }
    if (u->write->timer_set) {
        ngx_del_timer(u->write);
    }
    relay_begin(r);
}


ngx_int_t
xrootd_relay_start(ngx_stream_session_t *s, ngx_connection_t *c, void *srv_conf)
{
    ngx_stream_xrootd_srv_conf_t *conf = srv_conf;
    xrootd_ctx_t                 *ctx;
    xrootd_relay_t               *r;
    ngx_connection_t             *u;
    ngx_int_t                     rc;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_xrootd_module);

    r = ngx_pcalloc(c->pool, sizeof(xrootd_relay_t));
    if (r == NULL) {
        return NGX_ERROR;
    }
    r->cu = ngx_pnalloc(c->pool, XROOTD_RELAY_BUF);
    r->uc = ngx_pnalloc(c->pool, XROOTD_RELAY_BUF);
    if (r->cu == NULL || r->uc == NULL) {
        return NGX_ERROR;
    }

    r->s       = s;
    r->client  = c;
    r->metrics = ctx->metrics;

    /* No pre-read prefix in transparent mode: the pump reads the client hello. */
    r->cu_off = r->cu_end = 0;
    r->uc_off = r->uc_end = 0;

    /* Tap: a stable log copy (server error-log destination, no stale session
     * appender), then register the audit sink + a decoder per direction. */
    r->log         = *c->log;
    r->log.handler = NULL;
    r->log.data    = NULL;
    r->log.action  = NULL;
    xrootd_tap_register_sink(&r->tap, relay_audit_sink, &r->log);
    xrootd_tap_stream_init(&r->cu_dec, &r->tap, XROOTD_TAP_C2U);
    xrootd_tap_stream_init(&r->uc_dec, &r->tap, XROOTD_TAP_U2C);

    /* Bad-actor guard (xrootd_guard_stream): classify each tapped frame and
     * let the pump drop the connection on a BOUNCE verdict. */
    xrootd_relay_guard_init(&r->guard, conf->relay_guard_enable == 1,
                            &c->addr_text, &r->log);
    if (r->guard.enable) {
        xrootd_tap_register_sink(&r->tap, xrootd_relay_guard_sink, &r->guard);
    }

    /* The xrootd recv/send handlers and any deadline timer must not fire on this
     * connection again — the relay owns it now. */
    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }
    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }
    ctx->state = XRD_ST_PROXY;
    ctx->relay = r;

    r->peer.sockaddr  = conf->relay_addr->sockaddr;
    r->peer.socklen   = conf->relay_addr->socklen;
    r->peer.name      = &conf->relay_name;
    r->peer.get       = relay_peer_get;
    r->peer.free      = relay_peer_free;
    r->peer.log       = c->log;
    r->peer.log_error = NGX_ERROR_ERR;

    rc = ngx_event_connect_peer(&r->peer);
    if (rc == NGX_ERROR || rc == NGX_BUSY || rc == NGX_DECLINED) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "xrootd relay: cannot connect to %V", &conf->relay_name);
        return NGX_ERROR;
    }

    u           = r->peer.connection;
    r->upstream = u;
    u->data     = r;
    u->pool     = c->pool;
    u->read->handler  = relay_upstream_read;
    u->write->handler = relay_connect_done;

    if (rc == NGX_OK) {
        /* Connected synchronously (loopback) — start relaying immediately. */
        relay_begin(r);
    } else {
        /* NGX_AGAIN: connect in progress; arm a connect deadline. */
        ngx_add_timer(u->write, XROOTD_RELAY_IDLE);
    }

    return NGX_OK;
}
