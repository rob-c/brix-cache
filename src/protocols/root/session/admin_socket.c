/*
 * admin_socket.c — §1.16 runtime admin unix socket. See admin_socket.h for the
 * protocol, scope (worker-0 slice) and security model.
 */

#include "admin_socket.h"
#include "offload_registry.h"
#include "registry.h"
#include "protocols/root/response/async.h"   /* brix_send_attn_asyncms */

#include <sys/un.h>
#include <sys/stat.h>

/* Directive state (parse-time, node-global — same file-static pattern as
 * brix_posc_persist): the LAST brix_admin_socket wins across server blocks. */
static char  s_admin_path[sizeof(((struct sockaddr_un *) 0)->sun_path)];

/* Per-admin-connection parse/reply state, allocated from the conn's pool. */
typedef struct {
    u_char  cmd[512];      /* accumulated request line                 */
    size_t  cmd_len;
    u_char *reply;         /* pending reply bytes (pool-allocated)     */
    size_t  reply_len;
    size_t  reply_sent;
} brix_admin_conn_t;

#define BRIX_ADMIN_REPLY_MAX  (64 * 1024)

/* `list` enumeration state threaded through the offload-registry callback. */
typedef struct {
    u_char *buf;
    size_t  len;
    size_t  cap;
    size_t  n;
} admin_list_state_t;

char *
brix_conf_set_admin_socket(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t *value = cf->args->elts;

    (void) cmd;
    (void) conf;

    if (value[1].len == 0 || value[1].len >= sizeof(s_admin_path)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_admin_socket: path empty or longer than a unix socket "
            "path (%uz max)", sizeof(s_admin_path) - 1);
        return NGX_CONF_ERROR;
    }
    ngx_memcpy(s_admin_path, value[1].data, value[1].len);
    s_admin_path[value[1].len] = '\0';
    return NGX_CONF_OK;
}

/* ---- command helpers ---------------------------------------------------- */

/* Parse 32 lowercase/uppercase hex chars into a 16-byte sessid; 0 on error. */
static int
admin_parse_sessid(const u_char *hex, size_t len,
    u_char out[BRIX_SESSION_ID_LEN])
{
    size_t i;

    if (len != BRIX_SESSION_ID_LEN * 2) {
        return 0;
    }
    for (i = 0; i < BRIX_SESSION_ID_LEN; i++) {
        int hi = ngx_hextoi((u_char *) &hex[i * 2], 1);
        int lo = ngx_hextoi((u_char *) &hex[i * 2 + 1], 1);
        if (hi == NGX_ERROR || lo == NGX_ERROR) {
            return 0;
        }
        out[i] = (u_char) ((hi << 4) | lo);
    }
    return 1;
}

static int
admin_list_cb(void *ud, const unsigned char *sessid, unsigned pathid,
    void *conn)
{
    admin_list_state_t *st = ud;
    ngx_connection_t   *tc = conn;
    char                dn[512];
    char                vo[512];
    ngx_uint_t          token_auth;
    size_t              i;
    u_char             *p;

    if (pathid != BRIX_ADMIN_PATHID) {
        return 0;   /* a bound data channel, not a session's primary */
    }
    /* Room for: 32 hex + peer(<=64) + dn(<=128 shown) + separators + '\n'. */
    if (st->cap - st->len < 32 + 1 + 64 + 1 + 128 + 2) {
        return 1;   /* reply buffer full — stop enumerating */
    }

    p = st->buf + st->len;
    for (i = 0; i < BRIX_SESSION_ID_LEN; i++) {
        p = ngx_sprintf(p, "%02xd", sessid[i]);
    }
    /* Peer address: the operator's handle for choosing a session to act on. */
    if (tc->addr_text.len > 0) {
        size_t alen = ngx_min(tc->addr_text.len, 64);
        *p++ = ' ';
        p = ngx_cpymem(p, tc->addr_text.data, alen);
    } else {
        p = ngx_sprintf(p, " -");
    }
    dn[0] = '\0';
    if (brix_session_lookup(sessid, dn, sizeof(dn), vo, sizeof(vo),
                              &token_auth)
        && dn[0] != '\0')
    {
        p = ngx_snprintf(p, 1 + 128, " %s", dn);
    } else {
        p = ngx_sprintf(p, " -");
    }
    *p++ = '\n';
    st->len = (size_t) (p - st->buf);
    st->n++;
    return 0;
}

/* One-shot timed-pause resume: clears the pause flag and posts the read event
 * so the recv loop drains whatever backed up. The connection is guaranteed
 * alive while the timer is armed — disconnect deletes it (disconnect.c). */
static void
admin_pause_timeout(ngx_event_t *ev)
{
    ngx_connection_t *tc = ev->data;
    brix_ctx_t       *tctx;

    tctx = ngx_stream_get_module_ctx((ngx_stream_session_t *) tc->data,
                                       ngx_stream_brix_module);
    if (tctx == NULL || tctx->destroyed) {
        return;
    }
    tctx->admin_paused = 0;
    ngx_post_event(tc->read, &ngx_posted_events);
}

/* Length of `line` with any trailing CR/LF run stripped. */
static size_t
admin_strip_eol(const u_char *line, size_t len)
{
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
        len--;
    }
    return len;
}

/* Set st->reply_len from a formatted one-shot reply into `out`. */
static void
admin_reply(brix_admin_conn_t *st, u_char *out, const char *msg)
{
    st->reply_len = (size_t) (ngx_snprintf(out, BRIX_ADMIN_REPLY_MAX,
        "%s", msg) - out);
}

/* Resolve a session id to its local ctx (NULL when unknown/not-local/destroyed);
 * *target_out receives the connection when found. */
static brix_ctx_t *
admin_resolve_ctx(const u_char *sessid, ngx_connection_t **target_out)
{
    ngx_connection_t *target = brix_offload_lookup(sessid, BRIX_ADMIN_PATHID);
    brix_ctx_t       *tctx;

    *target_out = target;
    if (target == NULL) {
        return NULL;
    }
    tctx = ngx_stream_get_module_ctx((ngx_stream_session_t *) target->data,
                                     ngx_stream_brix_module);
    return (tctx == NULL || tctx->destroyed) ? NULL : tctx;
}

/* "list" — enumerate the local offloaded sessions. */
static void
admin_cmd_list(brix_admin_conn_t *st, u_char *out)
{
    admin_list_state_t ls;
    u_char head[32];
    u_char *he;
    size_t  hlen;

    ls.buf = out + 32;                  /* body after the "ok <n>\n" header */
    ls.len = 0;
    ls.cap = BRIX_ADMIN_REPLY_MAX - 64;
    ls.n = 0;
    (void) brix_offload_foreach(admin_list_cb, &ls);

    he = ngx_snprintf(head, sizeof(head), "ok %uz\n", ls.n);
    hlen = (size_t) (he - head);
    /* The body was built past the largest possible header; slide the header in
     * front of it so the reply is one contiguous run. */
    ngx_memcpy(out + 32 - hlen, head, hlen);
    st->reply = out + 32 - hlen;
    st->reply_len = hlen + ls.len;
}

/* "disc <sid>" — graceful shutdown(2); the loop's EOF path does the teardown. */
static void
admin_cmd_disc(brix_admin_conn_t *st, u_char *out, u_char *line, size_t len)
{
    u_char            sessid[BRIX_SESSION_ID_LEN];
    ngx_connection_t *target;

    if (!admin_parse_sessid(line + 5, len - 5, sessid)) {
        admin_reply(st, out, "err unknown-command\n");
        return;
    }
    target = brix_offload_lookup(sessid, BRIX_ADMIN_PATHID);
    if (target == NULL) {
        admin_reply(st, out, "err unknown-or-not-local\n");
        return;
    }
    (void) shutdown(target->fd, SHUT_RDWR);
    admin_reply(st, out, "ok\n");
}

/* "msg <sid> <text>" — deliver an async attn message to the target session. */
static void
admin_cmd_msg(brix_admin_conn_t *st, u_char *out, u_char *line, size_t len)
{
    u_char           *sp = ngx_strlchr(line + 4, line + len, ' ');
    u_char            sessid[BRIX_SESSION_ID_LEN];
    ngx_connection_t *target;
    brix_ctx_t       *tctx;
    const char       *text;
    size_t            tlen;

    if (sp == NULL
        || !admin_parse_sessid(line + 4, (size_t) (sp - (line + 4)), sessid)) {
        admin_reply(st, out, "err unknown-command\n");
        return;
    }
    text = (const char *) sp + 1;
    tlen = (size_t) (line + len - (sp + 1));
    tctx = admin_resolve_ctx(sessid, &target);
    if (target == NULL) {
        admin_reply(st, out, "err unknown-or-not-local\n");
    } else if (tctx == NULL || tlen == 0) {
        admin_reply(st, out, "err target-unusable\n");
    } else if (brix_send_attn_asyncms(tctx, target, text, tlen) != NGX_OK) {
        admin_reply(st, out, "err send-failed\n");
    } else {
        admin_reply(st, out, "ok\n");
    }
}

/* "pause <sid> [secs]" — stop parsing the target; optional auto-resume timer. */
static void
admin_cmd_pause(brix_admin_conn_t *st, u_char *out, u_char *line, size_t len)
{
    u_char           *sp = ngx_strlchr(line + 6, line + len, ' ');
    size_t            hexlen = sp ? (size_t) (sp - (line + 6)) : len - 6;
    u_char            sessid[BRIX_SESSION_ID_LEN];
    ngx_connection_t *target;
    brix_ctx_t       *tctx;
    ngx_int_t         secs = 0;

    if (sp != NULL) {
        secs = ngx_atoi(sp + 1, (size_t) (line + len - (sp + 1)));
        if (secs == NGX_ERROR || secs < 0) {
            admin_reply(st, out, "err bad-seconds\n");
            return;
        }
    }
    if (!admin_parse_sessid(line + 6, hexlen, sessid)) {
        admin_reply(st, out, "err unknown-command\n");
        return;
    }
    tctx = admin_resolve_ctx(sessid, &target);
    if (tctx == NULL) {
        admin_reply(st, out, "err unknown-or-not-local\n");
        return;
    }
    tctx->admin_paused = 1;
    if (secs > 0) {
        tctx->admin_pause_ev.handler = admin_pause_timeout;
        tctx->admin_pause_ev.data = target;
        tctx->admin_pause_ev.log = target->log;
        ngx_add_timer(&tctx->admin_pause_ev, (ngx_msec_t) secs * 1000);
    }
    admin_reply(st, out, "ok\n");
}

/* "cont <sid>" — clear a pause and repost the read event. */
static void
admin_cmd_cont(brix_admin_conn_t *st, u_char *out, u_char *line, size_t len)
{
    u_char            sessid[BRIX_SESSION_ID_LEN];
    ngx_connection_t *target;
    brix_ctx_t       *tctx;

    if (!admin_parse_sessid(line + 5, len - 5, sessid)) {
        admin_reply(st, out, "err unknown-command\n");
        return;
    }
    tctx = admin_resolve_ctx(sessid, &target);
    if (tctx == NULL) {
        admin_reply(st, out, "err unknown-or-not-local\n");
        return;
    }
    if (tctx->admin_pause_ev.timer_set) {
        ngx_del_timer(&tctx->admin_pause_ev);
    }
    tctx->admin_paused = 0;
    /* Resume parsing whatever backed up while paused: the recv loop yielded
     * without re-arming, so the read event must be posted. */
    ngx_post_event(target->read, &ngx_posted_events);
    admin_reply(st, out, "ok\n");
}

/* "abort <sid>" — RST-on-close (SO_LINGER{1,0}) then shutdown(2). */
static void
admin_cmd_abort(brix_admin_conn_t *st, u_char *out, u_char *line, size_t len)
{
    u_char            sessid[BRIX_SESSION_ID_LEN];
    ngx_connection_t *target;
    struct linger     lg;

    if (!admin_parse_sessid(line + 6, len - 6, sessid)) {
        admin_reply(st, out, "err unknown-command\n");
        return;
    }
    target = brix_offload_lookup(sessid, BRIX_ADMIN_PATHID);
    if (target == NULL) {
        admin_reply(st, out, "err unknown-or-not-local\n");
        return;
    }
    /* Abort = disconnect WITHOUT ceremony: SO_LINGER{1,0} makes the teardown's
     * eventual close(2) send an RST instead of a FIN, so the client sees
     * ECONNRESET — stock abort semantics. The teardown still runs through the
     * normal event-loop EOF path (no re-entrancy), exactly like disc. */
    lg.l_onoff = 1;
    lg.l_linger = 0;
    (void) setsockopt(target->fd, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
    (void) shutdown(target->fd, SHUT_RDWR);
    admin_reply(st, out, "ok\n");
}

/* Dispatch one complete command line into a pool-allocated reply. */
static void
admin_dispatch(ngx_connection_t *c, brix_admin_conn_t *st)
{
    u_char *line = st->cmd;
    size_t  len = st->cmd_len;
    u_char *out;

    out = ngx_pnalloc(c->pool, BRIX_ADMIN_REPLY_MAX);
    if (out == NULL) {
        return;
    }
    st->reply = out;
    st->reply_sent = 0;
    len = admin_strip_eol(line, len);

    /* Prefix-match the verb; each handler parses its own operands and owns its
     * reply (falling back to unknown-command on a malformed session id). */
    if (len == 4 && ngx_strncmp(line, "list", 4) == 0) {
        admin_cmd_list(st, out);
    } else if (len > 5 && ngx_strncmp(line, "disc ", 5) == 0) {
        admin_cmd_disc(st, out, line, len);
    } else if (len > 4 && ngx_strncmp(line, "msg ", 4) == 0) {
        admin_cmd_msg(st, out, line, len);
    } else if (len > 6 && ngx_strncmp(line, "pause ", 6) == 0) {
        admin_cmd_pause(st, out, line, len);
    } else if (len > 5 && ngx_strncmp(line, "cont ", 5) == 0) {
        admin_cmd_cont(st, out, line, len);
    } else if (len > 6 && ngx_strncmp(line, "abort ", 6) == 0) {
        admin_cmd_abort(st, out, line, len);
    } else {
        admin_reply(st, out, "err unknown-command\n");
    }
}

/* ---- event handlers ----------------------------------------------------- */

static void
admin_close(ngx_connection_t *c)
{
    ngx_pool_t *pool = c->pool;

    ngx_close_connection(c);
    if (pool != NULL) {
        ngx_destroy_pool(pool);
    }
}

static void
admin_write_handler(ngx_event_t *wev)
{
    ngx_connection_t  *c = wev->data;
    brix_admin_conn_t *st = c->data;
    ssize_t            n;

    while (st->reply_sent < st->reply_len) {
        n = c->send(c, st->reply + st->reply_sent,
                    st->reply_len - st->reply_sent);
        if (n > 0) {
            st->reply_sent += (size_t) n;
            continue;
        }
        if (n == NGX_AGAIN) {
            if (ngx_handle_write_event(wev, 0) != NGX_OK) {
                admin_close(c);
            }
            return;
        }
        admin_close(c);
        return;
    }

    /* Reply fully flushed — reset for the next command on the same conn. */
    st->reply_len = 0;
    st->reply_sent = 0;
    st->cmd_len = 0;
}

static void
admin_read_handler(ngx_event_t *rev)
{
    ngx_connection_t  *c = rev->data;
    brix_admin_conn_t *st = c->data;
    ssize_t            n;

    for ( ;; ) {
        if (st->cmd_len >= sizeof(st->cmd)) {
            admin_close(c);   /* oversized command line — refuse */
            return;
        }
        n = c->recv(c, st->cmd + st->cmd_len, sizeof(st->cmd) - st->cmd_len);
        if (n > 0) {
            st->cmd_len += (size_t) n;
            if (ngx_strlchr(st->cmd, st->cmd + st->cmd_len, '\n') != NULL) {
                admin_dispatch(c, st);
                admin_write_handler(c->write);
                return;   /* one command per read pass; next arrives as data */
            }
            continue;
        }
        if (n == NGX_AGAIN) {
            if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                admin_close(c);
            }
            return;
        }
        admin_close(c);   /* EOF or error */
        return;
    }
}

static void
admin_accept_handler(ngx_event_t *rev)
{
    ngx_connection_t  *lc = rev->data;
    ngx_socket_t       fd;
    ngx_connection_t  *c;
    brix_admin_conn_t *st;

    for ( ;; ) {
        fd = accept(lc->fd, NULL, NULL);
        if (fd == (ngx_socket_t) -1) {
            return;   /* EAGAIN or transient — nothing more to accept */
        }
        if (ngx_nonblocking(fd) == -1) {
            (void) close(fd);
            continue;
        }
        c = ngx_get_connection(fd, rev->log);
        if (c == NULL) {
            (void) close(fd);
            continue;
        }
        /* ngx_get_connection() hands out a BARE connection: the I/O vtable is
         * ngx_event_accept()'s job, so wire it here or c->recv/c->send are
         * NULL function pointers. */
        c->recv = ngx_recv;
        c->send = ngx_send;
        c->recv_chain = ngx_recv_chain;
        c->send_chain = ngx_send_chain;
        c->log = rev->log;
        c->read->log = c->log;
        c->write->log = c->log;
        c->type = SOCK_STREAM;
        c->pool = ngx_create_pool(2048, rev->log);
        if (c->pool == NULL) {
            ngx_close_connection(c);
            continue;
        }
        st = ngx_pcalloc(c->pool, sizeof(*st));
        if (st == NULL) {
            admin_close(c);
            continue;
        }
        c->data = st;
        c->read->handler = admin_read_handler;
        c->write->handler = admin_write_handler;
        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            admin_close(c);
        }
    }
}

void
brix_admin_socket_init(ngx_cycle_t *cycle)
{
    struct sockaddr_un  sa;
    ngx_socket_t        fd;
    ngx_connection_t   *lc;
    char                path[sizeof(sa.sun_path)];
    int                 n;

    if (s_admin_path[0] == '\0') {
        return;
    }

    /*
     * MULTI-WORKER REACH: every worker serves its OWN admin socket — worker 0
     * at the configured <path>, worker n at "<path>.<n>". Sessions are per-
     * worker (nginx process model), so each socket lists/controls exactly the
     * sessions its worker owns; an admin tool sweeps the socket set. This is
     * the natural mapping of stock's single-daemon adminpath onto nginx's
     * process model — a documented divergence.
     */
    if (ngx_worker == 0) {
        n = snprintf(path, sizeof(path), "%s", s_admin_path);
    } else {
        n = snprintf(path, sizeof(path), "%s.%lu", s_admin_path,
                     (unsigned long) ngx_worker);
    }
    if (n < 0 || (size_t) n >= sizeof(path)) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                      "brix admin: per-worker path for \"%s\" exceeds unix "
                      "socket path limit — admin socket disabled on worker %ui",
                      s_admin_path, ngx_worker);
        return;
    }

    (void) unlink(path);   /* drop a stale socket from a prior run */ /* vfs-seam-allow: NOT_STORAGE — admin unix socket, not export namespace */

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == (ngx_socket_t) -1) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, ngx_errno,
                      "brix admin: socket(%s) failed", path);
        return;
    }

    ngx_memzero(&sa, sizeof(sa));
    sa.sun_family = AF_UNIX;
    ngx_memcpy(sa.sun_path, path, (size_t) n + 1);

    if (bind(fd, (struct sockaddr *) &sa, sizeof(sa)) == -1
        || chmod(path, 0600) == -1 /* vfs-seam-allow: NOT_STORAGE — admin socket 0600 privilege boundary */
        || listen(fd, 8) == -1
        || ngx_nonblocking(fd) == -1)
    {
        ngx_log_error(NGX_LOG_ERR, cycle->log, ngx_errno,
                      "brix admin: bind/listen(%s) failed", path);
        (void) close(fd);
        return;
    }

    lc = ngx_get_connection(fd, cycle->log);
    if (lc == NULL) {
        (void) close(fd);
        return;
    }
    lc->read->handler = admin_accept_handler;
    if (ngx_handle_read_event(lc->read, 0) != NGX_OK) {
        ngx_close_connection(lc);
        return;
    }

    ngx_log_error(NGX_LOG_INFO, cycle->log, 0,
                  "brix admin: listening on \"%s\" (worker %ui)", path,
                  ngx_worker);
}
