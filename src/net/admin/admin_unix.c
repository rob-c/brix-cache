/*
 * admin_unix.c — verb-agnostic unix-domain admin transport. See admin_unix.h
 * for the model, the per-worker path rule and the security boundary.
 */

#include "admin_unix.h"

#include <sys/un.h>
#include <sys/stat.h>

/* Per-connection parse/reply state, allocated from the connection's pool. */
typedef struct {
    const brix_admin_unix_t *srv;
    u_char                   cmd[BRIX_ADMIN_CMD_MAX];
    size_t                   cmd_len;
    brix_admin_reply_t       rep;
    size_t                   sent;
} admin_unix_conn_t;

void
brix_admin_reply_set(brix_admin_reply_t *rep, const char *msg)
{
    rep->out = rep->buf;
    rep->len = (size_t) (ngx_snprintf(rep->buf, rep->cap, "%s", msg)
                         - rep->buf);
}

/* Length of `line` with any trailing CR/LF run stripped. */
static size_t
admin_unix_strip_eol(const u_char *line, size_t len)
{
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
        len--;
    }
    return len;
}

/*
 * Match one line against one verb. A bare verb must match the whole line; a
 * verb taking operands must be followed by a space AND at least one operand
 * byte, so "disc" alone is unknown-command rather than a disc of the empty
 * session id.
 */
static int
admin_unix_verb_match(const brix_admin_verb_t *v, const u_char *line,
    size_t len, size_t *args_off)
{
    if (len < v->nlen || ngx_strncmp(line, v->name, v->nlen) != 0) {
        return 0;
    }
    if (!v->wants_args) {
        return len == v->nlen;
    }
    if (len <= v->nlen + 1 || line[v->nlen] != ' ') {
        return 0;
    }
    *args_off = v->nlen + 1;
    return 1;
}

/* Dispatch one complete command line into a pool-allocated reply. */
static void
admin_unix_dispatch(ngx_connection_t *c, admin_unix_conn_t *st)
{
    const brix_admin_unix_t *srv = st->srv;
    size_t     len = admin_unix_strip_eol(st->cmd, st->cmd_len);
    size_t     off = 0;
    ngx_uint_t i;

    st->rep.buf = ngx_pnalloc(c->pool, BRIX_ADMIN_REPLY_MAX);
    if (st->rep.buf == NULL) {
        return;
    }
    st->rep.cap = BRIX_ADMIN_REPLY_MAX;
    st->rep.out = st->rep.buf;
    st->rep.len = 0;
    st->sent = 0;

    for (i = 0; i < srv->nverbs; i++) {
        if (admin_unix_verb_match(&srv->verbs[i], st->cmd, len, &off)) {
            srv->verbs[i].handler(srv->ud, off ? st->cmd + off : NULL,
                                  off ? len - off : 0, &st->rep);
            return;
        }
    }
    brix_admin_reply_set(&st->rep, "err unknown-command\n");
}

/* ---- event handlers ----------------------------------------------------- */

static void
admin_unix_close(ngx_connection_t *c)
{
    ngx_pool_t *pool = c->pool;

    ngx_close_connection(c);
    if (pool != NULL) {
        ngx_destroy_pool(pool);
    }
}

static void
admin_unix_write_handler(ngx_event_t *wev)
{
    ngx_connection_t   *c = wev->data;
    admin_unix_conn_t  *st = c->data;
    ssize_t             n;

    while (st->sent < st->rep.len) {
        n = c->send(c, st->rep.out + st->sent, st->rep.len - st->sent);
        if (n > 0) {
            st->sent += (size_t) n;
            continue;
        }
        if (n == NGX_AGAIN) {
            if (ngx_handle_write_event(wev, 0) != NGX_OK) {
                admin_unix_close(c);
            }
            return;
        }
        admin_unix_close(c);
        return;
    }

    /* Reply fully flushed — reset for the next command on the same conn. */
    st->rep.len = 0;
    st->sent = 0;
    st->cmd_len = 0;
}

static void
admin_unix_read_handler(ngx_event_t *rev)
{
    ngx_connection_t   *c = rev->data;
    admin_unix_conn_t  *st = c->data;
    ssize_t             n;

    for ( ;; ) {
        if (st->cmd_len >= sizeof(st->cmd)) {
            admin_unix_close(c);   /* oversized command line — refuse */
            return;
        }
        n = c->recv(c, st->cmd + st->cmd_len, sizeof(st->cmd) - st->cmd_len);
        if (n > 0) {
            st->cmd_len += (size_t) n;
            if (ngx_strlchr(st->cmd, st->cmd + st->cmd_len, '\n') != NULL) {
                admin_unix_dispatch(c, st);
                admin_unix_write_handler(c->write);
                return;   /* one command per read pass; next arrives as data */
            }
            continue;
        }
        if (n == NGX_AGAIN) {
            if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                admin_unix_close(c);
            }
            return;
        }
        admin_unix_close(c);   /* EOF or error */
        return;
    }
}

/* Wire one accepted fd into a connection with its own pool and state. */
static void
admin_unix_setup_conn(ngx_connection_t *c, ngx_event_t *rev)
{
    admin_unix_conn_t *st;

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
    c->pool = ngx_create_pool(BRIX_ADMIN_POOL_SIZE, rev->log);
    if (c->pool == NULL) {
        ngx_close_connection(c);
        return;
    }
    st = ngx_pcalloc(c->pool, sizeof(*st));
    if (st == NULL) {
        admin_unix_close(c);
        return;
    }
    st->srv = ((ngx_connection_t *) rev->data)->data;
    c->data = st;
    c->read->handler = admin_unix_read_handler;
    c->write->handler = admin_unix_write_handler;
    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        admin_unix_close(c);
    }
}

static void
admin_unix_accept_handler(ngx_event_t *rev)
{
    ngx_connection_t *lc = rev->data;
    ngx_socket_t      fd;
    ngx_connection_t *c;

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
        admin_unix_setup_conn(c, rev);
    }
}

/* ---- listener ----------------------------------------------------------- */

/*
 * This worker's socket path. Worker 0 serves the configured <path>; worker n
 * serves "<path>.<n>". Returns the length, or -1 when the result would exceed
 * sun_path (a silently truncated path would be a DIFFERENT socket).
 */
static int
admin_unix_worker_path(char *out, size_t cap, const char *path)
{
    int n;

    if (ngx_worker == 0) {
        n = snprintf(out, cap, "%s", path);
    } else {
        n = snprintf(out, cap, "%s.%lu", path, (unsigned long) ngx_worker);
    }
    return (n < 0 || (size_t) n >= cap) ? -1 : n;
}

/* Bind + chmod + listen a fresh AF_UNIX socket; -1 on any failure. */
static ngx_socket_t
admin_unix_bind(const char *path, size_t plen, ngx_log_t *log)
{
    struct sockaddr_un sa;
    ngx_socket_t       fd;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == (ngx_socket_t) -1) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                      "brix admin: socket(%s) failed", path);
        return (ngx_socket_t) -1;
    }

    ngx_memzero(&sa, sizeof(sa));
    sa.sun_family = AF_UNIX;
    ngx_memcpy(sa.sun_path, path, plen + 1);

    if (bind(fd, (struct sockaddr *) &sa, sizeof(sa)) == -1
        || chmod(path, 0600) == -1 /* vfs-seam-allow: NOT_STORAGE — admin socket 0600 privilege boundary */
        || listen(fd, 8) == -1
        || ngx_nonblocking(fd) == -1)
    {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                      "brix admin: bind/listen(%s) failed", path);
        (void) close(fd);
        return (ngx_socket_t) -1;
    }
    return fd;
}

void
brix_admin_unix_listen(ngx_cycle_t *cycle, const char *path,
    const brix_admin_unix_t *srv)
{
    char              wpath[sizeof(((struct sockaddr_un *) 0)->sun_path)];
    ngx_socket_t      fd;
    ngx_connection_t *lc;
    int               n;

    if (path == NULL || path[0] == '\0') {
        return;
    }

    n = admin_unix_worker_path(wpath, sizeof(wpath), path);
    if (n < 0) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                      "brix %s: per-worker path for \"%s\" exceeds unix "
                      "socket path limit — socket disabled on worker %ui",
                      srv->label, path, ngx_worker);
        return;
    }

    (void) unlink(wpath);   /* drop a stale socket from a prior run */ /* vfs-seam-allow: NOT_STORAGE — admin unix socket, not export namespace */

    fd = admin_unix_bind(wpath, (size_t) n, cycle->log);
    if (fd == (ngx_socket_t) -1) {
        return;
    }

    lc = ngx_get_connection(fd, cycle->log);
    if (lc == NULL) {
        (void) close(fd);
        return;
    }
    lc->data = (void *) srv;   /* the accept handler's route to the verbs */
    lc->read->handler = admin_unix_accept_handler;
    if (ngx_handle_read_event(lc->read, 0) != NGX_OK) {
        ngx_close_connection(lc);
        return;
    }

    ngx_log_error(NGX_LOG_INFO, cycle->log, 0,
                  "brix %s: listening on \"%s\" (worker %ui)", srv->label,
                  wpath, ngx_worker);
}
