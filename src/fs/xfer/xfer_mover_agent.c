/*
 * xfer_mover_agent.c — the single crash-safe out-of-process transfer agent.
 *
 * WHAT: A payload-agnostic harness that runs an external transfer in a
 *       double-forked, reparented-to-init agent process and shuttles fixed-size
 *       request/reply frames over a socketpair, driving completions on the nginx
 *       event loop. Each transfer kind supplies an brix_xfer_agent_ops_t (frame
 *       sizes + agent-side process() + worker-side on_reply()).
 *
 * WHY:  See xfer.h: reaping a worker child crashes the nginx master via the
 *       SHM-zone-as-slab-pool SIGCHLD handler. The reparented agent is the only
 *       safe way to fork/exec/waitpid a transfer command from a worker. This was
 *       proven in the FRM tape path (src/frm/stage.c); it is lifted here verbatim
 *       so write-through and TPC inherit the same one fork/reap path instead of
 *       each rolling their own (the posix_spawn-at-close hazard).
 *
 * HOW:  attach: socketpair → block SIGCHLD → fork → fork(agent) → intermediate
 *       _exit (agent reparents to init) → reap the intermediate while SIGCHLD is
 *       blocked (nginx never sees it). The worker side is non-blocking and
 *       registered as an nginx read event. The agent loop reads a request, calls
 *       ops->process(), writes a reply; the worker read handler drains replies
 *       (ops->on_reply each), respawns on agent death, and calls ops->after_drain
 *       once. No goto; early-return throughout.
 */

#include "xfer.h"

#include <ngx_event.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

/* ======================= framed socket I/O (both sides) ==================== */

/* Read exactly len bytes. Returns len, 0 on EOF, -1 on error. EINTR retried. */
static ssize_t
xfer_read_full(int fd, void *buf, size_t len)
{
    u_char *p = buf;
    size_t  got = 0;

    while (got < len) {
        ssize_t n = read(fd, p + got, len - got);
        if (n == 0) {
            return 0;
        }
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        got += (size_t) n;
    }
    return (ssize_t) len;
}

/* Write exactly len bytes. Returns len, or -1 on error. EINTR retried. */
static ssize_t
xfer_write_full(int fd, const void *buf, size_t len)
{
    const u_char *p = buf;
    size_t        put = 0;

    while (put < len) {
        ssize_t n = write(fd, p + put, len - put);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        put += (size_t) n;
    }
    return (ssize_t) len;
}

/* ============================ agent (child) side =========================== */

/* The agent loop: read a request, process it into a reply, send the reply.
 * Exits on EOF (worker closed) or a fatal frame error. Never returns. */
static void
xfer_agent_loop(int fd, const brix_xfer_agent_ops_t *ops)
{
    void *req;
    void *rep;

    signal(SIGCHLD, SIG_DFL);            /* our own waitpid() must work */

    req = malloc(ops->req_size);
    rep = malloc(ops->rep_size);
    if (req == NULL || rep == NULL) {
        _exit(0);
    }

    for ( ;; ) {
        if (xfer_read_full(fd, req, ops->req_size) <= 0) {
            _exit(0);                    /* worker closed → shut down */
        }
        ops->process(req, rep, ops->data);
        if (xfer_write_full(fd, rep, ops->rep_size) < 0) {
            _exit(0);
        }
    }
}

/* Double-fork the agent (reparented to init so nginx never reaps it), reaping the
 * intermediate while SIGCHLD is blocked. Returns the non-blocking worker-side fd,
 * or -1. */
static int
xfer_agent_spawn(const brix_xfer_agent_ops_t *ops, ngx_log_t *log)
{
    int      sv[2];
    sigset_t block, prev;
    pid_t    inter;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno, "xfer: %s socketpair failed",
                      ops->name);
        return -1;
    }

    sigemptyset(&block);
    sigaddset(&block, SIGCHLD);
    sigprocmask(SIG_BLOCK, &block, &prev);

    inter = fork();
    if (inter < 0) {
        sigprocmask(SIG_SETMASK, &prev, NULL);
        close(sv[0]);
        close(sv[1]);
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno, "xfer: %s agent fork failed",
                      ops->name);
        return -1;
    }
    if (inter == 0) {
        pid_t agent = fork();
        if (agent == 0) {
            close(sv[0]);
            xfer_agent_loop(sv[1], ops);     /* never returns */
            _exit(0);
        }
        _exit(0);                            /* intermediate → agent reparents */
    }

    /* parent: reap the intermediate ourselves (nginx never sees it). */
    close(sv[1]);
    while (waitpid(inter, NULL, 0) < 0 && errno == EINTR) { }
    sigprocmask(SIG_SETMASK, &prev, NULL);

    (void) fcntl(sv[0], F_SETFL, O_NONBLOCK);
    return sv[0];
}

/* ============================ worker side ================================= */

static void xfer_agent_on_reply(ngx_event_t *rev);

/* Recover from a dead agent: tear down the old socketpair/connection and spawn a
 * fresh agent so transfers keep flowing. On respawn failure a->fd stays -1 and
 * dispatch fails closed. */
static void
xfer_agent_respawn(brix_xfer_agent_t *a)
{
    brix_xfer_agent_teardown(a);
    if (brix_xfer_agent_attach(a, a->ops, a->log) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, a->log, 0,
                      "xfer: %s agent respawn failed — transfers paused until "
                      "the next reload", a->ops->name);
    } else {
        ngx_log_error(NGX_LOG_NOTICE, a->log, 0,
                      "xfer: %s agent respawned after exit", a->ops->name);
    }
}

/* nginx read-event handler: drain all pending agent replies. */
static void
xfer_agent_on_reply(ngx_event_t *rev)
{
    ngx_connection_t    *c = rev->data;
    brix_xfer_agent_t *a = c->data;
    const size_t         rep_size = a->ops->rep_size;

    for ( ;; ) {
        ssize_t n = recv(c->fd, a->rep_buf, rep_size, 0);

        if (n == 0) {
            /* Agent exited (EOF): respawn frees this connection, so return
             * immediately — c/rev must not be touched afterward. */
            ngx_log_error(NGX_LOG_ERR, c->log, 0, "xfer: %s agent exited",
                          a->ops->name);
            xfer_agent_respawn(a);
            return;
        }
        if (n < 0) {
            if (ngx_errno == NGX_EAGAIN) {
                break;
            }
            if (ngx_errno == NGX_EINTR) {
                continue;
            }
            ngx_log_error(NGX_LOG_ERR, c->log, ngx_errno, "xfer: %s agent recv",
                          a->ops->name);
            xfer_agent_respawn(a);
            return;
        }
        if (n != (ssize_t) rep_size) {
            /* partial frame: finish it (small, rare) */
            if (xfer_read_full(c->fd, (u_char *) a->rep_buf + n,
                               rep_size - (size_t) n) <= 0)
            {
                xfer_agent_respawn(a);
                return;
            }
        }
        a->ops->on_reply(a->rep_buf, a->ops->data);
    }

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "xfer: %s agent read-event re-arm",
                      a->ops->name);
    }
    if (a->ops->after_drain != NULL) {
        a->ops->after_drain(a->ops->data);
    }
}

void
brix_xfer_agent_teardown(brix_xfer_agent_t *a)
{
    if (a->conn != NULL) {
        ngx_close_connection(a->conn);   /* frees conn + closes the fd */
        a->conn = NULL;
    }
    a->fd = -1;                           /* dispatch now fails closed */
}

ngx_int_t
brix_xfer_agent_attach(brix_xfer_agent_t *a,
    const brix_xfer_agent_ops_t *ops, ngx_log_t *log)
{
    a->ops = ops;
    a->log = log;

    if (a->rep_buf == NULL) {
        a->rep_buf = malloc(ops->rep_size);
        if (a->rep_buf == NULL) {
            ngx_log_error(NGX_LOG_ERR, log, 0, "xfer: %s reply-buf alloc failed",
                          ops->name);
            return NGX_ERROR;
        }
    }

    a->fd = xfer_agent_spawn(ops, log);
    if (a->fd < 0) {
        return NGX_ERROR;
    }

    a->conn = ngx_get_connection(a->fd, log);
    if (a->conn == NULL) {
        close(a->fd);
        a->fd = -1;
        return NGX_ERROR;
    }
    a->conn->data          = a;                 /* recover the handle in handler */
    a->conn->read->handler = xfer_agent_on_reply;
    a->conn->read->log     = log;
    a->conn->recv          = ngx_recv;
    if (ngx_handle_read_event(a->conn->read, 0) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "xfer: %s cannot arm agent read event",
                      ops->name);
        brix_xfer_agent_teardown(a);
        return NGX_ERROR;
    }
    return NGX_OK;
}

ngx_int_t
brix_xfer_agent_dispatch(brix_xfer_agent_t *a, const void *req)
{
    const size_t req_size = a->ops->req_size;
    ssize_t      n;

    if (a->fd < 0) {
        return NGX_ERROR;
    }

    n = write(a->fd, req, req_size);
    if (n == (ssize_t) req_size) {
        return NGX_OK;
    }
    if (n < 0 && (ngx_errno == NGX_EAGAIN || ngx_errno == NGX_EINTR)) {
        return NGX_AGAIN;                    /* agent backed up — retry later */
    }
    /* a partial/failed write: finish it blocking (small, rare) */
    if (n >= 0 && xfer_write_full(a->fd, (const u_char *) req + n,
                                  req_size - (size_t) n)
                  == (ssize_t) (req_size - (size_t) n))
    {
        return NGX_OK;
    }
    return NGX_ERROR;
}
