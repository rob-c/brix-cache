/*
 * broker.c - (kept) routing + shared helpers
 * Phase-38 split of broker.c; behavior-identical.
 */
#include "broker_internal.h"

uid_t brix_imp_broker_allow_uid = 0;
uid_t  imp_base_uid;

gid_t  imp_base_gid;

gid_t  imp_base_groups[BRIX_IDMAP_MAXGROUPS];

int    imp_base_ngroups;

uid_t  imp_self_uid;


int
imp_peer_allowed(int conn_fd)
{
    struct ucred cred;
    socklen_t    len = sizeof(cred);

    if (brix_imp_broker_allow_uid == 0) {
        return 1;                        /* gate disabled */
    }
    if (getsockopt(conn_fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0) {
        return 0;                        /* cannot verify -> refuse */
    }
    return cred.uid == brix_imp_broker_allow_uid || cred.uid == 0;
}



/* Read exactly n bytes; returns 1 ok, 0 EOF, -1 error. */
int
imp_read_full(int fd, void *buf, size_t n)
{
    u_char *p = buf;
    size_t  got = 0;

    while (got < n) {
        ssize_t r = read(fd, p + got, n - got);
        if (r == 0) { return 0; }
        if (r < 0) {
            if (errno == EINTR) { continue; }
            return -1;
        }
        got += (size_t) r;
    }
    return 1;
}


/*
 * Send the reply frame, optionally with `data_len` trailing bytes (READLINK
 * target) in the same message, and attaching `fd` via SCM_RIGHTS when fd >= 0.
 */
int
imp_send_reply(int conn_fd, const imp_rep_t *rep, int fd,
               const void *data, size_t data_len)
{
    struct msghdr   msg;
    struct iovec    iov[2];
    union {
        struct cmsghdr align;
        char           buf[CMSG_SPACE(sizeof(int))];
    } cmsgbuf;
    ssize_t n;

    ngx_memzero(&msg, sizeof(msg));
    iov[0].iov_base = (void *) rep;
    iov[0].iov_len  = sizeof(*rep);
    msg.msg_iov     = iov;
    msg.msg_iovlen  = 1;
    if (data_len > 0) {
        iov[1].iov_base = (void *) data;
        iov[1].iov_len  = data_len;
        msg.msg_iovlen  = 2;
    }

    if (fd >= 0) {
        struct cmsghdr *c;
        ngx_memzero(&cmsgbuf, sizeof(cmsgbuf));
        msg.msg_control    = cmsgbuf.buf;
        msg.msg_controllen = sizeof(cmsgbuf.buf);
        c = CMSG_FIRSTHDR(&msg);
        c->cmsg_level = SOL_SOCKET;
        c->cmsg_type  = SCM_RIGHTS;
        c->cmsg_len   = CMSG_LEN(sizeof(int));
        ngx_memcpy(CMSG_DATA(c), &fd, sizeof(int));
    }

    do {
        n = sendmsg(conn_fd, &msg, MSG_NOSIGNAL);
    } while (n < 0 && errno == EINTR);

    return (n == (ssize_t) (sizeof(*rep) + data_len)) ? 0 : -1;
}



/*
 * imp_recv_request — read and normalise one request frame off conn_fd.
 * WHAT: reads the fixed frame, zeroes the reply, NUL-terminates the wire
 * strings, and — for SETXATTR — drains the trailing inbound value payload.
 * WHY: framing and payload draining are security-load-bearing (a leftover
 * SETXATTR value would desync the SOCK_STREAM into the next request), so they
 * are isolated as one indivisible receive stage with explicit outcomes.
 * HOW: returns 1 = frame ready to dispatch, 0 = drop the connection, or 2 =
 * the frame's version was rejected (BADREQ, keep-connection decided by caller).
 * On a 0 return that still owes the peer a reply (bad length), the reply is
 * sent here.  `*in_len` receives the SETXATTR value length (0 for every other
 * op).  The version check precedes the SETXATTR drain, exactly as before.
 */
static int
imp_recv_request(int conn_fd, imp_req_t *req, imp_rep_t *rep,
                 char *data_in, size_t *in_len)
{
    int rc;

    *in_len = 0;

    rc = imp_read_full(conn_fd, req, sizeof(*req));
    if (rc <= 0) {
        return 0;                        /* EOF or error -> drop the connection */
    }

    ngx_memzero(rep, sizeof(*rep));

    /* Validate the frame: version, NUL-termination, op range. */
    req->principal[IMP_PRINC_MAX - 1] = '\0';
    req->path[IMP_PATH_MAX - 1]       = '\0';
    req->path2[IMP_PATH_MAX - 1]      = '\0';
    if (req->version != IMP_PROTO_VERSION) {
        return 2;                        /* caller emits BADREQ (pre-drain) */
    }

    /*
     * SETXATTR carries an inbound value payload after the fixed frame.  It MUST
     * be drained from the SOCK_STREAM before any deny/early-return path, or the
     * leftover bytes would be mis-read as the next request frame (desync).  An
     * over-large declared length is rejected and the connection dropped (we
     * cannot trust the stream position).  Only SETXATTR consumes inbound data;
     * every other op leaves req_data_len == 0.
     */
    if (req->op == IMP_OP_SETXATTR) {
        if (req->req_data_len > IMP_XATTR_MAX) {
            rep->status = IMP_STATUS_BADREQ;
            (void) imp_send_reply(conn_fd, rep, -1, NULL, 0);
            return 0;                    /* close: stream position untrustworthy */
        }
        *in_len = req->req_data_len;
        if (*in_len > 0 && imp_read_full(conn_fd, data_in, *in_len) <= 0) {
            return 0;                    /* EOF/error mid-payload -> drop */
        }
    }

    return 1;
}


/*
 * imp_fatal_priv_refused — handle the should-be-impossible RESERVED-credential
 * refusal at the setfsuid edge.  Does not return.
 * WHAT: replies IMP_STATUS_PRIV_REFUSED, logs loudly to both nginx log and
 * stderr, and terminates the broker process.
 * WHY: reaching this means an upstream mapping-layer guard was bypassed; NO
 * credential change was made, but continuing would risk a privileged file op,
 * so the broker fails closed + fail-loud.  Workers then fail closed on every
 * subsequent impersonated op.
 * HOW: extracted verbatim from imp_serve_one so the dispatch path stays under
 * the complexity gate; identical reply, log text, and _exit as before.
 */
static void
imp_fatal_priv_refused(int conn_fd, imp_rep_t *rep,
                       const brix_idmap_creds_t *creds, ngx_log_t *log)
{
    rep->status = IMP_STATUS_PRIV_REFUSED;
    (void) imp_send_reply(conn_fd, rep, -1, NULL, 0);
    if (log) ngx_log_error(NGX_LOG_CRIT, log, 0,
                           "impersonate broker: FATAL — refused RESERVED "
                           "credential at the setfsuid edge (uid=%d gid=%d, "
                           "floor=%d); terminating broker to guarantee no "
                           "privileged file op runs",
                           (int) creds->uid, (int) creds->gid,
                           BRIX_IMP_HARD_MIN_ID);
    /* Also emit to stderr: this is fatal and log may be NULL (tests, or a
     * mis-set error_log), and the reason must never be silently swallowed. */
    fprintf(stderr, "impersonate broker: FATAL — refused RESERVED credential "
            "(uid=%d gid=%d floor=%d); terminating\n",
            (int) creds->uid, (int) creds->gid, BRIX_IMP_HARD_MIN_ID);
    _exit(EXIT_FAILURE);
}


/*
 * imp_dispatch_op — impersonate, run the fs op, and restore base creds.
 * WHAT: becomes the mapped user, invokes imp_do_op via the caller-populated
 * imp_op_ctx_t, then always restores (even on error).  On a fatal reserved-id
 * refusal it does not return (terminates the broker).
 * WHY: the impersonate→op→restore trio is the security-critical core; keeping
 * it in one helper guarantees imp_restore() pairs every successful imp_become()
 * on every path.  The OPEN result fd flows back through op_ctx->out_fd.
 * HOW: `op_ctx` is fully filled by the caller except `rel` (imp_do_op derives
 * it).  Returns the op status (0 or -errno) to place in rep->status.  A become
 * failure short-circuits to -EPERM after restoring, matching prior behaviour.
 */
static int
imp_dispatch_op(int conn_fd, imp_op_ctx_t *op_ctx,
                const brix_idmap_creds_t *creds, ngx_log_t *log)
{
    int rc;

    /* Impersonate -> op -> restore (always restore, even on error). */
    rc = imp_become(creds);
    if (rc == IMP_REFUSE_PRIV) {
        /* does not return */
        imp_fatal_priv_refused(conn_fd, op_ctx->rep, creds, log);
    }
    if (rc != 0) {
        imp_restore();
        if (log) ngx_log_error(NGX_LOG_ERR, log, 0,
                               "impersonate broker: could not become uid=%d",
                               (int) creds->uid);
        return -EPERM;
    }

    op_ctx->rel = NULL;                  /* imp_do_op derives it from req.path */
    rc = imp_do_op(op_ctx);
    imp_restore();

    return rc;                           /* 0 or -errno */
}


/* Serve one request on conn_fd.  Returns 1 to keep the connection, 0 to close. */
int
imp_serve_one(int conn_fd, int rootfd, ngx_log_t *log)
{
    /*
     * Outbound (READLINK/GETXATTR/LISTXATTR) and inbound (SETXATTR value)
     * trailing-payload scratch.  `static` rather than stack: the broker serve
     * loop is strictly single-threaded and non-reentrant, so two 64 KiB frames
     * on the stack per request would be wasteful; each request fully overwrites
     * the bytes it sends (only rep.data_len of data_buf is ever transmitted), so
     * nothing stale leaks across requests.
     */
    static char          data_buf[IMP_XATTR_MAX]; /* outbound reply payload */
    static char          data_in[IMP_XATTR_MAX];  /* inbound SETXATTR value */
    imp_req_t            req;
    imp_rep_t            rep;
    imp_op_ctx_t         op_ctx;
    brix_idmap_creds_t creds;
    size_t               in_len = 0;
    int                  rc, fd = -1;

    rc = imp_recv_request(conn_fd, &req, &rep, data_in, &in_len);
    if (rc == 0) {
        return 0;                        /* dropped (EOF/error/bad length) */
    }
    if (rc == 2) {                       /* version rejected, before any drain */
        rep.status = IMP_STATUS_BADREQ;
        return imp_send_reply(conn_fd, &rep, -1, NULL, 0) == 0 ? 1 : 0;
    }

    if (req.op == IMP_OP_PING) {
        rep.status = IMP_STATUS_OK;
        return imp_send_reply(conn_fd, &rep, -1, NULL, 0) == 0 ? 1 : 0;
    }

    /* Map the principal -> UNIX creds.  Anything that is not a concrete OK/SQUASH
     * mapping (deny uid 0 / below floor, or a hard resolver error) fails closed —
     * the broker must never impersonate on an uncertain mapping. */
    rc = brix_idmap_resolve(NULL, req.principal, &creds, log);
    if (rc != BRIX_IDMAP_OK && rc != BRIX_IDMAP_SQUASH) {
        rep.status = IMP_STATUS_DENY;
        return imp_send_reply(conn_fd, &rep, -1, NULL, 0) == 0 ? 1 : 0;
    }

    op_ctx.rootfd      = rootfd;
    op_ctx.req         = &req;
    op_ctx.rep         = &rep;
    op_ctx.out_fd      = &fd;
    op_ctx.data_out    = data_buf;
    op_ctx.data_max    = sizeof(data_buf);
    op_ctx.data_in     = data_in;
    op_ctx.data_in_len = in_len;
    op_ctx.rel         = NULL;           /* imp_dispatch_op/imp_do_op derive it */
    rep.status = imp_dispatch_op(conn_fd, &op_ctx, &creds, log);

    rc = imp_send_reply(conn_fd, &rep, fd, data_buf, rep.data_len);
    if (fd >= 0) {
        close(fd);                       /* the kernel duped it into the worker */
    }
    return rc == 0 ? 1 : 0;
}



/*
 * imp_broker_init_creds — drop privileges and capture the base identity.
 * WHAT: minimises capabilities (and optionally drops to a service account),
 * then records imp_base_uid/gid/groups and imp_self_uid.
 * WHY: privileges are dropped FIRST so the base/idle identity the broker
 * restores to between ops, and imp_self_uid (the never-impersonate-to-self
 * guard), reflect the final, minimal identity.  Fails closed if caps cannot be
 * dropped (DAC would otherwise not be enforced).
 * HOW: returns 0 on success, -1 to abort broker startup.  No behaviour change
 * from the inline sequence it replaces.
 */
static int
imp_broker_init_creds(ngx_log_t *log)
{
    int ng;

    if (brix_imp_broker_drop_caps(log) != 0) {
        return -1;                       /* fail closed: DAC would not be enforced */
    }

    imp_base_uid = geteuid();
    imp_base_gid = getegid();
    imp_self_uid = getuid();
    ng = getgroups(BRIX_IDMAP_MAXGROUPS, imp_base_groups);
    imp_base_ngroups = (ng > 0) ? ng : 0;

    return 0;
}


/*
 * imp_broker_accept — admit or reject a pending worker connection.
 * WHAT: accepts on listen_fd, applies the SO_PEERCRED gate, and registers the
 * fd into the pollfd array if there is room.
 * WHY: peer-credential verification is security-load-bearing; over-capacity and
 * disallowed peers must be closed, never queued.  Isolating it keeps the run
 * loop under the complexity gate with identical admission behaviour.
 * HOW: takes the pollfd array and its live count by pointer; on a successful
 * admit it appends a fresh slot (events POLLIN, revents cleared) and bumps
 * *nfds.  No return value — every outcome is fully handled here.
 */
static void
imp_broker_accept(int listen_fd, struct pollfd *pfds, nfds_t *nfds,
                  ngx_log_t *log)
{
    int c = accept4(listen_fd, NULL, NULL, SOCK_CLOEXEC);

    if (c < 0) {
        return;
    }
    if (!imp_peer_allowed(c)) {
        if (log) ngx_log_error(NGX_LOG_ERR, log, 0,
                               "impersonate broker: rejected peer "
                               "(SO_PEERCRED uid mismatch)");
        close(c);
        return;
    }
    if (*nfds > IMP_BROKER_MAXCONN) {
        close(c);                        /* at capacity */
        return;
    }

    pfds[*nfds].fd      = c;
    pfds[*nfds].events  = POLLIN;
    pfds[*nfds].revents = 0;             /* MUST clear: the swap-remove
                                          * compaction below may move this
                                          * freshly-accepted slot into an
                                          * active index and re-examine it in
                                          * this same pass; a stale POLLHUP
                                          * left in the slot would otherwise
                                          * close the brand-new connection. */
    (*nfds)++;
}


/*
 * imp_broker_reap — serve ready worker connections and compact the array.
 * WHAT: walks slots [1, *nfds), serves POLLIN slots via imp_serve_one, and
 * swap-removes any slot that errored, hung up, or asked to close.
 * WHY: keeps the connection lifetime (serve→keep/close→compact) in one place,
 * preserving the exact swap-remove ordering the accept path relies on.
 * HOW: takes the pollfd array and its live count by pointer; decrements *nfds
 * as slots are removed.  Behaviour is byte-for-byte the prior inner loop.
 */
static void
imp_broker_reap(struct pollfd *pfds, nfds_t *nfds, int rootfd, ngx_log_t *log)
{
    nfds_t i;

    for (i = 1; i < *nfds; ) {
        short re   = pfds[i].revents;
        int   keep = 1;

        if (re & (POLLERR | POLLHUP | POLLNVAL)) {
            keep = 0;
        } else if (re & POLLIN) {
            keep = imp_serve_one(pfds[i].fd, rootfd, log);
        }

        if (!keep) {
            close(pfds[i].fd);
            pfds[i] = pfds[*nfds - 1];   /* swap-remove */
            (*nfds)--;
        } else {
            i++;
        }
    }
}


int
brix_imp_broker_run(int listen_fd, int rootfd,
                      const volatile sig_atomic_t *stop, ngx_log_t *log)
{
    struct pollfd pfds[IMP_BROKER_MAXCONN + 1];
    nfds_t        nfds = 1;

    if (imp_broker_init_creds(log) != 0) {
        return -1;                       /* fail closed: DAC would not be enforced */
    }

    pfds[0].fd     = listen_fd;
    pfds[0].events = POLLIN;

    for ( ;; ) {
        int n;

        if (stop != NULL && *stop) {
            return 0;
        }
        n = poll(pfds, nfds, 1000);
        if (n < 0) {
            if (errno == EINTR) { continue; }
            return -1;
        }
        if (n == 0) {
            continue;
        }

        /* New worker connection. */
        if (pfds[0].revents & POLLIN) {
            imp_broker_accept(listen_fd, pfds, &nfds, log);
        }

        /* Serve / reap worker connections (compact the array in place). */
        imp_broker_reap(pfds, &nfds, rootfd, log);
    }
}
