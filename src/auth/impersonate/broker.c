/*
 * broker.c - (kept) routing + shared helpers
 * Phase-38 split of broker.c; behavior-identical.
 */
#include "broker_internal.h"

uid_t xrootd_imp_broker_allow_uid = 0;
uid_t  imp_base_uid;

gid_t  imp_base_gid;

gid_t  imp_base_groups[XROOTD_IDMAP_MAXGROUPS];

int    imp_base_ngroups;

uid_t  imp_self_uid;


int
imp_peer_allowed(int conn_fd)
{
    struct ucred cred;
    socklen_t    len = sizeof(cred);

    if (xrootd_imp_broker_allow_uid == 0) {
        return 1;                        /* gate disabled */
    }
    if (getsockopt(conn_fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0) {
        return 0;                        /* cannot verify -> refuse */
    }
    return cred.uid == xrootd_imp_broker_allow_uid || cred.uid == 0;
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
    xrootd_idmap_creds_t creds;
    size_t               in_len = 0;
    int                  rc, fd = -1;

    rc = imp_read_full(conn_fd, &req, sizeof(req));
    if (rc <= 0) {
        return 0;                        /* EOF or error -> drop the connection */
    }

    ngx_memzero(&rep, sizeof(rep));

    /* Validate the frame: version, NUL-termination, op range. */
    req.principal[IMP_PRINC_MAX - 1] = '\0';
    req.path[IMP_PATH_MAX - 1]       = '\0';
    req.path2[IMP_PATH_MAX - 1]      = '\0';
    if (req.version != IMP_PROTO_VERSION) {
        rep.status = IMP_STATUS_BADREQ;
        return imp_send_reply(conn_fd, &rep, -1, NULL, 0) == 0 ? 1 : 0;
    }

    /*
     * SETXATTR carries an inbound value payload after the fixed frame.  It MUST
     * be drained from the SOCK_STREAM before any deny/early-return path, or the
     * leftover bytes would be mis-read as the next request frame (desync).  An
     * over-large declared length is rejected and the connection dropped (we
     * cannot trust the stream position).  Only SETXATTR consumes inbound data;
     * every other op leaves req_data_len == 0.
     */
    if (req.op == IMP_OP_SETXATTR) {
        if (req.req_data_len > IMP_XATTR_MAX) {
            rep.status = IMP_STATUS_BADREQ;
            (void) imp_send_reply(conn_fd, &rep, -1, NULL, 0);
            return 0;                    /* close: stream position untrustworthy */
        }
        in_len = req.req_data_len;
        if (in_len > 0 && imp_read_full(conn_fd, data_in, in_len) <= 0) {
            return 0;                    /* EOF/error mid-payload -> drop */
        }
    }

    if (req.op == IMP_OP_PING) {
        rep.status = IMP_STATUS_OK;
        return imp_send_reply(conn_fd, &rep, -1, NULL, 0) == 0 ? 1 : 0;
    }

    /* Map the principal -> UNIX creds.  Anything that is not a concrete OK/SQUASH
     * mapping (deny uid 0 / below floor, or a hard resolver error) fails closed —
     * the broker must never impersonate on an uncertain mapping. */
    rc = xrootd_idmap_resolve(NULL, req.principal, &creds, log);
    if (rc != XROOTD_IDMAP_OK && rc != XROOTD_IDMAP_SQUASH) {
        rep.status = IMP_STATUS_DENY;
        return imp_send_reply(conn_fd, &rep, -1, NULL, 0) == 0 ? 1 : 0;
    }

    /* Impersonate -> op -> restore (always restore, even on error). */
    rc = imp_become(&creds);
    if (rc == IMP_REFUSE_PRIV) {
        /*
         * CRITICAL, should-be-impossible: a reserved uid/gid reached the setfsuid
         * edge despite the mapping-layer floor.  NO credential change was made.
         * Refuse, return an explicit error to the worker, log loudly, and
         * TERMINATE the privileged broker (fail-closed + fail-loud) so a
         * privileged file op can never be executed.  Workers then fail closed on
         * every subsequent impersonated op.  This is not reachable in correct
         * operation (idmap denies reserved ids first); reaching it means an
         * upstream guard was bypassed, which we treat as fatal.
         */
        rep.status = IMP_STATUS_PRIV_REFUSED;
        (void) imp_send_reply(conn_fd, &rep, -1, NULL, 0);
        if (log) ngx_log_error(NGX_LOG_CRIT, log, 0,
                               "impersonate broker: FATAL — refused RESERVED "
                               "credential at the setfsuid edge (uid=%d gid=%d, "
                               "floor=%d); terminating broker to guarantee no "
                               "privileged file op runs",
                               (int) creds.uid, (int) creds.gid,
                               XROOTD_IMP_HARD_MIN_ID);
        /* Also emit to stderr: this is fatal and log may be NULL (tests, or a
         * mis-set error_log), and the reason must never be silently swallowed. */
        fprintf(stderr, "impersonate broker: FATAL — refused RESERVED credential "
                "(uid=%d gid=%d floor=%d); terminating\n",
                (int) creds.uid, (int) creds.gid, XROOTD_IMP_HARD_MIN_ID);
        _exit(EXIT_FAILURE);
    }
    if (rc != 0) {
        imp_restore();
        rep.status = -EPERM;
        if (log) ngx_log_error(NGX_LOG_ERR, log, 0,
                               "impersonate broker: could not become uid=%d",
                               (int) creds.uid);
        return imp_send_reply(conn_fd, &rep, -1, NULL, 0) == 0 ? 1 : 0;
    }
    rc = imp_do_op(rootfd, &req, &rep, &fd, data_buf, sizeof(data_buf),
                   data_in, in_len);
    imp_restore();

    rep.status = rc;                     /* 0 or -errno */

    rc = imp_send_reply(conn_fd, &rep, fd, data_buf, rep.data_len);
    if (fd >= 0) {
        close(fd);                       /* the kernel duped it into the worker */
    }
    return rc == 0 ? 1 : 0;
}



int
xrootd_imp_broker_run(int listen_fd, int rootfd,
                      const volatile sig_atomic_t *stop, ngx_log_t *log)
{
    struct pollfd pfds[IMP_BROKER_MAXCONN + 1];
    nfds_t        nfds = 1;
    int           ng;

    /*
     * Drop privileges FIRST (cap minimisation + optional drop to a non-root
     * service account), THEN capture the base credentials — so the base/idle
     * identity the broker restores to between ops, and imp_self_uid (the
     * never-impersonate-to-self guard), reflect the final, minimal identity.
     */
    if (xrootd_imp_broker_drop_caps(log) != 0) {
        return -1;                       /* fail closed: DAC would not be enforced */
    }

    imp_base_uid = geteuid();
    imp_base_gid = getegid();
    imp_self_uid = getuid();
    ng = getgroups(XROOTD_IDMAP_MAXGROUPS, imp_base_groups);
    imp_base_ngroups = (ng > 0) ? ng : 0;

    pfds[0].fd     = listen_fd;
    pfds[0].events = POLLIN;

    for ( ;; ) {
        nfds_t i;
        int    n;

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
            int c = accept4(listen_fd, NULL, NULL, SOCK_CLOEXEC);
            if (c >= 0) {
                if (!imp_peer_allowed(c)) {
                    if (log) ngx_log_error(NGX_LOG_ERR, log, 0,
                                           "impersonate broker: rejected peer "
                                           "(SO_PEERCRED uid mismatch)");
                    close(c);
                } else if (nfds <= IMP_BROKER_MAXCONN) {
                    pfds[nfds].fd      = c;
                    pfds[nfds].events  = POLLIN;
                    pfds[nfds].revents = 0;  /* MUST clear: the swap-remove
                                              * compaction below may move this
                                              * freshly-accepted slot into an
                                              * active index and re-examine it in
                                              * this same pass; a stale POLLHUP
                                              * left in the slot would otherwise
                                              * close the brand-new connection. */
                    nfds++;
                } else {
                    close(c);            /* at capacity */
                }
            }
        }

        /* Serve / reap worker connections (compact the array in place). */
        for (i = 1; i < nfds; ) {
            short re = pfds[i].revents;
            int   keep = 1;

            if (re & (POLLERR | POLLHUP | POLLNVAL)) {
                keep = 0;
            } else if (re & POLLIN) {
                keep = imp_serve_one(pfds[i].fd, rootfd, log);
            }

            if (!keep) {
                close(pfds[i].fd);
                pfds[i] = pfds[nfds - 1];   /* swap-remove */
                nfds--;
            } else {
                i++;
            }
        }
    }
}
