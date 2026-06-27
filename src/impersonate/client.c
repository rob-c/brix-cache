/*
 * client.c — the unprivileged worker side of the impersonation broker (phase 40).
 *
 * WHAT: Worker-resident client for the privileged root broker.  Holds one
 *   persistent AF_UNIX connection per worker, a per-request "current principal",
 *   and the op wrappers (open/stat/mkdir/unlink/rmdir/rename/link/truncate/chmod/
 *   chown) that the confined beneath helpers call when `map` mode is active.  Each
 *   wrapper performs one synchronous request/reply round-trip; OPEN receives the
 *   resulting fd back over SCM_RIGHTS.
 *
 * WHY: The worker is fully unprivileged — it cannot setfsuid or hold any
 *   capability.  Delegating the open/metadata syscalls to the broker is what lets
 *   files be owned by, and DAC be enforced for, the real mapped user while the
 *   worker stays a plain svc-uid process.  The round-trip is synchronous because
 *   these helpers were already blocking syscalls in the worker's view; the data
 *   plane (read/write on the returned fd) never touches the broker.
 *
 * HOW: A tiny state singleton (one connection fd + the remembered socket path +
 *   the current principal).  write_full sends a fixed imp_req_t; recv_reply reads
 *   the fixed imp_rep_t and, for OPEN, the SCM_RIGHTS fd.  A broken connection
 *   (broker respawn) is reconnected once and the op retried; a second failure
 *   fails closed (errno=EIO).  No goto; pure helpers, side effects at the edges.
 */

#include "impersonate.h"
#include "impersonate_proto.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>


static int       imp_enabled;                       /* map mode configured */
static int       imp_conn_fd = -1;                  /* -1 = not connected */
static char      imp_sock_path[108];                /* sun_path bound */
static ngx_log_t *imp_log;                          /* may be NULL */
static char      imp_principal[IMP_PRINC_MAX];      /* "" = none set */
static int       imp_in_request;                    /* inside a per-request bracket */


/* Open a fresh connected socket to imp_sock_path.  Returns fd or -1 (errno). */
static int
imp_dial(void)
{
    struct sockaddr_un addr;
    int                fd;
    size_t             plen = ngx_strlen(imp_sock_path);

    if (plen == 0 || plen >= sizeof(addr.sun_path)) {
        errno = EINVAL;
        return -1;
    }
    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        return -1;
    }
    ngx_memzero(&addr, sizeof(addr));
    addr.sun_family = AF_UNIX;
    ngx_memcpy(addr.sun_path, imp_sock_path, plen + 1);
    if (connect(fd, (struct sockaddr *) &addr, sizeof(addr)) != 0) {
        int e = errno;
        close(fd);
        errno = e;
        return -1;
    }
    return fd;
}

/* Ensure a live connection; (re)dial if needed.  Returns the fd or -1. */
static int
imp_ensure_conn(void)
{
    if (imp_conn_fd >= 0) {
        return imp_conn_fd;
    }
    imp_conn_fd = imp_dial();
    return imp_conn_fd;
}

/* Drop the current connection (after an IO error) so the next op re-dials. */
static void
imp_drop_conn(void)
{
    if (imp_conn_fd >= 0) {
        close(imp_conn_fd);
        imp_conn_fd = -1;
    }
}

ngx_int_t
xrootd_imp_client_connect(const char *path, ngx_log_t *log)
{
    size_t plen;

    if (path == NULL) {
        return NGX_ERROR;
    }
    plen = ngx_strlen(path);
    if (plen == 0 || plen >= sizeof(imp_sock_path)) {
        return NGX_ERROR;
    }
    ngx_memcpy(imp_sock_path, path, plen + 1);
    imp_log     = log;
    imp_enabled = 1;

    imp_drop_conn();
    if (imp_ensure_conn() < 0) {
        if (log) ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                               "impersonate client: connect to broker \"%s\" failed",
                               path);
        return NGX_ERROR;
    }
    return NGX_OK;
}

int
xrootd_imp_client_active(void)
{
    /*
     * Route the confined FS op to the broker when map mode is active AND we are
     * either (a) inside a request that resolved to a real principal, or (b)
     * inside a request whose authenticated identity yielded NO mappable principal
     * (empty subject / no DN) — case (b) still goes to the broker, which denies
     * the empty principal (idmap can't map "") so the op FAILS CLOSED instead of
     * silently falling back to the unprivileged WORKER (which owns the export and
     * can read svc-only files — a real fail-open).  Outside any request bracket
     * (housekeeping: checkpoint recovery, FRM) there is no principal AND no active
     * request, so we run locally as the worker, as intended.
     */
    return imp_enabled && (imp_principal[0] != '\0' || imp_in_request);
}

int
xrootd_imp_enabled(void)
{
    return imp_enabled;
}

void
xrootd_imp_mark_in_request(int on)
{
    imp_in_request = on ? 1 : 0;
}

void
xrootd_imp_set_principal(const char *principal)
{
    size_t n;

    if (principal == NULL || principal[0] == '\0') {
        imp_principal[0] = '\0';
        return;
    }
    n = ngx_strlen(principal);
    if (n >= sizeof(imp_principal)) {
        n = sizeof(imp_principal) - 1;
    }
    ngx_memcpy(imp_principal, principal, n);
    imp_principal[n] = '\0';
}

void
xrootd_imp_clear_principal(void)
{
    imp_principal[0] = '\0';
}


/* Write exactly n bytes.  Returns 0 ok, -1 error. */
static int
imp_write_full(int fd, const void *buf, size_t n)
{
    const u_char *p = buf;
    size_t        sent = 0;

    while (sent < n) {
        ssize_t w = write(fd, p + sent, n - sent);
        if (w < 0) {
            if (errno == EINTR) { continue; }
            return -1;
        }
        sent += (size_t) w;
    }
    return 0;
}

/*
 * Receive one imp_rep_t and, when present, the SCM_RIGHTS fd (IMP_REP_HAS_FD) and
 * the trailing data payload (IMP_REP_HAS_DATA, READLINK target) into data_buf.
 * Returns 0 on success (*out_fd is the received fd or -1), -1 on IO error.
 */
static int
imp_recv_reply(int fd, imp_rep_t *rep, int *out_fd, char *data_buf,
               size_t data_bufsz)
{
    struct msghdr   msg;
    struct iovec    iov[2];
    union {
        struct cmsghdr align;
        char           buf[CMSG_SPACE(sizeof(int))];
    } cmsgbuf;
    struct cmsghdr *c;
    ssize_t         n;

    *out_fd = -1;

    ngx_memzero(&msg, sizeof(msg));
    ngx_memzero(&cmsgbuf, sizeof(cmsgbuf));
    iov[0].iov_base = rep;
    iov[0].iov_len  = sizeof(*rep);
    msg.msg_iov     = iov;
    msg.msg_iovlen  = 1;
    /* A second iovec receives any trailing payload (READLINK target / GETXATTR
     * value / LISTXATTR names) IN THE SAME message.  data_buf must be large enough
     * for the op's reply payload: a READLINK target is bounded by PATH_MAX, while
     * GET/LISTXATTR replies are bounded by IMP_XATTR_MAX (imp_get_or_list sizes its
     * buffer accordingly).  recvmsg never writes past iov_len, and the data_len
     * cross-check below fails closed on any mismatch, so an over-long reply is
     * rejected rather than overflowing or desyncing. */
    if (data_buf != NULL && data_bufsz > 0) {
        iov[1].iov_base = data_buf;
        iov[1].iov_len  = data_bufsz;
        msg.msg_iovlen  = 2;
    }
    msg.msg_control    = cmsgbuf.buf;
    msg.msg_controllen = sizeof(cmsgbuf.buf);

    do {
        n = recvmsg(fd, &msg, MSG_CMSG_CLOEXEC);
    } while (n < 0 && errno == EINTR);

    if (n < (ssize_t) sizeof(*rep)) {
        return -1;                       /* short read / EOF / error */
    }
    /* A reply that declares trailing data we gave nowhere to receive (no iov[1])
     * cannot be consumed without desyncing — reject explicitly and fail closed. */
    if (rep->data_len > 0 && (data_buf == NULL || data_bufsz == 0)) {
        return -1;
    }
    /* The frame declares its trailing length; if what we received does not match,
     * the stream is desynced — fail so the caller drops + reconnects. */
    if ((size_t) (n - (ssize_t) sizeof(*rep)) != (size_t) rep->data_len) {
        return -1;
    }

    for (c = CMSG_FIRSTHDR(&msg); c != NULL; c = CMSG_NXTHDR(&msg, c)) {
        if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS
            && c->cmsg_len == CMSG_LEN(sizeof(int)))
        {
            ngx_memcpy(out_fd, CMSG_DATA(c), sizeof(int));
        }
    }
    return 0;
}


/* Build a request frame for the current principal. */
static void
imp_build_req(imp_req_t *req, uint32_t op, const char *path, const char *path2,
              uint32_t flags, uint32_t mode, int64_t length)
{
    ngx_memzero(req, sizeof(*req));
    req->version    = IMP_PROTO_VERSION;
    req->op         = op;
    req->open_flags = flags;
    req->mode       = mode;
    req->length     = length;

    ngx_cpystrn((u_char *) req->principal, (u_char *) imp_principal, IMP_PRINC_MAX);
    if (path) {
        ngx_cpystrn((u_char *) req->path, (u_char *) path, IMP_PATH_MAX);
    }
    if (path2) {
        ngx_cpystrn((u_char *) req->path2, (u_char *) path2, IMP_PATH_MAX);
    }
}

/* Translate a positive IMP_STATUS_* into the conventional errno for callers. */
static int
imp_status_errno(int status)
{
    switch (status) {
    case IMP_STATUS_DENY:        return EACCES;
    case IMP_STATUS_BADREQ:      return EINVAL;
    case IMP_STATUS_INTERNAL:    return EIO;
    case IMP_STATUS_PRIV_REFUSED: return EPERM;  /* reserved-id refused at broker */
    default:                     return EIO;
    }
}

/*
 * One request/reply exchange with transparent single reconnect.  On success
 * returns 0 and fills *rep / *out_fd; on a transport failure returns -1
 * (errno=EIO).  The op is retried exactly once across a dropped connection
 * (broker respawn), never more — a persistently dead broker fails closed.
 *
 * `data_in` (length `data_in_len`) is an optional inbound payload written
 * immediately after the fixed frame (SETXATTR value); the broker reads exactly
 * req->req_data_len trailing bytes.  `data_buf`/`data_bufsz` receive an optional
 * outbound reply payload (READLINK/GETXATTR/LISTXATTR).  A retry re-sends the
 * whole [frame][data_in] on a fresh connection, so a half-written payload on a
 * dying connection never desyncs the broker.
 */
static int
imp_exchange(const imp_req_t *req, imp_rep_t *rep, int *out_fd,
             char *data_buf, size_t data_bufsz,
             const void *data_in, size_t data_in_len)
{
    int attempt;

    for (attempt = 0; attempt < 2; attempt++) {
        int fd = imp_ensure_conn();
        if (fd < 0) {
            continue;                    /* could not dial; retry once */
        }
        if (imp_write_full(fd, req, sizeof(*req)) != 0
            || (data_in_len > 0
                && imp_write_full(fd, data_in, data_in_len) != 0)
            || imp_recv_reply(fd, rep, out_fd, data_buf, data_bufsz) != 0)
        {
            imp_drop_conn();             /* transport broke — reconnect & retry */
            continue;
        }
        return 0;
    }

    if (imp_log) {
        ngx_log_error(NGX_LOG_ERR, imp_log, 0,
                      "impersonate client: broker unreachable (op=%ud)", req->op);
    }
    errno = EIO;
    return -1;
}

/*
 * Run an op that returns 0/-1 (no fd).  Maps the broker reply to errno: 0 ->
 * success; status < 0 -> -status (the impersonated syscall's errno); status > 0
 * -> the IMP_STATUS_* errno.  Returns 0 or -1.
 */
static int
imp_call_status(uint32_t op, const char *path, const char *path2,
                uint32_t mode, int64_t length)
{
    imp_req_t req;
    imp_rep_t rep;
    int       fd = -1;

    imp_build_req(&req, op, path, path2, 0, mode, length);
    if (imp_exchange(&req, &rep, &fd, NULL, 0, NULL, 0) != 0) {
        return -1;                       /* errno=EIO set by imp_exchange */
    }
    if (fd >= 0) {
        close(fd);                       /* a non-OPEN op should never send an fd */
    }
    if (rep.status == 0) {
        return 0;
    }
    errno = (rep.status < 0) ? -rep.status : imp_status_errno(rep.status);
    return -1;
}


int
xrootd_imp_open(const char *reqpath, int flags, mode_t mode)
{
    imp_req_t req;
    imp_rep_t rep;
    int       fd = -1;

    imp_build_req(&req, IMP_OP_OPEN, reqpath, NULL,
                  (uint32_t) flags, (uint32_t) mode, 0);
    if (imp_exchange(&req, &rep, &fd, NULL, 0, NULL, 0) != 0) {
        return -1;
    }
    if (rep.status == 0 && (rep.rep_flags & IMP_REP_HAS_FD) && fd >= 0) {
        return fd;                       /* caller owns the fd */
    }
    if (fd >= 0) {
        close(fd);                       /* unexpected fd on a failed open */
    }
    errno = (rep.status < 0) ? -rep.status
                             : imp_status_errno(rep.status ? rep.status
                                                           : IMP_STATUS_INTERNAL);
    return -1;
}

/* Fill a caller struct stat from the portable imp_stat_t. */
static void
imp_unpack_stat(struct stat *st, const imp_stat_t *s)
{
    ngx_memzero(st, sizeof(*st));
    st->st_ino     = (ino_t)     s->ino;
    st->st_dev     = (dev_t)     s->dev;
    st->st_size    = (off_t)     s->size;
    st->st_blocks  = (blkcnt_t)  s->blocks;
    st->st_mtime   = (time_t)    s->mtime;
    st->st_ctime   = (time_t)    s->ctime;
    st->st_atime   = (time_t)    s->atime;
    st->st_mode    = (mode_t)    s->mode;
    st->st_uid     = (uid_t)     s->uid;
    st->st_gid     = (gid_t)     s->gid;
    st->st_nlink   = (nlink_t)   s->nlink;
    st->st_blksize = (blksize_t) s->blksize;
}

int
xrootd_imp_stat(const char *reqpath, struct stat *st, int nofollow)
{
    imp_req_t req;
    imp_rep_t rep;
    int       fd = -1;

    imp_build_req(&req, nofollow ? IMP_OP_LSTAT : IMP_OP_STAT,
                  reqpath, NULL, 0, 0, 0);
    if (imp_exchange(&req, &rep, &fd, NULL, 0, NULL, 0) != 0) {
        return -1;
    }
    if (fd >= 0) {
        close(fd);
    }
    if (rep.status == 0 && (rep.rep_flags & IMP_REP_HAS_STAT)) {
        imp_unpack_stat(st, &rep.st);
        return 0;
    }
    errno = (rep.status < 0) ? -rep.status
                             : imp_status_errno(rep.status ? rep.status
                                                           : IMP_STATUS_INTERNAL);
    return -1;
}

int
xrootd_imp_mkdir(const char *reqpath, mode_t mode)
{
    return imp_call_status(IMP_OP_MKDIR, reqpath, NULL, (uint32_t) mode, 0);
}

int
xrootd_imp_unlink(const char *reqpath, int is_dir)
{
    return imp_call_status(is_dir ? IMP_OP_RMDIR : IMP_OP_UNLINK,
                           reqpath, NULL, 0, 0);
}

int
xrootd_imp_rmdir(const char *reqpath)
{
    return imp_call_status(IMP_OP_RMDIR, reqpath, NULL, 0, 0);
}

int
xrootd_imp_rename(const char *src, const char *dst)
{
    return imp_call_status(IMP_OP_RENAME, src, dst, 0, 0);
}

int
xrootd_imp_rename_noreplace(const char *src, const char *dst)
{
    return imp_call_status(IMP_OP_RENAME_NOREPLACE, src, dst, 0, 0);
}

int
xrootd_imp_link(const char *src, const char *dst)
{
    return imp_call_status(IMP_OP_LINK, src, dst, 0, 0);
}

int
xrootd_imp_truncate(const char *reqpath, off_t length)
{
    return imp_call_status(IMP_OP_TRUNCATE, reqpath, NULL, 0, (int64_t) length);
}

int
xrootd_imp_chmod(const char *reqpath, mode_t mode)
{
    return imp_call_status(IMP_OP_CHMOD, reqpath, NULL, (uint32_t) mode, 0);
}

int
xrootd_imp_chown_gid(const char *reqpath, gid_t gid)
{
    /* CHOWN carries the gid in the mode field (uid is fixed by ownership). */
    return imp_call_status(IMP_OP_CHOWN, reqpath, NULL, (uint32_t) gid, 0);
}

int
xrootd_imp_setattr(const char *reqpath, int set_times,
                   const struct timespec times[2],
                   int set_owner, uid_t uid, gid_t gid)
{
    imp_req_t req;
    imp_rep_t rep;
    int       fd = -1;

    imp_build_req(&req, IMP_OP_SETATTR, reqpath, NULL, 0, 0, 0);
    req.attr_flags = (uint32_t) ((set_times ? IMP_ATTR_TIMES : 0)
                                 | (set_owner ? IMP_ATTR_OWNER : 0));
    if (set_times && times != NULL) {
        req.atime_sec  = (int64_t) times[0].tv_sec;
        req.atime_nsec = (int64_t) times[0].tv_nsec;
        req.mtime_sec  = (int64_t) times[1].tv_sec;
        req.mtime_nsec = (int64_t) times[1].tv_nsec;
    }
    req.set_uid = (uid == (uid_t) -1) ? (uint32_t) -1 : (uint32_t) uid;
    req.set_gid = (gid == (gid_t) -1) ? (uint32_t) -1 : (uint32_t) gid;

    if (imp_exchange(&req, &rep, &fd, NULL, 0, NULL, 0) != 0) {
        return -1;
    }
    if (fd >= 0) { close(fd); }
    if (rep.status == 0) {
        return 0;
    }
    errno = (rep.status < 0) ? -rep.status : imp_status_errno(rep.status);
    return -1;
}

int
xrootd_imp_symlink(const char *target, const char *linkpath)
{
    /* path = link location (root-relative), path2 = verbatim target string. */
    return imp_call_status(IMP_OP_SYMLINK, linkpath, target, 0, 0);
}

ssize_t
xrootd_imp_readlink(const char *reqpath, char *buf, size_t bufsz)
{
    imp_req_t req;
    imp_rep_t rep;
    int       fd = -1;
    char      linkbuf[IMP_PATH_MAX];
    size_t    n;

    imp_build_req(&req, IMP_OP_READLINK, reqpath, NULL, 0, 0, 0);
    if (imp_exchange(&req, &rep, &fd, linkbuf, sizeof(linkbuf), NULL, 0) != 0) {
        return -1;
    }
    if (fd >= 0) { close(fd); }
    if (rep.status == 0 && (rep.rep_flags & IMP_REP_HAS_DATA)) {
        n = rep.data_len;
        if (n > bufsz) { n = bufsz; }    /* truncate to caller's buffer (readlink) */
        ngx_memcpy(buf, linkbuf, n);
        return (ssize_t) n;              /* readlinkat returns the byte count */
    }
    errno = (rep.status < 0) ? -rep.status
                             : imp_status_errno(rep.status ? rep.status
                                                           : IMP_STATUS_INTERNAL);
    return -1;
}

/*
 * imp_get_or_list — shared body for getxattr/listxattr (both return a
 * variable-length payload via the reply-side trailing data).  The broker fills
 * its own IMP_XATTR_MAX buffer; we receive it into a process-private buffer and
 * then honour the POSIX f*xattr contract against the caller's buffer: bufsz==0
 * is a size probe (return the length, copy nothing); bufsz < length is ERANGE;
 * otherwise copy and return the length.  `xbuf` is static — the worker event
 * loop is single-threaded and the broker round-trip is fully synchronous, so the
 * call never overlaps itself; this keeps a 64 KiB buffer off the request stack.
 */
static ssize_t
imp_get_or_list(uint32_t op, const char *reqpath, const char *name,
                void *buf, size_t bufsz)
{
    static char xbuf[IMP_XATTR_MAX];
    imp_req_t   req;
    imp_rep_t   rep;
    int         fd = -1;
    size_t      n;

    imp_build_req(&req, op, reqpath, name, 0, 0, 0);
    if (imp_exchange(&req, &rep, &fd, xbuf, sizeof(xbuf), NULL, 0) != 0) {
        return -1;
    }
    if (fd >= 0) { close(fd); }
    if (rep.status != 0) {
        errno = (rep.status < 0) ? -rep.status : imp_status_errno(rep.status);
        return -1;
    }
    n = (rep.rep_flags & IMP_REP_HAS_DATA) ? rep.data_len : 0;
    if (bufsz == 0) {
        return (ssize_t) n;              /* size probe */
    }
    if (n > bufsz) {
        errno = ERANGE;
        return -1;
    }
    ngx_memcpy(buf, xbuf, n);
    return (ssize_t) n;
}

ssize_t
xrootd_imp_getxattr(const char *reqpath, const char *name,
                    void *buf, size_t bufsz)
{
    return imp_get_or_list(IMP_OP_GETXATTR, reqpath, name, buf, bufsz);
}

ssize_t
xrootd_imp_listxattr(const char *reqpath, void *buf, size_t bufsz)
{
    return imp_get_or_list(IMP_OP_LISTXATTR, reqpath, NULL, buf, bufsz);
}

int
xrootd_imp_setxattr(const char *reqpath, const char *name,
                    const void *value, size_t len, int flags)
{
    imp_req_t req;
    imp_rep_t rep;
    int       fd = -1;

    if (len > IMP_XATTR_MAX) {
        errno = E2BIG;                   /* broker bounds the inbound payload */
        return -1;
    }
    /* xattr flags (XATTR_CREATE/XATTR_REPLACE/0) ride in the mode field. */
    imp_build_req(&req, IMP_OP_SETXATTR, reqpath, name, 0, (uint32_t) flags, 0);
    req.req_data_len = (uint32_t) len;
    if (imp_exchange(&req, &rep, &fd, NULL, 0, value, len) != 0) {
        return -1;
    }
    if (fd >= 0) { close(fd); }
    if (rep.status == 0) {
        return 0;
    }
    errno = (rep.status < 0) ? -rep.status : imp_status_errno(rep.status);
    return -1;
}

int
xrootd_imp_removexattr(const char *reqpath, const char *name)
{
    imp_req_t req;
    imp_rep_t rep;
    int       fd = -1;

    imp_build_req(&req, IMP_OP_REMOVEXATTR, reqpath, name, 0, 0, 0);
    if (imp_exchange(&req, &rep, &fd, NULL, 0, NULL, 0) != 0) {
        return -1;
    }
    if (fd >= 0) { close(fd); }
    if (rep.status == 0) {
        return 0;
    }
    errno = (rep.status < 0) ? -rep.status : imp_status_errno(rep.status);
    return -1;
}
