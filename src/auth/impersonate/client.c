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
#include "client_internal.h"

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
brix_imp_client_connect(const char *path, ngx_log_t *log)
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
brix_imp_client_active(void)
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
brix_imp_enabled(void)
{
    return imp_enabled;
}

void
brix_imp_mark_in_request(int on)
{
    imp_in_request = on ? 1 : 0;
}

void
brix_imp_set_principal(const char *principal)
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
brix_imp_clear_principal(void)
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
void
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
int
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

