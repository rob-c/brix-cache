#include "tpc_internal.h"
#include "fs/vfs/vfs.h"   /* brix_vfs_open_fd_at (handle-table confined open) */
#include "core/compat/host_format.h"  /* brix_format_host_port — IPv6 bracketing */
#include "observability/sesslog/sesslog_ngx.h"
/* File: launch.c — TPC pull entry point and destination-side preparation for native root:// third-party copy
 * WHAT: Six functions implement the TPC pull launch pipeline on the event thread. tpc_send_open_response builds kXR_ok open response body (fhandle + optional statbuf) → brix_queue_response; tpc_build_origin_id constructs origin ID string from ctx->login.user+ngx_pid+getnameinfo host via snprintf+cpystrn; tpc_destination_open_flags derives O_CREAT/O_EXCL/O_TRUNC flags from options bitmask for POSIX open; brix_tpc_prepare_pull validates thread_pool + TPC source host/path → checks src policy (allow_local/allow_private) → alloc fhandle idx → brix_open_confined(canonical path) → set file metadata (writable=1, tpc_destination=1) → generate+register key if empty → store token_mode → send open response; brix_tpc_start_pull validates fhandle_idx + tpc_destination flag → alloc ngx_thread_task → populate brix_tpc_pull_t struct from file fields → set handler=brix_tpc_pull_thread, event.handler=brix_tpc_pull_done → post to thread pool; brix_tpc_launch_pull is wrapper for prepare_pull. Non-NGX_THREADS stubs return kXR_ServerError "TPC pull requires NGX_THREADS support". Caller: dispatch.c (kXR_open TPC opaque param path).
 *
 * WHY: The destination server needs to create the local file handle before connecting to the source — this ensures the write target exists with correct permissions and metadata before the thread-pool worker starts pulling data. The launch pipeline separates preparation (event-thread, synchronous) from execution (thread-pool, blocking I/O), allowing nginx to respond immediately to the client open request while the actual fetch runs asynchronously.
 *
 * HOW: prepare_pull — conf->common.thread_pool == NULL → error; tpc->src_host/path empty → error; brix_tpc_check_src_policy → error if denied; idx = brix_alloc_fhandle(ctx) → fd = brix_open_confined(c->log, &conf->common.root, dst_path, tpc_destination_open_flags(options), create_mode) → fstat(fd, &st) → file[idx] metadata set (writable=1, readable=0, tpc_destination=1, tpc_key generated or echoed from tpc->key, token_mode stored) → send open response with fhandle idx + stat if kXR_retstat. start_pull — fhandle_idx valid + file->tpc_destination true → ngx_thread_task_alloc(sizeof(brix_tpc_pull_t)) → memcpy src_host/path/key/org/token_mode/dst_path from file fields → task->handler=brix_tpc_pull_thread, event.handler=brix_tpc_pull_done → ngx_thread_task_post(thread_pool, task) → file->tpc_started=1, ctx->state=XRD_ST_AIO.
 * */
#include "protocols/root/session/registry.h"

#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include <netdb.h>
#include "core/compat/alloc_guard.h"
#include "core/compat/cstr.h"

static brix_sess_am_t
tpc_sess_auth_method(const brix_tpc_pull_t *t)
{
    if (t == NULL || t->conf == NULL) {
        return BRIX_SESS_AM_ANON;
    }

    if ((t->token_mode[0] != '\0' && ngx_strcmp(t->token_mode, "none") != 0)
        || t->conf->tpc_outbound_bearer_file.len > 0)
    {
        return BRIX_SESS_AM_TOKEN;
    }

    if (t->deleg_cred_len > 0
        || (t->conf->certificate.len > 0 && t->conf->certificate_key.len > 0))
    {
        return BRIX_SESS_AM_GSI;
    }

    return BRIX_SESS_AM_ANON;
}

static const char *
tpc_sess_identity_user(const brix_tpc_pull_t *t)
{
    const char *subject;

    if (t == NULL || t->ctx == NULL || t->ctx->identity == NULL) {
        return "-";
    }

    subject = brix_identity_subject_cstr(t->ctx->identity);
    if (subject != NULL && subject[0] != '\0') {
        return subject;
    }

    subject = brix_identity_dn_cstr(t->ctx->identity);
    return subject != NULL && subject[0] != '\0' ? subject : "-";
}

static const char *
tpc_sess_identity_vo(const brix_tpc_pull_t *t)
{
    const char *vo;

    if (t == NULL || t->ctx == NULL || t->ctx->identity == NULL) {
        return "-";
    }

    vo = brix_identity_vo_csv_cstr(t->ctx->identity);
    return vo != NULL && vo[0] != '\0' ? vo : "-";
}

static void
tpc_sess_begin_pull(brix_tpc_pull_t *t)
{
    char          peer[320];
    uint16_t      sport;
    brix_sess_am_t method;

    if (t == NULL || t->sess != NULL || t->conf == NULL) {
        return;
    }

    sport = t->src_port ? t->src_port : 1094;
    brix_format_host_port(t->src_host, sport, peer, sizeof(peer));
    method = tpc_sess_auth_method(t);
    t->sess = brix_sess_begin(t->conf->session_log, t->conf->access_log_fd,
                              BRIX_SESS_PROTO_TPC, BRIX_SESS_DIR_OUT,
                              peer, ngx_strlen(peer), method,
                              t->ctx != NULL ? t->ctx->sess : NULL);
    brix_sess_auth_once(t->sess, method, tpc_sess_identity_user(t),
                        tpc_sess_identity_vo(t));
    brix_sess_attempt(t->sess, t->src_path, BRIX_SESS_MODE_READ);
    brix_sess_xfer_start(t->sess, &t->sess_xfer, t->src_path,
                         BRIX_SESS_MODE_READ, -1);
}

static void
tpc_sess_abort_pull(brix_tpc_pull_t *t, const char *err)
{
    if (t == NULL) {
        return;
    }

    brix_sess_result(t->sess, 0, t->src_path, BRIX_SESS_MODE_READ, err);
    brix_sess_xfer_end(t->sess, &t->sess_xfer, BRIX_SESS_XFER_ABORTED);
    brix_sess_end(t->sess, BRIX_SESS_END_ERROR);
    t->sess = NULL;
}

/* WHAT: Build kXR_ok open response body (fhandle + optional statbuf from fstat) → brix_build_resp_hdr → brix_queue_response. Returns NGX_OK or NGX_ERROR on alloc failure. Caller: brix_tpc_prepare_pull (end of pull prep pipeline). */
static ngx_int_t
tpc_send_open_response(brix_ctx_t *ctx, ngx_connection_t *c, int idx,
    int fd, uint16_t options)
{
    ServerOpenBody  body;
    struct stat     st;
    char            statbuf[256];
    size_t          bodylen;
    size_t          total;
    u_char         *buf;
    ngx_flag_t      want_stat;

    want_stat = (options & kXR_retstat) ? 1 : 0;
    statbuf[0] = '\0';
    bodylen = sizeof(ServerOpenBody);

    if (want_stat && fstat(fd, &st) == 0) {
        int stat_flags = 0;

        if (st.st_mode & (S_IRUSR | S_IRGRP | S_IROTH)) {
            stat_flags |= kXR_readable;
        }
        if (st.st_mode & (S_IWUSR | S_IWGRP | S_IWOTH)) {
            stat_flags |= kXR_writable;
        }

        snprintf(statbuf, sizeof(statbuf), "%llu %lld %d %ld",
                 (unsigned long long) st.st_ino,
                 (long long) st.st_size,
                 stat_flags,
                 (long) st.st_mtime);
        bodylen += strlen(statbuf) + 1;
    }

    total = XRD_RESPONSE_HDR_LEN + bodylen;
    BRIX_PALLOC_OR_RETURN(buf, c->pool, total, NGX_ERROR);

    brix_build_resp_hdr(ctx->recv.cur_streamid, kXR_ok, (uint32_t) bodylen,
                          (ServerResponseHdr *) buf);

    ngx_memzero(&body, sizeof(body));
    body.fhandle[0] = (u_char) idx;
    ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN, &body, sizeof(body));

    if (statbuf[0] != '\0') {
        ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN + sizeof(ServerOpenBody),
                   statbuf, strlen(statbuf) + 1);
    }

    return brix_queue_response(ctx, c, buf, total);
}

/* WHAT: Construct origin ID string from ctx->login.user+ngx_pid+getnameinfo host via snprintf("%s.%u@host") — falls back to "xrd" for empty user, ngx_pid for zero pid, addr_text.len then "unknown" for unresolved host. Caller: brix_tpc_prepare_pull (origin ID storage step). */

static void
tpc_build_origin_id(brix_ctx_t *ctx, ngx_connection_t *c, char *dst,
    size_t dst_size)
{
    char        host[NI_MAXHOST];
    const char *user;
    uint32_t    pid;

    user = ctx->login.user[0] != '\0' ? ctx->login.user : "xrd";
    pid = ctx->login.pid != 0 ? ctx->login.pid : (uint32_t) ngx_pid;

    host[0] = '\0';
    if (c->sockaddr != NULL
        && getnameinfo(c->sockaddr, c->socklen, host, sizeof(host),
                       NULL, 0, NI_NAMEREQD) != 0) {
        host[0] = '\0';
    }

    if (host[0] == '\0' && c->addr_text.len > 0) {
        size_t host_len = c->addr_text.len;

        if (host_len >= sizeof(host)) {
            host_len = sizeof(host) - 1;
        }
        ngx_memcpy(host, c->addr_text.data, host_len);
        host[host_len] = '\0';
    }

    if (host[0] == '\0') {
        ngx_cpystrn((u_char *) host, (u_char *) "unknown", sizeof(host));
    }

    {
        int prefix_len;

        prefix_len = snprintf(dst, dst_size, "%s.%u@", user, (unsigned) pid);
        if (prefix_len < 0 || (size_t) prefix_len >= dst_size) {
            dst[0] = '\0';
            return;
        }

        ngx_cpystrn((u_char *) dst + prefix_len, (u_char *) host,
                    dst_size - (size_t) prefix_len);
    }
}

/* WHAT: Translate the kXR_open options bitmask into POSIX open(2) flags for the
 * TPC destination file.
 * WHY: The wire-level create semantics differ from POSIX, so the mapping is
 * explicit: kXR_new alone => create, fail if it already exists (O_EXCL);
 * kXR_new + kXR_delete or kXR_delete alone => create-or-truncate; neither flag
 * (the common "just receive the copy") => create-or-truncate as well. The
 * O_EXCL is deliberately dropped whenever kXR_delete is present, since delete
 * means "overwrite is intended". Always O_RDWR (we read back for stat) and
 * O_NOCTTY (never acquire a controlling terminal). */
static int
tpc_destination_open_flags(uint16_t options)
{
    int oflags;

    oflags = O_RDWR | O_NOCTTY;
    if (options & kXR_new) {
        oflags |= O_CREAT;
        if (!(options & kXR_delete)) {
            oflags |= O_EXCL;     /* create-new only: refuse existing target */
        }
    }
    if (options & kXR_delete) {
        oflags |= O_CREAT | O_TRUNC;   /* overwrite intended */
    }
    if (!(options & (kXR_new | kXR_delete))) {
        oflags |= O_CREAT | O_TRUNC;   /* default: create or replace */
    }

    return oflags;
}

/* WHAT: Register this pull in the shared TPC transfer registry and return its
 * transfer id (0 on failure / registry full).
 * WHY: Active transfers are tracked centrally for the dashboard, metrics, and
 * progress reporting; the id is stored on the file handle and later used by the
 * worker/done callback to update state. Reconstructs a canonical source URL
 * from the handle's stored host/port/path for display.
 * HOW: default port to 1094 if unset, format "root://host:port/path" into a
 * stack buffer, fill an brix_tpc_transfer_t (PROTO_STREAM/DIR_PULL/PENDING),
 * and hand it to brix_tpc_registry_add. */
static uint64_t
tpc_register_stream_transfer(ngx_connection_t *c, brix_file_t *file)
{
    brix_tpc_transfer_t transfer;
    ngx_str_t             src_url;
    ngx_str_t             dst_path;
    u_char                src_buf[PATH_MAX + 320];
    u_char               *last;
    uint16_t              sport;

    if (file == NULL || file->path == NULL) {
        return 0;
    }

    /* Reconstruct the transfer URL.  Bracket an IPv6 literal source host —
     * tpc_src_host is stored bare (parse.c strips the brackets off "[::1]"), so
     * "root://[::1]:1094/path" must be re-bracketed here or the URL is
     * unparseable.  No NUL is written; src_url.len is the returned end pointer. */
    sport = file->tpc_src_port ? file->tpc_src_port : 1094;
    {
        char hostport[288];
        brix_format_host_port(file->tpc_src_host, sport,
                                hostport, sizeof(hostport));
        last = ngx_snprintf(src_buf, sizeof(src_buf), "root://%s%s",
                            hostport, file->tpc_src_path);
    }

    src_url.data = src_buf;
    src_url.len = (size_t) (last - src_buf);
    dst_path.data = (u_char *) file->path;
    dst_path.len = ngx_strlen(file->path);

    ngx_memzero(&transfer, sizeof(transfer));
    transfer.protocol = BRIX_TPC_PROTO_STREAM;
    transfer.direction = BRIX_TPC_DIR_PULL;
    transfer.src_url = src_url;
    transfer.dst_path = dst_path;
    transfer.state = BRIX_TPC_STATE_PENDING;

    return brix_tpc_registry_add(&transfer, c->log);
}

/* WHAT: Validate the pull preconditions before any state is allocated — a
 * configured thread pool, a non-empty TPC source host+path, and an SSRF-safe
 * source address per the loopback/private allow flags. Sends the matching kXR
 * error (and logs it) and returns non-NGX_OK on the first failure; returns
 * NGX_OK when the request may proceed to fhandle allocation.
 * WHY: prepare_pull's guard ladder is the security-load-bearing front door
 * (SSRF gate included); isolating it keeps the orchestrator a flat sequence and
 * the checks independently reviewable. Behaviour (order, codes, log strings) is
 * unchanged.
 * HOW: thread_pool NULL → kXR_ServerError; empty src host/path → kXR_ArgInvalid;
 * brix_tpc_check_src_policy != 0 → kXR_NotAuthorized with its filled err text.
 * Each failure routes through the same BRIX_RETURN_ERR / brix_send_error edges
 * the inline code used. */
static ngx_int_t
tpc_prepare_check_preconditions(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const brix_tpc_params_t *tpc,
    const char *dst_path)
{
    char     policy_err[512];
    uint16_t sport;

    if (conf->common.thread_pool == NULL) {
        brix_log_access(ctx, c, "OPEN", dst_path, "tpc-pull",
                          0, kXR_ServerError, "TPC requires brix_thread_pool",
                          0);
        BRIX_OP_ERR(ctx, BRIX_OP_OPEN_WR);
        return brix_send_error(ctx, c, kXR_ServerError,
                                 "TPC pull requires brix_thread_pool "
                                 "to be configured");
    }

    if (tpc->src_host[0] == '\0' || tpc->src_path[0] == '\0') {
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_OPEN_WR, "OPEN", dst_path,
                          "tpc-pull", kXR_ArgInvalid,
                          "invalid or incomplete TPC source");
    }

    /*
     * Source policy gate (SSRF defence): before we ever connect outbound, the
     * resolved source host/port is checked against the loopback/private-range
     * allow flags. A destination server must not be coercible into pulling from
     * internal addresses unless the operator explicitly permits it.
     */
    sport = tpc->src_port ? tpc->src_port : 1094;
    if (brix_tpc_check_src_policy(tpc->src_host, sport,
            conf->tpc_allow_local, conf->tpc_allow_private,
            policy_err, sizeof(policy_err))
        != 0)
    {
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_OPEN_WR, "OPEN", dst_path,
                          "tpc-pull", kXR_NotAuthorized, policy_err);
    }

    return NGX_OK;
}

/* WHAT: Open the TPC destination file relative to the export root, returning the
 * new fd (or -1 with errno set). Strips the root_canon prefix off the absolute
 * dst_path first so brix_vfs_open_fd_at() receives the LOGICAL export path.
 * WHY: brix_vfs_open_fd_at() resolves relative to conf->rootfd (it strips the
 * leading '/' via brix_beneath_rel), so it must be handed the logical path —
 * passing the absolute root_canon-prefixed path doubles the root prefix and
 * openat2() fails with ENOENT. dst_path itself must stay absolute for
 * authz/logging/fhandle metadata, so the strip is confined here.
 * HOW: if root_canon (len>1) is a prefix of dst_path at a '/' or end boundary,
 * advance past it; open with tpc_destination_open_flags(options) + create_mode. */
static int
tpc_open_dst_logical(ngx_stream_brix_srv_conf_t *conf, const char *dst_path,
    uint16_t options, mode_t create_mode)
{
    const char *dst_logical = dst_path;
    size_t      root_len = ngx_strlen(conf->common.root_canon);

    if (root_len > 1
        && ngx_strncmp(dst_path, conf->common.root_canon, root_len) == 0
        && (dst_path[root_len] == '/' || dst_path[root_len] == '\0'))
    {
        dst_logical = dst_path + root_len;
    }

    return brix_vfs_open_fd_at(conf->rootfd, dst_logical,
                               tpc_destination_open_flags(options),
                               create_mode);
}

/* WHAT: Populate a freshly-allocated ctx->files[] slot as a TPC destination:
 * base file metadata from the fstat result, the TPC destination flags, the
 * rendezvous key (echoed from tpc->key or freshly minted), the origin id, the
 * stored source host/path, and the token_mode.
 * WHY: prepare_pull's per-field initialisation is a long, purely-local block; a
 * dedicated helper keeps the orchestrator flat while the field assignment order
 * and values (and therefore behaviour) stay byte-for-byte identical.
 * HOW: set rw/cache/size/time scalars → tpc_destination=1 → echo-or-generate
 * tpc_key → tpc_build_origin_id → cpystrn src_host/src_path → store token_mode
 * from tpc->token_mode when has_token_mode, else the opportunistic
 * "passthrough-opt" when conf->tpc_outbound_passthrough is enabled (default on),
 * else empty. The caller sets
 * file->fd before calling. Pure side-effect on *file (no I/O beyond the
 * origin-id host lookup already isolated in its own helper). */
static void
tpc_init_dst_file(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, brix_file_t *file,
    const brix_tpc_params_t *tpc, const struct stat *st)
{
    file->writable = 1;
    file->readable = 0;
    file->from_cache = 0;
    file->is_regular = S_ISREG(st->st_mode) ? 1 : 0;
    file->device = st->st_dev;
    file->inode = st->st_ino;
    file->cached_size = (off_t) st->st_size;
    file->read_last_end = -1;
    file->read_ahead_end = 0;
    file->bytes_read = 0;
    file->bytes_written = 0;
    file->open_time = ngx_current_msec;
    file->tpc_destination = 1;
    file->tpc_armed = 0;
    file->tpc_started = 0;
    file->tpc_done = 0;
    file->tpc_src_port = tpc->src_port;
    file->tpc_transfer_id = 0;

    /* TPC rendezvous key: echo the client-supplied key if present (the source
     * side already knows it), otherwise mint a fresh random one for this leg. */
    if (tpc->key[0] != '\0') {
        ngx_cpystrn((u_char *) file->tpc_key, (u_char *) tpc->key,
                    sizeof(file->tpc_key));
    } else {
        brix_tpc_generate_key(file->tpc_key, sizeof(file->tpc_key));
    }

    tpc_build_origin_id(ctx, c, file->tpc_org, sizeof(file->tpc_org));
    ngx_cpystrn((u_char *) file->tpc_src_host, (u_char *) tpc->src_host,
                sizeof(file->tpc_src_host));
    ngx_cpystrn((u_char *) file->tpc_src_path, (u_char *) tpc->src_path,
                sizeof(file->tpc_src_path));

    /*
     * Store token_mode for use during pull task execution. There are two distinct
     * passthrough flavours so a default-on flag never creates a new denial:
     *   - An explicit tpc.token_mode= in the client's opaque wins VERBATIM. A
     *     client that explicitly requests "passthrough" gets STRICT/fail-closed
     *     semantics (no inbound token → kXR_AuthFailed).
     *   - Otherwise, when brix_tpc_outbound_passthrough is enabled (default on),
     *     select the OPPORTUNISTIC internal mode "passthrough-opt": the client's
     *     inbound bearer JWT is forwarded when present, but its absence falls back
     *     to GSI proxy delegation / static bearer file / anonymous — never denied.
     *   - Disabled → empty (no token_mode).
     * See tpc_pull_capture_passthrough_token for the actual inbound-token capture.
     */
    if (tpc->has_token_mode && tpc->token_mode[0] != '\0') {
        ngx_cpystrn((u_char *) file->tpc_token_mode,
                    (u_char *) tpc->token_mode, sizeof(file->tpc_token_mode));
    } else if (conf->tpc_outbound_passthrough) {
        ngx_cpystrn((u_char *) file->tpc_token_mode,
                    (u_char *) "passthrough-opt", sizeof(file->tpc_token_mode));
    } else {
        file->tpc_token_mode[0] = '\0';
    }
}

/* WHAT: Derive O_CREAT/O_EXCL/O_TRUNC flags from options bitmask — kXR_new → O_CREAT+O_EXCL, kXR_delete → O_CREAT+O_TRUNC, neither → O_CREAT+O_TRUNC (default create-new). Always includes O_RDWR|O_NOCTTY. Caller: brix_tpc_prepare_pull (open flags step). */
ngx_int_t
brix_tpc_prepare_pull(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const brix_tpc_params_t *tpc,
    const char *dst_path, uint16_t options, uint16_t mode_bits)
{
    brix_file_t *file;
    struct stat    st;
    mode_t         create_mode;
    ngx_int_t      pre;
    int            idx;
    int            fd;

    pre = tpc_prepare_check_preconditions(ctx, c, conf, tpc, dst_path);
    if (pre != NGX_OK) {
        return pre;
    }

    idx = brix_alloc_fhandle(ctx);
    if (idx < 0) {
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_OPEN_WR, "OPEN", dst_path,
                          "tpc-pull", kXR_ServerError, "too many open files");
    }

    create_mode = (mode_bits & 0777) ? (mode_t) (mode_bits & 0777) : 0644;

    fd = tpc_open_dst_logical(conf, dst_path, options, create_mode);
    if (fd < 0) {
        int err = errno;

        BRIX_RETURN_ERR(ctx, c, BRIX_OP_OPEN_WR, "OPEN", dst_path,
                          "tpc-pull", kXR_IOError, strerror(err));
    }

    if (fstat(fd, &st) != 0) {
        int err = errno;

        close(fd);
        BRIX_OP_ERR(ctx, BRIX_OP_OPEN_WR);
        return brix_send_error(ctx, c, kXR_IOError, strerror(err));
    }

    file = &ctx->files[idx];
    file->fd = fd;
    tpc_init_dst_file(ctx, c, conf, file, tpc, &st);

    if (brix_set_fhandle_path(ctx, c, idx, dst_path) != NGX_OK) {
        brix_free_fhandle(ctx, idx);
        return NGX_ERROR;
    }

    if (!ctx->is_bound) {
        brix_session_handle_publish(ctx->login.sessid, idx, file);
    }

    brix_log_access(ctx, c, "OPEN", dst_path, "tpc-pull", 1, 0, NULL, 0);
    BRIX_OP_OK(ctx, BRIX_OP_OPEN_WR);

    return tpc_send_open_response(ctx, c, idx, fd, options);
}

/* WHAT: Copy every field the off-thread worker needs out of the connection and
 * the ctx->files[] slot into the freshly-allocated task context t (by value).
 * WHY: The worker runs on a thread-pool thread and must NOT touch ctx->files or
 * the connection's mutable state, so all source/dest info is snapshotted here on
 * the event loop. The streamid is captured so done.c can re-bind the deferred
 * request on completion. Isolating the copy keeps start_pull's orchestrator flat
 * and the field set (and behaviour) unchanged.
 * HOW: memzero t → set connection/ctx/conf refs, streamid, dst_fd, reply_kind,
 * src_port, transfer_id scalars → cpystrn src_host/src_path/tpc_key/tpc_org/
 * token_mode/dst_path from the file's stored fields. The caller sets
 * t->fhandle_idx (the slot index it already holds) after this returns. */
static void
tpc_populate_pull_task(brix_tpc_pull_t *t, brix_ctx_t *ctx,
    ngx_connection_t *c, ngx_stream_brix_srv_conf_t *conf,
    brix_file_t *file)
{
    ngx_memzero(t, sizeof(*t));
    t->c = c;
    t->ctx = ctx;
    t->conf = conf;
    t->streamid[0] = ctx->recv.cur_streamid[0];
    t->streamid[1] = ctx->recv.cur_streamid[1];
    t->dst_fd = file->fd;
    t->reply_kind = BRIX_TPC_REPLY_SYNC;
    t->src_port = file->tpc_src_port;
    t->transfer_id = file->tpc_transfer_id;

    ngx_cpystrn((u_char *) t->src_host, (u_char *) file->tpc_src_host,
                sizeof(t->src_host));
    ngx_cpystrn((u_char *) t->src_path, (u_char *) file->tpc_src_path,
                sizeof(t->src_path));
    ngx_cpystrn((u_char *) t->tpc_key, (u_char *) file->tpc_key,
                sizeof(t->tpc_key));
    ngx_cpystrn((u_char *) t->tpc_org, (u_char *) file->tpc_org,
                sizeof(t->tpc_org));
    ngx_cpystrn((u_char *) t->token_mode, (u_char *) file->tpc_token_mode,
                sizeof(t->token_mode));
    ngx_cpystrn((u_char *) t->dst_path, (u_char *) file->path,
                sizeof(t->dst_path));
}

/* WHAT: For either passthrough token_mode ("passthrough" strict or
 * "passthrough-opt" opportunistic), snapshot the client's own inbound bearer JWT
 * (ctx->bearer_token, captured at login by the token auth path) into
 * t->delegated_token so the outbound ztn leg forwards it verbatim to the source.
 * WHY (phase-70): passthrough makes the SOURCE authenticate the END USER, not a
 * static service credential. The capture MUST happen here on the event loop — the
 * off-thread worker must never touch ctx — and the token must be snapshotted by
 * value into the task before hand-off. An empty (or over-length) inbound token is
 * left empty: the downstream fetch/dispatch then denies cleanly for the strict
 * "passthrough" mode (kXR_AuthFailed) but opportunistically falls back to
 * GSI/bearer-file/anonymous for the default "passthrough-opt" mode. Capture is
 * identical for both — the divergence lives entirely in tpc_fetch_delegated_token.
 * HOW: only when t->token_mode is "passthrough" or "passthrough-opt"; measure
 * ctx->bearer_token; on a non-empty token that fits (with its NUL) memcpy it into
 * t->delegated_token, else leave t->delegated_token empty. Pure side-effect on *t. */
static void
tpc_pull_capture_passthrough_token(brix_tpc_pull_t *t, brix_ctx_t *ctx)
{
    size_t token_len;

    if (ngx_strcmp(t->token_mode, "passthrough") != 0
        && ngx_strcmp(t->token_mode, "passthrough-opt") != 0) {
        return;
    }

    token_len = ngx_strlen(ctx->bearer_token);
    if (token_len == 0 || token_len >= sizeof(t->delegated_token)) {
        /* No inbound token (or one too large): leave delegated_token empty so
         * have_ztn_cred is false and the pull is denied cleanly. */
        t->delegated_token[0] = '\0';
        return;
    }

    ngx_memcpy(t->delegated_token, ctx->bearer_token, token_len + 1);
}

/* WHAT: Attach outbound source-auth credentials to the pull task — the captured
 * delegated proxy (§F6) when delegation is enabled and a proxy was captured, the
 * passthrough inbound bearer JWT when token_mode is "passthrough" or
 * "passthrough-opt", and the configured token exchange scope.
 * WHY: These auth inputs are conditional and were inline branch blocks in
 * start_pull; grouping them keeps the orchestrator flat. Behaviour is unchanged
 * for GSI/scope: the delegated proxy is malloc'd (thread-owned, freed in
 * thread.c) only when brix_tpc_delegate is set AND a proxy was actually captured
 * during inbound GSI login; the scope is copied only when configured. The
 * passthrough capture (phase-70) snapshots ctx->bearer_token into the task on the
 * event loop so the worker never touches ctx.
 * HOW: on delegate+captured-proxy, malloc + memcpy the PEM and set deleg_cred_len
 * (malloc failure leaves deleg_cred_pem NULL → fall back to the gateway cert);
 * tpc_pull_capture_passthrough_token for the inbound-token snapshot; token_scope
 * defaults to empty then filled from conf->tpc_outbound_scope. */
static void
tpc_pull_attach_creds(brix_tpc_pull_t *t, brix_ctx_t *ctx,
    ngx_stream_brix_srv_conf_t *conf)
{
    /*
     * §F6: if proxy delegation captured the user's proxy during the inbound GSI
     * login, hand the full credential (proxy cert + key + chain) to the pull so it
     * authenticates to the source AS THE USER. malloc (thread-owned, freed in
     * thread.c). Off unless brix_tpc_delegate + a proxy was actually captured.
     */
    if (conf->tpc_delegate && ctx->gsi.deleg_proxy_pem != NULL
        && ctx->gsi.deleg_proxy_len > 0) {
        t->deleg_cred_pem = malloc(ctx->gsi.deleg_proxy_len);
        if (t->deleg_cred_pem != NULL) {
            ngx_memcpy(t->deleg_cred_pem, ctx->gsi.deleg_proxy_pem,
                       ctx->gsi.deleg_proxy_len);
            t->deleg_cred_len = ctx->gsi.deleg_proxy_len;
        }
    }

    tpc_pull_capture_passthrough_token(t, ctx);

    t->token_scope[0] = '\0';
    if (conf->tpc_outbound_scope.len > 0) {
        (void) brix_str_cbuf(t->token_scope, sizeof(t->token_scope),
                             &conf->tpc_outbound_scope);
    }
}

/* WHAT: Resolve the SciTags (experiment, activity) codes for this pull on the
 * event loop and stash them on the task (0/0 when not applicable).
 * WHY (phase-34): identity + path are available here and pmark runtime init is
 * single-threaded, so the resolve must happen on the event loop; the thread
 * (connect.c) only reads the codes and stamps the outbound socket's IPv6 flow
 * label. Fail-open: 0/0 means the outbound socket is not labelled. Extracting it
 * removes the pull's most branch-dense block from the orchestrator unchanged.
 * HOW: default 0/0 → only when pmark.enable && pmark.flowlabel && runtime ensure
 * succeeds, build a flow_id from the identity VO/DN + dst_path and map codes;
 * on success store pmark_exp / pmark_act. */
static void
tpc_pull_resolve_pmark(brix_tpc_pull_t *t, brix_ctx_t *ctx,
    ngx_connection_t *c, ngx_stream_brix_srv_conf_t *conf)
{
    ngx_uint_t e, a;
    brix_pmark_flow_id_t flow_id;

    t->pmark_exp = 0;
    t->pmark_act = 0;

    if (!conf->common.pmark.enable || !conf->common.pmark.flowlabel
        || brix_pmark_runtime_ensure(&conf->common.pmark, ngx_cycle->pool,
                                       c->log) != NGX_OK)
    {
        return;
    }

    ngx_memzero(&flow_id, sizeof(flow_id));
    flow_id.vo_csv = ctx->identity
                   ? brix_identity_vo_csv_cstr(ctx->identity) : "";
    flow_id.user   = ctx->identity
                   ? brix_identity_dn_cstr(ctx->identity) : "";
    flow_id.path   = t->dst_path;
    flow_id.cgi    = NULL;

    if (brix_pmark_map_codes(&conf->common.pmark, &flow_id, &e, &a) == NGX_OK) {
        t->pmark_exp = e;
        t->pmark_act = a;
    }
}

/* WHAT: Allocate ngx_thread_task(sizeof(brix_tpc_pull_t)) → populate struct from file fields (src_host/path/key/org/token_mode/dst_path) → set handler=brix_tpc_pull_thread, event.handler=brix_tpc_pull_done → post to thread pool. Returns NGX_OK or error on alloc/post failure. Caller: dispatch.c (kXR_sync TPC launch path). */
ngx_int_t
brix_tpc_start_pull(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, int fhandle_idx)
{
    ngx_thread_task_t *task;
    brix_tpc_pull_t *t;
    brix_file_t     *file;

    if (fhandle_idx < 0 || fhandle_idx >= BRIX_MAX_FILES) {
        return NGX_ERROR;
    }

    /* The handle must be a live TPC destination opened by prepare_pull. */
    file = &ctx->files[fhandle_idx];
    if (!file->tpc_destination || file->fd < 0) {
        return brix_send_error(ctx, c, kXR_FileNotOpen,
                                 "invalid TPC destination handle");
    }

    /* Idempotent re-trigger: a sync arriving while the worker is already
     * running gets a kXR_wait, not a second thread post. */
    if (file->tpc_started) {
        return brix_send_wait(ctx, c, 1);
    }

    if (file->tpc_transfer_id == 0) {
        file->tpc_transfer_id = tpc_register_stream_transfer(c, file);
        if (file->tpc_transfer_id == 0) {
            BRIX_RETURN_ERR(ctx, c, BRIX_OP_SYNC, "SYNC", file->path,
                              "tpc-pull", kXR_Overloaded,
                              "TPC transfer registry full");
        }
    }

    task = ngx_thread_task_alloc(c->pool, sizeof(brix_tpc_pull_t));
    if (task == NULL) {
        (void) brix_tpc_registry_remove(file->tpc_transfer_id, c->log);
        file->tpc_transfer_id = 0;
        return NGX_ERROR;
    }

    t = task->ctx;
    tpc_populate_pull_task(t, ctx, c, conf, file);
    t->fhandle_idx = fhandle_idx;
    tpc_pull_attach_creds(t, ctx, conf);
    tpc_sess_begin_pull(t);
    tpc_pull_resolve_pmark(t, ctx, c, conf);

    brix_task_bind(task, brix_tpc_pull_thread, brix_tpc_pull_done);

    if (ngx_thread_task_post(conf->common.thread_pool, task) != NGX_OK) {
        (void) brix_tpc_registry_remove(file->tpc_transfer_id, c->log);
        file->tpc_transfer_id = 0;
        tpc_sess_abort_pull(t, "io");
        brix_log_access(ctx, c, "SYNC", file->path, "tpc-pull",
                          0, kXR_ServerError, "thread post failed", 0);
        BRIX_OP_ERR(ctx, BRIX_OP_SYNC);
        return brix_send_error(ctx, c, kXR_ServerError,
                                 "TPC pull thread post failed");
    }

    /* Hand-off committed: mark started and park the connection in AIO state so
     * the event loop defers further request processing until done.c resumes it. */
    file->tpc_started = 1;
    ctx->state = XRD_ST_AIO;
    return NGX_OK;
}

/* WHAT: Wrapper for brix_tpc_prepare_pull — delegates full validation + fhandle allocation + confined fd open + metadata setup + key generation to prepare_pull. Returns prepare_pull result (NGX_OK or error). Caller: dispatch.c (kXR_open TPC opaque param path entry point). */
ngx_int_t
brix_tpc_launch_pull(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const brix_tpc_params_t *tpc,
    const char *dst_path, uint16_t options, uint16_t mode_bits)
{
    return brix_tpc_prepare_pull(ctx, c, conf, tpc, dst_path, options,
                                   mode_bits);
}
