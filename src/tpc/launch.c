#include "tpc_internal.h"
#include "../compat/host_format.h"  /* xrootd_format_host_port — IPv6 bracketing */
/* ---- File: launch.c — TPC pull entry point and destination-side preparation for native root:// third-party copy ----
 *
 * WHAT: Six functions implement the TPC pull launch pipeline on the event thread. tpc_send_open_response builds kXR_ok open response body (fhandle + optional statbuf) → xrootd_queue_response; tpc_build_origin_id constructs origin ID string from ctx->login_user+ngx_pid+getnameinfo host via snprintf+cpystrn; tpc_destination_open_flags derives O_CREAT/O_EXCL/O_TRUNC flags from options bitmask for POSIX open; xrootd_tpc_prepare_pull validates thread_pool + TPC source host/path → checks src policy (allow_local/allow_private) → alloc fhandle idx → xrootd_open_confined(canonical path) → set file metadata (writable=1, tpc_destination=1) → generate+register key if empty → store token_mode → send open response; xrootd_tpc_start_pull validates fhandle_idx + tpc_destination flag → alloc ngx_thread_task → populate xrootd_tpc_pull_t struct from file fields → set handler=xrootd_tpc_pull_thread, event.handler=xrootd_tpc_pull_done → post to thread pool; xrootd_tpc_launch_pull is wrapper for prepare_pull. Non-NGX_THREADS stubs return kXR_ServerError "TPC pull requires NGX_THREADS support". Caller: dispatch.c (kXR_open TPC opaque param path).
 *
 * WHY: The destination server needs to create the local file handle before connecting to the source — this ensures the write target exists with correct permissions and metadata before the thread-pool worker starts pulling data. The launch pipeline separates preparation (event-thread, synchronous) from execution (thread-pool, blocking I/O), allowing nginx to respond immediately to the client open request while the actual fetch runs asynchronously.
 *
 * HOW: prepare_pull — conf->common.thread_pool == NULL → error; tpc->src_host/path empty → error; xrootd_tpc_check_src_policy → error if denied; idx = xrootd_alloc_fhandle(ctx) → fd = xrootd_open_confined(c->log, &conf->common.root, dst_path, tpc_destination_open_flags(options), create_mode) → fstat(fd, &st) → file[idx] metadata set (writable=1, readable=0, tpc_destination=1, tpc_key generated or echoed from tpc->key, token_mode stored) → send open response with fhandle idx + stat if kXR_retstat. start_pull — fhandle_idx valid + file->tpc_destination true → ngx_thread_task_alloc(sizeof(xrootd_tpc_pull_t)) → memcpy src_host/path/key/org/token_mode/dst_path from file fields → task->handler=xrootd_tpc_pull_thread, event.handler=xrootd_tpc_pull_done → ngx_thread_task_post(thread_pool, task) → file->tpc_started=1, ctx->state=XRD_ST_AIO.
 * ------------------------------------------------------------------ */
#include "../session/registry.h"

#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include <netdb.h>

/* WHAT: Build kXR_ok open response body (fhandle + optional statbuf from fstat) → xrootd_build_resp_hdr → xrootd_queue_response. Returns NGX_OK or NGX_ERROR on alloc failure. Caller: xrootd_tpc_prepare_pull (end of pull prep pipeline). */
static ngx_int_t
tpc_send_open_response(xrootd_ctx_t *ctx, ngx_connection_t *c, int idx,
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
    buf = ngx_palloc(c->pool, total);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    xrootd_build_resp_hdr(ctx->cur_streamid, kXR_ok, (uint32_t) bodylen,
                          (ServerResponseHdr *) buf);

    ngx_memzero(&body, sizeof(body));
    body.fhandle[0] = (u_char) idx;
    ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN, &body, sizeof(body));

    if (statbuf[0] != '\0') {
        ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN + sizeof(ServerOpenBody),
                   statbuf, strlen(statbuf) + 1);
    }

    return xrootd_queue_response(ctx, c, buf, total);
}

/* WHAT: Construct origin ID string from ctx->login_user+ngx_pid+getnameinfo host via snprintf("%s.%u@host") — falls back to "xrd" for empty user, ngx_pid for zero pid, addr_text.len then "unknown" for unresolved host. Caller: xrootd_tpc_prepare_pull (origin ID storage step). */

static void
tpc_build_origin_id(xrootd_ctx_t *ctx, ngx_connection_t *c, char *dst,
    size_t dst_size)
{
    char        host[NI_MAXHOST];
    const char *user;
    uint32_t    pid;

    user = ctx->login_user[0] != '\0' ? ctx->login_user : "xrd";
    pid = ctx->login_pid != 0 ? ctx->login_pid : (uint32_t) ngx_pid;

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
 * stack buffer, fill an xrootd_tpc_transfer_t (PROTO_STREAM/DIR_PULL/PENDING),
 * and hand it to xrootd_tpc_registry_add. */
static uint64_t
tpc_register_stream_transfer(ngx_connection_t *c, xrootd_file_t *file)
{
    xrootd_tpc_transfer_t transfer;
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
        xrootd_format_host_port(file->tpc_src_host, sport,
                                hostport, sizeof(hostport));
        last = ngx_snprintf(src_buf, sizeof(src_buf), "root://%s%s",
                            hostport, file->tpc_src_path);
    }

    src_url.data = src_buf;
    src_url.len = (size_t) (last - src_buf);
    dst_path.data = (u_char *) file->path;
    dst_path.len = ngx_strlen(file->path);

    ngx_memzero(&transfer, sizeof(transfer));
    transfer.protocol = XROOTD_TPC_PROTO_STREAM;
    transfer.direction = XROOTD_TPC_DIR_PULL;
    transfer.src_url = src_url;
    transfer.dst_path = dst_path;
    transfer.state = XROOTD_TPC_STATE_PENDING;

    return xrootd_tpc_registry_add(&transfer, c->log);
}

/* WHAT: Derive O_CREAT/O_EXCL/O_TRUNC flags from options bitmask — kXR_new → O_CREAT+O_EXCL, kXR_delete → O_CREAT+O_TRUNC, neither → O_CREAT+O_TRUNC (default create-new). Always includes O_RDWR|O_NOCTTY. Caller: xrootd_tpc_prepare_pull (open flags step). */
ngx_int_t
xrootd_tpc_prepare_pull(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf, const xrootd_tpc_params_t *tpc,
    const char *dst_path, uint16_t options, uint16_t mode_bits)
{
    xrootd_file_t *file;
    struct stat    st;
    mode_t         create_mode;
    int            idx;
    int            fd;

    if (conf->common.thread_pool == NULL) {
        xrootd_log_access(ctx, c, "OPEN", dst_path, "tpc-pull",
                          0, kXR_ServerError, "TPC requires xrootd_thread_pool",
                          0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_OPEN_WR);
        return xrootd_send_error(ctx, c, kXR_ServerError,
                                 "TPC pull requires xrootd_thread_pool "
                                 "to be configured");
    }

    if (tpc->src_host[0] == '\0' || tpc->src_path[0] == '\0') {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_OPEN_WR, "OPEN", dst_path,
                          "tpc-pull", kXR_ArgInvalid,
                          "invalid or incomplete TPC source");
    }

    /*
     * Source policy gate (SSRF defence): before we ever connect outbound, the
     * resolved source host/port is checked against the loopback/private-range
     * allow flags. A destination server must not be coercible into pulling from
     * internal addresses unless the operator explicitly permits it.
     */
    {
        char      policy_err[512];
        uint16_t  sport;

        sport = tpc->src_port ? tpc->src_port : 1094;
        if (xrootd_tpc_check_src_policy(tpc->src_host, sport,
                conf->tpc_allow_local, conf->tpc_allow_private,
                policy_err, sizeof(policy_err))
            != 0)
        {
            XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_OPEN_WR, "OPEN", dst_path,
                              "tpc-pull", kXR_NotAuthorized, policy_err);
        }
    }

    idx = xrootd_alloc_fhandle(ctx);
    if (idx < 0) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_OPEN_WR, "OPEN", dst_path,
                          "tpc-pull", kXR_ServerError, "too many open files");
    }

    create_mode = (mode_bits & 0777) ? (mode_t) (mode_bits & 0777) : 0644;

    /*
     * xrootd_open_beneath() resolves its path relative to conf->rootfd (it
     * strips the leading '/' via xrootd_beneath_rel), so it must receive the
     * LOGICAL export path — not the root_canon-prefixed absolute path that
     * dst_path carries for authz/logging/fhandle metadata.  Passing the
     * absolute path here doubles the root prefix and openat2() fails with
     * ENOENT.  Recover the logical path by stripping the root_canon prefix.
     */
    {
        const char *dst_logical = dst_path;
        size_t      root_len = ngx_strlen(conf->common.root_canon);

        if (root_len > 1
            && ngx_strncmp(dst_path, conf->common.root_canon, root_len) == 0
            && (dst_path[root_len] == '/' || dst_path[root_len] == '\0'))
        {
            dst_logical = dst_path + root_len;
        }

        fd = xrootd_open_beneath(conf->rootfd, dst_logical,
                                 tpc_destination_open_flags(options),
                                 create_mode);
    }
    if (fd < 0) {
        int err = errno;

        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_OPEN_WR, "OPEN", dst_path,
                          "tpc-pull", kXR_IOError, strerror(err));
    }

    if (fstat(fd, &st) != 0) {
        int err = errno;

        close(fd);
        XROOTD_OP_ERR(ctx, XROOTD_OP_OPEN_WR);
        return xrootd_send_error(ctx, c, kXR_IOError, strerror(err));
    }

    file = &ctx->files[idx];
    file->fd = fd;
    file->writable = 1;
    file->readable = 0;
    file->from_cache = 0;
    file->is_regular = S_ISREG(st.st_mode) ? 1 : 0;
    file->device = st.st_dev;
    file->inode = st.st_ino;
    file->cached_size = (off_t) st.st_size;
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
        xrootd_tpc_generate_key(file->tpc_key, sizeof(file->tpc_key));
    }

    tpc_build_origin_id(ctx, c, file->tpc_org, sizeof(file->tpc_org));
    ngx_cpystrn((u_char *) file->tpc_src_host, (u_char *) tpc->src_host,
                sizeof(file->tpc_src_host));
    ngx_cpystrn((u_char *) file->tpc_src_path, (u_char *) tpc->src_path,
                sizeof(file->tpc_src_path));

    if (xrootd_set_fhandle_path(ctx, c, idx, dst_path) != NGX_OK) {
        xrootd_free_fhandle(ctx, idx);
        return NGX_ERROR;
    }

    if (!ctx->is_bound) {
        xrootd_session_handle_publish(ctx->sessid, idx, file);
    }

    /* Store token_mode for use during pull task execution. */
    if (tpc->has_token_mode && tpc->token_mode[0] != '\0') {
        ngx_cpystrn((u_char *) file->tpc_token_mode,
                    (u_char *) tpc->token_mode, sizeof(file->tpc_token_mode));
    } else {
        file->tpc_token_mode[0] = '\0';
    }

    xrootd_log_access(ctx, c, "OPEN", dst_path, "tpc-pull", 1, 0, NULL, 0);
    XROOTD_OP_OK(ctx, XROOTD_OP_OPEN_WR);

    return tpc_send_open_response(ctx, c, idx, fd, options);
}

/* WHAT: Allocate ngx_thread_task(sizeof(xrootd_tpc_pull_t)) → populate struct from file fields (src_host/path/key/org/token_mode/dst_path) → set handler=xrootd_tpc_pull_thread, event.handler=xrootd_tpc_pull_done → post to thread pool. Returns NGX_OK or error on alloc/post failure. Caller: dispatch.c (kXR_sync TPC launch path). */
ngx_int_t
xrootd_tpc_start_pull(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf, int fhandle_idx)
{
    ngx_thread_task_t *task;
    xrootd_tpc_pull_t *t;
    xrootd_file_t     *file;

    if (fhandle_idx < 0 || fhandle_idx >= XROOTD_MAX_FILES) {
        return NGX_ERROR;
    }

    /* The handle must be a live TPC destination opened by prepare_pull. */
    file = &ctx->files[fhandle_idx];
    if (!file->tpc_destination || file->fd < 0) {
        return xrootd_send_error(ctx, c, kXR_FileNotOpen,
                                 "invalid TPC destination handle");
    }

    /* Idempotent re-trigger: a sync arriving while the worker is already
     * running gets a kXR_wait, not a second thread post. */
    if (file->tpc_started) {
        return xrootd_send_wait(ctx, c, 1);
    }

    if (file->tpc_transfer_id == 0) {
        file->tpc_transfer_id = tpc_register_stream_transfer(c, file);
        if (file->tpc_transfer_id == 0) {
            XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_SYNC, "SYNC", file->path,
                              "tpc-pull", kXR_Overloaded,
                              "TPC transfer registry full");
        }
    }

    task = ngx_thread_task_alloc(c->pool, sizeof(xrootd_tpc_pull_t));
    if (task == NULL) {
        (void) xrootd_tpc_registry_remove(file->tpc_transfer_id, c->log);
        file->tpc_transfer_id = 0;
        return NGX_ERROR;
    }

    /*
     * Snapshot everything the worker thread needs into the task ctx. The worker
     * runs off-thread and must NOT touch ctx->files or the connection's mutable
     * state, so all source/dest fields are copied by value here. The streamid
     * is captured so done.c can re-bind the deferred request when it completes.
     */
    t = task->ctx;
    ngx_memzero(t, sizeof(*t));
    t->c = c;
    t->ctx = ctx;
    t->conf = conf;
    t->streamid[0] = ctx->cur_streamid[0];
    t->streamid[1] = ctx->cur_streamid[1];
    t->dst_fd = file->fd;
    t->fhandle_idx = fhandle_idx;
    t->reply_kind = XROOTD_TPC_REPLY_SYNC;
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
    t->token_scope[0] = '\0';
    if (conf->tpc_outbound_scope.len > 0
        && conf->tpc_outbound_scope.len < sizeof(t->token_scope)) {
        ngx_memcpy(t->token_scope, conf->tpc_outbound_scope.data,
                   conf->tpc_outbound_scope.len);
        t->token_scope[conf->tpc_outbound_scope.len] = '\0';
    }
    ngx_cpystrn((u_char *) t->dst_path, (u_char *) file->path,
                sizeof(t->dst_path));

    /*
     * SciTags packet marking (phase-34): resolve the (experiment, activity) for
     * this pull HERE on the event loop — where identity + path are available and
     * pmark runtime init is single-threaded — and stash on the task.  The thread
     * (connect.c) only reads the codes and stamps the outbound socket's IPv6 flow
     * label.  Fail-open: 0/0 means the outbound socket is not labelled.
     */
    t->pmark_exp = 0;
    t->pmark_act = 0;
    if (conf->common.pmark.enable && conf->common.pmark.flowlabel
        && xrootd_pmark_runtime_ensure(&conf->common.pmark, ngx_cycle->pool,
                                       c->log) == NGX_OK)
    {
        ngx_uint_t e, a;
        if (xrootd_pmark_map_codes(&conf->common.pmark,
                ctx->identity ? xrootd_identity_vo_csv_cstr(ctx->identity) : "",
                ctx->identity ? xrootd_identity_dn_cstr(ctx->identity) : "",
                t->dst_path, NULL, &e, &a) == NGX_OK)
        {
            t->pmark_exp = e;
            t->pmark_act = a;
        }
    }

    xrootd_task_bind(task, xrootd_tpc_pull_thread, xrootd_tpc_pull_done);

    if (ngx_thread_task_post(conf->common.thread_pool, task) != NGX_OK) {
        (void) xrootd_tpc_registry_remove(file->tpc_transfer_id, c->log);
        file->tpc_transfer_id = 0;
        xrootd_log_access(ctx, c, "SYNC", file->path, "tpc-pull",
                          0, kXR_ServerError, "thread post failed", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_SYNC);
        return xrootd_send_error(ctx, c, kXR_ServerError,
                                 "TPC pull thread post failed");
    }

    /* Hand-off committed: mark started and park the connection in AIO state so
     * the event loop defers further request processing until done.c resumes it. */
    file->tpc_started = 1;
    ctx->state = XRD_ST_AIO;
    return NGX_OK;
}

/* WHAT: Wrapper for xrootd_tpc_prepare_pull — delegates full validation + fhandle allocation + confined fd open + metadata setup + key generation to prepare_pull. Returns prepare_pull result (NGX_OK or error). Caller: dispatch.c (kXR_open TPC opaque param path entry point). */
ngx_int_t
xrootd_tpc_launch_pull(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf, const xrootd_tpc_params_t *tpc,
    const char *dst_path, uint16_t options, uint16_t mode_bits)
{
    return xrootd_tpc_prepare_pull(ctx, c, conf, tpc, dst_path, options,
                                   mode_bits);
}
