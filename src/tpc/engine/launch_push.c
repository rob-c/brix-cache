#include "tpc_internal.h"
#include "core/compat/host_format.h"      /* brix_format_host_port — IPv6 bracketing */
#include "observability/sesslog/sesslog_ngx.h"
/* File: launch_push.c — F16, the SOURCE side of a native root:// TPC PUSH.
 *
 * WHAT: the two event-thread entry points of the push dialect.
 * brix_tpc_prepare_push runs at kXR_open time: the operator opt-in
 * (brix_tpc_push), the destination host/path validation, the source-egress
 * allowlist and the cached SSRF verdict on the host this server would DIAL,
 * then it PARKS the intent on ctx->tpc_push_pending and declines so the
 * ordinary read-open resolves, authorizes and opens the local file.
 * brix_tpc_push_apply_pending stamps that park onto the finished handle.
 * brix_tpc_start_push runs at the second kXR_sync: it registers the transfer,
 * snapshots the handle into a brix_tpc_pull_t with is_push set and posts the
 * same thread-pool worker the pull uses.
 *
 * WHY: a push inverts who dials, not what is guarded. The security ladder is
 * the pull's, verbatim, evaluated against the DESTINATION host — one egress
 * gate, one refusal counter, one fail2ban signal, one SSRF policy. Parking the
 * role instead of opening the file here means the push source leg reuses the
 * server's real read-open (resolve_path, authz, VO ACL, throttle, monitor)
 * rather than a second, thinner copy of it.
 *
 * HOW: prepare = opt-in → host/path → egress guard (+ signal + counter) →
 * cached SSRF verdict → park. An UNKNOWN name is not parked on DNS: nothing has
 * been dialled, and connect.c re-checks every address it actually connects to
 * (I-DNS-3), so an offending address is refused there. start = validate handle
 * → registry add → task alloc → populate (remote peer in src_host/src_port,
 * remote path in push_lfn, local file in dst_*) → post.
 * */
#include "protocols/root/session/registry.h"

#include <string.h>

#include "core/compat/alloc_guard.h"
#include "fs/path/path.h"                 /* brix_sanitize_log_string */
#include "net/guard/guard.h"              /* guard_audit_format — fail2ban line */
#include "tpc/common/egress_guard.h"      /* brix_tpc_source_guard_check */
#include "observability/metrics/metrics_macros.h" /* BRIX_SRV_METRIC_INC */

/* Log, count and answer one push refusal. Mirrors brix_tpc_refuse (which is the
 * pull's, and logs the pull's op/tag), but a push open is a READ open — logging
 * it as a write would misattribute the refusal in the access log and in the
 * per-op counters. Always returns NGX_OK ("handled"), never a false success:
 * brix_open_handle_tpc's contract is that anything but NGX_DECLINED is the
 * finished answer. */
static ngx_int_t
tpc_push_refuse(brix_ctx_t *ctx, ngx_connection_t *c, const char *host,
    uint16_t code, const char *msg)
{
    brix_log_access(ctx, c, "OPEN", host, "tpc-push", 0, code, msg, 0);
    BRIX_OP_ERR(ctx, BRIX_OP_OPEN_RD);
    (void) brix_send_error(ctx, c, code, msg);
    return NGX_OK;
}

/* WHAT: emit one fail2ban-parseable audit line for a push destination the
 * egress allowlist refused.
 * WHY: originating a push is exactly the request-forgery primitive the pull's
 * source guard exists to bound — the only difference is the direction bytes
 * move — so a refused destination is banworthy on the same contract
 * (signal=tpc_egress) and is counted by the same labelless metric (INVARIANT 8).
 * HOW: identical to launch_prepare.c's pull signal, with GUARD_OP_READ: the
 * client's request here is a read open. */
static void
tpc_push_egress_signal(brix_ctx_t *ctx, ngx_connection_t *c, const char *host)
{
    guard_request_t req;
    char            line[512];
    char            ip[64];
    char            ts[sizeof("YYYY-MM-DDThh:mm:ss+00:00")];
    char            hostbuf[256];
    size_t          ip_len;
    size_t          ts_len;

    ip_len = ngx_min(c->addr_text.len, sizeof(ip) - 1);
    ngx_memcpy(ip, c->addr_text.data, ip_len);
    ip[ip_len] = '\0';

    ts_len = ngx_min(ngx_cached_http_log_iso8601.len, sizeof(ts) - 1);
    ngx_memcpy(ts, ngx_cached_http_log_iso8601.data, ts_len);
    ts[ts_len] = '\0';

    ngx_memzero(&req, sizeof(req));
    req.ip           = ip;
    req.proto        = "root";
    req.op           = GUARD_OP_READ;    /* a push originates from a read open */
    req.path         = hostbuf;
    req.path_len     = brix_sanitize_log_string(host, hostbuf, sizeof(hostbuf));
    req.cred_present = ctx->login.dn[0] != '\0' ? 1 : 0;
    req.outcome      = OUTCOME_AUTHFAIL;
    req.status_code  = kXR_NotAuthorized;

    if (guard_audit_format(&req, GUARD_R_TPCEGRESS, ts, line, sizeof(line)) > 0) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0, "%s", line);
    }
}

/* WHAT: the security ladder, evaluated against the DESTINATION this server
 * would dial. NGX_OK to proceed; NGX_OK is never returned after a refusal —
 * *answered is set instead and holds the finished rc.
 * WHY: keeps brix_tpc_prepare_push flat and the gates independently reviewable,
 * exactly as tpc_prepare_check_preconditions does for the pull.
 * HOW: opt-in off → kXR_Unsupported; no thread pool → kXR_ServerError; empty
 * host/path/key → kXR_ArgInvalid; egress allowlist → kXR_NotAuthorized + guard
 * signal + counter; cached SSRF verdict < 0 → kXR_NotAuthorized. A verdict of
 * "unknown" proceeds: the connect-time recheck is the authoritative one. */
static ngx_int_t
tpc_push_check_preconditions(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const brix_tpc_params_t *tpc,
    ngx_int_t *answered)
{
    char     policy_err[512];
    char     egress_err[512];
    uint16_t dport;

    if (!conf->tpc_push) {
        *answered = tpc_push_refuse(ctx, c, tpc->dst_host, kXR_Unsupported,
                          "native TPC push is disabled (brix_tpc_push off)");
        return NGX_ERROR;
    }

    if (conf->common.thread_pool == NULL) {
        *answered = tpc_push_refuse(ctx, c, tpc->dst_host, kXR_ServerError,
                          "TPC push requires brix_thread_pool to be configured");
        return NGX_ERROR;
    }

    if (tpc->dst_host[0] == '\0' || tpc->dst_path[0] == '\0'
        || !tpc->has_key || tpc->key[0] == '\0')
    {
        *answered = tpc_push_refuse(ctx, c, tpc->dst_host, kXR_ArgInvalid,
                          "invalid or incomplete TPC push destination");
        return NGX_ERROR;
    }

    /* Destination-egress allowlist (naming policy): the host this server is
     * asked to dial must appear on brix_tpc_source_allow when the guard is on.
     * Same list as the pull's: the directive names the peers this server may
     * originate to, and a push originates to its destination. */
    if (brix_tpc_source_guard_check(conf->common.tpc_source_guard,
            conf->common.tpc_source_allow, tpc->dst_host,
            egress_err, sizeof(egress_err))
        != 0)
    {
        BRIX_SRV_METRIC_INC(ctx, tpc_egress_refused_total);
        tpc_push_egress_signal(ctx, c, tpc->dst_host);
        *answered = tpc_push_refuse(ctx, c, tpc->dst_host, kXR_NotAuthorized,
                                    egress_err);
        return NGX_ERROR;
    }

    /*
     * SSRF range gate. The verdict comes from an IP literal or the per-worker
     * DNS cache; a definitively prohibited address refuses the open here. An
     * unknown name is NOT parked on an async resolve as the pull's open is:
     * the pull must decide before it CREATES the destination file, whereas a
     * push has created nothing and dialled nothing at open time. The pull
     * thread re-checks every candidate address it actually connects to
     * (connect.c, I-DNS-3), so an offending address is still refused — one
     * frame later, with no local side effect to undo.
     */
    dport = tpc->dst_port ? tpc->dst_port : TPC_DEFAULT_PORT;
    if (brix_tpc_check_src_policy(conf, tpc->dst_host, dport, policy_err,
                                  sizeof(policy_err)) < 0)
    {
        *answered = tpc_push_refuse(ctx, c, tpc->dst_host, kXR_NotAuthorized,
                                    policy_err);
        return NGX_ERROR;
    }

    return NGX_OK;
}

ngx_int_t
brix_tpc_prepare_push(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const brix_tpc_params_t *tpc)
{
    brix_tpc_push_pending_t *pend;
    ngx_int_t                answered = NGX_OK;

    if (tpc_push_check_preconditions(ctx, c, conf, tpc, &answered) != NGX_OK) {
        return answered;
    }

    BRIX_PALLOC_OR_RETURN(pend, c->pool, sizeof(*pend), NGX_ERROR);
    ngx_memzero(pend, sizeof(*pend));

    ngx_cpystrn((u_char *) pend->host, (u_char *) tpc->dst_host,
                sizeof(pend->host));
    ngx_cpystrn((u_char *) pend->lfn, (u_char *) tpc->dst_path,
                sizeof(pend->lfn));
    ngx_cpystrn((u_char *) pend->key, (u_char *) tpc->key, sizeof(pend->key));
    pend->port = tpc->dst_port;
    /* The tpc.org identity of the CLIENT that asked for this push, resolved on
     * the event loop exactly as the pull's is (origin_id.c): a cached PTR, or
     * the numeric fallback with org_unresolved set so the worker finishes the
     * lookup off-loop. The destination logs it as the requester. */
    pend->org_unresolved = brix_tpc_origin_build(ctx, c,
                               conf->common.dns.policy, pend->org,
                               sizeof(pend->org)) ? 1u : 0u;
    /* F7's clamp, reused verbatim: the client's tpc.str wish is bounded by this
     * server's brix_tpc_streams and by TPC_STREAMS_MAX — never trusted raw, in
     * either direction. */
    pend->streams = tpc_stream_plan_clamp(tpc->has_str ? tpc->str : NULL,
                                          (int) conf->tpc_streams);

    ctx->tpc_push_pending = pend;

    ngx_log_debug3(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "brix: TPC push parked dst=%s:%d lfn=%s",
                   pend->host, (int) (pend->port ? pend->port : TPC_DEFAULT_PORT),
                   pend->lfn);

    /* The ordinary read-open continues from here and does every check a read
     * open does; brix_open_finalize_handle stamps the park onto its handle. */
    return NGX_DECLINED;
}

void
brix_tpc_push_apply_pending(brix_ctx_t *ctx, brix_file_t *file)
{
    brix_tpc_push_pending_t *pend = ctx->tpc_push_pending;

    if (pend == NULL || file == NULL) {
        return;
    }
    ctx->tpc_push_pending = NULL;

    file->tpc_push    = 1;
    file->tpc_armed   = 0;
    file->tpc_started = 0;
    file->tpc_done    = 0;
    file->tpc_src_port = pend->port;
    file->tpc_streams  = pend->streams > 0 ? pend->streams : 1;
    file->tpc_transfer_id = 0;

    ngx_cpystrn((u_char *) file->tpc_src_host, (u_char *) pend->host,
                sizeof(file->tpc_src_host));
    ngx_cpystrn((u_char *) file->tpc_src_path, (u_char *) pend->lfn,
                sizeof(file->tpc_src_path));
    ngx_cpystrn((u_char *) file->tpc_key, (u_char *) pend->key,
                sizeof(file->tpc_key));
    ngx_cpystrn((u_char *) file->tpc_org, (u_char *) pend->org,
                sizeof(file->tpc_org));
    file->tpc_org_unresolved = pend->org_unresolved ? 1 : 0;
}

/* WHAT: register this push in the shared TPC transfer registry and return its
 * id (0 on failure / registry full).
 * WHY: a push is a transfer like any other — the dashboard, the metrics and the
 * abandoned-transfer reaper must see it. The URL is built the same way as the
 * pull's, but the REMOTE side is the destination, so src_url names the local
 * file and dst_path the remote one.
 * HOW: bracket an IPv6 literal destination, format "root://host:port/path",
 * fill an brix_tpc_transfer_t (PROTO_STREAM/DIR_PUSH/PENDING), registry add. */
static uint64_t
tpc_register_push_transfer(ngx_connection_t *c, brix_file_t *file)
{
    brix_tpc_transfer_t transfer;
    ngx_str_t             src_url;
    ngx_str_t             dst_url;
    u_char                dst_buf[PATH_MAX + 320];
    u_char               *last;
    char                  hostport[288];

    if (file == NULL || file->path == NULL) {
        return 0;
    }

    brix_format_host_port(file->tpc_src_host,
                          file->tpc_src_port ? file->tpc_src_port : TPC_DEFAULT_PORT,
                          hostport, sizeof(hostport));
    last = ngx_snprintf(dst_buf, sizeof(dst_buf), "root://%s%s", hostport,
                        file->tpc_src_path);

    src_url.data = (u_char *) file->path;
    src_url.len  = ngx_strlen(file->path);
    dst_url.data = dst_buf;
    dst_url.len  = (size_t) (last - dst_buf);

    ngx_memzero(&transfer, sizeof(transfer));
    transfer.protocol  = BRIX_TPC_PROTO_STREAM;
    transfer.direction = BRIX_TPC_DIR_PUSH;
    transfer.src_url   = src_url;
    transfer.dst_path  = dst_url;
    transfer.state     = BRIX_TPC_STATE_PENDING;

    return brix_tpc_registry_add(&transfer, c->log, 0);
}

/* WHAT: copy everything the off-thread worker needs out of the connection and
 * the ctx->files[] slot into the task, by value.
 * WHY: the worker must never touch ctx->files or the connection's mutable
 * state. The field mapping is the push's one real subtlety: src_host/src_port
 * carry the REMOTE DESTINATION (so connect.c's egress guard and per-address
 * recheck cover a push with no new code), push_lfn is the remote path, and
 * dst_path/dst_fd/dst_obj stay "the local file" — here the SOURCE, opened
 * read-only, which done.c must therefore never unlink.
 * HOW: memzero → refs/streamid/is_push → local file → remote peer → key/org. */
static void
tpc_populate_push_task(brix_tpc_pull_t *t, brix_ctx_t *ctx,
    ngx_connection_t *c, ngx_stream_brix_srv_conf_t *conf,
    brix_file_t *file)
{
    ngx_memzero(t, sizeof(*t));
    t->c    = c;
    t->ctx  = ctx;
    t->conf = conf;
    t->streamid[0] = ctx->recv.cur_streamid[0];
    t->streamid[1] = ctx->recv.cur_streamid[1];
    t->is_push     = 1;
    t->reply_kind  = BRIX_TPC_REPLY_SYNC;
    t->transfer_id = file->tpc_transfer_id;
    t->streams_requested = file->tpc_streams > 0 ? file->tpc_streams : 1;

    /* The local file: source of the bytes, read-only. */
    t->dst_fd  = file->fd;
    t->dst_obj = file->sd_obj;
    t->push_size = file->cached_size > 0 ? (uint64_t) file->cached_size : 0;
    ngx_cpystrn((u_char *) t->dst_path, (u_char *) file->path,
                sizeof(t->dst_path));

    /* The remote peer: the destination we dial and write to. */
    t->src_port = file->tpc_src_port;
    ngx_cpystrn((u_char *) t->src_host, (u_char *) file->tpc_src_host,
                sizeof(t->src_host));
    ngx_cpystrn((u_char *) t->src_path, (u_char *) file->tpc_src_path,
                sizeof(t->src_path));
    ngx_cpystrn((u_char *) t->push_lfn, (u_char *) file->tpc_src_path,
                sizeof(t->push_lfn));

    ngx_cpystrn((u_char *) t->tpc_key, (u_char *) file->tpc_key,
                sizeof(t->tpc_key));
    ngx_cpystrn((u_char *) t->tpc_org, (u_char *) file->tpc_org,
                sizeof(t->tpc_org));
    t->tpc_org_unresolved = file->tpc_org_unresolved ? 1 : 0;
    brix_tpc_origin_snapshot_peer(t, ctx, c);
}

ngx_int_t
brix_tpc_start_push(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, int fhandle_idx)
{
    ngx_thread_task_t *task;
    brix_tpc_pull_t   *t;
    brix_file_t       *file;

    if (fhandle_idx < 0 || fhandle_idx >= BRIX_MAX_FILES) {
        return NGX_ERROR;
    }

    file = &ctx->files[fhandle_idx];
    if (!file->tpc_push || file->fd < 0) {
        return brix_send_error(ctx, c, kXR_FileNotOpen,
                                 "invalid TPC push handle");
    }

    /* Idempotent re-trigger: a sync arriving while the worker is already
     * running gets a kXR_wait, not a second thread post. */
    if (file->tpc_started) {
        return brix_send_wait(ctx, c, 1);
    }

    if (file->tpc_transfer_id == 0) {
        file->tpc_transfer_id = tpc_register_push_transfer(c, file);
        if (file->tpc_transfer_id == 0) {
            BRIX_RETURN_ERR(ctx, c, BRIX_OP_SYNC, "SYNC", file->path,
                              "tpc-push", kXR_Overloaded,
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
    tpc_populate_push_task(t, ctx, c, conf, file);
    t->fhandle_idx = fhandle_idx;

    brix_task_bind(task, brix_tpc_pull_thread, brix_tpc_pull_done);

    if (ngx_thread_task_post(conf->common.thread_pool, task) != NGX_OK) {
        (void) brix_tpc_registry_remove(file->tpc_transfer_id, c->log);
        file->tpc_transfer_id = 0;
        brix_log_access(ctx, c, "SYNC", file->path, "tpc-push",
                          0, kXR_ServerError, "thread post failed", 0);
        BRIX_OP_ERR(ctx, BRIX_OP_SYNC);
        return brix_send_error(ctx, c, kXR_ServerError,
                                 "TPC push thread post failed");
    }

    file->tpc_started = 1;
    ctx->state = XRD_ST_AIO;
    return NGX_OK;
}
