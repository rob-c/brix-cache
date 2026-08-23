#include "tpc_internal.h"
#include "fs/vfs/vfs.h"   /* brix_vfs_open_fd_at (handle-table confined open) */
#include "core/compat/host_format.h"  /* brix_format_host_port — IPv6 bracketing */
#include "observability/sesslog/sesslog_ngx.h"
/* File: launch_prepare.c — TPC pull destination-side preparation for native
 * root:// third-party copy.
 *
 * WHAT: The prepare pipeline (split verbatim out of launch.c on 2026-07-14 for
 * file-size). tpc_refuse answers every refusal on this path;
 * tpc_prepare_check_preconditions is the security-load-bearing guard ladder
 * (thread pool → source host/path → source-name allowlist → SSRF range gate);
 * tpc_open_destination opens the destination through the identity-bound VFS,
 * random-write handle or staged writer; tpc_init_dst_file populates the
 * ctx->files[] slot; tpc_send_open_response builds the kXR_ok body (fhandle +
 * optional statbuf); brix_tpc_prepare_pull orchestrates them. Caller:
 * open_tpc.c (kXR_open TPC opaque path) via brix_tpc_launch_pull.
 *
 * WHY: the destination server must create the local file handle before dialing
 * the source, so the write target exists with the right permissions and metadata
 * before the thread-pool worker starts pulling. Preparation runs synchronously on
 * the event thread; execution runs in the pool, so nginx answers the client's
 * open immediately while the fetch proceeds.
 *
 * HOW: preconditions → brix_alloc_fhandle → tpc_open_destination →
 * tpc_init_dst_file → brix_set_fhandle_path → session publish → open response.
 * Any gate that refuses returns TPC_ANSWERED and the pipeline stops there.
 * */
#include "protocols/root/session/registry.h"
#include "protocols/root/path/op_path.h"
#include "fs/vfs/vfs_internal.h"

#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include <netdb.h>
#include <netinet/in.h>   /* sockaddr_in6 / in6_addr — IPv4-mapped tpc.org */
#include <arpa/inet.h>    /* inet_ntop — XrdNetAddr-matching numeric literal */
#include "core/compat/alloc_guard.h"
#include "core/compat/cstr.h"
#include "fs/path/path.h"                 /* brix_sanitize_log_string */
#include "net/guard/guard.h"              /* guard_audit_format — fail2ban line */
#include "tpc/common/egress_guard.h"      /* brix_tpc_source_guard_check */
#include "observability/metrics/metrics_macros.h" /* BRIX_SRV_METRIC_INC */

/*
 * A queued response is not a return value. brix_send_error() returns NGX_OK once
 * the kXR_error is on the wire, so a function that ends `return
 * brix_send_error(...)` reports SUCCESS to whoever called it. At a protocol entry
 * point that is exactly right: NGX_OK there means "request handled" and nothing
 * runs afterwards. One call deep it is a gate bypass - the caller reads NGX_OK as
 * "the check passed, carry on" and carries on past a refusal it has already
 * answered, allocating the handle and queueing a second, contradictory response.
 * The gates below therefore return TPC_ANSWERED, "refused, and the client has
 * been told", which only brix_tpc_prepare_pull - the entry point, where the
 * distinction stops mattering - folds back into the wire contract's NGX_OK.
 */
/* Log, count and answer one refusal. Never reports success; a failed write is
 * still NGX_ERROR, so connection teardown is unchanged. */
ngx_int_t
brix_tpc_refuse(brix_ctx_t *ctx, ngx_connection_t *c, const char *dst_path,
    uint16_t code, const char *msg)
{
    brix_log_access(ctx, c, "OPEN", dst_path, "tpc-pull", 0, code, msg, 0);
    BRIX_OP_ERR(ctx, BRIX_OP_OPEN_WR);

    return brix_send_error(ctx, c, code, msg) == NGX_OK
           ? TPC_ANSWERED : NGX_ERROR;
}

/* WHAT: Build kXR_ok open response body (fhandle + optional statbuf from fstat) → brix_build_resp_hdr → brix_queue_response. Returns NGX_OK or NGX_ERROR on alloc failure. Caller: brix_tpc_prepare_pull (end of pull prep pipeline). */
static ngx_int_t
tpc_send_open_response(brix_ctx_t *ctx, ngx_connection_t *c, int idx,
    const struct stat *st, uint16_t options)
{
    ServerOpenBody  body;
    char            statbuf[256];
    size_t          bodylen;
    size_t          total;
    u_char         *buf;
    ngx_flag_t      want_stat;

    want_stat = (options & kXR_retstat) ? 1 : 0;
    statbuf[0] = '\0';
    bodylen = sizeof(ServerOpenBody);

    if (want_stat && st != NULL) {
        int stat_flags = 0;

        if (st->st_mode & (S_IRUSR | S_IRGRP | S_IROTH)) {
            stat_flags |= kXR_readable;
        }
        if (st->st_mode & (S_IWUSR | S_IWGRP | S_IWOTH)) {
            stat_flags |= kXR_writable;
        }

        snprintf(statbuf, sizeof(statbuf), "%llu %lld %d %ld",
                 (unsigned long long) st->st_ino,
                 (long long) st->st_size,
                 stat_flags,
                 (long) st->st_mtime);
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

    /* Present the client host EXACTLY as the XRootD TPC source stores it in the
     * rendezvous grant (XrdOfsTPC::genOrg -> XrdNetAddr::Name): the source pairs
     * the destination's tpc.org against the grant with a raw strcmp
     * (XrdOfsTPCInfo::Match), so any textual divergence leaves the grant
     * unredeemed until it TTL-expires — the destination's pull-open then hangs on
     * kXR_waitresp and finally fails "[3012] TPC kXR_open recv failed". Every
     * XRootD server is IPv6 dual-stack, so it sees an IPv4 client as the
     * IPv4-MAPPED address ::ffff:a.b.c.d and reverse-resolves THAT (which fails
     * for non-DNS hosts like loopback -> numeric bracketed literal). brix's TPC
     * listener is IPv4-only, so a naive getnameinfo() on the bare IPv4 resolves
     * 127.0.0.1 -> "localhost" while the grant holds "[::ffff:127.0.0.1]". Match
     * the source: map an IPv4 peer into ::ffff:a.b.c.d, reverse-resolve the mapped
     * form, and fall back to its bracketed numeric literal. */
    if (c->sockaddr != NULL) {
        struct sockaddr_in6  mapped;
        struct sockaddr     *sa    = c->sockaddr;
        socklen_t            salen = c->socklen;

        if (c->sockaddr->sa_family == AF_INET) {
            const struct sockaddr_in *s4 =
                (const struct sockaddr_in *) c->sockaddr;

            ngx_memzero(&mapped, sizeof(mapped));
            mapped.sin6_family = AF_INET6;
            mapped.sin6_port   = s4->sin_port;
            mapped.sin6_addr.s6_addr[10] = 0xff;
            mapped.sin6_addr.s6_addr[11] = 0xff;
            ngx_memcpy(&mapped.sin6_addr.s6_addr[12], &s4->sin_addr, 4);
            sa    = (struct sockaddr *) &mapped;
            salen = (socklen_t) sizeof(mapped);
        }

        if (getnameinfo(sa, salen, host, sizeof(host), NULL, 0,
                        NI_NAMEREQD) != 0) {
            host[0] = '\0';
        }

        if (host[0] == '\0' && sa->sa_family == AF_INET6) {
            char                       numeric[INET6_ADDRSTRLEN];
            const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *) sa;

            if (inet_ntop(AF_INET6, &s6->sin6_addr, numeric,
                          sizeof(numeric)) != NULL) {
                (void) snprintf(host, sizeof(host), "[%s]", numeric);
            }
        }
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

/* WHAT: Emit one fail2ban-parseable audit line for a TPC egress the source
 * allowlist refused, at WARN on the connection log (the stream side has no
 * per-location audit file). The attacker-chosen source host rides the sanitized
 * path field; the labelless metric carries the count (INVARIANT 8).
 * WHY: an un-guarded gateway is a request-forgery primitive; a client probing
 * which internal hosts a gateway will dial should be banned like any scanner,
 * so the refusal shares the guard/fail2ban contract (signal=tpc_egress).
 * HOW: copy the cached ISO-8601 clock + client IP into NUL-terminated stacks,
 * sanitize the host into the path field, format via the shared guard formatter. */
static void
tpc_egress_emit_signal(brix_ctx_t *ctx, ngx_connection_t *c, const char *host)
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
    req.op           = GUARD_OP_WRITE;   /* a TPC pull opens a write destination */
    req.path         = hostbuf;
    req.path_len     = brix_sanitize_log_string(host, hostbuf, sizeof(hostbuf));
    req.cred_present = ctx->login.dn[0] != '\0' ? 1 : 0;
    req.outcome      = OUTCOME_AUTHFAIL;
    req.status_code  = kXR_NotAuthorized;

    if (guard_audit_format(&req, GUARD_R_TPCEGRESS, ts, line, sizeof(line)) > 0) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0, "%s", line);
    }
}

/* WHAT: Validate the pull preconditions before any state is allocated — a
 *       configured thread pool, a non-empty TPC source host+path, the operator's
 *       source-name allowlist, and an SSRF-safe source address per the
 *       loopback/private allow flags. NGX_OK when the request may proceed;
 *       TPC_ANSWERED once a refusal has been answered; NGX_ERROR if it could not.
 * WHY:  this is the security-load-bearing front door, SSRF gate included;
 *       isolating it keeps the orchestrator flat and the checks independently
 *       reviewable.
 * HOW:  thread_pool NULL → kXR_ServerError; empty src host/path → kXR_ArgInvalid;
 *       brix_tpc_source_guard_check != 0 → kXR_NotAuthorized + guard signal;
 *       brix_tpc_check_src_policy != 0 → kXR_NotAuthorized. */
static ngx_int_t
tpc_prepare_check_preconditions(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const brix_tpc_params_t *tpc,
    const char *dst_path)
{
    char     policy_err[512];
    char     egress_err[512];
    uint16_t sport;

    if (conf->common.thread_pool == NULL) {
        return brix_tpc_refuse(ctx, c, dst_path, kXR_ServerError,
                          "TPC pull requires brix_thread_pool to be configured");
    }

    if (tpc->src_host[0] == '\0' || tpc->src_path[0] == '\0') {
        return brix_tpc_refuse(ctx, c, dst_path, kXR_ArgInvalid,
                          "invalid or incomplete TPC source");
    }

    /*
     * Source-egress allowlist gate (naming policy): when the operator enabled
     * brix_tpc_source_guard, the requested source host must appear on
     * brix_tpc_source_allow or we refuse to originate — before the address-range
     * check below, so a non-permitted host is rejected without a DNS lookup.
     * This is the server-side request-forgery control the client egress
     * self-test verifies; a refusal is banworthy, so it emits the guard signal
     * and bumps the labelless refusal counter.
     */
    if (brix_tpc_source_guard_check(conf->tpc_source_guard,
            conf->tpc_source_allow, tpc->src_host,
            egress_err, sizeof(egress_err))
        != 0)
    {
        BRIX_SRV_METRIC_INC(ctx, tpc_egress_refused_total);
        tpc_egress_emit_signal(ctx, c, tpc->src_host);
        return brix_tpc_refuse(ctx, c, dst_path, kXR_NotAuthorized, egress_err);
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
        return brix_tpc_refuse(ctx, c, dst_path, kXR_NotAuthorized, policy_err);
    }

    return NGX_OK;
}


ngx_int_t
brix_tpc_prepare_pull(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const brix_tpc_params_t *tpc,
    const char *dst_path, uint16_t options, uint16_t mode_bits)
{
    brix_file_t *file;
    struct stat    st;
    ngx_int_t      pre;
    int            idx;

    /* TPC_ANSWERED means the gate refused and already said so on the wire; the
     * wire contract spells "handled, nothing more to send" NGX_OK. Collapsing the
     * two here — and only here — is what keeps a refusal from reading as consent
     * one frame up while still ending the request. */
    pre = tpc_prepare_check_preconditions(ctx, c, conf, tpc, dst_path);
    if (pre != NGX_OK) {
        return pre == TPC_ANSWERED ? NGX_OK : pre;
    }

    idx = brix_alloc_fhandle(ctx);
    if (idx < 0) {
        pre = brix_tpc_refuse(ctx, c, dst_path, kXR_ServerError,
                         "too many open files");
        return pre == TPC_ANSWERED ? NGX_OK : pre;
    }

    file = &ctx->files[idx];
    pre = brix_tpc_open_destination(ctx, c, conf, dst_path, options, mode_bits,
                               idx, file, &st);
    if (pre != NGX_OK) {
        return pre == TPC_ANSWERED ? NGX_OK : NGX_ERROR;
    }

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

    return tpc_send_open_response(ctx, c, idx, &st, options);
}
