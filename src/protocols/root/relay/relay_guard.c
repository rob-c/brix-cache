/*
 * relay_guard.c — frame classification + drop enforcement for the relay.
 *
 * WHAT: maps decoded tap frames onto the pure-C guard core: request opcodes
 *   -> op-classes for the pre-verdict (junk path signatures / grammar),
 *   kXR_error responses -> outcomes for the post-signal (notfound/authfail),
 *   and one guard audit line per flagged frame on the relay's log.
 * WHY:  a root:// scanner probing junk paths through the relay must be cut
 *   off before the backend serves it, and weak signals must reach fail2ban
 *   in the same key=value shape the HTTP guard emits.
 * HOW:  pure mapping helpers feed guard_classify_pre/post; the only side
 *   effects are the drop flag and the audit log line. The relay pump checks
 *   the flag after every tap feed and tears the connection down.
 */

#include "core/ngx_xrootd_module.h"
#include "relay_guard.h"
#include "protocols/root/protocol/opcodes.h"
#include "fs/path/path.h"           /* xrootd_sanitize_log_string */

/* ---- kXR_* request opcode -> guard op-class ----
 *
 * WHAT: maps the wire requestid to the guard's protocol-agnostic op-class;
 *   unlisted opcodes are GUARD_OP_UNKNOWN.
 *
 * WHY: the "root" grammar profile permits op-classes, not raw opcodes, so
 *   ruleset semantics stay identical across the three guarded surfaces.
 *
 * HOW: 1. switch over the opcodes the relay can meaningfully classify
 *         (session/handshake ops map to HANDSHAKE so login flows are never
 *         grammar-bounced).
 *      2. Every other opcode inside the legal request range (kXR_auth ..
 *         kXR_clone: ping/close/sync/bind/fattr/prepare/…) is legitimate
 *         housekeeping -> INFO; only out-of-range requestids are UNKNOWN
 *         (a non-XRootD client talking to the port).
 */
static guard_op_class_t
opcode_to_op(uint16_t opcode)
{
    switch (opcode) {
    case kXR_open:
    case kXR_read:
    case kXR_readv:
    case kXR_pgread:
    case kXR_locate:
    case kXR_statx:    return GUARD_OP_READ;
    case kXR_write:
    case kXR_pgwrite:
    case kXR_writev:
    case kXR_mkdir:
    case kXR_mv:
    case kXR_chmod:
    case kXR_truncate: return GUARD_OP_WRITE;
    case kXR_dirlist:  return GUARD_OP_LIST;
    case kXR_rm:
    case kXR_rmdir:    return GUARD_OP_DELETE;
    case kXR_stat:
    case kXR_query:    return GUARD_OP_INFO;
    case kXR_prepare:  return GUARD_OP_STAGE;
    case kXR_login:
    case kXR_auth:
    case kXR_protocol:
    case kXR_bind:
    case kXR_endsess:
    case kXR_sigver:   return GUARD_OP_HANDSHAKE;
    default:
        if (opcode >= kXR_auth && opcode <= kXR_clone) {
            return GUARD_OP_INFO;     /* legal housekeeping (ping/close/…) */
        }
        return GUARD_OP_UNKNOWN;      /* off-spec requestid */
    }
}

/* ---- kXR_error errnum -> guard outcome ----
 *
 * WHAT: maps the error code carried in a kXR_error response payload (surfaced
 *   as frame->errnum by the tap) to the outcomes the guard flags.
 *
 * WHY: kXR_NotFound storms and kXR_NotAuthorized streaks are the root://
 *   equivalents of HTTP 404/401 — the same fail2ban thresholds apply.
 *
 * HOW: 1. kXR_NotFound -> NOTFOUND; kXR_NotAuthorized -> AUTHFAIL.
 *      2. Any other kXR_error -> ERROR; non-error statuses -> OK.
 */
static guard_outcome_t
errnum_to_outcome(uint16_t status, uint32_t errnum)
{
    if (status != kXR_error) {
        return OUTCOME_OK;
    }
    if (errnum == kXR_NotFound) {
        return OUTCOME_NOTFOUND;
    }
    if (errnum == kXR_NotAuthorized) {
        return OUTCOME_AUTHFAIL;
    }
    return OUTCOME_ERROR;
}

/* ---- Emit one guard audit line on the relay log ----
 *
 * WHAT: formats req/reason with the shared guard formatter (cached ISO-8601
 *   timestamp) and logs it at INFO on the relay's stable log.
 *
 * WHY: the stream relay has no per-location audit file; the error log is the
 *   operator-visible destination, and the line body keeps the exact
 *   key=value contract so it stays grep/fail2ban-parseable.
 *
 * HOW: 1. Copy the cached ISO-8601 clock (adapters own the clock).
 *      2. guard_audit_format; log only complete lines.
 */
static void
relay_guard_audit(xrootd_relay_guard_t *g, const guard_request_t *req,
    guard_reason_t reason)
{
    char    line[1280];
    char    ts[sizeof("YYYY-MM-DDThh:mm:ss+00:00")];
    size_t  ts_len;

    ts_len = ngx_cached_http_log_iso8601.len;
    if (ts_len >= sizeof(ts)) {
        ts_len = sizeof(ts) - 1;
    }
    ngx_memcpy(ts, ngx_cached_http_log_iso8601.data, ts_len);
    ts[ts_len] = '\0';

    if (guard_audit_format(req, reason, ts, line, sizeof(line)) > 0) {
        ngx_log_error(NGX_LOG_INFO, g->log, 0, "%s", line);
    }
}

/* ---- Initialize the per-relay guard state ----
 *
 * WHAT: zeroes the state; when enabled, builds the ruleset (built-in scanner
 *   signatures + "root" profile grammar) and copies the client address.
 *
 * WHY: the ruleset is per-connection state assembled once at relay start —
 *   the sink then classifies allocation-free for the connection's life.
 *
 * HOW: 1. Zero; store log; bail if disabled.
 *      2. guard_ruleset_init + default signatures + "root" profile.
 *      3. NUL-terminate the client addr_text copy (audit line ip= field).
 */
void
xrootd_relay_guard_init(xrootd_relay_guard_t *g, int enable,
    const ngx_str_t *client_addr, ngx_log_t *log)
{
    size_t ip_len;

    ngx_memzero(g, sizeof(*g));
    g->log = log;
    if (!enable) {
        return;
    }
    g->enable = 1;

    guard_ruleset_init(&g->rules);
    guard_ruleset_add_default_signatures(&g->rules);
    guard_ruleset_load_profile(&g->rules, "root");

    ip_len = client_addr->len < sizeof(g->ip) - 1
           ? client_addr->len : sizeof(g->ip) - 1;
    ngx_memcpy(g->ip, client_addr->data, ip_len);
    g->ip[ip_len] = '\0';
}

/* ---- Tap sink: classify one decoded frame ----
 *
 * WHAT: C2U request frames run the pre-verdict (signature/grammar) and set
 *   the drop flag on BOUNCE; U2C response frames run the post-signal
 *   (notfound/authfail). Either way a flagged frame emits one audit line.
 *
 * WHY: this is the whole guard enforcement surface for root:// — the relay
 *   never terminates the protocol, so classification rides the tap.
 *
 * HOW: 1. No-op when disabled.
 *      2. NUL-terminate + sanitize the wire path (INVARIANT: every logged
 *         wire string passes xrootd_sanitize_log_string).
 *      3. Requests: opcode->op, classify_pre, set drop + status=0 audit.
 *      4. Responses: errnum->outcome, classify_post.
 *      5. Log the audit line when a reason fired.
 */
void
xrootd_relay_guard_sink(void *ctx, const xrootd_tap_frame_t *f,
    xrootd_tap_dir_t dir, const uint8_t *payload, size_t payload_len)
{
    xrootd_relay_guard_t *g = ctx;
    guard_request_t       req;
    guard_reason_t        why = GUARD_R_NONE;
    char                  raw_path[XROOTD_TAP_PATH_CAP + 1];
    char                  san_path[XROOTD_TAP_PATH_CAP + 1];
    size_t                raw_len = 0;

    (void) payload;
    (void) payload_len;

    if (!g->enable || g->drop) {
        return;
    }

    if (f->path != NULL && f->path_len > 0) {
        raw_len = f->path_len < XROOTD_TAP_PATH_CAP
                ? f->path_len : XROOTD_TAP_PATH_CAP;
        ngx_memcpy(raw_path, f->path, raw_len);
    }
    raw_path[raw_len] = '\0';

    req.ip           = g->ip;
    req.proto        = "root";
    req.path_len     = xrootd_sanitize_log_string(raw_path, san_path,
                                                  sizeof(san_path));
    req.path         = san_path;
    req.cred_present = 0;      /* the relay never sees the credential */
    req.status_code  = 0;

    if (dir == XROOTD_TAP_C2U && f->is_request) {
        req.op      = opcode_to_op(f->opcode);
        req.outcome = OUTCOME_PENDING;
        if (guard_classify_pre(&g->rules, &req, &why) == GUARD_BOUNCE) {
            g->drop = 1;          /* the pump tears the relay down */
        }
    } else if (dir == XROOTD_TAP_U2C && !f->is_request) {
        req.op          = GUARD_OP_UNKNOWN;
        req.status_code = (int) f->status;
        req.outcome     = errnum_to_outcome(f->status, f->errnum);
        why             = guard_classify_post(&g->rules, &req);
    }

    if (why != GUARD_R_NONE) {
        relay_guard_audit(g, &req, why);
    }
}

/* ---- Drop-flag accessor for the relay pump ----
 *
 * WHAT: returns 1 once a classified frame demanded connection teardown.
 *
 * WHY: the pump owns the connection lifecycle; the sink only records the
 *   verdict (no side effects on connections from inside a tap callback).
 *
 * HOW: 1. Read the flag.
 */
int
xrootd_relay_guard_should_drop(const xrootd_relay_guard_t *g)
{
    return g->drop;
}
