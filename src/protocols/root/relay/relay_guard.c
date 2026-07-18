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

#include "core/ngx_brix_module.h"
#include "relay_guard.h"
#include "protocols/root/protocol/opcodes.h"
#include "fs/path/path.h"           /* brix_sanitize_log_string */

/* ---- kXR_* request opcode -> guard op-class ----
 *
 * WHAT: dense op-class table over the legal request range [kXR_auth,
 *   kXR_clone], indexed by opcode - kXR_auth; unlisted/off-spec opcodes are
 *   GUARD_OP_UNKNOWN.
 *
 * WHY: the "root" grammar profile permits op-classes, not raw opcodes, so
 *   ruleset semantics stay identical across the three guarded surfaces; a
 *   static const table (phase-72 D4 kxr_names pattern) reads as a flat spec
 *   instead of a branch ladder and keeps the mapping auditable at a glance.
 *
 * HOW: 1. Every opcode inside the legal request range carries an explicit
 *         entry — the read/write/list/delete data ops map to their action
 *         classes, session/handshake ops map to HANDSHAKE (login flows are
 *         never grammar-bounced), and the remaining housekeeping ops
 *         (ping/close/sync/gpfile/set/fattr/clone) map to INFO.
 *      2. opcode_to_op() indexes the table; anything outside the range is a
 *         non-XRootD client talking to the port -> GUARD_OP_UNKNOWN.
 */
static const guard_op_class_t  opcode_op_class[kXR_clone - kXR_auth + 1] = {
    /* phase79-fp: misc-redundant-expression — `kXR_auth - kXR_auth` is the
     * deliberate `[opcode - kXR_auth]` base-offset idiom shared by every row; the
     * zero-valued first index is intentional, not a copy-paste mistake. */
    [kXR_auth     - kXR_auth] = GUARD_OP_HANDSHAKE,
    [kXR_query    - kXR_auth] = GUARD_OP_INFO,
    [kXR_chmod    - kXR_auth] = GUARD_OP_WRITE,
    [kXR_close    - kXR_auth] = GUARD_OP_INFO,
    [kXR_dirlist  - kXR_auth] = GUARD_OP_LIST,
    [kXR_gpfile   - kXR_auth] = GUARD_OP_INFO,
    [kXR_protocol - kXR_auth] = GUARD_OP_HANDSHAKE,
    [kXR_login    - kXR_auth] = GUARD_OP_HANDSHAKE,
    [kXR_mkdir    - kXR_auth] = GUARD_OP_WRITE,
    [kXR_mv       - kXR_auth] = GUARD_OP_WRITE,
    [kXR_open     - kXR_auth] = GUARD_OP_READ,
    [kXR_ping     - kXR_auth] = GUARD_OP_INFO,
    [kXR_chkpoint - kXR_auth] = GUARD_OP_WRITE,
    [kXR_read     - kXR_auth] = GUARD_OP_READ,
    [kXR_rm       - kXR_auth] = GUARD_OP_DELETE,
    [kXR_rmdir    - kXR_auth] = GUARD_OP_DELETE,
    [kXR_sync     - kXR_auth] = GUARD_OP_INFO,
    [kXR_stat     - kXR_auth] = GUARD_OP_INFO,
    [kXR_set      - kXR_auth] = GUARD_OP_INFO,
    [kXR_write    - kXR_auth] = GUARD_OP_WRITE,
    [kXR_fattr    - kXR_auth] = GUARD_OP_INFO,
    [kXR_prepare  - kXR_auth] = GUARD_OP_STAGE,
    [kXR_statx    - kXR_auth] = GUARD_OP_READ,
    [kXR_endsess  - kXR_auth] = GUARD_OP_HANDSHAKE,
    [kXR_bind     - kXR_auth] = GUARD_OP_HANDSHAKE,
    [kXR_readv    - kXR_auth] = GUARD_OP_READ,
    [kXR_pgwrite  - kXR_auth] = GUARD_OP_WRITE,
    [kXR_locate   - kXR_auth] = GUARD_OP_READ,
    [kXR_truncate - kXR_auth] = GUARD_OP_WRITE,
    [kXR_sigver   - kXR_auth] = GUARD_OP_HANDSHAKE,
    [kXR_pgread   - kXR_auth] = GUARD_OP_READ,
    [kXR_writev   - kXR_auth] = GUARD_OP_WRITE,
    [kXR_clone    - kXR_auth] = GUARD_OP_INFO,
};

static guard_op_class_t
opcode_to_op(uint16_t opcode)
{
    if (opcode < kXR_auth || opcode > kXR_clone) {
        return GUARD_OP_UNKNOWN;      /* off-spec requestid */
    }
    return opcode_op_class[opcode - kXR_auth];
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
relay_guard_audit(brix_relay_guard_t *g, const guard_request_t *req,
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
brix_relay_guard_init(brix_relay_guard_t *g, int enable,
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

/* ---- First-bytes wire check: is this even a root:// client? ----
 *
 * WHAT: runs the pure-C handshake classifier over the opening
 *   client->upstream bytes. A genuine kXR handshake (or its still-incomplete
 *   zero-prefix) is let through; anything else sets the drop flag and emits
 *   one signal=notroot audit line naming the wire (tls/http/ssh/junk).
 *
 * WHY: the tap sink only classifies DECODED kXR frames — a client that never
 *   speaks root produces no frame and would reach the backend unclassified.
 *   This closes the "who is knocking on the root port" gap the tap cannot see,
 *   and does it before the first chunk is forwarded.
 *
 * HOW: 1. One-shot: skip when disabled, already dropped, or already decided.
 *      2. Accumulate the opening bytes (the pump hands each recv() chunk
 *         separately, so a handshake split across TCP segments must be
 *         reassembled here before classifying — fail-open on fragmentation).
 *      3. Classify; defer (return, leaving hs_seen unset) while a zero-prefix
 *         is still shorter than the signature — the next chunk retries.
 *      4. Root -> latch the verdict and let the pump forward normally.
 *      5. Non-root -> drop + audit; the wire token rides the (sanitized) path.
 */
void
brix_relay_guard_handshake(brix_relay_guard_t *g,
    const unsigned char *buf, size_t len)
{
    guard_wire_t     wire;
    int              need_more;
    guard_request_t  req;
    const char      *tok;
    char             raw_tok[64];
    char             san_tok[64];
    size_t           tok_len;
    size_t           take;

    if (!g->enable || g->drop || g->hs_seen) {
        return;
    }

    /* Accumulate up to the 20-byte signature across fragmented chunks. */
    take = sizeof(g->hs_buf) - g->hs_len;
    if (take > len) {
        take = len;
    }
    if (take > 0) {
        ngx_memcpy(g->hs_buf + g->hs_len, buf, take);
        g->hs_len += (unsigned char) take;
    }

    wire = guard_classify_handshake(g->hs_buf, g->hs_len, &need_more);
    if (wire == GUARD_WIRE_ROOT && need_more) {
        return;                     /* zero-prefix so far: wait for more bytes */
    }
    g->hs_seen = 1;                 /* verdict reached: never re-check */

    if (wire == GUARD_WIRE_ROOT) {
        return;                     /* genuine kXR client -> forward normally */
    }

    tok     = guard_wire_str(wire);
    tok_len = ngx_strlen(tok);
    if (tok_len > sizeof(raw_tok) - 1) {
        tok_len = sizeof(raw_tok) - 1;
    }
    ngx_memcpy(raw_tok, tok, tok_len);
    raw_tok[tok_len] = '\0';

    req.ip           = g->ip;
    req.proto        = "root";
    req.op           = GUARD_OP_HANDSHAKE;
    req.path_len     = brix_sanitize_log_string(raw_tok, san_tok,
                                                 sizeof(san_tok));
    req.path         = san_tok;
    req.cred_present = 0;
    req.outcome      = OUTCOME_PENDING;
    req.status_code  = 0;

    g->drop = 1;                    /* the pump tears the relay down */
    relay_guard_audit(g, &req, GUARD_R_NOTROOT);
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
 *         wire string passes brix_sanitize_log_string).
 *      3. Requests: opcode->op, classify_pre, set drop + status=0 audit.
 *      4. Responses: errnum->outcome, classify_post.
 *      5. Log the audit line when a reason fired.
 */
void
brix_relay_guard_sink(void *ctx, const brix_tap_frame_t *f,
    brix_tap_dir_t dir, const uint8_t *payload, size_t payload_len)
{
    brix_relay_guard_t *g = ctx;
    guard_request_t       req;
    guard_reason_t        why = GUARD_R_NONE;
    char                  raw_path[BRIX_TAP_PATH_CAP + 1];
    char                  san_path[BRIX_TAP_PATH_CAP + 1];
    size_t                raw_len = 0;

    (void) payload;
    (void) payload_len;

    if (!g->enable || g->drop) {
        return;
    }

    if (f->path != NULL && f->path_len > 0) {
        raw_len = f->path_len < BRIX_TAP_PATH_CAP
                ? f->path_len : BRIX_TAP_PATH_CAP;
        ngx_memcpy(raw_path, f->path, raw_len);
    }
    raw_path[raw_len] = '\0';

    req.ip           = g->ip;
    req.proto        = "root";
    req.path_len     = brix_sanitize_log_string(raw_path, san_path,
                                                  sizeof(san_path));
    req.path         = san_path;
    req.cred_present = 0;      /* the relay never sees the credential */
    req.status_code  = 0;

    if (dir == BRIX_TAP_C2U && f->is_request) {
        req.op      = opcode_to_op(f->opcode);
        req.outcome = OUTCOME_PENDING;
        if (guard_classify_pre(&g->rules, &req, &why) == GUARD_BOUNCE) {
            g->drop = 1;          /* the pump tears the relay down */
        }
    } else if (dir == BRIX_TAP_U2C && !f->is_request) {
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
brix_relay_guard_should_drop(const brix_relay_guard_t *g)
{
    return g->drop;
}
