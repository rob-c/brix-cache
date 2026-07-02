/*
 * guard_audit.c — fail2ban audit line formatting.
 *
 * WHAT: renders one flagged request as a single stable key=value line, plus
 *   the reason/op-class token maps the line (and the fail2ban filters) use.
 * WHY:  the audit line IS the fail2ban contract — field order and token
 *   spelling are load-bearing; keeping the formatter pure and in one place
 *   guarantees every adapter emits the identical shape.
 * HOW:  snprintf into a caller buffer; adapters own the clock (ts string) and
 *   path sanitization, mirroring src/net/tap/tap_audit.c.
 */
#include "guard.h"
#include <stdio.h>

/* ---- Reason -> stable lowercase token ----
 *
 * WHAT: returns the audit-line token for a guard_reason_t ("signature",
 *   "grammar", "notfound", "authfail", "none").
 *
 * WHY: fail2ban filters match `signal=<token>` literally — the spelling here
 *   and in deploy/fail2ban/filter.d/ must never drift apart.
 *
 * HOW: 1. Switch over the enum; unknown values map to "none".
 */
const char *
guard_reason_str(guard_reason_t r)
{
    switch (r) {
    case GUARD_R_SIGNATURE: return "signature";
    case GUARD_R_GRAMMAR:   return "grammar";
    case GUARD_R_NOTFOUND:  return "notfound";
    case GUARD_R_AUTHFAIL:  return "authfail";
    case GUARD_R_NONE:      default: return "none";
    }
}

/* ---- Op-class -> stable lowercase token ----
 *
 * WHAT: returns the audit-line token for a guard_op_class_t.
 *
 * WHY: gives operators grep-able op context in the audit log without
 *   exposing protocol-specific opcode numbers.
 *
 * HOW: 1. Switch over the enum; unknown values map to "unknown".
 */
const char *
guard_op_str(guard_op_class_t op)
{
    switch (op) {
    case GUARD_OP_READ:      return "read";
    case GUARD_OP_WRITE:     return "write";
    case GUARD_OP_LIST:      return "list";
    case GUARD_OP_DELETE:    return "delete";
    case GUARD_OP_JOBCTL:    return "jobctl";
    case GUARD_OP_STAGE:     return "stage";
    case GUARD_OP_INFO:      return "info";
    case GUARD_OP_DELEG:     return "deleg";
    case GUARD_OP_HANDSHAKE: return "handshake";
    case GUARD_OP_UNKNOWN:   default: return "unknown";
    }
}

/* ---- Format one flagged request as a key=value audit line ----
 *
 * WHAT: writes `<ts> ip=<ip> proto=<proto> signal=<reason> op=<op>
 *   path="<path>" status=<code>` into out[0..outsz). Returns bytes written
 *   (excluding the NUL), or 0 if the line would not fit (nothing partial is
 *   ever emitted).
 *
 * WHY: single-line, fixed field order is what the fail2ban failregex and the
 *   operator's grep both key on; a truncated line could split an attacker's
 *   path across the status field, so it is all-or-nothing.
 *
 * HOW: 1. One snprintf with the caller's pre-sanitized fields (the adapter
 *         escaped control/quote bytes; the formatter only wraps in quotes).
 *      2. Treat encoding errors and truncation as "does not fit" -> 0.
 */
size_t
guard_audit_format(const guard_request_t *req, guard_reason_t reason,
    const char *ts, char *out, size_t outsz)
{
    int written;

    written = snprintf(out, outsz,
        "%s ip=%s proto=%s signal=%s op=%s path=\"%.*s\" status=%d",
        ts, req->ip, req->proto, guard_reason_str(reason),
        guard_op_str(req->op), (int) req->path_len, req->path,
        req->status_code);
    if (written < 0 || (size_t) written >= outsz) {
        return 0;                       /* truncated -> emit nothing */
    }
    return (size_t) written;
}
