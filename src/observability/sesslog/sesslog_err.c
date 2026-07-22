#include "observability/sesslog/sesslog.h"
#include "protocols/root/protocol/opcodes.h"

#include <errno.h>
#include <stdio.h>

/*
 * WHAT: One (numeric code -> stable token) mapping row.
 * WHY: The three err-from-* families share an identical shape — a small fixed
 * set of codes collapsing onto a low-cardinality token — so expressing each as
 * data (a table) rather than a switch ladder removes the per-family branching
 * complexity while keeping the emitted strings byte-identical.
 * HOW: Plain value struct scanned linearly by brix_sess_err_lookup().
 */
typedef struct {
    int         code;
    const char *token;
} brix_sess_err_entry_t;

/*
 * WHAT: Resolve a numeric code against a fixed mapping table, returning the
 * matched token or a formatted "code:<n>" fallback.
 * WHY: All three public err-from-* accessors want the same lookup-then-fallback
 * behaviour; centralising it keeps the fallback formatting (and the scratch/NULL
 * contract) in exactly one place.
 * HOW: (1) Linearly scan the table for an exact code match and return its token.
 * (2) On no match, write "code:<code>" into scratch when a buffer is supplied,
 * otherwise return the static "code:0" sentinel — matching the prior default arm.
 */
static const char *
brix_sess_err_lookup(const brix_sess_err_entry_t *table, size_t count,
    int code, char *scratch, size_t n)
{
    size_t i;

    for (i = 0; i < count; i++) {
        if (table[i].code == code) {
            return table[i].token;
        }
    }

    if (scratch != NULL && n > 0) {
        snprintf(scratch, n, "code:%d", code);
        return scratch;
    }

    return "code:0";
}

/*
 * errno -> stable sesslog token map. EDQUOT/EOPNOTSUPP are conditionally present
 * because they are not defined on every platform; keeping them behind the same
 * #ifdef guards as the former switch arms preserves byte-identical behaviour.
 */
static const brix_sess_err_entry_t  brix_sess_errno_table[] = {
    { ENOENT,       "not-found" },
    { ENOTDIR,      "not-found" },
    { EACCES,       "permission" },
    { EPERM,        "permission" },
    { EINVAL,       "invalid" },
    { ENAMETOOLONG, "invalid" },
    { EIO,          "io" },
    { ENOMEM,       "no-memory" },
    { ENOSPC,       "no-space" },
#ifdef EDQUOT
    { EDQUOT,       "no-space" },
#endif
    { EEXIST,       "exists" },
    { EBUSY,        "busy" },
#ifdef EOPNOTSUPP
    { EOPNOTSUPP,   "unsupported" },
#endif
    { ETIMEDOUT,    "timeout" },
};

/* XRootD kXR_* error code -> stable sesslog token map. */
static const brix_sess_err_entry_t  brix_sess_kxr_table[] = {
    { kXR_NotFound,       "not-found" },
    { kXR_NotFile,        "not-found" },
    { kXR_isDirectory,    "not-found" },
    { kXR_AttrNotFound,   "not-found" },
    { kXR_NotAuthorized,  "permission" },
    { kXR_fsReadOnly,     "permission" },
    { kXR_ArgInvalid,     "invalid" },
    { kXR_ArgMissing,     "invalid" },
    { kXR_ArgTooLong,     "invalid" },
    { kXR_Conflict,       "invalid" },
    { kXR_Impossible,     "invalid" },
    { kXR_IOError,        "io" },
    { kXR_FSError,        "io" },
    { kXR_ServerError,    "io" },
    { kXR_ChkSumErr,      "io" },
    { kXR_NoMemory,       "no-memory" },
    { kXR_NoSpace,        "no-space" },
    { kXR_overQuota,      "no-space" },
    { kXR_FileLocked,     "locked" },
    { kXR_InvalidRequest, "exists" },
    { kXR_ItExists,       "exists" },
    { kXR_inProgress,     "busy" },
    { kXR_Overloaded,     "busy" },
    { kXR_Unsupported,    "unsupported" },
    { kXR_TLSRequired,    "auth-required" },
    { kXR_AuthFailed,     "bad-signature" },
    { kXR_Cancelled,      "session-closed" },
};

/* HTTP status code -> stable sesslog token map. */
static const brix_sess_err_entry_t  brix_sess_http_table[] = {
    { 400, "invalid" },
    { 401, "auth-required" },
    { 403, "permission" },
    { 404, "not-found" },
    { 405, "unsupported" },
    { 501, "unsupported" },
    { 409, "exists" },
    { 412, "exists" },
    { 423, "locked" },
    { 500, "io" },
    { 502, "io" },
    { 503, "busy" },
    { 504, "timeout" },
    { 507, "no-space" },
};

/*
 * WHAT: Map POSIX errno values to stable sesslog err tokens.
 * WHY: Raw strerror text is locale- and platform-dependent; operators need
 * low-cardinality tokens.
 * HOW: Look the code up in brix_sess_errno_table, falling back to code:<n>.
 */
const char *
brix_sesslog_err_from_errno(int err, char *scratch, size_t n)
{
    return brix_sess_err_lookup(brix_sess_errno_table,
        sizeof(brix_sess_errno_table) / sizeof(brix_sess_errno_table[0]),
        err, scratch, n);
}

/*
 * WHAT: Map XRootD kXR_* error codes to stable sesslog err tokens.
 * WHY: Operators need one low-cardinality token per class of wire error rather
 * than the raw numeric kXR code.
 * HOW: Look the code up in brix_sess_kxr_table, falling back to code:<n>.
 */
const char *
brix_sesslog_err_from_kxr(int kxr, char *scratch, size_t n)
{
    return brix_sess_err_lookup(brix_sess_kxr_table,
        sizeof(brix_sess_kxr_table) / sizeof(brix_sess_kxr_table[0]),
        kxr, scratch, n);
}

/*
 * WHAT: Map HTTP status codes to stable sesslog err tokens.
 * WHY: The WebDAV/S3 paths report failures as HTTP status; operators want the
 * same token vocabulary the errno/kXR mappers emit.
 * HOW: Look the status up in brix_sess_http_table, falling back to code:<n>.
 */
const char *
brix_sesslog_err_from_http(int status, char *scratch, size_t n)
{
    return brix_sess_err_lookup(brix_sess_http_table,
        sizeof(brix_sess_http_table) / sizeof(brix_sess_http_table[0]),
        status, scratch, n);
}
