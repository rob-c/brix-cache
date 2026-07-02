/*
 * audit.c — authorization grant/deny audit log (XrdAccAudit).
 *
 * WHAT: xrootd_acc_audit() emits one structured line per authorization decision
 *   when auditing is enabled — deny-only, grant-only, or both — mirroring
 *   XRootD's `acc.audit`.  Untrusted fields (id, host, path come off the wire)
 *   are sanitised so a crafted path cannot inject log lines.
 *
 * WHY: operators need an auth trail; the `native` engine only logs denials ad
 *   hoc.  This is the XrdAcc-parity audit sink, gated by xrootd_authdb_audit.
 *
 * HOW: a level bitmask (1=deny, 2=grant) decides whether to log; the line is
 *   "<id>@<host> grant|deny <op> <path>" with control/quote bytes escaped.
 */

#include "acc.h"

#define XROOTD_ACC_AUDIT_DENY   0x1
#define XROOTD_ACC_AUDIT_GRANT  0x2

/* Copy src into dst (capacity cap) escaping control bytes, quotes and
 * backslashes to keep the audit line single-valued and injection-safe. */
static void
acc_audit_sanitize(u_char *dst, size_t cap, const char *src)
{
    size_t i = 0;

    if (src == NULL) { src = "-"; }
    while (*src && i + 4 < cap) {
        u_char c = (u_char) *src++;
        if (c == '\\' || c == '"') {
            dst[i++] = '\\';
            dst[i++] = c;
        } else if (c < 0x20 || c >= 0x7f) {
            dst[i++] = '?';
        } else {
            dst[i++] = c;
        }
    }
    dst[i] = '\0';
}

void
xrootd_acc_audit(ngx_log_t *log, ngx_uint_t level, int granted,
                 const char *op, const char *id, const char *host,
                 const char *path)
{
    u_char  idbuf[256], hostbuf[256], pathbuf[1024];

    if (level == 0) {
        return;
    }
    if (granted && !(level & XROOTD_ACC_AUDIT_GRANT)) {
        return;
    }
    if (!granted && !(level & XROOTD_ACC_AUDIT_DENY)) {
        return;
    }

    acc_audit_sanitize(idbuf, sizeof(idbuf), id);
    acc_audit_sanitize(hostbuf, sizeof(hostbuf), host);
    acc_audit_sanitize(pathbuf, sizeof(pathbuf), path);

    ngx_log_error(NGX_LOG_NOTICE, log, 0,
                  "xrootd authz: %s@%s %s %s \"%s\"",
                  idbuf, hostbuf, granted ? "grant" : "deny",
                  (op != NULL) ? op : "?", pathbuf);
}
