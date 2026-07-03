/*
 * status.c — error carrier + kXR name lookup + shell exit-code mapping.
 *
 * WHAT: Format a human message into brix_status, name a kXR_* code, and derive a
 *       process exit code the way scripts expect.
 * WHY:  xrdcp/xrdfs print a useful diagnostic and exit non-zero in a stable way;
 *       callers branch on $? so the codes must be predictable.
 * HOW:  Local/socket faults map to 51, usage to 50, any server error to 54
 *       (mirrors XrdCl's GetShellCode bucketing closely enough for scripting; the
 *       exhaustive per-code table is deferred to the M9/M10 conformance work).
 */
#include "brix.h"
#include "core/compat/kxr_names.h"      /* shared kXR error-name table (libxrdproto) */
#include "core/compat/error_mapping.h"  /* shared kXR↔errno canonical table (libxrdproto) */

#include <errno.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

void
brix_status_clear(brix_status *st)
{
    if (st != NULL) {
        st->kxr = 0;
        st->sys_errno = 0;
        st->msg[0] = '\0';
    }
}

void
brix_status_set(brix_status *st, int kxr, int sys_errno, const char *fmt, ...)
{
    va_list ap;

    if (st == NULL) {
        return;
    }
    st->kxr = kxr;
    st->sys_errno = sys_errno;

    va_start(ap, fmt);
    vsnprintf(st->msg, sizeof(st->msg), fmt, ap);
    va_end(ap);
}

/* kXR error code -> short name. Forwards to the shared table (libxrdproto's
 * kxr_names.c) so the module and client never drift. */
const char *
brix_kxr_name(int kxr)
{
    return brix_kxr_error_name(kxr);
}

/*
 * Classify a failed status as RETRYABLE (transient — a reconnect + re-issue, or a
 * later attempt, may succeed) vs FATAL (re-issuing cannot help). The async
 * resilience layer (aio.c) uses this to decide whether to transparently reconnect
 * and re-drive a request rather than surface the error. Returns 1 = retryable.
 *
 * Retryable: transport faults (socket/connect/timeout/reset → XRDC_ESOCK), a frame
 * desync that a fresh session heals (XRDC_EPROTO), and the server's own "try again"
 * family (Overloaded / inProgress / noserver / ServerError). Everything else —
 * auth, not-found, bad-arg, exists, no-space, checksum, unsupported, local missing
 * feature support, … — is fatal: the request is well-formed but the answer is
 * "no", and retrying just amplifies load.
 */
int
brix_status_retryable(const brix_status *st)
{
    if (st == NULL || st->kxr == 0) {
        return 0;
    }
    switch (st->kxr) {
    case XRDC_ESOCK:        /* transport: connect/timeout/reset/peer-closed */
    case XRDC_EPROTO:       /* desync — a clean reconnect re-syncs framing */
    case kXR_Overloaded:    /* server explicitly busy */
    case kXR_inProgress:    /* operation transiently in progress elsewhere */
    case kXR_noserver:      /* cluster: no server right now, maybe shortly */
    case kXR_ServerError:   /* generic server-side fault, often transient */
        return 1;
    default:
        return 0;
    }
}

int
brix_shellcode(const brix_status *st)
{
    if (st == NULL || st->kxr == 0) {
        return 0;
    }
    switch (st->kxr) {
    case XRDC_ESOCK:   return 51;   /* socket/connect/timeout */
    case XRDC_ERESOLVE: return 51;  /* permanent name-resolution failure */
    case XRDC_EREDIRECT: return 52; /* redirect loop / budget exhausted */
    case XRDC_EPROTO:  return 52;   /* malformed server frame */
    case XRDC_EUSAGE:  return 50;   /* CLI / argument error */
    case XRDC_EAUTH:   return 53;   /* auth needed/failed */
    case XRDC_EINTEGRITY: return 51;/* data corruption → I/O-error class */
    case XRDC_EUNSUPPORTED: return 54; /* local feature unsupported */
    default:           return 54;   /* a server kXR_error response */
    }
}

/*
 * Map a failed status to a NEGATIVE errno, for the POSIX layers (FUSE / preload)
 * that must hand the kernel a -errno. Server kXR_* codes translate per the
 * project's canonical errno↔kXR table (CLAUDE.md); the local XRDC_E* sentinels
 * fall back to st->sys_errno when set, else a sensible default. A clean status
 * (kxr == 0) maps to 0 (success).
 */
int
brix_kxr_to_errno(const brix_status *st)
{
    int e;

    if (st == NULL || st->kxr == 0) {
        return 0;
    }

    /* Server kXR_* wire codes go through the shared canonical kXR↔errno table
     * (libxrdproto), so the two directions stay in sync with the module's
     * errno→kXR. A 0 return means "not a kXR wire error" — fall through to the
     * client-only XRDC_E* sentinel handling below. */
    e = brix_errno_from_kxr((uint16_t) st->kxr);
    if (e != 0) {
        return -e;
    }

    switch (st->kxr) {
    /* Local-side sentinels: prefer the captured sys_errno, else a default. */
    case XRDC_ESOCK:   return st->sys_errno ? -st->sys_errno : -EIO;
    case XRDC_EPROTO:  return -EPROTO;
    case XRDC_EUSAGE:  return -EINVAL;
    case XRDC_EAUTH:   return -EACCES;
    case XRDC_EINTEGRITY: return -EIO;   /* data corruption surfaces as EIO */
    case XRDC_EUNSUPPORTED: return -ENOTSUP;
    default:           return st->sys_errno ? -st->sys_errno : -EIO;
    }
}
