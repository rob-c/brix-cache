/*
 * residency.c — file residency probe + marker (the "is it on disk vs tape" gate).
 *
 * WHAT: frm_residency_probe() classifies a file as ONLINE (resident),
 *   NEARLINE/OFFLINE (on the backend, needs staging), or LOST (gone);
 *   frm_residency_set() writes/clears the marker (the stage worker flips
 *   nearline → online when a recall completes).
 *
 * WHY: This is the single source of truth every protocol face calls
 *   (stream stat/statx/open, WebDAV PROPFIND, S3 HEAD) so residency reporting
 *   never drifts between them. The marker is the `user.frm.residency` xattr on a
 *   disk stub: a present file with xattr "nearline"/"offline" is non-resident;
 *   absent xattr (or "online") means resident — so EXISTING exports need no
 *   migration (zero xattrs ⇒ everything reads as ONLINE).
 *
 * HOW: stat() the absolute export path (already confined by the caller). Missing
 *   → LOST. Present → read the xattr and map it. The stub model matches dCache /
 *   HSM gateways: a 0-byte (or placeholder) file carries the marker until a
 *   recall overwrites it with real bytes and clears the marker.
 */

#include "frm.h"

#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/xattr.h>

#define FRM_RES_XATTR  "user.frm.residency"

/*
 * phase-46 W2b: process-global "FRM configured" flag.  Set once at
 * postconfiguration in the master before any worker forks (so every worker
 * inherits the value — no atomics needed, write-once then read-only).  When it
 * stays 0, FRM was never enabled, no object carries a residency marker, and
 * frm_residency_probe() short-circuits to ONLINE without a stat+getxattr.
 */
static int frm_g_configured = 0;

void
frm_mark_configured(void)
{
    frm_g_configured = 1;
}

int
frm_is_configured(void)
{
    return frm_g_configured;
}


static frm_residency_state_t
frm_res_parse(const char *s)
{
    if (ngx_strncmp(s, "nearline", 8) == 0) { return FRM_RES_NEARLINE; }
    if (ngx_strncmp(s, "offline", 7)  == 0) { return FRM_RES_OFFLINE; }
    if (ngx_strncmp(s, "lost", 4)     == 0) { return FRM_RES_LOST; }
    return FRM_RES_ONLINE;                 /* "online" / anything else */
}

/* Read the residency marker. NGX_OK + *out on success; NGX_DECLINED if absent. */
static ngx_int_t
frm_res_xattr_read(const char *path, frm_residency_state_t *out)
{
    char    buf[32];
    ssize_t n = getxattr(path, FRM_RES_XATTR, buf, sizeof(buf) - 1);

    if (n < 0) {
        return NGX_DECLINED;               /* ENODATA / unsupported → no marker */
    }
    buf[n] = '\0';
    *out = frm_res_parse(buf);
    return NGX_OK;
}


ngx_int_t
frm_residency_probe(ngx_log_t *log, const char *full_path, frm_residency_t *out)
{
    struct stat            st;
    frm_residency_state_t  xstate;

    out->state          = FRM_RES_UNKNOWN;
    out->backend_exists = 0;

    if (full_path == NULL) {
        return NGX_ERROR;
    }

    /*
     * phase-46 W2b: FRM was never configured on this process → no object can
     * carry a residency marker, so every file is ONLINE.  Skip the stat+getxattr
     * the rest of this function would do.  Callers that need existence (S3
     * GET/HEAD, WebDAV PROPFIND) have already opened/stat'd the object, so the
     * LOST-on-missing branch below is not needed here — matching how the native
     * stat/open paths simply don't call this probe when conf->frm.enable is off.
     */
    if (!frm_g_configured) {
        out->state = FRM_RES_ONLINE;
        return NGX_OK;
    }

    if (stat(full_path, &st) != 0) {
        out->state = FRM_RES_LOST;         /* not on disk at all */
        return NGX_OK;
    }
    if (!S_ISREG(st.st_mode)) {
        out->state = FRM_RES_ONLINE;       /* dirs etc. are never "nearline" */
        return NGX_OK;
    }

    if (frm_res_xattr_read(full_path, &xstate) == NGX_OK
        && (xstate == FRM_RES_NEARLINE
            || xstate == FRM_RES_OFFLINE
            || xstate == FRM_RES_LOST))
    {
        out->state          = xstate;
        out->backend_exists = 1;           /* a backend copy is implied         */
        return NGX_OK;
    }

    out->state = FRM_RES_ONLINE;
    return NGX_OK;
}


ngx_int_t
frm_residency_set(ngx_log_t *log, const char *full_path,
                  frm_residency_state_t state)
{
    const char *v;

    if (full_path == NULL) {
        return NGX_ERROR;
    }

    if (state == FRM_RES_ONLINE) {
        /* Resident == no marker (matches the absent-xattr default). */
        if (removexattr(full_path, FRM_RES_XATTR) != 0 && errno != ENODATA) {
            ngx_log_error(NGX_LOG_WARN, log, ngx_errno,
                          "frm: removexattr residency on \"%s\"", full_path);
        }
        return NGX_OK;
    }

    switch (state) {
    case FRM_RES_NEARLINE: v = "nearline"; break;
    case FRM_RES_OFFLINE:  v = "offline";  break;
    case FRM_RES_LOST:     v = "lost";     break;
    default:               v = "online";   break;
    }
    if (setxattr(full_path, FRM_RES_XATTR, v, ngx_strlen(v), 0) != 0) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                      "frm: setxattr residency=\"%s\" on \"%s\"", v, full_path);
        return NGX_ERROR;
    }
    return NGX_OK;
}
