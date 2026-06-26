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
#include "frm_internal.h"   /* frm_lfn_hash (shared FNV-1a-64 path hash) */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

#define FRM_RES_XATTR  "user.frm.residency"

/*
 * Where the residency marker lives.  Empty (the default) = on the export object
 * itself (a `user.frm.residency` xattr on the disk stub) — the POSIX model, and
 * the behaviour every existing deployment relies on.
 *
 * When the primary storage is NON-POSIX (S3/block) the export object cannot carry
 * a POSIX xattr, so the marker moves to a LOCAL POSIX "control" mount: one flat
 * stub per logical name, keyed by a hash of the absolute path, holding the same
 * xattr.  This is the storage-agnostic answer to "where does the stub live" — a
 * control plane separate from the data, alongside the staging scratch mount.
 * Seeded once in the master (frm_mark_configured) from xrootd_frm_control_dir so
 * every worker inherits it (write-once, then read-only — no atomics).
 */
/* Sized below PATH_MAX so the "<dir>/<16hex>.res" stub path provably fits in a
 * PATH_MAX buffer (silences -Werror=format-truncation; a real control mount path
 * is far shorter). */
static char frm_g_control_dir[PATH_MAX - 64];

/* The filesystem path of the residency marker for `full_path`: the object itself
 * (export model), or a flat hashed control stub (control model). */
static void
frm_res_marker_path(const char *full_path, char *out, size_t outsz)
{
    if (frm_g_control_dir[0] == '\0') {
        ngx_cpystrn((u_char *) out, (u_char *) full_path, outsz);
        return;
    }
    /* FNV-1a over the absolute path (shared frm_lfn_hash) → a
     * collision-free-in-practice flat stub, so the control mount needs no
     * mirrored directory tree. */
    (void) snprintf(out, outsz, "%s/%016llx.res", frm_g_control_dir,
                    (unsigned long long) frm_lfn_hash(full_path));
}

/*
 * phase-46 W2b: process-global "FRM configured" flag.  Set once at
 * postconfiguration in the master before any worker forks (so every worker
 * inherits the value — no atomics needed, write-once then read-only).  When it
 * stays 0, FRM was never enabled, no object carries a residency marker, and
 * frm_residency_probe() short-circuits to ONLINE without a stat+getxattr.
 */
static int frm_g_configured = 0;

void
frm_mark_configured(const char *control_dir)
{
    frm_g_configured = 1;

    /* xrootd_frm_control_dir: a local POSIX control mount for residency markers
     * when the primary storage cannot carry an xattr (see frm_g_control_dir). */
    if (control_dir != NULL && control_dir[0] != '\0') {
        ngx_cpystrn((u_char *) frm_g_control_dir, (u_char *) control_dir,
                    sizeof(frm_g_control_dir));
    }
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

    {
        char marker[PATH_MAX];
        int  control = (frm_g_control_dir[0] != '\0');

        frm_res_marker_path(full_path, marker, sizeof(marker));

        if (stat(marker, &st) != 0) {
            if (!control) {
                /* Export model: the marker IS the object — absent ⇒ LOST. */
                out->state = FRM_RES_LOST;
                return NGX_OK;
            }
            /* Control model: no stub ⇒ not nearline/offline.  The object is then
             * either resident (ONLINE) or genuinely gone (LOST); resolve that by
             * the storage object's existence rather than blindly assuming ONLINE.
             * POSIX backend = stat the export path; a non-POSIX backend would route
             * this through storage->driver->stat (metadata, not a data path). */
            {
                struct stat ost;
                out->state = (stat(full_path, &ost) == 0 && S_ISREG(ost.st_mode))
                             ? FRM_RES_ONLINE : FRM_RES_LOST;
            }
            return NGX_OK;
        }
        if (!control && !S_ISREG(st.st_mode)) {
            out->state = FRM_RES_ONLINE;   /* dirs etc. are never "nearline" */
            return NGX_OK;
        }

        if (frm_res_xattr_read(marker, &xstate) == NGX_OK
            && (xstate == FRM_RES_NEARLINE
                || xstate == FRM_RES_OFFLINE
                || xstate == FRM_RES_LOST))
        {
            out->state          = xstate;
            out->backend_exists = 1;       /* a backend copy is implied         */
            return NGX_OK;
        }
    }

    out->state = FRM_RES_ONLINE;
    return NGX_OK;
}


ngx_int_t
frm_residency_set(ngx_log_t *log, const char *full_path,
                  frm_residency_state_t state)
{
    const char *v;
    char        marker[PATH_MAX];
    int         control = (frm_g_control_dir[0] != '\0');

    if (full_path == NULL) {
        return NGX_ERROR;
    }
    frm_res_marker_path(full_path, marker, sizeof(marker));

    if (state == FRM_RES_ONLINE) {
        /* Resident == no marker (matches the absent-xattr default).  In the
         * control model that means dropping the whole stub; in the export model,
         * just the xattr. */
        if (control) {
            (void) unlink(marker);
            return NGX_OK;
        }
        if (removexattr(marker, FRM_RES_XATTR) != 0 && errno != ENODATA) {
            ngx_log_error(NGX_LOG_WARN, log, ngx_errno,
                          "frm: removexattr residency on \"%s\"", marker);
        }
        return NGX_OK;
    }

    /* Non-online: the control model needs the flat stub to exist before it can
     * carry the marker xattr. */
    if (control) {
        int fd = open(marker, O_CREAT | O_WRONLY | O_CLOEXEC, 0600);
        if (fd < 0) {
            ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                          "frm: residency stub create \"%s\"", marker);
            return NGX_ERROR;
        }
        close(fd);
    }

    switch (state) {
    case FRM_RES_NEARLINE: v = "nearline"; break;
    case FRM_RES_OFFLINE:  v = "offline";  break;
    case FRM_RES_LOST:     v = "lost";     break;
    default:               v = "online";   break;
    }
    if (setxattr(marker, FRM_RES_XATTR, v, ngx_strlen(v), 0) != 0) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                      "frm: setxattr residency=\"%s\" on \"%s\"", v, marker);
        return NGX_ERROR;
    }
    return NGX_OK;
}
