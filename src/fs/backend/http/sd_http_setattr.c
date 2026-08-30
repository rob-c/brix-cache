/*
 * sd_http_setattr.c — advisory POSIX metadata over WebDAV dead properties: the
 * http driver's setattr pair.
 *
 * WHAT: `setattr` / `setattr_cred` — kXR_chmod and kXR_setattr against an HTTP
 *       origin, persisted as the ONE reserved dead property every object
 *       backend shares (BRIX_META_ADVISORY_XATTR), read-modify-written.
 *
 * WHY:  RFC 4918 gives a resource a display name, a length and two timestamps;
 *       it gives it no mode, no owner and no settable mtime. Without this slot
 *       the VFS read the missing driver entry as "nothing to do" and told the
 *       client a chmod had succeeded that never left this host — the same silent
 *       lie the ceph and s3 drivers used to tell, and it is worse over WebDAV
 *       than anywhere else because the http driver already carries a full
 *       xattr plane, so the metadata had a home and simply was not being put in
 *       it. The advisory blob is what stat() overlays, so a mode written here is
 *       the mode the next stat reports.
 *
 * HOW:  Composed entirely from slots this driver already exports — the sentinel
 *       translation (brix_meta_advisory_from_setattr), one named-prop PROPFIND
 *       (sd_http_getxattr_common) and one PROPPATCH (sd_http_setxattr_cred) —
 *       so there is no second wire spelling of the property and no second
 *       credential path. A request carrying nothing representable returns
 *       success BEFORE the round trip: an atime-only setattr costs no requests.
 *       Existence needs no probe of its own: PROPPATCH on an absent resource is
 *       404, which the property writer already maps to ENOENT, so this file
 *       never has to decide whether a resource exists.
 */

#include "sd_http_internal.h"
#include "sd_http_xattr_internal.h"      /* sd_http_getxattr_common */

#include "fs/backend/meta_advisory.h"
#include "fs/backend/meta_advisory_sd.h"

#include <errno.h>
#include <string.h>

/* The encoded blob is short and bounded by the codec's own grammar (a version
 * token plus five small integers); this is the same ceiling the ceph and s3
 * carriers use, so a blob written through one backend cannot straddle two
 * limits when the object is later served through another. */
#define SD_HTTP_ADVISORY_MAX  512


/*
 * WHAT: The one setattr body; `cred` NULL runs as the instance's service
 *       identity, non-NULL as the requesting user.
 * WHY:  The plain and _cred slots differ only in that pointer, and the
 *       read-modify-write in between must be identical for both — a second copy
 *       is a second chance to overlay a delta onto the wrong base blob.
 * HOW:  Size-enquiry-free single read into a fixed buffer: ENODATA (no property
 *       yet, or a 404 propstat) starts from an empty blob, and any other read
 *       failure aborts rather than silently discarding metadata that IS there.
 *       ERANGE is aborted too, for exactly that reason — a blob too big for this
 *       buffer is one this build cannot safely rewrite.
 */
static ngx_int_t
sd_http_setattr_common(brix_sd_instance_t *inst, const char *path,
    const brix_sd_setattr_t *attr, const brix_sd_cred_t *cred)
{
    brix_meta_advisory_t delta;
    char                 blob[SD_HTTP_ADVISORY_MAX];
    ssize_t              n;
    int                  len;

    if (inst == NULL || inst->state == NULL || path == NULL || attr == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    if (!brix_meta_advisory_from_setattr(attr, &delta)) {
        return NGX_OK;             /* nothing representable — no round trip */
    }

    n = sd_http_getxattr_common(inst, path, BRIX_META_ADVISORY_XATTR, blob,
                                sizeof(blob) - 1, cred);
    if (n < 0) {
        if (errno != ENODATA) {
            return NGX_ERROR;      /* EACCES/ENOTSUP/ERANGE/EIO — do not guess */
        }
        n = 0;
    }
    blob[n] = '\0';

    len = brix_meta_advisory_patch(blob, sizeof(blob), &delta);
    if (len < 0) {
        errno = EIO;
        return NGX_ERROR;
    }
    return sd_http_setxattr_cred(inst, path, BRIX_META_ADVISORY_XATTR, blob,
                                 (size_t) len, 0, cred);
}


/* sd_http_setattr — vtable setattr slot: amend the advisory metadata as the
 * instance's own identity (the service credential, or anonymous). */
ngx_int_t
sd_http_setattr(brix_sd_instance_t *inst, const char *path,
    const brix_sd_setattr_t *attr)
{
    return sd_http_setattr_common(inst, path, attr, NULL);
}


/* sd_http_setattr_cred — the per-user twin. The blob is an ordinary dead
 * property, so writing it MUST be authorized as the requesting user for the same
 * reason setxattr_cred is: a user who cannot PROPPATCH the resource must not be
 * able to rewrite its mode by going through the metadata plane instead. */
ngx_int_t
sd_http_setattr_cred(brix_sd_instance_t *inst, const char *path,
    const brix_sd_setattr_t *attr, const brix_sd_cred_t *cred)
{
    return sd_http_setattr_common(inst, path, attr, cred);
}
