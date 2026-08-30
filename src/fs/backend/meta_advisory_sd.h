#ifndef BRIX_META_ADVISORY_SD_H
#define BRIX_META_ADVISORY_SD_H

/*
 * meta_advisory_sd.h — the one translation from an SD setattr request to an
 * advisory-metadata delta.
 *
 * WHAT: brix_meta_advisory_from_setattr() maps brix_sd_setattr_t (the storage-
 *       neutral union of kXR_chmod and kXR_setattr) onto brix_meta_advisory_t
 *       (the reserved blob object stores persist and overlay on stat).
 * WHY:  Every backend with no native POSIX metadata — S3/remote, RADOS/ceph,
 *       WebDAV/http — needs exactly this translation, and it is not mechanical:
 *       UTIME_OMIT means "leave it", UTIME_NOW means "stamp wall time", and a
 *       lone (uid_t)-1 or (gid_t)-1 means the owner change CANNOT be represented
 *       at all in a model that carries uid and gid together. Three copies of
 *       that reasoning is three chances to get one of the sentinels wrong, and
 *       getting one wrong writes a bogus owner onto an object.
 * HOW:  A separate TU from meta_advisory.c on purpose: the codec itself is
 *       deliberately dependency-free (libc only) so it unit-tests standalone and
 *       links into libxrdproto; this half needs sd.h for brix_sd_setattr_t, so
 *       it is kept out of the codec rather than dragging sd.h into it.
 */

#include "fs/backend/sd.h"
#include "fs/backend/meta_advisory.h"

/* Fill *delta with the fields of *attr the advisory model can represent, and
 * only those: an unset group is left absent so a patch leaves it untouched.
 * Returns 1 when at least one field was set (there is something to persist),
 * 0 when the request carries nothing representable (the caller returns success
 * without a write — a setattr that changes nothing is not an error). */
int brix_meta_advisory_from_setattr(const brix_sd_setattr_t *attr,
                                    brix_meta_advisory_t *delta);

#endif /* BRIX_META_ADVISORY_SD_H */
