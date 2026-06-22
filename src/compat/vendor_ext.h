/*
 * vendor_ext.h — codec for the vendor-extension wire bodies (shared).
 *
 * WHAT: pack/unpack the kXR_setattr 44-byte big-endian attribute prefix.
 * WHY:  the module decodes this prefix (xrootd_handle_setattr) and the native
 *       client encodes it (xrdc_setattr); the offsets are a wire contract that
 *       should live in exactly one place so the two cannot drift.
 * HOW:  fixed-offset big-endian field copies over a caller buffer; the caller
 *       appends/strips the trailing path and decides omit/zero-fill semantics via
 *       the flags. Pure ptr+len, ngx-free. (libxrdproto)
 */
#ifndef XROOTD_COMPAT_VENDOR_EXT_H
#define XROOTD_COMPAT_VENDOR_EXT_H

#include <stdint.h>

/* Wire fact: the kXR_setattr attribute prefix is 44 bytes (see wire_vendor_ext.h
 * XROOTD_SETATTR_PREFIX_LEN). Kept locally so the codec's offsets are self-contained. */
#define XRDP_SETATTR_PREFIX_LEN 44

/*
 * Decoded kXR_setattr attribute prefix. Times are RAW sec/nsec pairs; the caller
 * decides omit/zero-fill via flags (kXR_sa_times / kXR_sa_owner) at the edge.
 */
typedef struct {
    uint32_t flags;
    int64_t  atime_sec, atime_nsec;
    int64_t  mtime_sec, mtime_nsec;
    int32_t  uid, gid;
} xrdp_setattr_t;

/* Pack `a` into the 44-byte prefix at buf (offsets 0/4/12/20/28/36/40). */
void xrdp_setattr_prefix_pack(const xrdp_setattr_t *a, uint8_t buf[44]);
/* Unpack the 44-byte prefix at buf into *a. */
void xrdp_setattr_prefix_unpack(const uint8_t buf[44], xrdp_setattr_t *a);

#endif /* XROOTD_COMPAT_VENDOR_EXT_H */
