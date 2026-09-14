/*
 * vendor_ext.c — kXR_setattr attribute-prefix codec (see vendor_ext.h).
 *
 * Shared by the module's setattr decode and the client's setattr encode; the
 * 44-byte big-endian offset layout lives here so both sides cannot drift.
 * ngx-free; libc only.
 */
#include "vendor_ext.h"
#include "protocols/root/protocol/codec/wire_codec.h"

/* WHAT: Encode the fixed 44-byte setattr prefix in network byte order.
 * WHY: The client and module share one wire layout without nginx dependencies.
 * HOW: Store each field with the shared unaligned-safe wire codec. */
void
xrdp_setattr_prefix_pack(const xrdp_setattr_t *a, uint8_t buf[44])
{
    xrdw_put_u32(buf, a->flags);
    xrdw_put_u64(buf + 4, (uint64_t) a->atime_sec);
    xrdw_put_u64(buf + 12, (uint64_t) a->atime_nsec);
    xrdw_put_u64(buf + 20, (uint64_t) a->mtime_sec);
    xrdw_put_u64(buf + 28, (uint64_t) a->mtime_nsec);
    xrdw_put_u32(buf + 36, (uint32_t) a->uid);
    xrdw_put_u32(buf + 40, (uint32_t) a->gid);
}

/* WHAT: Decode the fixed setattr prefix into host-order attribute values.
 * WHY: Negative timestamps and sentinel owner IDs retain their wire bits.
 * HOW: Load each field with the shared unaligned-safe wire codec. */
void
xrdp_setattr_prefix_unpack(const uint8_t buf[44], xrdp_setattr_t *a)
{
    a->flags = xrdw_get_u32(buf);
    a->atime_sec = (int64_t) xrdw_get_u64(buf + 4);
    a->atime_nsec = (int64_t) xrdw_get_u64(buf + 12);
    a->mtime_sec = (int64_t) xrdw_get_u64(buf + 20);
    a->mtime_nsec = (int64_t) xrdw_get_u64(buf + 28);
    a->uid = (int32_t) xrdw_get_u32(buf + 36);
    a->gid = (int32_t) xrdw_get_u32(buf + 40);
}
