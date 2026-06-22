/*
 * vendor_ext.c — kXR_setattr attribute-prefix codec (see vendor_ext.h).
 *
 * Shared by the module's setattr decode and the client's setattr encode; the
 * 44-byte big-endian offset layout lives here so both sides cannot drift.
 * ngx-free; libc only.
 */
#include "vendor_ext.h"

#include <string.h>
#include <arpa/inet.h>   /* htonl / ntohl */
#include <endian.h>      /* htobe64 / be64toh */

void
xrdp_setattr_prefix_pack(const xrdp_setattr_t *a, uint8_t buf[44])
{
    uint32_t v32;
    uint64_t v64;

    v32 = htonl(a->flags);                    memcpy(buf + 0,  &v32, 4);
    v64 = htobe64((uint64_t) a->atime_sec);   memcpy(buf + 4,  &v64, 8);
    v64 = htobe64((uint64_t) a->atime_nsec);  memcpy(buf + 12, &v64, 8);
    v64 = htobe64((uint64_t) a->mtime_sec);   memcpy(buf + 20, &v64, 8);
    v64 = htobe64((uint64_t) a->mtime_nsec);  memcpy(buf + 28, &v64, 8);
    v32 = htonl((uint32_t) a->uid);           memcpy(buf + 36, &v32, 4);
    v32 = htonl((uint32_t) a->gid);           memcpy(buf + 40, &v32, 4);
}

void
xrdp_setattr_prefix_unpack(const uint8_t buf[44], xrdp_setattr_t *a)
{
    uint32_t v32;
    uint64_t v64;

    memcpy(&v32, buf + 0,  4); a->flags      = ntohl(v32);
    memcpy(&v64, buf + 4,  8); a->atime_sec  = (int64_t) be64toh(v64);
    memcpy(&v64, buf + 12, 8); a->atime_nsec = (int64_t) be64toh(v64);
    memcpy(&v64, buf + 20, 8); a->mtime_sec  = (int64_t) be64toh(v64);
    memcpy(&v64, buf + 28, 8); a->mtime_nsec = (int64_t) be64toh(v64);
    memcpy(&v32, buf + 36, 4); a->uid        = (int32_t) ntohl(v32);
    memcpy(&v32, buf + 40, 4); a->gid        = (int32_t) ntohl(v32);
}
