#include "cms_internal.h"

/* ---- ngx_xrootd_cms_get16 — read big-endian 16-bit value from wire buffer ----
 *
 * WHAT: Extracts a uint16_t from the first two bytes of buffer p in big-endian order (MSB first). Used to decode CMS frame header fields. */

uint16_t
ngx_xrootd_cms_get16(const u_char *p)
{
    return (uint16_t) (((uint16_t) p[0] << 8) | p[1]);
}

/* ---- ngx_xrootd_cms_get32 — read big-endian 32-bit value from wire buffer ----
 *
 * WHAT: Extracts a uint32_t from the first four bytes of buffer p in big-endian order (MSB first). Used to decode CMS streamid field. */

uint32_t
ngx_xrootd_cms_get32(const u_char *p)
{
    return ((uint32_t) p[0] << 24)
         | ((uint32_t) p[1] << 16)
         | ((uint32_t) p[2] << 8)
         | (uint32_t) p[3];
}

/* ---- ngx_xrootd_cms_put16 — write big-endian 16-bit value to wire buffer ----
 *
 * WHAT: Stores a uint16_t into the first two bytes of buffer p in big-endian order. Used to encode CMS frame header fields. Returns nothing (void). */

void
ngx_xrootd_cms_put16(u_char *p, uint16_t value)
{
    p[0] = (u_char) (value >> 8);
    p[1] = (u_char) value;
}

/* ---- ngx_xrootd_cms_put32 — write big-endian 32-bit value to wire buffer ----
 *
 * WHAT: Stores a uint32_t into the first four bytes of buffer p in big-endian order. Used to encode CMS streamid field and payload values. */

void
ngx_xrootd_cms_put32(u_char *p, uint32_t value)
{
    p[0] = (u_char) (value >> 24);
    p[1] = (u_char) (value >> 16);
    p[2] = (u_char) (value >> 8);
    p[3] = (u_char) value;
}

/* ---- ngx_xrootd_cms_put_short — write variable-length encoded 16-bit value ----
 *
 * WHAT: Writes a CMS type-tagged short value: prefix byte CMS_PT_SHORT (0x80), then big-endian uint16_t. Returns pointer advanced by 2 bytes past the written value. Used for payload encoding of small values like version numbers and port numbers. */

u_char *
ngx_xrootd_cms_put_short(u_char *p, uint16_t value)
{
    *p++ = CMS_PT_SHORT;
    ngx_xrootd_cms_put16(p, value);
    return p + 2;
}

/* ---- ngx_xrootd_cms_put_int — write variable-length encoded 32-bit value ----
 *
 * WHAT: Writes a CMS type-tagged int value: prefix byte CMS_PT_INT (0xa0), then big-endian uint32_t. Returns pointer advanced by 4 bytes past the written value. Used for payload encoding of space metrics, streamid correlation keys, and other larger values. */

u_char *
ngx_xrootd_cms_put_int(u_char *p, uint32_t value)
{
    *p++ = CMS_PT_INT;
    ngx_xrootd_cms_put32(p, value);
    return p + 4;
}
