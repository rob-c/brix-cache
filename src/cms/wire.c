#include "cms_internal.h"
/*
 * wire.c — CMS frame header and XrdOucPup payload codec
 *
 * WHAT: Low-level get/put primitives for the XRootD CMS wire format. Two layers
 *       live here: (1) raw big-endian scalar I/O for the fixed CMS frame header
 *       (get16/get32, put16/put32), and (2) the tagged/packed payload codec
 *       (put_short, put_int, put_string) that serialises the variable-length
 *       fields of a kYR_login payload.
 *
 * WHY: The real XrdCms manager (cmsd) speaks a specific binary dialect. The
 *      header is plain big-endian; the payload after the Fence is encoded by
 *      XrdOucPup, which tags scalars with a type byte but writes strings with NO
 *      tag — the parser tells them apart by the PT_short (0x80) bit of the first
 *      byte. Getting the byte layout wrong silently breaks interop with cmsd.
 *
 * HOW: Scalars are tagged: put_short emits CMS_PT_SHORT (0x80) then a 2-byte BE
 *      value; put_int emits CMS_PT_INT (0xa0) then a 4-byte BE value. Strings are
 *      packed as [2B BE length][raw bytes][trailing NUL], where the length field
 *      counts the NUL (strlen+1) to match XrdOucPup::Pack; an empty/absent string
 *      is a bare 2-byte zero length with no data and no NUL. Every put_* returns
 *      the cursor advanced past the bytes it wrote so callers can chain writes.
 */

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
    /* p already stepped over the tag byte above, so +2 covers only the value;
     * net 3 bytes (1 tag + 2 BE) consumed from the caller's original cursor. */
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
    /* p already stepped over the tag byte above, so +4 covers only the value;
     * net 5 bytes (1 tag + 4 BE) consumed from the caller's original cursor. */
    return p + 4;
}

/* ---- ngx_xrootd_cms_put_string — write an XrdOucPup-style packed string ----
 *
 * WHAT: Encodes a string in the real XrdCms wire format used after the Fence in
 *      a kYR_login payload: a 2-byte big-endian length followed by the raw bytes
 *      INCLUDING a trailing NUL.  The encoded length counts the NUL (strlen+1),
 *      matching XrdOucPup::Pack.  A NULL or zero-length string is encoded as a
 *      bare 2-byte zero length (no data, no NUL) — exactly how XrdOucPup emits an
 *      empty/absent string.  Unlike put_short/put_int there is NO type tag byte;
 *      the real Parser distinguishes a string from a scalar by the absence of the
 *      PT_short (0x80) bit in the first byte. Returns the advanced cursor. */

u_char *
ngx_xrootd_cms_put_string(u_char *p, const u_char *data, size_t len)
{
    if (data == NULL || len == 0) {
        ngx_xrootd_cms_put16(p, 0);
        return p + 2;
    }

    ngx_xrootd_cms_put16(p, (uint16_t) (len + 1));
    p += 2;
    ngx_memcpy(p, data, len);
    p += len;
    *p++ = '\0';
    return p;
}
