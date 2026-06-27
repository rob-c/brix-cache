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

/* ngx_xrootd_cms_get16 — read a big-endian uint16_t (CMS frame header fields). */
uint16_t
ngx_xrootd_cms_get16(const u_char *p)
{
    return (uint16_t) (((uint16_t) p[0] << 8) | p[1]);
}

/* ngx_xrootd_cms_get32 — read a big-endian uint32_t (e.g. the CMS streamid). */
uint32_t
ngx_xrootd_cms_get32(const u_char *p)
{
    return ((uint32_t) p[0] << 24)
         | ((uint32_t) p[1] << 16)
         | ((uint32_t) p[2] << 8)
         | (uint32_t) p[3];
}

/* ngx_xrootd_cms_put16 — write a big-endian uint16_t (CMS frame header fields). */
void
ngx_xrootd_cms_put16(u_char *p, uint16_t value)
{
    p[0] = (u_char) (value >> 8);
    p[1] = (u_char) value;
}

/* ngx_xrootd_cms_put32 — write a big-endian uint32_t (streamid, payload values). */
void
ngx_xrootd_cms_put32(u_char *p, uint32_t value)
{
    p[0] = (u_char) (value >> 24);
    p[1] = (u_char) (value >> 16);
    p[2] = (u_char) (value >> 8);
    p[3] = (u_char) value;
}

/* ngx_xrootd_cms_put_short — write a CMS type-tagged short: the CMS_PT_SHORT (0x80)
 * tag then a big-endian uint16_t (version/port-style payload values); returns the
 * advanced cursor. */
u_char *
ngx_xrootd_cms_put_short(u_char *p, uint16_t value)
{
    *p++ = CMS_PT_SHORT;
    ngx_xrootd_cms_put16(p, value);
    /* p already stepped over the tag byte above, so +2 covers only the value;
     * net 3 bytes (1 tag + 2 BE) consumed from the caller's original cursor. */
    return p + 2;
}

/* ngx_xrootd_cms_put_int — write a CMS type-tagged int: the CMS_PT_INT (0xa0) tag
 * then a big-endian uint32_t (space metrics, streamid keys); returns the advanced
 * cursor. */
u_char *
ngx_xrootd_cms_put_int(u_char *p, uint32_t value)
{
    *p++ = CMS_PT_INT;
    ngx_xrootd_cms_put32(p, value);
    /* p already stepped over the tag byte above, so +4 covers only the value;
     * net 5 bytes (1 tag + 4 BE) consumed from the caller's original cursor. */
    return p + 4;
}

/* ngx_xrootd_cms_put_string — encode a string in XrdOucPup::Pack format (kYR_login
 * payload after the Fence): a 2-byte big-endian length (counting a trailing NUL, so
 * strlen+1) then the bytes + NUL; a NULL/empty string is a bare 2-byte zero length.
 * No type tag byte — the Parser tells a string from a scalar by the absent PT_short
 * (0x80) bit. Returns the advanced cursor. */
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
