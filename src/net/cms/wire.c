#include "cms_internal.h"
#include "login_wire.h"

#include <stdio.h>

/* ---- Measure the complete login payload before writing any bytes ----
 * WHAT: Return its size, or 0 for invalid spans, wire lengths or capacity.
 * WHY: Both login directions share the exact scalar/string order and bounds.
 * HOW: 1. Reserve 40 scalar and eight empty-string bytes. 2. Bound each tail.
 */
static size_t
cms_login_payload_size(size_t capacity, const brix_cms_login_fields_t *fields)
{
    const ngx_str_t *strings[] = {
        &fields->sid, &fields->paths, &fields->interfaces, &fields->environment
    };
    size_t required = 48;

    if (capacity < required) {
        return 0;
    }
    for (size_t index = 0; index < sizeof(strings) / sizeof(strings[0]); index++) {
        size_t length = strings[index]->len;
        if (length == 0) {
            continue;
        }
        if (strings[index]->data == NULL || length > UINT16_MAX - 1
            || length + 1 > capacity - required) {
            return 0;
        }
        required += length + 1;
    }
    return required;
}

/* ---- Encode a complete, bounded CmsLoginData payload ----
 * WHAT: Return the encoded size, or 0 without modifying output on error.
 * WHY: A manager must acknowledge LOGIN, using the same wire schema as a node.
 * HOW: 1. Validate all spans. 2. Use the shared Pup primitives in schema order.
 */
size_t
brix_cms_login_encode(u_char *output, size_t capacity,
    const brix_cms_login_fields_t *fields)
{
    u_char *cursor = output;
    size_t required;

    if (output == NULL || fields == NULL) {
        return 0;
    }
    required = cms_login_payload_size(capacity, fields);
    if (required == 0) {
        return 0;
    }
    cursor = ngx_brix_cms_put_short(cursor, CMS_LOGIN_VERSION);
    cursor = ngx_brix_cms_put_int(cursor, fields->mode);
    cursor = ngx_brix_cms_put_int(cursor, fields->hold_time);
    cursor = ngx_brix_cms_put_int(cursor, fields->total_gb);
    cursor = ngx_brix_cms_put_int(cursor, fields->free_mb);
    cursor = ngx_brix_cms_put_int(cursor, fields->min_free_mb);
    cursor = ngx_brix_cms_put_short(cursor, fields->fs_num);
    cursor = ngx_brix_cms_put_short(cursor, fields->fs_util);
    cursor = ngx_brix_cms_put_short(cursor, fields->data_port);
    cursor = ngx_brix_cms_put_short(cursor, fields->subscriber_port);
    cursor = ngx_brix_cms_put_string(cursor, fields->sid.data, fields->sid.len);
    cursor = ngx_brix_cms_put_string(cursor, fields->paths.data, fields->paths.len);
    cursor = ngx_brix_cms_put_string(cursor, fields->interfaces.data, fields->interfaces.len);
    (void) ngx_brix_cms_put_string(cursor, fields->environment.data, fields->environment.len);
    return required;
}

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

/* ngx_brix_cms_get16 — read a big-endian uint16_t (CMS frame header fields). */
uint16_t
ngx_brix_cms_get16(const u_char *p)
{
    return (uint16_t) (((uint16_t) p[0] << 8) | p[1]);
}

/* ngx_brix_cms_get32 — read a big-endian uint32_t (e.g. the CMS streamid). */
uint32_t
ngx_brix_cms_get32(const u_char *p)
{
    return ((uint32_t) p[0] << 24)
         | ((uint32_t) p[1] << 16)
         | ((uint32_t) p[2] << 8)
         | (uint32_t) p[3];
}

/* ngx_brix_cms_put16 — write a big-endian uint16_t (CMS frame header fields). */
void
ngx_brix_cms_put16(u_char *p, uint16_t value)
{
    p[0] = (u_char) (value >> 8);
    p[1] = (u_char) value;
}

/* ngx_brix_cms_put32 — write a big-endian uint32_t (streamid, payload values). */
void
ngx_brix_cms_put32(u_char *p, uint32_t value)
{
    p[0] = (u_char) (value >> 24);
    p[1] = (u_char) (value >> 16);
    p[2] = (u_char) (value >> 8);
    p[3] = (u_char) value;
}

/* ngx_brix_cms_put_short — write a CMS type-tagged short: the CMS_PT_SHORT (0x80)
 * tag then a big-endian uint16_t (version/port-style payload values); returns the
 * advanced cursor. */
u_char *
ngx_brix_cms_put_short(u_char *p, uint16_t value)
{
    *p++ = CMS_PT_SHORT;
    ngx_brix_cms_put16(p, value);
    /* p already stepped over the tag byte above, so +2 covers only the value;
     * net 3 bytes (1 tag + 2 BE) consumed from the caller's original cursor. */
    return p + 2;
}

/* ngx_brix_cms_put_int — write a CMS type-tagged int: the CMS_PT_INT (0xa0) tag
 * then a big-endian uint32_t (space metrics, streamid keys); returns the advanced
 * cursor. */
u_char *
ngx_brix_cms_put_int(u_char *p, uint32_t value)
{
    *p++ = CMS_PT_INT;
    ngx_brix_cms_put32(p, value);
    /* p already stepped over the tag byte above, so +4 covers only the value;
     * net 5 bytes (1 tag + 4 BE) consumed from the caller's original cursor. */
    return p + 4;
}

/* ngx_brix_cms_put_string — encode a string in XrdOucPup::Pack format (kYR_login
 * payload after the Fence): a 2-byte big-endian length (counting a trailing NUL, so
 * strlen+1) then the bytes + NUL; a NULL/empty string is a bare 2-byte zero length.
 * No type tag byte — the Parser tells a string from a scalar by the absent PT_short
 * (0x80) bit. Returns the advanced cursor. */
u_char *
ngx_brix_cms_put_string(u_char *p, const u_char *data, size_t len)
{
    if (data == NULL || len == 0) {
        ngx_brix_cms_put16(p, 0);
        return p + 2;
    }

    ngx_brix_cms_put16(p, (uint16_t) (len + 1));
    p += 2;
    ngx_memcpy(p, data, len);
    p += len;
    *p++ = '\0';
    return p;
}

/* ngx_brix_cms_stats_doc — render the Cluster.Stats document (the kYR_stats
 * full-form text: CMS_STATS_FMT with the node's XrdCmsRole::Type substituted).
 * Both CMS legs share this one renderer so the wire document has a single
 * truth. Returns the snprintf length (no NUL) or -1 on truncation (cannot
 * happen for a buf sized from CMS_STATS_BUFSZ: role is at most 2 chars vs the
 * 8-byte slack stock reserves). */
int
ngx_brix_cms_stats_doc(u_char *buf, size_t buflen, const char *role)
{
    int  len;

    len = snprintf((char *) buf, buflen, CMS_STATS_FMT, role);
    if (len < 0 || (size_t) len >= buflen) {
        return -1;
    }
    return len;
}
