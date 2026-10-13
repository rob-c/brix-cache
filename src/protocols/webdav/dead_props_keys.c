/*
 * dead_props_keys.c - WebDAV dead-property xattr key encode/decode/validate.
 *
 * The flat "user." xattr keyspace cannot hold arbitrary XML namespace URIs or
 * element names directly, so a dead property is keyed by an encoded
 * (namespace, local-name) pair under a fixed prefix.  The legacy spelling is
 * hex; keys that exceed the host xattr-name limit use a marked base64url
 * spelling.  This file owns both encodings: building a key, decoding a key
 * back, and validating that a decoded local name is safe to splice into a
 * PROPFIND response.  Split from dead_props.c; consumed by it via
 * dead_props_internal.h.
 */

#include "webdav.h"
#include "fs/path/path.h"
#include "fs/vfs/vfs.h"
#include "core/http/http_xml.h"
#include "core/compat/hex.h"
#include "core/compat/namespace_ops.h"

#include <errno.h>
#include <string.h>
#include "platform/platform_api.h"
#include "core/compat/alloc_guard.h"

#include "dead_props_internal.h"

/*
 * WHAT: True if `c` is an ASCII letter or '_' (the XML NameStartChar subset we
 *       permit for a dead-property local name).
 * WHY:  Splitting the character-class test out of the validator collapses the
 *       validator's branch fan-out (each range test is one branch) into a
 *       single call, keeping the validator's complexity low and the accepted
 *       set stated in exactly one place.
 * HOW:  Pure predicate over the raw byte; no side effects.
 */
static ngx_flag_t
webdav_xml_name_start_char(unsigned char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_';
}

/*
 * WHAT: True if `c` is a permitted XML NameChar for a dead-property local name
 *       (a NameStartChar, or a digit, '-', or '.').
 * WHY:  Same rationale as webdav_xml_name_start_char — one predicate per
 *       character class keeps the validator loop a single-branch scan.
 * HOW:  Reuses the start-char predicate, then admits the trailing-only extras.
 */
static ngx_flag_t
webdav_xml_name_char(unsigned char c)
{
    return webdav_xml_name_start_char(c)
           || (c >= '0' && c <= '9') || c == '-' || c == '.';
}

/*
 * Validate that a decoded local name is a safe XML element name before it is
 * spliced back into a PROPFIND response.  This is the injection guard: a name
 * read from an xattr is attacker-influenced, so we restrict it to the XML
 * NameStartChar/NameChar subset (ASCII letters, '_', then also digits, '-',
 * '.') and reject anything else (notably '<', '>', '&', '/', whitespace).
 */
ngx_flag_t
webdav_dead_prop_xml_name_ok(const char *name)
{
    const unsigned char *p = (const unsigned char *) name;

    if (p == NULL || *p == '\0') {
        return 0;
    }

    if (!webdav_xml_name_start_char(*p)) {
        return 0;
    }

    for (p++; *p != '\0'; p++) {
        if (!webdav_xml_name_char(*p)) {
            return 0;
        }
    }

    return 1;
}

/*
 * WHAT: Append one C string as unpadded base64url to a bounded key buffer.
 * WHY:  Compact dead-property keys encode namespace and local name twice less
 *       expansively than hex while retaining a reversible, xattr-safe alphabet.
 * HOW:  nginx's base64url primitive writes at the current cursor; the helper
 *       advances the caller's cursor/budget only after the capacity check.
 */
static ngx_int_t
webdav_dead_prop_append_b64(const char *value, char **out, size_t *left)
{
    ngx_str_t src;
    ngx_str_t dst;
    size_t    need;

    src.data = (u_char *) ((value == NULL) ? "" : value);
    src.len = (value == NULL) ? 0 : strlen(value);
    need = ngx_base64_encoded_length(src.len);
    if (*left <= need) {
        return NGX_ERROR;
    }
    dst.data = (u_char *) *out;
    dst.len = 0;
    ngx_encode_base64url(&dst, &src);
    *out += dst.len;
    *left -= dst.len;
    return NGX_OK;
}

/*
 * WHAT: Build the marked compact dead-property xattr key.
 * WHY:  Darwin accepts 127-byte xattr names, so the legacy double-hex spelling
 *       can reject an otherwise valid WebDAV property that Linux stores.
 * HOW:  Write PREFIX + '~' + b64url(ns) + '.' + b64url(local), then enforce
 *       both the supplied buffer and selected host's PAL name budget.
 */
static ngx_int_t
webdav_dead_prop_attr_name_b64(const char *ns, const char *local,
    char *out, size_t outsz)
{
    char   *d = out;
    size_t  left = outsz;
    size_t  n = WEBDAV_DEAD_PROP_PREFIX_LEN;

    if (left <= n + 1) {
        return NGX_ERROR;
    }
    ngx_memcpy(d, WEBDAV_DEAD_PROP_PREFIX, n);
    d += n;
    left -= n;
    *d++ = '~';
    left--;

    if (webdav_dead_prop_append_b64(ns, &d, &left) != NGX_OK || left <= 1) {
        return NGX_ERROR;
    }
    *d++ = '.';
    left--;
    if (webdav_dead_prop_append_b64(local, &d, &left) != NGX_OK) {
        return NGX_ERROR;
    }
    *d = '\0';
    return ((size_t) (d - out) <= BRIX_XATTR_NAME_MAX) ? NGX_OK : NGX_ERROR;
}

/*
 * Encode (namespace URI, local name) into the flat xattr key documented above:
 * PREFIX + hex(ns) + '.' + hex(local).  Writes a NUL-terminated string into
 * out[0..outsz).  Every append is bounds-checked against `left` and returns
 * NGX_ERROR (caller maps to ENAMETOOLONG) rather than truncating, since a
 * truncated key would silently collide with a different property.
 */
ngx_int_t
webdav_dead_prop_attr_name(const char *ns, const char *local,
    char *out, size_t outsz)
{
    static const char hex[] = "0123456789abcdef";
    const unsigned char *p;
    char                *d = out;
    size_t               left = outsz;
    size_t               n;
    size_t               ns_len = (ns == NULL) ? 0 : strlen(ns);
    size_t               local_len = (local == NULL) ? 0 : strlen(local);

    n = WEBDAV_DEAD_PROP_PREFIX_LEN + 2 * ns_len + 1 + 2 * local_len;
    if (n > BRIX_XATTR_NAME_MAX) {
        return webdav_dead_prop_attr_name_b64(ns, local, out, outsz);
    }

    /* Prefix is fixed-length and always written first. */
    n = WEBDAV_DEAD_PROP_PREFIX_LEN;
    if (left <= n) {
        return NGX_ERROR;
    }
    ngx_memcpy(d, WEBDAV_DEAD_PROP_PREFIX, n);
    d += n;
    left -= n;

    /* hex(namespace): two output bytes per source byte; need >2 left so a
     * trailing '.' and NUL still fit. */
    for (p = (const unsigned char *) ns; p != NULL && *p != '\0'; p++) {
        if (left <= 2) {
            return NGX_ERROR;
        }
        *d++ = hex[*p >> 4];
        *d++ = hex[*p & 0x0f];
        left -= 2;
    }

    if (left <= 1) {
        return NGX_ERROR;
    }
    *d++ = '.';   /* the one literal separator; source dots are hex "2e" */
    left--;

    /* hex(local name) */
    for (p = (const unsigned char *) local; p != NULL && *p != '\0'; p++) {
        if (left <= 2) {
            return NGX_ERROR;
        }
        *d++ = hex[*p >> 4];
        *d++ = hex[*p & 0x0f];
        left -= 2;
    }

    if (left == 0) {
        return NGX_ERROR;
    }
    *d = '\0';
    return NGX_OK;
}

/*
 * Inverse of the hex encoder: decode `len` hex chars into len/2 raw bytes plus
 * a NUL.  Returns NULL on odd length or any non-hex digit (a corrupted/foreign
 * xattr key), which the caller treats as "not one of ours" rather than fatal.
 */
static char *
webdav_dead_prop_decode_hex(ngx_pool_t *pool, const char *hex, size_t len)
{
    char   *out;
    size_t  i;

    if ((len & 1) != 0) {     /* hex always comes in pairs */
        return NULL;
    }

    BRIX_PNALLOC_OR_RETURN(out, pool, len / 2 + 1, NULL);

    for (i = 0; i < len; i += 2) {
        int hi = brix_hex_from_char((unsigned char) hex[i]);
        int lo = brix_hex_from_char((unsigned char) hex[i + 1]);
        if (hi < 0 || lo < 0) {
            return NULL;
        }
        out[i / 2] = (char) ((hi << 4) | lo);
    }
    out[len / 2] = '\0';
    return out;
}

/*
 * WHAT: Decode one compact-key base64url component into pool memory.
 * WHY:  Enumeration must recover the exact XML namespace/local pair, while a
 *       malformed foreign xattr must be ignored rather than partially decoded.
 * HOW:  Allocate the nginx decoded-length ceiling, decode atomically, reject
 *       embedded NUL bytes, and append the C-string terminator.
 */
static char *
webdav_dead_prop_decode_b64(ngx_pool_t *pool, const char *encoded, size_t len)
{
    ngx_str_t src;
    ngx_str_t dst;
    size_t    cap;

    cap = ngx_base64_decoded_length(len);
    dst.data = ngx_pnalloc(pool, cap + 1);
    if (dst.data == NULL) {
        return NULL;
    }
    src.data = (u_char *) encoded;
    src.len = len;
    dst.len = cap;
    if (ngx_decode_base64url(&dst, &src) != NGX_OK
        || memchr(dst.data, '\0', dst.len) != NULL)
    {
        return NULL;
    }
    dst.data[dst.len] = '\0';
    return (char *) dst.data;
}

/*
 * Parse one listxattr entry back into (namespace, local name).
 * Returns NGX_DECLINED for any key that is not a well-formed dead-property key
 * (wrong prefix, no '.' separator, bad hex, or a local name that fails the XML
 * safety check) so the caller can skip foreign xattrs silently.
 */
ngx_int_t
webdav_dead_prop_decode_attr(ngx_pool_t *pool, const char *attr,
    char **ns_out, char **local_out)
{
    const char *payload;
    const char *dot;

    if (ngx_strncmp(attr, WEBDAV_DEAD_PROP_PREFIX,
                   WEBDAV_DEAD_PROP_PREFIX_LEN) != 0)
    {
        return NGX_DECLINED;
    }

    payload = attr + WEBDAV_DEAD_PROP_PREFIX_LEN;
    if (*payload == '~') {
        payload++;
    }
    dot = strchr(payload, '.');
    if (dot == NULL) {
        return NGX_DECLINED;
    }

    if (attr[WEBDAV_DEAD_PROP_PREFIX_LEN] == '~') {
        *ns_out = webdav_dead_prop_decode_b64(pool, payload,
                                              (size_t) (dot - payload));
        *local_out = webdav_dead_prop_decode_b64(pool, dot + 1,
                                                 strlen(dot + 1));
    } else {
        *ns_out = webdav_dead_prop_decode_hex(pool, payload,
                                              (size_t) (dot - payload));
        *local_out = webdav_dead_prop_decode_hex(pool, dot + 1,
                                                 strlen(dot + 1));
    }
    if (*ns_out == NULL || *local_out == NULL
        || !webdav_dead_prop_xml_name_ok(*local_out))
    {
        return NGX_DECLINED;
    }

    return NGX_OK;
}
