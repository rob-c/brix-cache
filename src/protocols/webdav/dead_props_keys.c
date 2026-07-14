/*
 * dead_props_keys.c - WebDAV dead-property xattr key encode/decode/validate.
 *
 * The flat "user." xattr keyspace cannot hold arbitrary XML namespace URIs or
 * element names directly, so a dead property is keyed by a hex-encoded
 * (namespace, local-name) pair under a fixed prefix.  This file owns that
 * encoding: building a key, decoding a key back, and validating that a decoded
 * local name is safe to splice into a PROPFIND response.  Split verbatim from
 * dead_props.c; consumed by it via dead_props_internal.h.
 */

#include "webdav.h"
#include "fs/path/path.h"
#include "fs/vfs/vfs.h"
#include "core/http/http_xml.h"
#include "core/compat/hex.h"
#include "core/compat/namespace_ops.h"

#include <errno.h>
#include <string.h>
#include <sys/xattr.h>
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
    dot = strchr(payload, '.');
    if (dot == NULL) {
        return NGX_DECLINED;
    }

    *ns_out = webdav_dead_prop_decode_hex(pool, payload,
                                          (size_t) (dot - payload));
    *local_out = webdav_dead_prop_decode_hex(pool, dot + 1, strlen(dot + 1));
    if (*ns_out == NULL || *local_out == NULL
        || !webdav_dead_prop_xml_name_ok(*local_out))
    {
        return NGX_DECLINED;
    }

    return NGX_OK;
}
