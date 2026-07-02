/*
 * http_query.c - shared nginx args-string scanner for HTTP protocols.
 *
 * nginx exposes the raw query string as one ngx_str_t.  WebDAV/XrdHttp and S3
 * need the same bounded key/value scan with slightly different policies:
 * case-sensitive vs case-insensitive keys, raw vs percent-decoded values, and
 * bare-flag detection.  This helper centralises the scan while keeping those
 * protocol choices explicit at each call site.
 */

#include "http_query.h"
#include "uri.h"

/*
 * xrootd_http_query_key_eq - case-sensitive or case-insensitive key comparison.
 *
 * WHAT: Compares query-key bytes a[0..len] against literal b using ngx_strncmp
 *       (case-sensitive) or ngx_strncasecmp (case-insensitive), depending on flags.
 *      Returns 1 (match) or 0 (no match).
 *
 * WHY: S3 GET uses case-sensitive query-key matching; WebDAV may use case-insensitive.
 *      This helper centralises the comparison so callers pass one flag and get
 *      correct behaviour without duplicating both branches at each callsite.
 *
 * HOW: flags & CASE_INSENSITIVE → ngx_strncasecmp(b, a, len); else ngx_strncmp(a, b, len).
 */

static int
xrootd_http_query_key_eq(const u_char *a, const char *b, size_t len,
    unsigned flags)
{
    if (flags & XROOTD_HTTP_QUERY_CASE_INSENSITIVE) {
        return ngx_strncasecmp((u_char *) b, (u_char *) a, len) == 0;
    }

    return ngx_strncmp(a, (u_char *) b, len) == 0;
}

/*
 * xrootd_http_query_hex - decode single hex digit to byte value.
 *
 * WHAT: Converts ASCII hex character (0-9/a-f/A-F) to its numeric byte value
 *       via out pointer. Returns 1 on success, 0 on invalid input.
 *
 * WHY: Percent-encoded query values use two hex digits per byte (%XX). This
 *      helper validates and decodes each digit during percent-decode loops in
 *      decode_trunc().
 *
 * HOW: c-'0' for '0'..'9'; c-'a'+10 for 'a'..'f'; c-'A'+10 for 'A'..'F'.
 *      Any other char → return 0.
 */

static int
xrootd_http_query_hex(u_char c, u_char *out)
{
    if (c >= '0' && c <= '9') { *out = (u_char) (c - '0'); return 1; }
    if (c >= 'a' && c <= 'f') { *out = (u_char) (c - 'a' + 10); return 1; }
    if (c >= 'A' && c <= 'F') { *out = (u_char) (c - 'A' + 10); return 1; }
    return 0;
}

/*
 * xrootd_http_query_decode_trunc - percent-decode src into dst with truncation and NUL rejection.
 *
 * WHAT: Scans src[0..src_len], decoding %XX sequences to bytes, converting '+' to
 *       space when flag set, rejecting decoded/raw NUL bytes when flag set,
 *      and writing at most dst_sz-1 chars (null-terminating). Returns 1 on success,
 *      -1 on truncation overflow or NUL rejection.
 *
 * WHY: S3 query values like "prefix" and "delimiter" arrive percent-encoded. This
 *      decoder handles the bounded buffer case where decoded output may exceed dst_sz,
 *      ensuring safe null-termination without overflow.
 *
 * HOW: loop si=0..src_len: '%' + 2 hex digits → decode byte; '+' → 'space';
 *      check NUL reject, di+1<dst_sz before write. Null-terminate at di.
 */

static int
xrootd_http_query_decode_trunc(const u_char *src, size_t src_len,
    char *dst, size_t dst_sz, unsigned flags)
{
    size_t si, di;

    if (dst == NULL || dst_sz == 0) {
        return -1;
    }

    si = 0;
    di = 0;

    while (si < src_len) {
        u_char c;

        if (src[si] == '%' && si + 2 < src_len) {
            u_char hi, lo;

            if (xrootd_http_query_hex(src[si + 1], &hi)
                && xrootd_http_query_hex(src[si + 2], &lo))
            {
                c = (u_char) ((hi << 4) | lo);
                if (c == '\0' && (flags & XROOTD_HTTP_QUERY_REJECT_NUL)) {
                    return -1;
                }
                if (di + 1 < dst_sz) {
                    dst[di++] = (char) c;
                }
                si += 3;
                continue;
            }
        }

        c = src[si++];
        if (c == '+' && (flags & XROOTD_HTTP_QUERY_PLUS_TO_SPACE)) {
            c = ' ';
        }
        if (c == '\0' && (flags & XROOTD_HTTP_QUERY_REJECT_NUL)) {
            return -1;
        }
        if (di + 1 < dst_sz) {
            dst[di++] = (char) c;
        }
    }

    dst[di] = '\0';
    return 1;
}

/*
 * xrootd_http_query_copy_value - copy or decode query value into dst buffer.
 *
 * WHAT: If DECODE_VALUE flag set: percent-decode via truncate helper (bounded) or
 *       full urldecode (returns XROOTD_URLDECODE_OK→1, else -1). If not decoded:
 *      memcpy src_len bytes into dst with optional truncation to dst_sz-1.
 *      Returns 1 on success, -1 on overflow when truncate flag not set.
 *
 * WHY: Query values may be raw (S3 bare-flag detection) or percent-encoded
 *      (S3 prefix/delimiter keys). This function centralises both copy and decode
 *      paths so callers pass one flags parameter to get correct behaviour.
 *
 * HOW: DECODE_VALUE → truncate helper (bounded loop) or xrootd_http_urldecode;
 *      else ngx_memcpy(src, dst, min(src_len,dst_sz-1)) + null-term. Return 1/-1.
 */

static int
xrootd_http_query_copy_value(const u_char *src, size_t src_len,
    char *dst, size_t dst_sz, unsigned flags)
{
    size_t copy;
    unsigned uri_flags;
    int rc;

    if (dst == NULL || dst_sz == 0) {
        return -1;
    }

    if (flags & XROOTD_HTTP_QUERY_DECODE_VALUE) {
        uri_flags = ((flags & XROOTD_HTTP_QUERY_PLUS_TO_SPACE)
                        ? XROOTD_URLDECODE_PLUS_TO_SPACE : 0)
                  | ((flags & XROOTD_HTTP_QUERY_REJECT_NUL)
                        ? XROOTD_URLDECODE_REJECT_NUL : 0);

        if (flags & XROOTD_HTTP_QUERY_TRUNCATE) {
            return xrootd_http_query_decode_trunc(src, src_len, dst, dst_sz,
                                                  flags);
        }

        rc = xrootd_http_urldecode(src, src_len, dst, dst_sz, uri_flags);
        return (rc == XROOTD_URLDECODE_OK) ? 1 : -1;
    }

    if (src_len >= dst_sz) {
        if (!(flags & XROOTD_HTTP_QUERY_TRUNCATE)) {
            return -1;
        }
        copy = dst_sz - 1;
    } else {
        copy = src_len;
    }

    ngx_memcpy(dst, src, copy);
    dst[copy] = '\0';
    return 1;
}

/*
 * xrootd_http_query_get - scan query string for key and return decoded value into out buffer.
 *
 * WHAT: Iterates args[0..len] split by '&', finds segment where key matches
 *       (case-sensitive/insensitive per flags), extracts value after '=', then
 *      copies/decodes value into out[0..outsz]. Returns 1 on found, 0 if not found.
 *
 * WHY: S3 ListObjectsV2 uses query keys like prefix/delimiter/max-keys. WebDAV may
 *      also parse query parameters. This function centralises the bounded scan,
 *      key comparison, and value decode into one reusable call.
 *
 * HOW: while p<end: ngx_strlchr(&) → seg_end; ngx_strlchr(=) → eq; if eq-p==key_len
 *      && key_eq(p,key,len,flags): val=eq+1, val_len=seg_end-val;
 *      copy_value(val,val_len,out,outsz,flags). Return result or 0.
 */

int
xrootd_http_query_get(ngx_str_t args, const char *key, char *out,
    size_t outsz, unsigned flags)
{
    u_char *p, *end;
    size_t  key_len;

    if (args.len == 0 || key == NULL || out == NULL || outsz == 0) {
        return 0;
    }

    key_len = ngx_strlen(key);
    p = args.data;
    end = args.data + args.len;

    while (p < end) {
        u_char *amp = ngx_strlchr(p, end, '&');
        u_char *seg_end = amp ? amp : end;
        u_char *eq = ngx_strlchr(p, seg_end, '=');

        if (eq != NULL && (size_t) (eq - p) == key_len
            && xrootd_http_query_key_eq(p, key, key_len, flags))
        {
            u_char *val = eq + 1;
            size_t  val_len = (size_t) (seg_end - val);

            if (val_len == 0 && !(flags & XROOTD_HTTP_QUERY_ALLOW_EMPTY)) {
                return 0;
            }

            return xrootd_http_query_copy_value(val, val_len, out, outsz,
                                                flags);
        }

        p = (amp != NULL) ? amp + 1 : end;
    }

    return 0;
}

/*
 * xrootd_http_query_has - scan query string for key existence (with optional value check).
 *
 * WHAT: Iterates args[0..len] split by '&', finds segment where key matches
 *       (case-sensitive/insensitive per flags). Returns 1 if found. If HAS_VALUE_OK
 *      flag set, bare keys without '=' also pass. Otherwise requires '=' present.
 *
 * WHY: S3 bare-flag detection (e.g., ?delimiter with no value) needs to distinguish
 *      "key exists" from "key=value pair exists". This helper provides both modes:
 *      HAS_VALUE_OK accepts bare keys, unset requires '=' after key.
 *
 * HOW: while p<end: ngx_strlchr(&) → seg_end; eq=ngx_strlchr(=); key_end=eq?eq:seg_end;
 *      if key_end-p==key_len && key_eq(p,key,len,flags): return 1 (or require eq!=NULL).
 */

int
xrootd_http_query_has(ngx_str_t args, const char *key, unsigned flags)
{
    u_char *p, *end;
    size_t  key_len;

    if (args.len == 0 || key == NULL) {
        return 0;
    }

    key_len = ngx_strlen(key);
    p = args.data;
    end = args.data + args.len;

    while (p < end) {
        u_char *amp = ngx_strlchr(p, end, '&');
        u_char *seg_end = amp ? amp : end;
        u_char *eq = ngx_strlchr(p, seg_end, '=');
        u_char *key_end = eq ? eq : seg_end;

        if ((size_t) (key_end - p) == key_len
            && xrootd_http_query_key_eq(p, key, key_len, flags))
        {
            if (eq == NULL || (flags & XROOTD_HTTP_QUERY_HAS_VALUE_OK)) {
                return 1;
            }
        }

        p = (amp != NULL) ? amp + 1 : end;
    }

    return 0;
}
