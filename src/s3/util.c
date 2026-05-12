/*
 * util.c — shared helpers: URL decode, path resolve, ETag, ISO 8601,
 *           XML escape, error response.
 */

#include "s3.h"

#include <sys/stat.h>
#include <time.h>
#include <limits.h>
#include <string.h>
#include <stdio.h>

/* -------------------------------------------------------------------------
 * URL decode (percent-encoding)
 * ---------------------------------------------------------------------- */

static int
hex_digit(u_char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

ssize_t
s3_urldecode(const u_char *src, size_t slen, u_char *dst, size_t dsz)
{
    size_t  di = 0;
    size_t  si = 0;

    while (si < slen) {
        if (di >= dsz - 1) {
            return -1;
        }

        if (src[si] == '%' && si + 2 < slen) {
            int hi = hex_digit(src[si + 1]);
            int lo = hex_digit(src[si + 2]);
            if (hi >= 0 && lo >= 0) {
                dst[di++] = (u_char) ((hi << 4) | lo);
                si += 3;
                continue;
            }
        }

        if (src[si] == '+') {
            dst[di++] = ' ';
            si++;
            continue;
        }

        dst[di++] = src[si++];
    }

    dst[di] = '\0';
    return (ssize_t) di;
}

/* -------------------------------------------------------------------------
 * Filesystem path resolution
 * ---------------------------------------------------------------------- */

int
s3_resolve_key(const char *root, const char *key, char *out, size_t outsz)
{
    char        joined[PATH_MAX];
    const char *k = key;
    size_t      rlen, klen;
    char       *p, *end, *seg;

    /* strip leading slashes from key */
    while (*k == '/') {
        k++;
    }

    rlen = strlen(root);
    klen = strlen(k);

    if (rlen + 1 + klen + 1 > sizeof(joined)) {
        return 0;
    }

    ngx_memcpy(joined, root, rlen);
    joined[rlen] = '/';
    ngx_memcpy(joined + rlen + 1, k, klen + 1);

    /* Scan for ".." components without calling realpath (path may not exist) */
    end = joined + strlen(joined);
    p   = joined + rlen;   /* only scan the key portion */

    while (p < end) {
        while (*p == '/') {
            p++;
        }

        seg = p;
        while (p < end && *p != '/') {
            p++;
        }

        if (p - seg == 2 && seg[0] == '.' && seg[1] == '.') {
            return 0; /* path traversal attempt */
        }
    }

    if ((size_t) (rlen + 1 + klen + 1) > outsz) {
        return 0;
    }

    ngx_memcpy(out, joined, rlen + 1 + klen + 1);
    return 1;
}

/* -------------------------------------------------------------------------
 * ETag generation  (synthetic: "mtime-size")
 * ---------------------------------------------------------------------- */

void
s3_etag(const struct stat *st, char *buf, size_t bufsz)
{
    snprintf(buf, bufsz, "\"%lx-%lx\"",
             (unsigned long) st->st_mtime,
             (unsigned long) st->st_size);
}

/* -------------------------------------------------------------------------
 * ISO 8601 timestamp
 * ---------------------------------------------------------------------- */

void
s3_iso8601(time_t t, char *buf, size_t bufsz)
{
    struct tm tm;
    gmtime_r(&t, &tm);
    snprintf(buf, bufsz,
             "%04d-%02d-%02dT%02d:%02d:%02d.000Z",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec);
}

/* -------------------------------------------------------------------------
 * XML escape
 * ---------------------------------------------------------------------- */

void
s3_xml_escape(ngx_buf_t *b, const u_char *s, size_t len)
{
    static const struct { u_char c; const char *esc; size_t elen; } tbl[] = {
        { '&',  "&amp;",  5 },
        { '<',  "&lt;",   4 },
        { '>',  "&gt;",   4 },
        { '"',  "&quot;", 6 },
        { '\'', "&apos;", 6 },
    };

    for (size_t i = 0; i < len; i++) {
        u_char c = s[i];
        int escaped = 0;
        for (size_t t = 0; t < sizeof(tbl)/sizeof(tbl[0]); t++) {
            if (c == tbl[t].c) {
                b->last = ngx_cpymem(b->last,
                                     tbl[t].esc, tbl[t].elen);
                escaped = 1;
                break;
            }
        }
        if (!escaped) {
            *b->last++ = c;
        }
    }
}

/* -------------------------------------------------------------------------
 * XML error response
 * ---------------------------------------------------------------------- */

ngx_int_t
s3_send_xml_error(ngx_http_request_t *r,
                   ngx_uint_t status,
                   const char *code,
                   const char *message)
{
    static const char prefix[] =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<Error>"
        "<Code>";
    static const char mid[] = "</Code><Message>";
    static const char suffix[] = "</Message></Error>";

    size_t      codelen = strlen(code);
    size_t      msglen  = strlen(message);
    size_t      total   = sizeof(prefix) - 1
                        + codelen
                        + sizeof(mid) - 1
                        + msglen
                        + sizeof(suffix) - 1;
    ngx_buf_t  *b;
    ngx_chain_t out;

    b = ngx_create_temp_buf(r->pool, total + 4);
    if (b == NULL) {
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->last = ngx_cpymem(b->last, prefix, sizeof(prefix) - 1);
    b->last = ngx_cpymem(b->last, code, codelen);
    b->last = ngx_cpymem(b->last, mid, sizeof(mid) - 1);
    b->last = ngx_cpymem(b->last, message, msglen);
    b->last = ngx_cpymem(b->last, suffix, sizeof(suffix) - 1);
    b->last_buf = 1;

    r->headers_out.status          = status;
    r->headers_out.content_type    = (ngx_str_t) ngx_string("application/xml");
    r->headers_out.content_length_n = (off_t) (b->last - b->pos);

    XROOTD_S3_METRIC_ADD(bytes_tx_total, (size_t) (b->last - b->pos));
    ngx_http_send_header(r);

    out.buf  = b;
    out.next = NULL;
    return ngx_http_output_filter(r, &out);
}
