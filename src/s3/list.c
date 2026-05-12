/*
 * list.c — S3 ListObjectsV2 handler.
 *
 * Implements GET /<bucket>/?list-type=2 with:
 *   prefix=       - key prefix filter
 *   delimiter=    - hierarchy delimiter (usually "/")
 *   max-keys=     - page size (default from config, max 1000)
 *   continuation-token= - opaque page cursor (we use base64 of last key)
 *
 * The response is the standard ListBucketResult XML document.  Directory
 * sentinels (.xrdcls3.dirsentinel) are omitted from the listing.
 */

#include "s3.h"
#include <errno.h>
#include <stdlib.h>

#include <sys/stat.h>
#include <dirent.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <time.h>

/* Maximum number of entries we'll collect before sorting/paginating */
#define S3_LIST_MAX_ENTRIES  65536

/* One entry in the listing */
typedef struct {
    char    key[S3_MAX_KEY];   /* full object key (relative to root) */
    int     is_prefix;         /* 1 = CommonPrefix, 0 = Contents     */
    off_t   size;
    time_t  mtime;
    char    etag[48];
} s3_entry_t;

/* -------------------------------------------------------------------------
 * qsort comparator — lexicographic key order
 * ---------------------------------------------------------------------- */

static int
entry_cmp(const void *a, const void *b)
{
    return strcmp(((const s3_entry_t *) a)->key,
                  ((const s3_entry_t *) b)->key);
}

/* -------------------------------------------------------------------------
 * Recursive directory walker — fills entries[], returns count
 * ---------------------------------------------------------------------- */

static int
s3_walk(const char *root,          /* filesystem root            */
        const char *dir_path,      /* filesystem path to scan    */
        const char *key_prefix,    /* key prefix so far          */
        const char *filter_prefix, /* ListObjectsV2 prefix param */
        const char *delimiter,     /* hierarchy delimiter        */
        s3_entry_t *entries,       /* output array               */
        int         max_entries,   /* size of entries[]          */
        int        *count)         /* current fill index         */
{
    DIR            *dh;
    struct dirent  *de;
    struct stat     sb;
    char            child_path[PATH_MAX];
    char            child_key[S3_MAX_KEY];
    size_t          fp_len  = filter_prefix ? strlen(filter_prefix) : 0;
    size_t          del_len = delimiter     ? strlen(delimiter)      : 0;

    dh = opendir(dir_path);
    if (dh == NULL) {
        return 0;
    }

    while ((de = readdir(dh)) != NULL && *count < max_entries) {
        if (de->d_name[0] == '.') {
            continue; /* skip hidden / . / .. */
        }

        /* Build filesystem path */
        if ((size_t) snprintf(child_path, sizeof(child_path), "%s/%s",
                              dir_path, de->d_name) >= sizeof(child_path)) {
            continue;
        }

        /* Build key relative to root */
        if (key_prefix[0] != '\0') {
            if ((size_t) snprintf(child_key, sizeof(child_key), "%s/%s",
                                  key_prefix, de->d_name) >= sizeof(child_key)) {
                continue;
            }
        } else {
            if (strlen(de->d_name) >= sizeof(child_key)) {
                continue;
            }
            memcpy(child_key, de->d_name, strlen(de->d_name) + 1);
        }

        if (stat(child_path, &sb) != 0) {
            continue;
        }

        if (S_ISDIR(sb.st_mode)) {
            if (del_len > 0) {
                /* Build "dir_key/" to check against filter_prefix */
                char prefix_entry[S3_MAX_KEY];
                if ((size_t) snprintf(prefix_entry, sizeof(prefix_entry), "%s/",
                                      child_key) >= sizeof(prefix_entry)) {
                    continue;
                }
                size_t pe_len = strlen(prefix_entry);

                /*
                 * Recurse if filter_prefix starts with this dir (i.e. the
                 * user-supplied prefix descends into this directory).
                 * Example: dir="dlist_x", prefix="dlist_x/" → recurse.
                 */
                if (fp_len > 0 && fp_len >= pe_len
                    && strncmp(filter_prefix, prefix_entry, pe_len) == 0) {
                    s3_walk(root, child_path, child_key,
                            filter_prefix, delimiter, entries, max_entries, count);
                    continue;
                }

                /* Emit as CommonPrefix if it matches or starts with filter */
                if (fp_len > 0
                    && strncmp(prefix_entry, filter_prefix, fp_len) != 0) {
                    continue;
                }
                s3_entry_t *e = &entries[*count];
                ngx_cpystrn((u_char *) e->key, (u_char *) prefix_entry,
                            sizeof(e->key));
                e->is_prefix = 1;
                e->size      = 0;
                e->mtime     = sb.st_mtime;
                e->etag[0]   = '\0';
                (*count)++;
            } else {
                /* No delimiter: recurse unconditionally */
                s3_walk(root, child_path, child_key,
                        filter_prefix, delimiter, entries, max_entries, count);
            }
        } else if (S_ISREG(sb.st_mode)) {
            /* Skip directory sentinel */
            if (strcmp(de->d_name, S3_DIR_SENTINEL) == 0) {
                continue;
            }
            /* Filter by prefix */
            if (fp_len > 0 && strncmp(child_key, filter_prefix, fp_len) != 0) {
                continue;
            }
            /* With delimiter, skip entries that have delimiter after prefix */
            if (del_len > 0) {
                const char *after_prefix = child_key + fp_len;
                if (strstr(after_prefix, delimiter) != NULL) {
                    /* belongs under a CommonPrefix — skip */
                    continue;
                }
            }

            s3_entry_t *e = &entries[*count];
            ngx_cpystrn((u_char *) e->key, (u_char *) child_key,
                        sizeof(e->key));
            e->is_prefix = 0;
            e->size      = sb.st_size;
            e->mtime     = sb.st_mtime;

            struct stat *stp = &sb;
            s3_etag(stp, e->etag, sizeof(e->etag));
            (*count)++;
        }
    }

    closedir(dh);
    return *count;
}

/* -------------------------------------------------------------------------
 * Parse a query parameter value from the args string.
 * Returns 1 and fills buf if found, 0 otherwise.
 * ---------------------------------------------------------------------- */

static int
s3_get_arg(ngx_str_t args, const char *name, u_char *buf, size_t bufsz)
{
    size_t   nlen = strlen(name);
    u_char  *p    = args.data;
    u_char  *end  = args.data + args.len;

    while (p < end) {
        /* find '&' or end */
        u_char *amp = ngx_strlchr(p, end, '&');
        u_char *seg_end = amp ? amp : end;
        u_char *eq  = ngx_strlchr(p, seg_end, '=');

        if (eq != NULL && (size_t) (eq - p) == nlen
            && ngx_strncmp(p, (u_char *) name, nlen) == 0) {
            u_char *val = eq + 1;
            ssize_t dlen = s3_urldecode(val, (size_t) (seg_end - val), buf, bufsz);
            if (dlen < 0) {
                return 0;
            }
            return 1;
        }

        p = seg_end + (amp ? 1 : 0);
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * Minimal base64url encode for continuation tokens (key string → opaque)
 * ---------------------------------------------------------------------- */

static void
b64url_encode(const char *src, size_t slen, char *dst, size_t dsz)
{
    static const char tbl[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t di = 0;
    size_t i;

    for (i = 0; i + 2 < slen && di + 4 < dsz - 1; i += 3) {
        uint32_t v = ((uint32_t)(u_char)src[i]     << 16)
                   | ((uint32_t)(u_char)src[i + 1] << 8)
                   | ((uint32_t)(u_char)src[i + 2]);
        dst[di++] = tbl[(v >> 18) & 0x3f];
        dst[di++] = tbl[(v >> 12) & 0x3f];
        dst[di++] = tbl[(v >>  6) & 0x3f];
        dst[di++] = tbl[ v        & 0x3f];
    }
    if (i < slen && di + 2 < dsz - 1) {
        uint32_t v = (uint32_t)(u_char)src[i] << 16;
        if (i + 1 < slen) {
            v |= (uint32_t)(u_char)src[i + 1] << 8;
        }
        dst[di++] = tbl[(v >> 18) & 0x3f];
        dst[di++] = tbl[(v >> 12) & 0x3f];
        if (i + 1 < slen) {
            dst[di++] = tbl[(v >> 6) & 0x3f];
        }
    }
    dst[di] = '\0';
}

static void
b64url_decode(const char *src, size_t slen, char *dst, size_t dsz)
{
    /* Reverse of b64url_encode — decode back to the key string */
    size_t di = 0;
    size_t i;

    static const signed char inv[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,63,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    };

    for (i = 0; i + 3 < slen && di + 3 < dsz - 1; i += 4) {
        int a = inv[(u_char)src[i]];
        int b = inv[(u_char)src[i+1]];
        int c = inv[(u_char)src[i+2]];
        int d = inv[(u_char)src[i+3]];
        if (a < 0 || b < 0 || c < 0 || d < 0) break;
        dst[di++] = (char) ((a << 2) | (b >> 4));
        dst[di++] = (char) ((b << 4) | (c >> 2));
        dst[di++] = (char) ((c << 6) |  d);
    }
    /* handle remaining */
    if (i + 1 < slen && di < dsz - 1) {
        int a = inv[(u_char)src[i]];
        int b = inv[(u_char)src[i+1]];
        if (a >= 0 && b >= 0) {
            dst[di++] = (char) ((a << 2) | (b >> 4));
        }
        if (i + 2 < slen && di < dsz - 1) {
            int c = inv[(u_char)src[i+2]];
            if (b >= 0 && c >= 0) {
                dst[di++] = (char) ((b << 4) | (c >> 2));
            }
        }
    }
    dst[di] = '\0';
}


static void
s3_xml_append_escaped(u_char *xml, size_t xml_capacity, size_t *xml_len,
    const u_char *value, size_t value_len)
{
    ngx_buf_t scratch;

    scratch.pos = xml + *xml_len;
    scratch.last = xml + *xml_len;
    scratch.end = xml + xml_capacity - 1;

    s3_xml_escape(&scratch, value, value_len);
    *xml_len = (size_t) (scratch.last - xml);
}


/* -------------------------------------------------------------------------
 * URL-encode a key for encoding-type=url responses.
 * Unreserved chars (RFC 3986 §2.3) are passed through; everything else
 * becomes %XX.  The output is always NUL-terminated.
 * ---------------------------------------------------------------------- */
static void
s3_url_encode_key(const char *src, char *dst, size_t dst_size)
{
    static const char hex[] = "0123456789ABCDEF";
    size_t            di    = 0;

    while (*src && di + 3 < dst_size) {
        unsigned char c = (unsigned char) *src++;
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
            || (c >= '0' && c <= '9')
            || c == '-' || c == '_' || c == '.' || c == '~')
        {
            dst[di++] = (char) c;
        } else {
            dst[di++] = '%';
            dst[di++] = hex[c >> 4];
            dst[di++] = hex[c & 0x0f];
        }
    }
    dst[di] = '\0';
}

/* -------------------------------------------------------------------------
 * s3_handle_list — build ListObjectsV2 XML response
 * ---------------------------------------------------------------------- */

ngx_int_t
s3_handle_list(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf)
{
    u_char          prefix_buf[S3_MAX_PARAM]    = { 0 };
    u_char          delimiter_buf[S3_MAX_PARAM] = { 0 };
    u_char          token_buf[S3_MAX_PARAM]     = { 0 };
    u_char          max_keys_buf[32]            = { 0 };
    u_char          fetch_owner_buf[8]          = { 0 };
    u_char          encoding_type_buf[8]        = { 0 };
    char            start_after[S3_MAX_KEY]     = { 0 };
    int             max_keys;
    int             fetch_owner  = 0;
    int             url_encode   = 0;
    s3_entry_t     *entries;
    int             total = 0;
    int             start_idx = 0;
    int             end_idx;
    int             truncated;
    int             contents = 0;
    int             prefixes = 0;
    ngx_buf_t      *response_buf;
    ngx_chain_t     response_chain;
    size_t          xml_capacity;
    u_char         *xml;
    size_t          xml_len = 0;
    char            iso_buf[32];
    char            next_token[S3_MAX_KEY * 2];

    /* Parse query parameters */
    s3_get_arg(r->args, "prefix",             prefix_buf,       sizeof(prefix_buf));
    s3_get_arg(r->args, "delimiter",          delimiter_buf,    sizeof(delimiter_buf));
    s3_get_arg(r->args, "continuation-token", token_buf,        sizeof(token_buf));
    s3_get_arg(r->args, "fetch-owner",        fetch_owner_buf,  sizeof(fetch_owner_buf));
    s3_get_arg(r->args, "encoding-type",      encoding_type_buf,sizeof(encoding_type_buf));

    if (ngx_strcasecmp(fetch_owner_buf, (u_char *) "true") == 0) {
        fetch_owner = 1;
    }
    if (ngx_strcasecmp(encoding_type_buf, (u_char *) "url") == 0) {
        url_encode = 1;
    }

    max_keys = (int) cf->max_keys;
    if (s3_get_arg(r->args, "max-keys",
                   max_keys_buf, sizeof(max_keys_buf)))
    {
        char *endp;
        long  mk;

        errno = 0;
        mk = strtol((const char *) max_keys_buf, &endp, 10);
        if (errno == 0 && endp != (char *) max_keys_buf
            && mk > 0 && mk < max_keys)
        {
            max_keys = (int) mk;
        }
    }
    if (max_keys <= 0) {
        max_keys = 1000;
    }

    /* Decode continuation token → last key we returned */
    if (token_buf[0] != '\0') {
        b64url_decode((const char *) token_buf, strlen((const char *) token_buf),
                      start_after, sizeof(start_after));
    }

    /* Collect entries */
    entries = ngx_palloc(r->pool, sizeof(s3_entry_t) * S3_LIST_MAX_ENTRIES);
    if (entries == NULL) {
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    s3_walk((const char *) cf->root.data,
            (const char *) cf->root.data,
            "",
            (const char *) prefix_buf,
            (const char *) delimiter_buf,
            entries, S3_LIST_MAX_ENTRIES, &total);

    qsort(entries, (size_t) total, sizeof(s3_entry_t), entry_cmp);

    /* Apply continuation token: find first entry > start_after */
    if (start_after[0] != '\0') {
        for (start_idx = 0; start_idx < total; start_idx++) {
            if (strcmp(entries[start_idx].key, start_after) > 0) {
                break;
            }
        }
    }

    end_idx  = start_idx + max_keys;
    if (end_idx > total) {
        end_idx = total;
    }
    truncated = (end_idx < total);

    /* Build next continuation token */
    next_token[0] = '\0';
    if (truncated && end_idx > 0) {
        b64url_encode(entries[end_idx - 1].key,
                      strlen(entries[end_idx - 1].key),
                      next_token, sizeof(next_token));
    }

    /* Estimate XML buffer size generously.
     * URL-encoded keys expand up to 3x; Owner adds ~128 bytes per entry. */
    xml_capacity = 512
                 + (size_t) cf->bucket.len + 32
                 + strlen((const char *) prefix_buf) * 3 + 32
                 + strlen((const char *) delimiter_buf) * 3 + 32
                 + strlen(next_token) + 64
                 + (size_t) (end_idx - start_idx)
                   * (S3_MAX_KEY * 3 + 256 + (fetch_owner ? 128 : 0));

    xml = ngx_palloc(r->pool, xml_capacity);
    if (xml == NULL) {
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

#define XML_APPEND(fmt, ...) \
    xml_len += (size_t) snprintf((char *) xml + xml_len, \
                                 xml_capacity - xml_len, fmt, ##__VA_ARGS__)

    XML_APPEND("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    XML_APPEND("<ListBucketResult "
               "xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");
    XML_APPEND("<Name>%.*s</Name>", (int) cf->bucket.len, cf->bucket.data);
    XML_APPEND("<Prefix>");
    s3_xml_append_escaped(xml, xml_capacity, &xml_len, prefix_buf,
                          strlen((const char *) prefix_buf));
    XML_APPEND("</Prefix>");
    XML_APPEND("<KeyCount>%d</KeyCount>", end_idx - start_idx);
    XML_APPEND("<MaxKeys>%d</MaxKeys>", max_keys);

    if (delimiter_buf[0] != '\0') {
        XML_APPEND("<Delimiter>");
        s3_xml_append_escaped(xml, xml_capacity, &xml_len, delimiter_buf,
                              strlen((const char *) delimiter_buf));
        XML_APPEND("</Delimiter>");
    }

    if (url_encode) {
        XML_APPEND("<EncodingType>url</EncodingType>");
    }
    XML_APPEND("<IsTruncated>%s</IsTruncated>",
               truncated ? "true" : "false");

    if (truncated && next_token[0] != '\0') {
        XML_APPEND("<NextContinuationToken>%s</NextContinuationToken>",
                   next_token);
    }

    /* Emit Contents and CommonPrefixes */
    for (int entry_index = start_idx; entry_index < end_idx; entry_index++) {
        s3_entry_t *entry = &entries[entry_index];

        if (entry->is_prefix) {
            prefixes++;
            XML_APPEND("<CommonPrefixes><Prefix>");
            s3_xml_append_escaped(xml, xml_capacity, &xml_len,
                                  (u_char *) entry->key, strlen(entry->key));
            XML_APPEND("</Prefix></CommonPrefixes>");
        } else {
            char encoded_key[S3_MAX_KEY * 3 + 1];

            contents++;
            s3_iso8601(entry->mtime, iso_buf, sizeof(iso_buf));
            XML_APPEND("<Contents>");
            XML_APPEND("<Key>");
            if (url_encode) {
                s3_url_encode_key(entry->key, encoded_key, sizeof(encoded_key));
                s3_xml_append_escaped(xml, xml_capacity, &xml_len,
                                      (u_char *) encoded_key,
                                      strlen(encoded_key));
            } else {
                s3_xml_append_escaped(xml, xml_capacity, &xml_len,
                                      (u_char *) entry->key,
                                      strlen(entry->key));
            }
            XML_APPEND("</Key>");
            XML_APPEND("<LastModified>%s</LastModified>", iso_buf);
            XML_APPEND("<ETag>%s</ETag>", entry->etag);
            XML_APPEND("<Size>%lld</Size>", (long long) entry->size);
            XML_APPEND("<StorageClass>STANDARD</StorageClass>");
            if (fetch_owner && cf->access_key.len > 0) {
                XML_APPEND("<Owner>"
                           "<ID>%.*s</ID>"
                           "<DisplayName>%.*s</DisplayName>"
                           "</Owner>",
                           (int) cf->access_key.len, cf->access_key.data,
                           (int) cf->access_key.len, cf->access_key.data);
            }
            XML_APPEND("</Contents>");
        }
    }

    XML_APPEND("</ListBucketResult>");

#undef XML_APPEND

    response_buf = ngx_create_temp_buf(r->pool, xml_len + 4);
    if (response_buf == NULL) {
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    response_buf->last = ngx_cpymem(response_buf->last, xml, xml_len);
    response_buf->last_buf = 1;

    r->headers_out.status            = NGX_HTTP_OK;
    r->headers_out.content_type      = (ngx_str_t) ngx_string("application/xml");
    r->headers_out.content_length_n  = (off_t) xml_len;

    XROOTD_S3_METRIC_ADD(list_contents_total, (size_t) contents);
    XROOTD_S3_METRIC_ADD(list_common_prefixes_total, (size_t) prefixes);
    if (truncated) {
        XROOTD_S3_METRIC_INC(list_truncated_total);
    }
    XROOTD_S3_METRIC_ADD(bytes_tx_total, xml_len);

    ngx_http_send_header(r);
    response_chain.buf = response_buf;
    response_chain.next = NULL;
    return ngx_http_output_filter(r, &response_chain);
}
