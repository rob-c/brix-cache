#include "s3.h"
#include "../token/b64url.h"
#include "../compat/http_query.h"
#include <string.h>

/* S3 list params: URL-decode, + → space, reject NUL, allow empty delimiter. */
#define S3_LIST_QUERY_FLAGS \
    (XROOTD_HTTP_QUERY_DECODE_VALUE | XROOTD_HTTP_QUERY_PLUS_TO_SPACE \
     | XROOTD_HTTP_QUERY_REJECT_NUL | XROOTD_HTTP_QUERY_ALLOW_EMPTY)

/*
 * s3_handle_list — ListObjectsV2 XML response builder
 *
 * WHAT: Builds the ListBucketResult XML for S3 ListObjectsV2 requests. Parses query
 *   parameters (prefix, delimiter, continuation-token, max-keys), walks the filesystem
 *   to collect matching entries, applies pagination via continuation tokens, and emits
 *   a compliant XML response with Contents (objects) and CommonPrefixes (directories).
 *
 * WHY: S3 clients paginate list results using continuation tokens — each token encodes
 *   the last key returned in base64url. The server must skip all entries <= that key on
 *   subsequent requests. Delimiter-based common prefixes group keys under shared prefixes
 *   into <CommonPrefixes> elements per the S3 spec. XML entities (quotes, ampersands) can
 *   expand up to 6× in worst case, so buffer sizing uses 6× as a safety multiplier.
 *
 * HOW:
 *   1. Parse query parameters: prefix, delimiter, continuation-token, max-keys,
 *      fetch-owner, encoding-type — all via s3_get_arg() with bounded buffers
 *   2. Decode continuation token (b64url → start_after) to find pagination offset
 *   3. Walk filesystem via s3_walk() collecting entries filtered by prefix/delimiter
 *   4. Sort entries lexicographically via qsort(entry_cmp)
 *   5. Skip entries <= start_after to apply continuation token (linear scan on sorted)
 *   6. Slice [start_idx, end_idx) capped at max_keys — set truncated flag
 *   7. Encode next continuation token from last returned key if truncated
 *   8. Estimate XML buffer capacity (512 header + per-key × 6× expansion)
 *   9. Append XML: ListBucketResult root → Name, Prefix, KeyCount, MaxKeys,
 *      IsTruncated, NextContinuationToken → Contents/CommonPrefixes loop
 *   10. Create response buffer, increment metrics, send via xrootd_http_send_xml_buffer()
 *
 * Pool allocation: entries array and xml buffer use ngx_palloc(r->pool) — lifetime
 *   survives until the HTTP response filter completes.
 */

ngx_int_t
s3_handle_list(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf)
{
    /* Query parameter buffers — S3_MAX_PARAM bounds all string params to prevent overflow */
    u_char          prefix_buf[S3_MAX_PARAM]    = { 0 };
    u_char          delimiter_buf[S3_MAX_PARAM] = { 0 };
    u_char          token_buf[S3_MAX_PARAM]     = { 0 };  // ContinuationToken decoded via b64url
    /* max-keys parsed as integer — 32 bytes sufficient for a 10-digit number */
    u_char          max_keys_buf[32]            = { 0 };
    /* Boolean flags: fetch-owner adds <Owner> to each Contents; url_encode applies URL-encoding to Keys */
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
    size_t          xml_capacity;
    u_char         *xml;
    size_t          xml_len = 0;
    char            iso_buf[32];
    char            next_token[S3_MAX_KEY * 2];

    /* Parse query parameters */
    xrootd_http_query_get(r->args, "prefix",             (char *) prefix_buf,        sizeof(prefix_buf),        S3_LIST_QUERY_FLAGS);
    xrootd_http_query_get(r->args, "delimiter",          (char *) delimiter_buf,     sizeof(delimiter_buf),     S3_LIST_QUERY_FLAGS);
    xrootd_http_query_get(r->args, "continuation-token", (char *) token_buf,         sizeof(token_buf),         S3_LIST_QUERY_FLAGS);
    xrootd_http_query_get(r->args, "fetch-owner",        (char *) fetch_owner_buf,   sizeof(fetch_owner_buf),   S3_LIST_QUERY_FLAGS);
    xrootd_http_query_get(r->args, "encoding-type",      (char *) encoding_type_buf, sizeof(encoding_type_buf), S3_LIST_QUERY_FLAGS);

    if (ngx_strcasecmp(fetch_owner_buf, (u_char *) "true") == 0) {
        fetch_owner = 1;
    }
    if (ngx_strcasecmp(encoding_type_buf, (u_char *) "url") == 0) {
        url_encode = 1;
    }

    max_keys = (int) cf->max_keys;
    if (xrootd_http_query_get(r->args, "max-keys",
                              (char *) max_keys_buf, sizeof(max_keys_buf),
                              S3_LIST_QUERY_FLAGS) > 0)
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

    /* Decode continuation token: b64url-encoded string of the last key returned in
     * the previous page. On decode failure, start_after stays empty — the server
     * returns from the beginning (graceful degradation for malformed tokens). */

    if (token_buf[0] != '\0') {
        ssize_t n = b64url_decode((const char *) token_buf,
                                  strlen((const char *) token_buf),
                                  (uint8_t *) start_after,
                                  sizeof(start_after) - 1);
        if (n >= 0) {
            start_after[n] = '\0';
        } else {
            start_after[0] = '\0';
        }
    }

    /* Allocate entry array on r->pool — lifetime survives until async callback completes. S3_LIST_MAX_ENTRIES
     * caps the walk to prevent unbounded memory growth on large buckets. */

    entries = ngx_palloc(r->pool, sizeof(s3_entry_t) * S3_LIST_MAX_ENTRIES);
    if (entries == NULL) {
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Walk filesystem under root, collecting entries matching prefix+delimiter filter.
     * s3_walk populates the entries array with is_prefix flags distinguishing objects
     * from directory-like common prefixes. total counts all matched entries (before pagination). */

    s3_walk((const char *) cf->common.root.data,
            (const char *) cf->common.root.data,
            "",
            (const char *) prefix_buf,
            (const char *) delimiter_buf,
            entries, S3_LIST_MAX_ENTRIES, &total);

    qsort(entries, (size_t) total, sizeof(s3_entry_t), entry_cmp);

    /* Pagination offset: linear scan through sorted entries to find the first key
     * strictly greater than start_after. All entries <= start_after were returned on
     * the previous page and must be skipped here. O(total) — acceptable since total
     * is already capped by S3_LIST_MAX_ENTRIES. */

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

    /* Encode the last returned key (entries[end_idx - 1]) into b64url as NextContinuationToken.
     * Only set when truncated=true and at least one entry was returned — clients use this
     * token to request the next page. end_idx-1 is the final index in our slice [start_idx, end_idx). */

    next_token[0] = '\0';
    if (truncated && end_idx > 0) {
        b64url_encode(entries[end_idx - 1].key,
                      strlen(entries[end_idx - 1].key),
                      next_token, sizeof(next_token));
    }

    /* Estimate XML buffer size.  XML entities expand characters up to 6×
     * (e.g. ' → &apos;), so use 6× as the per-byte worst-case. */
    xml_capacity = 512
                 + (size_t) cf->bucket.len + 32
                 + strlen((const char *) prefix_buf) * 6 + 32
                 + strlen((const char *) delimiter_buf) * 6 + 32
                 + strlen(next_token) + 64
                 + (size_t) (end_idx - start_idx)
                   * (S3_MAX_KEY * 6 + 512 + (fetch_owner ? 128 : 0));

    xml = ngx_palloc(r->pool, xml_capacity);
    if (xml == NULL) {
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    XML_APPEND("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    XML_APPEND("<ListBucketResult "
               "xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");
    XML_APPEND_ELEM("Name", cf->bucket.data, cf->bucket.len);
    XML_APPEND_ELEM("Prefix", prefix_buf, strlen((const char *) prefix_buf));
    XML_APPEND("<KeyCount>%d</KeyCount>", end_idx - start_idx);
    XML_APPEND("<MaxKeys>%d</MaxKeys>", max_keys);

    if (delimiter_buf[0] != '\0') {
        XML_APPEND_ELEM("Delimiter", delimiter_buf,
                        strlen((const char *) delimiter_buf));
    }

    if (url_encode) {
        XML_APPEND("<EncodingType>url</EncodingType>");
    }
    XML_APPEND("<IsTruncated>%s</IsTruncated>",
               truncated ? "true" : "false");

    if (truncated && next_token[0] != '\0') {
        XML_APPEND_ELEM("NextContinuationToken", next_token,
                        strlen(next_token));
    }

    /* Emit Contents and CommonPrefixes */
    for (int entry_index = start_idx; entry_index < end_idx; entry_index++) {
        s3_entry_t *entry = &entries[entry_index];

        if (entry->is_prefix) {
            prefixes++;
            XML_APPEND("<CommonPrefixes>");
            XML_APPEND_ELEM("Prefix", entry->key, strlen(entry->key));
            XML_APPEND("</CommonPrefixes>");
        } else {
            char encoded_key[S3_MAX_KEY * 3 + 1];

            contents++;
            xrootd_format_iso8601(entry->mtime, iso_buf, sizeof(iso_buf));
            XML_APPEND("<Contents>");
            if (url_encode) {
                xrootd_http_urlencode((const u_char *) entry->key,
                                      strlen(entry->key),
                                      encoded_key, sizeof(encoded_key), "");
                XML_APPEND_ELEM("Key", encoded_key, strlen(encoded_key));
            } else {
                XML_APPEND_ELEM("Key", entry->key, strlen(entry->key));
            }
            XML_APPEND("<LastModified>%s</LastModified>", iso_buf);
            XML_APPEND("<ETag>%s</ETag>", entry->etag);
            XML_APPEND("<Size>%lld</Size>", (long long) entry->size);
            XML_APPEND("<StorageClass>STANDARD</StorageClass>");
            if (fetch_owner && cf->access_key.len > 0) {
                XML_APPEND("<Owner>");
                XML_APPEND_ELEM("ID", cf->access_key.data, cf->access_key.len);
                XML_APPEND_ELEM("DisplayName", cf->access_key.data,
                                cf->access_key.len);
                XML_APPEND("</Owner>");
            }
            XML_APPEND("</Contents>");
        }
    }

    XML_APPEND("</ListBucketResult>");

    response_buf = ngx_create_temp_buf(r->pool, xml_len + 4);
    if (response_buf == NULL) {
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    response_buf->last = ngx_cpymem(response_buf->last, xml, xml_len);
    response_buf->last_buf = 1;

    /* Metrics: per-request counters for list operation observability
     * — contents tracks object count emitted, prefixes tracks CommonPrefixes groups,
     * truncated counts paginated responses, bytes_tx tracks XML payload size. */

    XROOTD_S3_METRIC_ADD(list_contents_total, (size_t) contents);
    XROOTD_S3_METRIC_ADD(list_common_prefixes_total, (size_t) prefixes);
    if (truncated) {
        XROOTD_S3_METRIC_INC(list_truncated_total);
    }
    XROOTD_S3_METRIC_ADD(bytes_tx_total, xml_len);

    return xrootd_http_send_xml_buffer(r, NGX_HTTP_OK,
        (ngx_str_t) ngx_string("application/xml"), response_buf);
}
