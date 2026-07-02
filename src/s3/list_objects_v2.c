#include "s3.h"
#include "token/b64url.h"
#include "core/compat/http_query.h"
#include <string.h>

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
    u_char       prefix_buf[S3_MAX_PARAM]    = { 0 };
    u_char       delimiter_buf[S3_MAX_PARAM] = { 0 };
    u_char       token_buf[S3_MAX_PARAM]     = { 0 };  /* ContinuationToken (b64url) */
    u_char       fetch_owner_buf[8]          = { 0 };
    u_char       encoding_type_buf[8]        = { 0 };
    char         start_after[S3_MAX_KEY]     = { 0 };
    int          max_keys;
    int          fetch_owner = 0;
    int          url_encode  = 0;
    s3_entry_t  *items = NULL;
    int          total = 0;
    int          start_idx;
    int          end_idx;
    int          truncated;
    int          contents = 0;
    int          prefixes = 0;
    size_t       xml_capacity;
    u_char      *xml;
    size_t       xml_len = 0;
    char         next_token[S3_MAX_KEY * 2];
    ngx_int_t    rc;

    /* Parse query parameters (max-keys via the shared helper). */
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

    max_keys = s3_list_parse_max_keys(r, (int) cf->max_keys);

    /* Decode continuation token: b64url-encoded last key from the previous page.
     * On decode failure start_after stays empty — the server returns from the
     * beginning (graceful degradation for malformed tokens). */
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

    if (s3_list_collect_sorted(r, cf, (const char *) prefix_buf,
                               (const char *) delimiter_buf,
                               &items, &total) != NGX_OK)
    {
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    truncated = s3_list_paginate(items, total, start_after, max_keys,
                                 &start_idx, &end_idx);

    /* NextContinuationToken: b64url of the last key in this slice, only when the
     * response is truncated and at least one entry was returned. */
    next_token[0] = '\0';
    if (truncated && end_idx > 0) {
        b64url_encode(items[end_idx - 1].key,
                      strlen(items[end_idx - 1].key),
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
    XML_APPEND("<IsTruncated>%s</IsTruncated>", truncated ? "true" : "false");

    if (truncated && next_token[0] != '\0') {
        XML_APPEND_ELEM("NextContinuationToken", next_token,
                        strlen(next_token));
    }

    rc = s3_list_emit_entries(r, cf, items, start_idx, end_idx,
                              url_encode, fetch_owner,
                              xml, &xml_len, xml_capacity,
                              &contents, &prefixes);
    if (rc != NGX_OK) {
        return rc;
    }

    XML_APPEND("</ListBucketResult>");

    return s3_list_finalize(r, xml, xml_len, contents, prefixes, truncated);
}
