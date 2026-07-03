/*
 * list_objects_v1.c — ListObjects (V1) XML response builder.
 *
 * WHAT: Builds the ListBucketResult XML for the original S3 ListObjects (V1)
 *   operation — GET /<bucket> with no `list-type=2`.  Rucio's S3 RSE and older
 *   tooling (some boto2-era clients, a few mirror utilities) still issue V1.
 *
 * WHY:  V1 and V2 walk and paginate the same filesystem the same way; they
 *   differ ONLY in their request pagination parameter and their response
 *   element names:
 *     - V1 paginates with `marker` (the exclusive start key) and reports
 *       `<Marker>` / `<NextMarker>`; there is no `<KeyCount>` and no
 *       continuation token.
 *     - V2 paginates with `continuation-token` / `start-after` and reports
 *       `<KeyCount>` + `<NextContinuationToken>` (see list_objects_v2.c).
 *   The directory walk (s3_walk) and the lexicographic comparator (entry_cmp)
 *   are already factored into list_walk.c and are shared verbatim — this file
 *   only adds the V1 pagination semantics and the V1 XML dialect.
 *
 * HOW:
 *   1. Parse query params: prefix, delimiter, marker, max-keys, encoding-type.
 *   2. Walk the bucket root via s3_walk(), qsort() by key.
 *   3. Skip entries <= marker (V1 marker is exclusive), slice at max-keys.
 *   4. Emit ListBucketResult with Marker / NextMarker (when truncated) and the
 *      Contents / CommonPrefixes loop (identical shape to V2).
 */

#include "s3.h"
#include "core/http/http_query.h"
#include <string.h>

ngx_int_t
s3_handle_list_v1(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf)
{
    u_char       prefix_buf[S3_MAX_PARAM]    = { 0 };
    u_char       delimiter_buf[S3_MAX_PARAM] = { 0 };
    u_char       marker_buf[S3_MAX_KEY]      = { 0 };
    u_char       encoding_type_buf[8]        = { 0 };
    int          max_keys;
    int          url_encode = 0;
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
    ngx_int_t    rc;

    brix_http_query_get(r->args, "prefix",        (char *) prefix_buf,        sizeof(prefix_buf),        S3_LIST_QUERY_FLAGS);
    brix_http_query_get(r->args, "delimiter",     (char *) delimiter_buf,     sizeof(delimiter_buf),     S3_LIST_QUERY_FLAGS);
    brix_http_query_get(r->args, "marker",        (char *) marker_buf,        sizeof(marker_buf),        S3_LIST_QUERY_FLAGS);
    brix_http_query_get(r->args, "encoding-type", (char *) encoding_type_buf, sizeof(encoding_type_buf), S3_LIST_QUERY_FLAGS);

    if (ngx_strcasecmp(encoding_type_buf, (u_char *) "url") == 0) {
        url_encode = 1;
    }

    max_keys = s3_list_parse_max_keys(r, (int) cf->max_keys);

    if (s3_list_collect_sorted(r, cf, (const char *) prefix_buf,
                               (const char *) delimiter_buf,
                               &items, &total) != NGX_OK)
    {
        BRIX_S3_METRIC_INC(events_total[BRIX_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* V1 marker is the exclusive start key — same skip semantics as V2. */
    truncated = s3_list_paginate(items, total, (const char *) marker_buf,
                                 max_keys, &start_idx, &end_idx);

    xml_capacity = 512
                 + (size_t) cf->bucket.len + 32
                 + strlen((const char *) prefix_buf) * 6 + 32
                 + strlen((const char *) delimiter_buf) * 6 + 32
                 + strlen((const char *) marker_buf) * 6 + 32
                 + (size_t) (end_idx - start_idx)
                   * (S3_MAX_KEY * 6 + 512);

    xml = ngx_palloc(r->pool, xml_capacity);
    if (xml == NULL) {
        BRIX_S3_METRIC_INC(events_total[BRIX_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    XML_APPEND("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    XML_APPEND("<ListBucketResult "
               "xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");
    XML_APPEND_ELEM("Name", cf->bucket.data, cf->bucket.len);
    XML_APPEND_ELEM("Prefix", prefix_buf, strlen((const char *) prefix_buf));
    XML_APPEND_ELEM("Marker", marker_buf, strlen((const char *) marker_buf));
    XML_APPEND("<MaxKeys>%d</MaxKeys>", max_keys);

    if (delimiter_buf[0] != '\0') {
        XML_APPEND_ELEM("Delimiter", delimiter_buf,
                        strlen((const char *) delimiter_buf));
    }
    if (url_encode) {
        XML_APPEND("<EncodingType>url</EncodingType>");
    }
    XML_APPEND("<IsTruncated>%s</IsTruncated>", truncated ? "true" : "false");

    /*
     * NextMarker: AWS returns it only when a delimiter is set, but clients that
     * paginate without a delimiter fall back to the last key — so emitting it
     * whenever the response is truncated is a safe superset and lets every V1
     * client page correctly.  The value is the last key in this slice.
     */
    if (truncated && end_idx > 0) {
        XML_APPEND_ELEM("NextMarker", items[end_idx - 1].key,
                        strlen(items[end_idx - 1].key));
    }

    rc = s3_list_emit_entries(r, cf, items, start_idx, end_idx,
                              url_encode, 0 /* fetch_owner: V1 has no Owner */,
                              xml, &xml_len, xml_capacity,
                              &contents, &prefixes);
    if (rc != NGX_OK) {
        return rc;
    }

    XML_APPEND("</ListBucketResult>");

    return s3_list_finalize(r, xml, xml_len, contents, prefixes, truncated);
}
