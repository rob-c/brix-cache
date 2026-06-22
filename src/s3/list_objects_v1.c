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
#include "list_cache.h"
#include "../compat/http_query.h"
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>

/* Same parse policy as V2: decode, + → space, reject NUL, allow empty value. */
#define S3_LIST_QUERY_FLAGS \
    (XROOTD_HTTP_QUERY_DECODE_VALUE | XROOTD_HTTP_QUERY_PLUS_TO_SPACE \
     | XROOTD_HTTP_QUERY_REJECT_NUL | XROOTD_HTTP_QUERY_ALLOW_EMPTY)

ngx_int_t
s3_handle_list_v1(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf)
{
    u_char      prefix_buf[S3_MAX_PARAM]    = { 0 };
    u_char      delimiter_buf[S3_MAX_PARAM] = { 0 };
    u_char      marker_buf[S3_MAX_KEY]      = { 0 };
    u_char      max_keys_buf[32]            = { 0 };
    u_char      encoding_type_buf[8]        = { 0 };
    int          max_keys;
    int          url_encode = 0;
    ngx_array_t *entries;
    s3_entry_t  *items = NULL;
    int          total = 0;
    int          cached = 0;
    time_t       dir_mtime = 0;
    int          start_idx = 0;
    int         end_idx;
    int         truncated;
    int         contents = 0;
    int         prefixes = 0;
    ngx_buf_t  *response_buf;
    size_t      xml_capacity;
    u_char     *xml;
    size_t      xml_len = 0;
    char        iso_buf[32];

    xrootd_http_query_get(r->args, "prefix",        (char *) prefix_buf,        sizeof(prefix_buf),        S3_LIST_QUERY_FLAGS);
    xrootd_http_query_get(r->args, "delimiter",     (char *) delimiter_buf,     sizeof(delimiter_buf),     S3_LIST_QUERY_FLAGS);
    xrootd_http_query_get(r->args, "marker",        (char *) marker_buf,        sizeof(marker_buf),        S3_LIST_QUERY_FLAGS);
    xrootd_http_query_get(r->args, "encoding-type", (char *) encoding_type_buf, sizeof(encoding_type_buf), S3_LIST_QUERY_FLAGS);

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

    /* W6c: per-worker sorted-listing cache (see list_objects_v2.c / list_cache.c). */
    if (cf->list_cache) {
        struct stat rst;
        if (stat((const char *) cf->common.root.data, &rst) == 0) {
            dir_mtime = rst.st_mtime;
        }
        cached = s3_list_cache_get(r, (const char *) cf->common.root.data,
                                   (const char *) prefix_buf,
                                   (const char *) delimiter_buf,
                                   dir_mtime, cf->list_cache_ttl,
                                   &items, &total);
    }

    if (!cached) {
        /* phase-45 W1: growable, pool-backed entry array (see list_objects_v2.c). */
        entries = ngx_array_create(r->pool, 256, sizeof(s3_entry_t));
        if (entries == NULL) {
            XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        s3_walk(r->connection->log,
                (const char *) cf->common.root.data,
                (const char *) cf->common.root.data,
                "",
                (const char *) prefix_buf,
                (const char *) delimiter_buf,
                entries, S3_LIST_MAX_ENTRIES);

        total = (int) entries->nelts;
        items = entries->elts;

        qsort(items, (size_t) total, sizeof(s3_entry_t), entry_cmp);

        if (cf->list_cache) {
            s3_list_cache_put(r->connection->log,
                              (const char *) cf->common.root.data,
                              (const char *) prefix_buf,
                              (const char *) delimiter_buf,
                              dir_mtime, items, total);
        }
    }

    /* V1 marker is the exclusive start key — skip everything <= marker. */
    if (marker_buf[0] != '\0') {
        for (start_idx = 0; start_idx < total; start_idx++) {
            if (strcmp(items[start_idx].key, (const char *) marker_buf) > 0) {
                break;
            }
        }
    }

    end_idx = start_idx + max_keys;
    if (end_idx > total) {
        end_idx = total;
    }
    truncated = (end_idx < total);

    xml_capacity = 512
                 + (size_t) cf->bucket.len + 32
                 + strlen((const char *) prefix_buf) * 6 + 32
                 + strlen((const char *) delimiter_buf) * 6 + 32
                 + strlen((const char *) marker_buf) * 6 + 32
                 + (size_t) (end_idx - start_idx)
                   * (S3_MAX_KEY * 6 + 512);

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

    for (int entry_index = start_idx; entry_index < end_idx; entry_index++) {
        s3_entry_t *entry = &items[entry_index];

        if (entry->is_prefix) {
            prefixes++;
            XML_APPEND("<CommonPrefixes>");
            XML_APPEND_ELEM("Prefix", entry->key, strlen(entry->key));
            XML_APPEND("</CommonPrefixes>");
        } else {
            char encoded_key[S3_MAX_KEY * 3 + 1];

            /* phase-45 W1: stat only the emitted page; skip vanished objects. */
            if (s3_entry_fill_stat(r->connection->log,
                                   (const char *) cf->common.root.data,
                                   entry) != NGX_OK) {
                continue;
            }

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

    XROOTD_S3_METRIC_ADD(list_contents_total, (size_t) contents);
    XROOTD_S3_METRIC_ADD(list_common_prefixes_total, (size_t) prefixes);
    if (truncated) {
        XROOTD_S3_METRIC_INC(list_truncated_total);
    }
    XROOTD_S3_METRIC_ADD(bytes_tx_total, xml_len);

    return xrootd_http_send_xml_buffer(r, NGX_HTTP_OK,
        (ngx_str_t) ngx_string("application/xml"), response_buf);
}
