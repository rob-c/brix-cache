/*
 * list_common.c — shared building blocks for the S3 ListObjects emitters.
 *
 * WHAT: The four steps that ListObjects V1 (list_objects_v1.c) and V2
 *   (list_objects_v2.c) perform identically — parse max-keys, acquire a sorted
 *   key listing (cache-or-walk), paginate it, emit the Contents/CommonPrefixes
 *   body, and finalize the response — plus they share the directory walker and
 *   comparator already in list_walk.c.
 *
 * WHY: V1 and V2 differ ONLY in their pagination parameter (`marker` vs
 *   `continuation-token`/`start-after`) and a few response element names
 *   (`<Marker>`/`<NextMarker>` vs `<KeyCount>`/`<NextContinuationToken>`).
 *   Everything else was copy-pasted between the two files; centralizing it here
 *   keeps the two dialects to just their genuine differences and removes the
 *   risk of the shared logic drifting apart.
 *
 * HOW: Each helper is a pure step with explicit inputs/outputs and no hidden
 *   state. s3_list_emit_entries() drives the flat-buffer XML_APPEND macros (which
 *   reference `xml`/`xml_len`/`xml_capacity` and return 500 on overflow), so it
 *   takes the buffer cursor by pointer and propagates that contract to its caller.
 */

#include "s3.h"
#include "list_cache.h"
#include "core/http/http_query.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/*
 * s3_list_parse_max_keys — parse the `max-keys` query arg, clamped to
 * (0, default_max). Returns default_max when the arg is absent or invalid, and
 * applies a 1000 floor (matching AWS) when default_max is non-positive.
 */
int
s3_list_parse_max_keys(ngx_http_request_t *r, int default_max)
{
    u_char max_keys_buf[32] = { 0 };
    int    max_keys = default_max;

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
    return max_keys;
}

/*
 * s3_list_collect_sorted — acquire the sorted (key + is_prefix) listing for the
 * (root, prefix, delimiter) view: try the per-worker sorted-listing cache (W6c)
 * and, on a miss, walk the bucket subtree (s3_walk), qsort by key (entry_cmp),
 * and populate the cache. On return *items / *total describe a sorted array
 * (pool- or cache-owned); size/mtime/ETag are filled lazily per emitted page by
 * s3_entry_fill_stat(). Returns NGX_OK, or NGX_ERROR on allocation failure.
 */
ngx_int_t
s3_list_collect_sorted(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf,
                       const char *prefix, const char *delimiter,
                       s3_entry_t **items, int *total)
{
    ngx_array_t *entries;
    int          cached = 0;
    time_t       dir_mtime = 0;

    if (cf->list_cache) {
        struct stat rst;

        if (stat((const char *) cf->common.root.data, &rst) == 0) {  /* vfs-seam-allow: export-root mtime for the list cache (the root itself, not a path beneath it) */
            dir_mtime = rst.st_mtime;
        }
        cached = s3_list_cache_get(r, (const char *) cf->common.root.data,
                                   prefix, delimiter,
                                   dir_mtime, cf->list_cache_ttl,
                                   items, total);
    }

    if (!cached) {
        entries = ngx_array_create(r->pool, 256, sizeof(s3_entry_t));
        if (entries == NULL) {
            return NGX_ERROR;
        }

        s3_walk(r->connection->log,
                (const char *) cf->common.root.data,
                (const char *) cf->common.root.data,
                "", prefix, delimiter, entries, S3_LIST_MAX_ENTRIES);

        *total = (int) entries->nelts;
        *items = entries->elts;

        qsort(*items, (size_t) *total, sizeof(s3_entry_t), entry_cmp);

        if (cf->list_cache) {
            s3_list_cache_put(r->connection->log,
                              (const char *) cf->common.root.data,
                              prefix, delimiter, dir_mtime, *items, *total);
        }
    }
    return NGX_OK;
}

/*
 * s3_list_paginate — shared pagination math. Skip every entry whose key is <=
 * `start_after` (the exclusive continuation marker; NULL/"" means start at the
 * beginning) — a linear scan, acceptable since `total` is already capped by
 * S3_LIST_MAX_ENTRIES — then take up to max_keys. Fills *start_idx / *end_idx
 * and returns 1 when the listing is truncated (entries remain), 0 otherwise.
 */
int
s3_list_paginate(const s3_entry_t *items, int total, const char *start_after,
                 int max_keys, int *start_idx, int *end_idx)
{
    int si = 0;
    int ei;

    if (start_after != NULL && start_after[0] != '\0') {
        for (si = 0; si < total; si++) {
            if (strcmp(items[si].key, start_after) > 0) {
                break;
            }
        }
    }

    ei = si + max_keys;
    if (ei > total) {
        ei = total;
    }

    *start_idx = si;
    *end_idx   = ei;
    return ei < total;
}

/*
 * s3_list_emit_entries — append the Contents / CommonPrefixes body for the page
 * slice [start_idx, end_idx) into the flat XML buffer. A CommonPrefix becomes a
 * <CommonPrefixes>; an object is lazily stat'd (s3_entry_fill_stat) and skipped
 * if it has vanished, else emitted as <Contents> (Key url-encoded when
 * url_encode, with an <Owner> block when fetch_owner and an access key is set).
 * The emitted-counts land in *contents_out / *prefixes_out. Returns NGX_OK, or
 * NGX_HTTP_INTERNAL_SERVER_ERROR if the buffer overflows (caller propagates).
 */
ngx_int_t
s3_list_emit_entries(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf,
                     s3_entry_t *items, int start_idx, int end_idx,
                     int url_encode, int fetch_owner,
                     u_char *xml, size_t *xml_len_io, size_t xml_capacity,
                     int *contents_out, int *prefixes_out)
{
    size_t xml_len   = *xml_len_io;
    int    contents  = 0;
    int    prefixes  = 0;
    char   iso_buf[32];

    for (int entry_index = start_idx; entry_index < end_idx; entry_index++) {
        s3_entry_t *entry = &items[entry_index];

        if (entry->is_prefix) {
            prefixes++;
            XML_APPEND("<CommonPrefixes>");
            XML_APPEND_ELEM("Prefix", entry->key, strlen(entry->key));
            XML_APPEND("</CommonPrefixes>");
            continue;
        }

        char encoded_key[S3_MAX_KEY * 3 + 1];

        /* phase-45 W1: stat is done HERE, only for the emitted page.  If the
         * object vanished or is no longer a regular file, skip it (matches the
         * eager walker's stat-failure skip). */
        if (s3_entry_fill_stat(r->pool, r->connection->log,
                               (const char *) cf->common.root.data,
                               entry) != NGX_OK)
        {
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
        if (fetch_owner && cf->access_key.len > 0) {
            XML_APPEND("<Owner>");
            XML_APPEND_ELEM("ID", cf->access_key.data, cf->access_key.len);
            XML_APPEND_ELEM("DisplayName", cf->access_key.data,
                            cf->access_key.len);
            XML_APPEND("</Owner>");
        }
        XML_APPEND("</Contents>");
    }

    *xml_len_io   = xml_len;
    *contents_out = contents;
    *prefixes_out = prefixes;
    return NGX_OK;
}

/*
 * s3_list_finalize — shared response tail: copy the built XML into a response
 * buffer, record the list metrics (contents/common-prefixes/truncated/bytes),
 * and send it as application/xml. Returns the send result, or 500 on
 * buffer-allocation failure.
 */
ngx_int_t
s3_list_finalize(ngx_http_request_t *r, const u_char *xml, size_t xml_len,
                 int contents, int prefixes, int truncated)
{
    ngx_buf_t *response_buf;

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
