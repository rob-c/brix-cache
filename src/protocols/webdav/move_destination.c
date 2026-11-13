/* Decode and confine MOVE's Destination header before authorization or I/O. */
#include "move_destination.h"

/*
 * webdav_move_resolve_dest — stage 1 of MOVE destination handling: read the
 * mandatory Destination header, strip its scheme://authority, URL-decode it,
 * and resolve+confine it to `dst_path`.
 *
 * WHAT: Turns the raw Destination request header into a confined absolute
 *       logical client-visible path and a confined absolute filesystem path.
 * WHY:  Lifts the four sequential "extract → decode → resolve" steps (each with
 *       its own early-return) out of webdav_handle_move so the top-level MOVE
 *       reads as a linear sequence of stages, dropping its branch count.
 * HOW:  Returns NGX_OK on success; on any failure returns the exact HTTP status
 *       the original inline code returned (400 for a missing Destination header,
 *       otherwise the sub-helper's rc) so the wire behavior is unchanged.
 */
ngx_int_t
webdav_move_resolve_dest(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, webdav_move_destination_t *dest)
{
    ngx_table_elt_t *dest_hdr;
    const u_char    *dest_path_start;
    size_t           dest_path_len;
    ngx_int_t        rc;

    /* Require Destination header (RFC 4918 §9.9.4 — missing → 400) */
    dest_hdr = webdav_tpc_find_header(r, "Destination",
                                      sizeof("Destination") - 1);
    if (dest_hdr == NULL) {
        return NGX_HTTP_BAD_REQUEST;
    }

    /* Extract path component from Destination URL, stripping scheme://authority. */
    rc = webdav_destination_extract_path(dest_hdr->value.data,
                                         dest_hdr->value.len,
                                         &dest_path_start, &dest_path_len);
    if (rc != NGX_OK) {
        return rc;
    }

    /* URL-decode the destination path */
    rc = webdav_urldecode(dest_path_start, dest_path_len,
                          dest->logical, sizeof(dest->logical));
    if (rc != NGX_OK) {
        return rc;
    }
    webdav_normalize_decoded_path(dest->logical);

    /* Resolve destination */
    return webdav_resolve_destination_path(r->connection->log, "MOVE",
                                           conf->common.root_canon, dest->logical,
                                           dest->resolved,
                                           sizeof(dest->resolved),
                                           conf->common.cache_store_endpoint);
}

