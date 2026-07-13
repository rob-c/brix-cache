/*
 * multipart_complete_list_parts.c — S3 ListParts handler + part-entry helpers.
 *
 * WHAT: This fragment implements the GET /bucket/key?uploadId=<id> → ListParts operation,
 *   which enumerates uploaded parts stored in a staging directory for an active multipart upload.
 *   It contains three components:
 *     - mpu_part_entry_t typedef: holds part_num (int), size (off_t), and mtime (time_t) — the
 *       metadata collected per-part during directory enumeration.
 *     - mpu_part_entry_cmp(): qsort comparator that sorts entries in ascending part-number order,
 *       ensuring the XML response lists parts numerically as required by S3 spec.
 *     - s3_handle_list_parts(): the main handler — validates uploadId, probes staging directory,
 *       enumerates "part.<N>" files (stat size/mtime), sorts by number, applies pagination
 *       (part-number-marker + max-parts), and emits a ListPartsResult XML document with each
 *       part's PartNumber, LastModified (ISO 8601), ETag ("mtime-size"), and Size.
 *   ETags are computed as "\"mtime-size\"" — the staging-file convention for multipart parts.
 *
 * WHY: Split from multipart.c to keep ListParts logic self-contained alongside its sibling fragments
 *      (multipart_complete_body.c, multipart_complete_upload_part_copy.c). The typedef + comparator pair
 *      is reused by CompleteMultipartUpload's own part-verification scan, keeping the sort logic shared.
 */

#include "s3.h"
#include "multipart_internal.h"
#include "fs/vfs/vfs.h"   /* confined dir probe/opendir/readdir via the VFS seam */

#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * GET /bucket/key?uploadId=<id>  →  ListParts
 * */

/*
 * Part entry collected during directory scan.
 */
typedef struct {
    int    part_num;
    off_t  size;
    time_t mtime;
} mpu_part_entry_t;

/*
 * lp_page_t — the fully-computed ListParts page to render.
 *
 * WHAT: Groups everything lp_render_xml emits — the identity strings (key/upload_id), the
 *   sorted parts array, its [start_idx, end_idx) slice, the total part count, and the echoed
 *   part-number-marker / max-parts — into one file-local struct.
 * WHY: Keeps lp_render_xml's parameter list within the project's 5-param budget (§8 explicit
 *   data flow) without splitting the rendering into more phases; these values all travel
 *   together as one concept (the page being emitted).
 */
typedef struct {
    const char       *key_str;
    const char       *upload_id;
    const mpu_part_entry_t *parts;
    int  start_idx;
    int  end_idx;
    int  nparts;
    int  part_number_marker;
    int  max_parts;
} lp_page_t;

/*
 * qsort comparator — ascending part number order.
 */
static int
mpu_part_entry_cmp(const void *a, const void *b)
{
    int pa = ((const mpu_part_entry_t *) a)->part_num;
    int pb = ((const mpu_part_entry_t *) b)->part_num;
    return pa - pb;
}

/*
 * lp_parse_query — read ListParts pagination parameters off the request.
 *
 * WHAT: Parses the optional "part-number-marker" and "max-parts" query params into
 *   *marker (default 0) and *max_parts (default MPU_MAX_PART_NUMBER), applying the same
 *   bounds the inline handler used (marker in [0, MPU_MAX_PART_NUMBER]; max-parts in
 *   (0, MPU_MAX_PART_NUMBER)). Out-of-range or unparsable values leave the default.
 * WHY: Isolates pure query parsing from the handler orchestration so the pagination
 *   window computation reads as a flat sequence (functional/modular §8).
 * HOW: Two independent strtol scans over stack buffers; no I/O, no side effects beyond
 *   writing the two out-params (zero-initialised by the caller-supplied defaults here).
 */
static void
lp_parse_query(ngx_http_request_t *r, int *marker, int *max_parts)
{
    char marker_str[16];
    char max_parts_str[16];

    *marker = 0;
    marker_str[0] = '\0';
    if (s3_get_query_param(r, "part-number-marker",
                           marker_str, sizeof(marker_str)))
    {
        char *endp;
        long  mn = strtol(marker_str, &endp, 10);
        if (endp != marker_str && mn >= 0 && mn <= MPU_MAX_PART_NUMBER) {
            *marker = (int) mn;
        }
    }

    *max_parts = MPU_MAX_PART_NUMBER;
    max_parts_str[0] = '\0';
    if (s3_get_query_param(r, "max-parts",
                           max_parts_str, sizeof(max_parts_str)))
    {
        char *endp;
        long  mp = strtol(max_parts_str, &endp, 10);
        if (endp != max_parts_str && mp > 0 && mp < MPU_MAX_PART_NUMBER) {
            *max_parts = (int) mp;
        }
    }
}

/*
 * lp_scan_staged_parts — enumerate "part.<N>" staging files into a sorted array.
 *
 * WHAT: Opens the multipart staging directory (mpu_dir) via the VFS seam, iterates its
 *   entries, matches "part.<N>" with N in [1, MPU_MAX_PART_NUMBER], probes each for
 *   size/mtime, records up to MPU_MAX_PART_NUMBER entries into parts[], and sorts them by
 *   ascending part number. Returns the count found, or -1 on opendir failure.
 * WHY: Extracts the directory-scan phase (the bulk of the handler's branching) so the
 *   orchestrator only decides the pagination window and rendering (§8).
 * HOW: brix_vfs_opendir_quiet + brix_vfs_readdir_kind loop under the caller's vctx
 *   (impersonation-aware); per-entry confined no-follow brix_vfs_probe for stat; qsort at
 *   the end. Side effects (opendir/closedir) stay inside this edge helper. The EACCES /
 *   impersonation confinement rationale is unchanged from the inline version.
 */
static int
lp_scan_staged_parts(ngx_http_request_t *r,
                     brix_vfs_ctx_t *vctx,
                     const char *mpu_dir,
                     ngx_http_s3_loc_conf_t *cf,
                     mpu_part_entry_t *parts)
{
    brix_vfs_dir_t *dp;
    int             nparts = 0;

    /* As the mapped user under impersonation (broker fd + fdopendir): the staging
     * dir is owned 0700 by the mapped user, so a raw worker opendir() fails EACCES
     * (ListParts 500).  Off impersonation this is a plain opendir(). Non-metered
     * (the ListParts op accounts for the scan). */
    dp = brix_vfs_opendir_quiet(vctx, NULL);
    if (dp == NULL) {
        return -1;
    }

    for ( ;; ) {
        ngx_str_t         name;
        const char       *dname;
        char              part_path[PATH_MAX];
        char             *endptr;
        long              pn;
        brix_vfs_ctx_t   pctx;
        brix_vfs_stat_t  pst;

        if (nparts >= MPU_MAX_PART_NUMBER) {
            break;
        }
        if (brix_vfs_readdir_kind(dp, &name, NULL) != NGX_OK) {
            break;   /* NGX_DONE (end) or error → stop */
        }
        dname = (const char *) name.data;

        /* Match "part.<N>" — must start with "part." */
        if (ngx_strncmp(dname, "part.", 5) != 0) {
            continue;
        }

        /* Parse the part number after "part." */
        pn = strtol(dname + 5, &endptr, 10);
        if (*endptr != '\0' || pn < 1 || pn > MPU_MAX_PART_NUMBER) {
            continue;
        }

        /* part_path is mpu_dir + "/" + name (readdir result); confinement is
         * inherited from mpu_dir (see confinement comment above). */
        if ((size_t) snprintf(part_path, sizeof(part_path), "%s/%s",
                              mpu_dir, dname) >= sizeof(part_path)) {
            continue;
        }

        /* Confined no-follow probe for size/mtime (non-metered). */
        s3_build_vfs_ctx(r, part_path, cf, &pctx);
        if (brix_vfs_probe(&pctx, 1 /* no-follow */, &pst) != NGX_OK
            || !pst.is_regular) {
            continue;
        }

        parts[nparts].part_num = (int) pn;
        parts[nparts].size     = pst.size;
        parts[nparts].mtime    = pst.mtime;
        nparts++;
    }
    brix_vfs_closedir(dp, r->connection->log);

    /* Sort by part number */
    if (nparts > 1) {
        qsort(parts, (size_t) nparts, sizeof(mpu_part_entry_t),
              mpu_part_entry_cmp);
    }

    return nparts;
}

/*
 * lp_render_xml — build and send the ListPartsResult XML document.
 *
 * WHAT: Allocates a right-sized XML buffer, emits the ListPartsResult header (Bucket/Key/
 *   UploadId/StorageClass/PartNumberMarker/MaxParts/IsTruncated, plus NextPartNumberMarker
 *   when truncated) and one <Part> element per entry in parts[start_idx, end_idx), then
 *   sends it as application/xml with HTTP 200. Returns the send result, or an internal
 *   error status on allocation failure.
 * WHY: Isolates the response-framing phase so the handler is a flat orchestration; the XML
 *   byte layout is frozen (identical XML_APPEND sequence and capacity formula as inline).
 * HOW: Same xml_capacity formula, same XML_APPEND macro calls, ETag "\"mtime-size\"" and
 *   ISO-8601 LastModified per entry; buffer copied into an ngx_create_temp_buf and handed
 *   to brix_http_send_xml_buffer. Side effects (alloc, send, metric on failure) at the edge.
 */
static ngx_int_t
lp_render_xml(ngx_http_request_t *r,
              ngx_http_s3_loc_conf_t *cf,
              const lp_page_t *page)
{
    size_t       xml_capacity;
    u_char      *xml;
    size_t       xml_len = 0;
    ngx_buf_t   *b;
    char         iso_buf[32];
    char         etag_buf[48];
    const char  *key_str = page->key_str;
    const char  *upload_id = page->upload_id;
    const mpu_part_entry_t *parts = page->parts;
    int          start_idx = page->start_idx;
    int          end_idx = page->end_idx;
    int          part_number_marker = page->part_number_marker;
    int          max_parts = page->max_parts;
    int          truncated = (end_idx < page->nparts);
    int          i;

    /* Allocate XML buffer: header + per-part entries */
    xml_capacity = 512
                 + (size_t) cf->bucket.len * 6 + 32
                 + strlen(key_str) * 6 + 32
                 + strlen(upload_id) * 6 + 32
                 + (size_t) (end_idx - start_idx) * 256
                 + (truncated ? 64 : 0);

    xml = ngx_palloc(r->pool, xml_capacity);
    if (xml == NULL) {
        BRIX_S3_METRIC_INC(events_total[BRIX_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    XML_APPEND("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    XML_APPEND("<ListPartsResult"
               " xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\n");
    XML_APPEND("  ");
    XML_APPEND_ELEM("Bucket", cf->bucket.data, cf->bucket.len);
    XML_APPEND("\n  ");
    XML_APPEND_ELEM("Key", key_str, strlen(key_str));
    XML_APPEND("\n  ");
    XML_APPEND_ELEM("UploadId", upload_id, strlen(upload_id));
    XML_APPEND("\n");
    XML_APPEND("  <StorageClass>STANDARD</StorageClass>\n");
    XML_APPEND("  <PartNumberMarker>%d</PartNumberMarker>\n",
               part_number_marker);
    XML_APPEND("  <MaxParts>%d</MaxParts>\n", max_parts);
    XML_APPEND("  <IsTruncated>%s</IsTruncated>\n",
               truncated ? "true" : "false");

    if (truncated) {
        XML_APPEND("  <NextPartNumberMarker>%d</NextPartNumberMarker>\n",
                   parts[end_idx - 1].part_num);
    }

    for (i = start_idx; i < end_idx; i++) {
        brix_format_iso8601(parts[i].mtime, iso_buf, sizeof(iso_buf));
        snprintf(etag_buf, sizeof(etag_buf),
                 "\"%ld-%lld\"",
                 (long) parts[i].mtime,
                 (long long) parts[i].size);
        XML_APPEND("  <Part>\n");
        XML_APPEND("    <PartNumber>%d</PartNumber>\n", parts[i].part_num);
        XML_APPEND("    <LastModified>%s</LastModified>\n", iso_buf);
        XML_APPEND("    <ETag>%s</ETag>\n", etag_buf);
        XML_APPEND("    <Size>%lld</Size>\n", (long long) parts[i].size);
        XML_APPEND("  </Part>\n");
    }

    XML_APPEND("</ListPartsResult>\n");

    b = ngx_create_temp_buf(r->pool, xml_len);
    if (b == NULL) {
        BRIX_S3_METRIC_INC(events_total[BRIX_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_memcpy(b->pos, xml, xml_len);
    b->last     = b->pos + xml_len;
    b->last_buf = 1;

    return brix_http_send_xml_buffer(r, NGX_HTTP_OK,
        (ngx_str_t) ngx_string("application/xml"), b);
}

ngx_int_t
s3_handle_list_parts(ngx_http_request_t *r,
                     const char *fs_path,
                     ngx_http_s3_loc_conf_t *cf,
                     const char *key_str)
{
    char              upload_id[128];
    char              mpu_dir[PATH_MAX];
    brix_vfs_ctx_t    vctx;
    brix_vfs_stat_t   vst;
    mpu_part_entry_t *parts;
    lp_page_t         page = { NULL, NULL, NULL, 0, 0, 0, 0, 0 };
    int               nparts = 0;
    int               part_number_marker = 0;
    int               max_parts = 0;
    int               start_idx = 0;
    int               end_idx = 0;

    /* Parse uploadId */
    if (!s3_get_query_param(r, "uploadId", upload_id, sizeof(upload_id))) {
        return s3_send_xml_error(r, NGX_HTTP_BAD_REQUEST,
                                 "InvalidArgument", "Missing uploadId.");
    }

    if (!mpu_validate_upload_id(upload_id)) {
        return s3_send_xml_error(r, NGX_HTTP_BAD_REQUEST,
                                 "InvalidArgument", "The uploadId is invalid.");
    }

    s3_get_mpu_dir(fs_path, upload_id, mpu_dir, sizeof(mpu_dir));

    /*
     * Confinement + impersonation: mpu_dir comes from s3_get_mpu_dir() (validated
     * upload_id + s3_resolve_key()-confined fs_path).  Under MAP mode the staging
     * dir / its parent are owned 0700 by the mapped user, so a bare worker lstat
     * EACCESes on the parent search bit and ListParts wrongly 404s for the owner.
     * Route through the VFS probe (broker stat as the mapped user under
     * impersonation; plain no-follow lstat off impersonation).
     */
    s3_build_vfs_ctx(r, mpu_dir, cf, &vctx);
    if (brix_vfs_probe(&vctx, 1 /* no-follow */, &vst) != NGX_OK
        || !vst.is_directory)
    {
        return s3_send_xml_error(r, NGX_HTTP_NOT_FOUND,
                                 "NoSuchUpload",
                                 "The specified upload does not exist.");
    }

    /* Enumerate part.* files — at most MPU_MAX_PART_NUMBER entries */
    parts = ngx_palloc(r->pool,
                       sizeof(mpu_part_entry_t) * (MPU_MAX_PART_NUMBER + 1));
    if (parts == NULL) {
        BRIX_S3_METRIC_INC(events_total[BRIX_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    nparts = lp_scan_staged_parts(r, &vctx, mpu_dir, cf, parts);
    if (nparts < 0) {
        BRIX_S3_METRIC_INC(events_total[BRIX_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Parse pagination parameters */
    lp_parse_query(r, &part_number_marker, &max_parts);

    /* Apply part-number-marker: skip parts whose number <= marker */
    start_idx = 0;
    if (part_number_marker > 0) {
        for (start_idx = 0; start_idx < nparts; start_idx++) {
            if (parts[start_idx].part_num > part_number_marker) {
                break;
            }
        }
    }

    end_idx = start_idx + max_parts;
    if (end_idx > nparts) {
        end_idx = nparts;
    }

    page.key_str            = key_str;
    page.upload_id          = upload_id;
    page.parts              = parts;
    page.start_idx          = start_idx;
    page.end_idx            = end_idx;
    page.nparts             = nparts;
    page.part_number_marker = part_number_marker;
    page.max_parts          = max_parts;

    return lp_render_xml(r, cf, &page);
}
