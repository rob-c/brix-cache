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
#include "../path/path.h"

#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* -------------------------------------------------------------------------
 * GET /bucket/key?uploadId=<id>  →  ListParts
 * ---------------------------------------------------------------------- */

/*
 * Part entry collected during directory scan.
 */
typedef struct {
    int    part_num;
    off_t  size;
    time_t mtime;
} mpu_part_entry_t;

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

ngx_int_t
s3_handle_list_parts(ngx_http_request_t *r,
                     const char *fs_path,
                     ngx_http_s3_loc_conf_t *cf,
                     const char *key_str)
{
    char              upload_id[128];
    char              mpu_dir[PATH_MAX];
    struct stat       mpu_sb;
    DIR              *dp;
    struct dirent    *de;
    mpu_part_entry_t *parts;
    int               nparts = 0;
    int               i;
    size_t            xml_capacity;
    u_char           *xml;
    size_t            xml_len = 0;
    ngx_buf_t        *b;
    char              iso_buf[32];
    char              etag_buf[48];
    char              marker_str[16];
    char              max_parts_str[16];
    int               part_number_marker;
    int               max_parts;
    int               start_idx;
    int               end_idx;
    int               truncated;

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
     * Route through xrootd_lstat_confined_canon (broker stat as the mapped user;
     * plain lstat off impersonation).
     */
    if (xrootd_lstat_confined_canon(r->connection->log, cf->common.root_canon,
                                    mpu_dir, &mpu_sb, 1) != 0
        || !S_ISDIR(mpu_sb.st_mode))
    {
        return s3_send_xml_error(r, NGX_HTTP_NOT_FOUND,
                                 "NoSuchUpload",
                                 "The specified upload does not exist.");
    }

    /* Enumerate part.* files — at most MPU_MAX_PART_NUMBER entries */
    parts = ngx_palloc(r->pool,
                       sizeof(mpu_part_entry_t) * (MPU_MAX_PART_NUMBER + 1));
    if (parts == NULL) {
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* As the mapped user under impersonation (broker fd + fdopendir): the staging
     * dir is owned 0700 by the mapped user, so a raw worker opendir() fails EACCES
     * (ListParts 500).  Off impersonation this is a plain opendir(). */
    dp = xrootd_opendir_confined_canon(r->connection->log,
                                       cf->common.root_canon, mpu_dir);
    if (dp == NULL) {
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    while ((de = readdir(dp)) != NULL && nparts < MPU_MAX_PART_NUMBER) {
        /* Match "part.<N>" — must start with "part." */
        if (ngx_strncmp(de->d_name, "part.", 5) != 0) {
            continue;
        }

        /* Parse the part number after "part." */
        char *endptr;
        long pn = strtol(de->d_name + 5, &endptr, 10);
        if (*endptr != '\0' || pn < 1 || pn > MPU_MAX_PART_NUMBER) {
            continue;
        }

        /* part_path is mpu_dir + "/" + de->d_name (readdir result); confinement
         * is inherited from mpu_dir (see confinement comment above). */
        char part_path[PATH_MAX];
        if ((size_t) snprintf(part_path, sizeof(part_path), "%s/%s",
                              mpu_dir, de->d_name) >= sizeof(part_path)) {
            continue;
        }

        struct stat psb;
        if (lstat(part_path, &psb) != 0 || !S_ISREG(psb.st_mode)) {
            continue;
        }

        parts[nparts].part_num = (int) pn;
        parts[nparts].size     = psb.st_size;
        parts[nparts].mtime    = psb.st_mtime;
        nparts++;
    }
    closedir(dp);

    /* Sort by part number */
    if (nparts > 1) {
        qsort(parts, (size_t) nparts, sizeof(mpu_part_entry_t),
              mpu_part_entry_cmp);
    }

    /* Parse pagination parameters */
    part_number_marker = 0;
    marker_str[0] = '\0';
    if (s3_get_query_param(r, "part-number-marker",
                           marker_str, sizeof(marker_str)))
    {
        char *endp;
        long  mn = strtol(marker_str, &endp, 10);
        if (endp != marker_str && mn >= 0 && mn <= MPU_MAX_PART_NUMBER) {
            part_number_marker = (int) mn;
        }
    }

    max_parts = MPU_MAX_PART_NUMBER;
    max_parts_str[0] = '\0';
    if (s3_get_query_param(r, "max-parts",
                           max_parts_str, sizeof(max_parts_str)))
    {
        char *endp;
        long  mp = strtol(max_parts_str, &endp, 10);
        if (endp != max_parts_str && mp > 0 && mp < MPU_MAX_PART_NUMBER) {
            max_parts = (int) mp;
        }
    }

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
    truncated = (end_idx < nparts);

    /* Allocate XML buffer: header + per-part entries */
    xml_capacity = 512
                 + (size_t) cf->bucket.len * 6 + 32
                 + strlen(key_str) * 6 + 32
                 + strlen(upload_id) * 6 + 32
                 + (size_t) (end_idx - start_idx) * 256
                 + (truncated ? 64 : 0);

    xml = ngx_palloc(r->pool, xml_capacity);
    if (xml == NULL) {
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
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
        xrootd_format_iso8601(parts[i].mtime, iso_buf, sizeof(iso_buf));
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
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_memcpy(b->pos, xml, xml_len);
    b->last     = b->pos + xml_len;
    b->last_buf = 1;

    return xrootd_http_send_xml_buffer(r, NGX_HTTP_OK,
        (ngx_str_t) ngx_string("application/xml"), b);
}
