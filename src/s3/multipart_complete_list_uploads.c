/*
 * multipart_complete_list_uploads.c — S3 ListMultipartUploads handler.
 *
 * WHAT: This fragment implements the GET /bucket/?uploads → ListMultipartUploads operation,
 *   which enumerates all in-progress multipart uploads across the entire bucket root directory.
 *   It contains four components:
 *     - mpu_upload_entry_t typedef: holds key (NAME_MAX+1 char), upload_id (128 char), and mtime —
 *       metadata collected per-upload during bucket-root directory scan. Keys are bounded by NAME_MAX
 *       because staging directory names follow the pattern ".<key>.mpu-<upload_id>" and must fit in
 *       a single POSIX directory entry.
 *     - MPU_MAX_LISTED_UPLOADS constant (1000): matches AWS S3's maximum per-page listing limit.
 *     - mpu_upload_entry_cmp(): qsort comparator that sorts entries by key in ascending lexicographic
 *       order, ensuring deterministic pagination across repeated requests.
 *     - s3_handle_list_multipart_uploads(): the main handler — scans the bucket root directory for hidden
 *       staging dirs matching ".<key>.mpu-<upload_id>", extracts key and upload_id from each name, sorts
 *       by key, applies pagination (key-marker + max-uploads), and emits a ListMultipartUploadsResult XML
 *       document with Key, UploadId, StorageClass (STANDARD), and Initiated (ISO 8601 mtime) per entry.
 *   The handler skips "." and ".." entries, non-directory files, and entries lacking the ".mpu-" marker.
 *
 * WHY: Split from multipart.c to keep ListMultipartUploads logic alongside its sibling fragments for
 *      CompleteMultipartUpload operations. The bucket-root scan is structurally different from per-upload
 *      part enumeration (ListParts), so separating them keeps each fragment focused on one distinct pattern.
 */
#include "s3.h"
#include "multipart_internal.h"

#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* -------------------------------------------------------------------------
 * GET /bucket/?uploads  →  ListMultipartUploads
 * ---------------------------------------------------------------------- */

/*
 * One in-progress upload record collected during the bucket scan.
 *
 * Key is bounded by NAME_MAX (255 on Linux): the staging directory name is
 * ".<key>.mpu-<upload_id>" and must fit in a single directory entry.
 * We use NAME_MAX + 1 for safety.
 */
typedef struct {
    char   key[NAME_MAX + 1];  /* object key (without leading '.') */
    char   upload_id[128];     /* upload id token                  */
    time_t mtime;              /* staging dir mtime (≈ initiation) */
} mpu_upload_entry_t;

/*
 * Maximum number of concurrent in-progress uploads we enumerate in a single
 * ListMultipartUploads response.  AWS S3 returns at most 1000 per page.
 */
#define MPU_MAX_LISTED_UPLOADS  1000

static int
mpu_upload_entry_cmp(const void *a, const void *b)
{
    return strcmp(((const mpu_upload_entry_t *) a)->key,
                  ((const mpu_upload_entry_t *) b)->key);
}

ngx_int_t
s3_handle_list_multipart_uploads(ngx_http_request_t *r,
                                  ngx_http_s3_loc_conf_t *cf)
{
    DIR                *dp;
    struct dirent      *de;
    mpu_upload_entry_t *uploads;
    int                 nuploads = 0;
    int                 i;
    size_t              xml_capacity;
    u_char             *xml;
    size_t              xml_len = 0;
    ngx_buf_t          *b;
    char                iso_buf[32];
    char                key_marker[NAME_MAX + 1];
    char                max_uploads_str[16];
    int                 max_uploads;
    int                 start_idx;
    int                 end_idx;
    int                 truncated;

    if (cf->common.root.data == NULL || cf->common.root.len == 0) {
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Parse pagination query parameters */
    key_marker[0] = '\0';
    s3_get_query_param(r, "key-marker", key_marker, sizeof(key_marker));

    max_uploads = MPU_MAX_LISTED_UPLOADS;
    if (s3_get_query_param(r, "max-uploads",
                           max_uploads_str, sizeof(max_uploads_str)))
    {
        char *endp;
        long  mu = strtol(max_uploads_str, &endp, 10);
        if (endp != max_uploads_str && mu > 0 && mu < MPU_MAX_LISTED_UPLOADS) {
            max_uploads = (int) mu;
        }
    }

    /* Collect matching entries first so we can size the XML buffer accurately. */
    uploads = ngx_palloc(r->pool,
                         sizeof(mpu_upload_entry_t) * MPU_MAX_LISTED_UPLOADS);
    if (uploads == NULL) {
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    dp = opendir((const char *) cf->common.root.data);
    if (dp == NULL) {
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    while ((de = readdir(dp)) != NULL && nuploads < MPU_MAX_LISTED_UPLOADS) {
        /*
         * We are looking for hidden directories (name starts with '.') that
         * contain ".mpu-" — pattern: .<key>.mpu-<upload_id>
         */
        if (de->d_name[0] != '.') {
            continue;
        }
        if (de->d_name[1] == '\0'
            || (de->d_name[1] == '.' && de->d_name[2] == '\0'))
        {
            continue;   /* "." or ".." */
        }

        /* Find ".mpu-" marker — must appear after the key portion */
        const char *mpu_marker = strstr(de->d_name + 1, ".mpu-");
        if (mpu_marker == NULL) {
            continue;
        }

        /* child_path is cf->common.root + "/" + de->d_name (readdir result from the
         * export root). Confinement: de->d_name is a server-generated staging
         * dir name from s3_get_mpu_dir(); bare lstat is safe. */
        char child_path[PATH_MAX];
        if ((size_t) snprintf(child_path, sizeof(child_path), "%s/%s",
                              (const char *) cf->common.root.data,
                              de->d_name) >= sizeof(child_path)) {
            continue;
        }
        struct stat sb;
        if (lstat(child_path, &sb) != 0 || !S_ISDIR(sb.st_mode)) {
            continue;
        }

        /*
         * Name format: ".<key>.mpu-<upload_id>"
         * key  = de->d_name[1 .. mpu_marker-1]
         * upload_id = mpu_marker + 5   (skip ".mpu-")
         */
        size_t key_len = (size_t) (mpu_marker - (de->d_name + 1));
        const char *uid = mpu_marker + 5;

        if (key_len == 0 || uid[0] == '\0') {
            continue;
        }
        if (key_len >= sizeof(uploads[nuploads].key)
            || strlen(uid) >= sizeof(uploads[nuploads].upload_id)) {
            continue;
        }

        ngx_memcpy(uploads[nuploads].key, de->d_name + 1, key_len);
        uploads[nuploads].key[key_len] = '\0';
        ngx_cpystrn((u_char *) uploads[nuploads].upload_id,
                    (u_char *) uid,
                    sizeof(uploads[nuploads].upload_id));
        uploads[nuploads].mtime = sb.st_mtime;
        nuploads++;
    }

    closedir(dp);

    /* Sort by key for deterministic pagination */
    if (nuploads > 1) {
        qsort(uploads, (size_t) nuploads, sizeof(mpu_upload_entry_t),
              mpu_upload_entry_cmp);
    }

    /* Apply key-marker: skip entries whose key <= marker */
    start_idx = 0;
    if (key_marker[0] != '\0') {
        for (start_idx = 0; start_idx < nuploads; start_idx++) {
            if (strcmp(uploads[start_idx].key, key_marker) > 0) {
                break;
            }
        }
    }

    end_idx = start_idx + max_uploads;
    if (end_idx > nuploads) {
        end_idx = nuploads;
    }
    truncated = (end_idx < nuploads);

    /* Size the XML buffer: header + per-upload block */
    xml_capacity = 512
                 + (size_t) cf->bucket.len * 6 + 32
                 + strlen(key_marker) * 6 + 32
                 + (end_idx - start_idx) * (NAME_MAX * 6 + 256)
                 + (truncated ? NAME_MAX * 6 + 128 : 0);

    xml = ngx_palloc(r->pool, xml_capacity);
    if (xml == NULL) {
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    XML_APPEND("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    XML_APPEND("<ListMultipartUploadsResult"
               " xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\n");
    XML_APPEND("  ");
    XML_APPEND_ELEM("Bucket", cf->bucket.data, cf->bucket.len);
    XML_APPEND("\n  ");
    XML_APPEND_ELEM("KeyMarker", key_marker, strlen(key_marker));
    XML_APPEND("\n");
    XML_APPEND("  <MaxUploads>%d</MaxUploads>\n", max_uploads);
    XML_APPEND("  <IsTruncated>%s</IsTruncated>\n",
               truncated ? "true" : "false");

    if (truncated) {
        XML_APPEND("  ");
        XML_APPEND_ELEM("NextKeyMarker", uploads[end_idx - 1].key,
                        strlen(uploads[end_idx - 1].key));
        XML_APPEND("\n  ");
        XML_APPEND_ELEM("NextUploadIdMarker", uploads[end_idx - 1].upload_id,
                        strlen(uploads[end_idx - 1].upload_id));
        XML_APPEND("\n");
    }

    for (i = start_idx; i < end_idx; i++) {
        xrootd_format_iso8601(uploads[i].mtime, iso_buf, sizeof(iso_buf));
        XML_APPEND("  <Upload>\n");
        XML_APPEND("    ");
        XML_APPEND_ELEM("Key", uploads[i].key, strlen(uploads[i].key));
        XML_APPEND("\n    ");
        XML_APPEND_ELEM("UploadId", uploads[i].upload_id,
                        strlen(uploads[i].upload_id));
        XML_APPEND("\n");
        XML_APPEND("    <StorageClass>STANDARD</StorageClass>\n");
        XML_APPEND("    <Initiated>%s</Initiated>\n", iso_buf);
        XML_APPEND("  </Upload>\n");
    }

    XML_APPEND("</ListMultipartUploadsResult>\n");

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
