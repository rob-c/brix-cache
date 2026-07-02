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
#include "fs/vfs.h"   /* confined opendir/readdir/probe via the VFS seam */

#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * GET /bucket/?uploads  →  ListMultipartUploads
 * */

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

/*
 * Recursion-depth cap for the bucket-tree scan — a runaway guard, generous
 * enough for realistically-nested object keys ("a/b/c/.../obj").
 */
#define MPU_LIST_MAX_DEPTH      16

static int
mpu_upload_entry_cmp(const void *a, const void *b)
{
    return strcmp(((const mpu_upload_entry_t *) a)->key,
                  ((const mpu_upload_entry_t *) b)->key);
}

/*
 * mpu_collect — recursively gather in-progress multipart staging dirs under
 * dir_path, reconstructing each upload's full object key from key_prefix.
 *
 * WHAT: Walks the bucket tree (impersonation-confined) collecting staging dirs
 *       named ".<segment>.mpu-<upload_id>".  The reported key is
 *       key_prefix + segment, so a path-keyed upload "alice/foo" staged at
 *       <root>/alice/.foo.mpu-<id> is listed with Key "alice/foo".  Plain
 *       subdirectories are recursed into as key-prefix components; a staging dir
 *       is recorded as a leaf and never descended.
 * WHY:  The original flat single-level opendir(root) only saw bucket-root-keyed
 *       uploads, and used a bare worker opendir.  Under `xrootd_impersonation
 *       map` a path-keyed upload lives in the mapped user's 0700 subdir, which
 *       the flat bare scan can neither reach (wrong scope) nor — as the
 *       unprivileged worker — open (EACCES).  Mirrors s3_walk()'s confined
 *       recursive enumeration in list_walk.c.
 * HOW:  Each directory is opened via xrootd_vfs_opendir_quiet (non-metered;
 *       broker-opened as the mapped user, a plain opendir off impersonation).  A directory
 *       the mapped user cannot traverse (e.g. another tenant's 0700) yields NULL
 *       and is simply skipped, so cross-tenant uploads are never enumerated.
 *       Bounded by *n < max and MPU_LIST_MAX_DEPTH; symlinks are skipped (lstat).
 */
static void
mpu_collect(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf,
            const char *dir_path, const char *key_prefix,
            mpu_upload_entry_t *uploads, int max, int *n, int depth)
{
    xrootd_vfs_ctx_t  vctx;
    xrootd_vfs_dir_t *dp;

    if (*n >= max || depth > MPU_LIST_MAX_DEPTH) {
        return;
    }

    /* Non-metered confined opendir (the ListMultipartUploads op accounts for the
     * whole recursive walk; broker fdopendir under impersonation). */
    s3_build_vfs_ctx(r, dir_path, cf, &vctx);
    dp = xrootd_vfs_opendir_quiet(&vctx, NULL);
    if (dp == NULL) {
        return;   /* unreadable as the mapped user (e.g. another tenant's 0700) */
    }

    for ( ;; ) {
        ngx_str_t          name;
        const char        *dname;
        char               child_path[PATH_MAX];
        xrootd_vfs_ctx_t   cctx;
        xrootd_vfs_stat_t  csb;
        const char        *mpu_marker;

        if (*n >= max) {
            break;
        }
        /* "."/".." filtered by readdir_kind. */
        if (xrootd_vfs_readdir_kind(dp, &name, NULL) != NGX_OK) {
            break;   /* NGX_DONE (end) or error → stop */
        }
        dname = (const char *) name.data;

        if ((size_t) snprintf(child_path, sizeof(child_path), "%s/%s",
                              dir_path, dname) >= sizeof(child_path)) {
            continue;
        }

        /* Confined no-follow probe (non-metered): need both the dir check and the
         * mtime for a staging dir. A symlink/file/special is skipped. */
        s3_build_vfs_ctx(r, child_path, cf, &cctx);
        if (xrootd_vfs_probe(&cctx, 1 /* no-follow */, &csb) != NGX_OK
            || !csb.is_directory)
        {
            continue;   /* not a directory (probe also rejects symlinks) */
        }

        /* A staging dir is hidden and carries the ".mpu-" marker. */
        mpu_marker = (dname[0] == '.') ? strstr(dname + 1, ".mpu-") : NULL;
        if (mpu_marker != NULL) {
            size_t      seg_len = (size_t) (mpu_marker - (dname + 1));
            const char *uid     = mpu_marker + 5;   /* skip ".mpu-" */
            char        keybuf[NAME_MAX + 1];
            int         kl;

            if (seg_len == 0 || uid[0] == '\0') {
                continue;
            }
            kl = snprintf(keybuf, sizeof(keybuf), "%s%.*s",
                          key_prefix, (int) seg_len, dname + 1);
            if (kl < 0 || (size_t) kl >= sizeof(keybuf)
                || strlen(uid) >= sizeof(uploads[*n].upload_id))
            {
                continue;   /* key / upload-id too long — skip (bounds-consistent) */
            }
            memcpy(uploads[*n].key, keybuf, (size_t) kl + 1);
            ngx_cpystrn((u_char *) uploads[*n].upload_id, (u_char *) uid,
                        sizeof(uploads[*n].upload_id));
            uploads[*n].mtime = csb.mtime;
            (*n)++;
            continue;   /* never descend INTO a staging dir */
        }

        /* A plain key-prefix directory (e.g. "alice/"): recurse with the prefix
         * extended by this segment + '/'. */
        {
            char next_prefix[PATH_MAX];
            if ((size_t) snprintf(next_prefix, sizeof(next_prefix), "%s%s/",
                                  key_prefix, dname) >= sizeof(next_prefix)) {
                continue;
            }
            mpu_collect(r, cf, child_path, next_prefix, uploads, max, n,
                        depth + 1);
        }
    }

    xrootd_vfs_closedir(dp, r->connection->log);
}

ngx_int_t
s3_handle_list_multipart_uploads(ngx_http_request_t *r,
                                  ngx_http_s3_loc_conf_t *cf)
{
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

    /*
     * Recursively enumerate staging dirs across the whole bucket tree, opened
     * impersonation-confined as the mapped user.  Replaces the original flat
     * single-level bare-opendir(root) scan, which (a) only saw bucket-root-keyed
     * uploads and (b) under `xrootd_impersonation map` could not open the mapped
     * user's own 0700 key subdirs as the unprivileged worker.  A dir the mapped
     * user cannot traverse is skipped, so no cross-tenant upload is enumerated.
     */
    mpu_collect(r, cf, (const char *) cf->common.root_canon, "",
                uploads, MPU_MAX_LISTED_UPLOADS, &nuploads, 0);

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
