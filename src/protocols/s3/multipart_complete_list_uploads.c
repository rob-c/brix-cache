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
#include "fs/vfs/vfs.h"   /* confined opendir/readdir/probe via the VFS seam */

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

/*
 * Bucket-scan accumulator threaded through the recursive walk.
 *
 * WHAT: Collapses the request/config context plus the collection sink
 *       (uploads array, capacity, running count) into one struct so the
 *       recursive walker stays under the 5-parameter cap.
 * WHY:  mpu_collect() recurses per directory level; carrying r/cf/uploads/max/n
 *       as loose arguments blew the parameter budget.  These fields are constant
 *       across the whole walk except *n (the write cursor), so a single shared
 *       context is the natural shape.
 */
typedef struct {
    ngx_http_request_t     *r;
    ngx_http_s3_loc_conf_t *cf;
    mpu_upload_entry_t     *uploads;   /* sink array (>= max entries)      */
    int                     max;       /* capacity of the sink array       */
    int                     n;         /* running count of recorded entries */
} mpu_scan_t;

/* Forward declaration: mpu_scan_entry() recurses back into the walker. */
static void mpu_collect(mpu_scan_t *scan, const char *dir_path,
                        const char *key_prefix, int depth);

/*
 * Resolved page view handed to the XML emitter.
 *
 * WHAT: Bundles the sorted uploads array with the pagination decisions
 *       (key-marker window [start_idx, end_idx), truncation flag, and the
 *       echoed request parameters) so the renderer takes one context, not eight.
 * WHY:  mpu_emit_xml() otherwise carried nine parameters; collapsing the
 *       pagination result into a single view keeps it under the 5-param cap.
 */
typedef struct {
    const mpu_upload_entry_t *uploads;      /* key-sorted entry array          */
    const char               *key_marker;   /* echoed KeyMarker (may be "")     */
    int                       max_uploads;  /* echoed MaxUploads                */
    int                       start_idx;    /* first listed entry (inclusive)   */
    int                       end_idx;      /* one past last listed (exclusive) */
    int                       truncated;    /* more entries beyond end_idx      */
} mpu_page_t;

static int
mpu_upload_entry_cmp(const void *a, const void *b)
{
    return strcmp(((const mpu_upload_entry_t *) a)->key,
                  ((const mpu_upload_entry_t *) b)->key);
}

/*
 * mpu_record_staging — record a ".<segment>.mpu-<upload_id>" staging dir.
 *
 * WHAT: Given a hidden entry name `dname` carrying the ".mpu-" marker, slices
 *       out the key segment and upload-id, reconstructs the full object key
 *       (key_prefix + segment), validates lengths, and appends an entry to
 *       scan->uploads, advancing scan->n.  Empty/oversized entries are skipped.
 * WHY:  Isolating the marker-parse + bounds-check + record step keeps the
 *       directory loop in mpu_collect() flat and drops its complexity below the
 *       CCN cap while preserving identical accept/reject behavior.
 * HOW:  The caller guarantees `dname[0] == '.'` and the marker is present.
 *       Empty segment, empty uid, oversized key, or oversized uid → skip.
 *       On accept, key and upload_id are copied and the probed mtime stored.
 */
static void
mpu_record_staging(mpu_scan_t *scan, const char *dname, const char *key_prefix,
                   time_t mtime)
{
    const char         *mpu_marker = strstr(dname + 1, ".mpu-");
    size_t              seg_len     = (size_t) (mpu_marker - (dname + 1));
    const char         *uid         = mpu_marker + 5;   /* skip ".mpu-" */
    mpu_upload_entry_t *e;
    char                keybuf[NAME_MAX + 1];
    int                 kl;

    if (seg_len == 0 || uid[0] == '\0') {
        return;
    }

    kl = snprintf(keybuf, sizeof(keybuf), "%s%.*s",
                  key_prefix, (int) seg_len, dname + 1);
    if (kl < 0 || (size_t) kl >= sizeof(keybuf)
        || strlen(uid) >= sizeof(scan->uploads[0].upload_id))
    {
        return;   /* key / upload-id too long — skip (bounds-consistent) */
    }

    e = &scan->uploads[scan->n];
    memcpy(e->key, keybuf, (size_t) kl + 1);
    ngx_cpystrn((u_char *) e->upload_id, (u_char *) uid,
                sizeof(e->upload_id));
    e->mtime = mtime;
    scan->n++;
}

/*
 * mpu_scan_entry — classify and dispatch one directory entry during the walk.
 *
 * WHAT: For a single readdir entry `dname` under `dir_path` (key `key_prefix`):
 *       builds the child path, confined no-follow-probes it, and either records
 *       it (staging dir), recurses into it (plain key-prefix dir), or skips it.
 * WHY:  Pulling the per-entry classification out of the readdir loop keeps
 *       mpu_collect() a thin driver and removes the nested branch ladder that
 *       drove its cyclomatic complexity over the cap.
 * HOW:  Oversized child path → skip.  Non-directory / symlink (probe no-follow) →
 *       skip.  Hidden name carrying ".mpu-" → record via mpu_record_staging.
 *       Otherwise a plain directory → recurse with the prefix extended by the
 *       segment + '/'.  Never descends INTO a staging dir.
 */
static void
mpu_scan_entry(mpu_scan_t *scan, const char *dir_path, const char *key_prefix,
               const char *dname, int depth)
{
    char             child_path[PATH_MAX];
    brix_vfs_ctx_t   cctx;
    brix_vfs_stat_t  csb;
    char             next_prefix[PATH_MAX];

    if ((size_t) snprintf(child_path, sizeof(child_path), "%s/%s",
                          dir_path, dname) >= sizeof(child_path)) {
        return;
    }

    /* Confined no-follow probe (non-metered): need both the dir check and the
     * mtime for a staging dir. A symlink/file/special is skipped. */
    s3_build_vfs_ctx(scan->r, child_path, scan->cf, &cctx);
    if (brix_vfs_probe(&cctx, 1 /* no-follow */, &csb) != NGX_OK
        || !csb.is_directory)
    {
        return;   /* not a directory (probe also rejects symlinks) */
    }

    /* A staging dir is hidden and carries the ".mpu-" marker. */
    if (dname[0] == '.' && strstr(dname + 1, ".mpu-") != NULL) {
        mpu_record_staging(scan, dname, key_prefix, csb.mtime);
        return;   /* never descend INTO a staging dir */
    }

    /* A plain key-prefix directory (e.g. "alice/"): recurse with the prefix
     * extended by this segment + '/'. */
    if ((size_t) snprintf(next_prefix, sizeof(next_prefix), "%s%s/",
                          key_prefix, dname) >= sizeof(next_prefix)) {
        return;
    }
    mpu_collect(scan, child_path, next_prefix, depth + 1);
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
 *       uploads, and used a bare worker opendir.  Under `brix_impersonation
 *       map` a path-keyed upload lives in the mapped user's 0700 subdir, which
 *       the flat bare scan can neither reach (wrong scope) nor — as the
 *       unprivileged worker — open (EACCES).  Mirrors s3_walk()'s confined
 *       recursive enumeration in list_walk.c.
 * HOW:  Each directory is opened via brix_vfs_opendir_quiet (non-metered;
 *       broker-opened as the mapped user, a plain opendir off impersonation).  A directory
 *       the mapped user cannot traverse (e.g. another tenant's 0700) yields NULL
 *       and is simply skipped, so cross-tenant uploads are never enumerated.
 *       Bounded by scan->n < max and MPU_LIST_MAX_DEPTH; per-entry classification
 *       (record vs. recurse vs. skip) is delegated to mpu_scan_entry().
 */
static void
mpu_collect(mpu_scan_t *scan, const char *dir_path, const char *key_prefix,
            int depth)
{
    brix_vfs_ctx_t  vctx;
    brix_vfs_dir_t *dp;

    if (scan->n >= scan->max || depth > MPU_LIST_MAX_DEPTH) {
        return;
    }

    /* Non-metered confined opendir (the ListMultipartUploads op accounts for the
     * whole recursive walk; broker fdopendir under impersonation). */
    s3_build_vfs_ctx(scan->r, dir_path, scan->cf, &vctx);
    dp = brix_vfs_opendir_quiet(&vctx, NULL);
    if (dp == NULL) {
        return;   /* unreadable as the mapped user (e.g. another tenant's 0700) */
    }

    for ( ;; ) {
        ngx_str_t   name;

        if (scan->n >= scan->max) {
            break;
        }
        /* "."/".." filtered by readdir_kind. */
        if (brix_vfs_readdir_kind(dp, &name, NULL) != NGX_OK) {
            break;   /* NGX_DONE (end) or error → stop */
        }

        mpu_scan_entry(scan, dir_path, key_prefix,
                       (const char *) name.data, depth);
    }

    brix_vfs_closedir(dp, scan->r->connection->log);
}

/*
 * mpu_parse_max_uploads — resolve the effective max-uploads page size.
 *
 * WHAT: Returns the clamped max-uploads value from the query string, defaulting
 *       to MPU_MAX_LISTED_UPLOADS when the parameter is absent or invalid.
 * WHY:  Isolating the strtol-parse + range clamp keeps the handler prologue flat
 *       and drops one of its nested branches.
 * HOW:  A present, fully-numeric value in (0, MPU_MAX_LISTED_UPLOADS) is used;
 *       anything else falls back to the default cap.  Behavior is byte-identical
 *       to the original inline parse.
 */
static int
mpu_parse_max_uploads(ngx_http_request_t *r)
{
    char max_uploads_str[16];

    if (s3_get_query_param(r, "max-uploads",
                           max_uploads_str, sizeof(max_uploads_str)))
    {
        char *endp;
        long  mu = strtol(max_uploads_str, &endp, 10);
        if (endp != max_uploads_str && mu > 0 && mu < MPU_MAX_LISTED_UPLOADS) {
            return (int) mu;
        }
    }
    return MPU_MAX_LISTED_UPLOADS;
}

/*
 * mpu_marker_start_idx — first entry index strictly after key_marker.
 *
 * WHAT: Given a key-sorted uploads array, returns the index of the first entry
 *       whose key sorts strictly after key_marker (0 when the marker is empty).
 * WHY:  Pagination "skip entries whose key <= marker" is a self-contained scan;
 *       extracting it keeps the handler linear.
 * HOW:  Empty marker → 0.  Otherwise a forward scan stopping at the first key
 *       that compares greater than the marker — identical to the inline loop.
 */
static int
mpu_marker_start_idx(const mpu_upload_entry_t *uploads, int nuploads,
                     const char *key_marker)
{
    int start_idx;

    if (key_marker[0] == '\0') {
        return 0;
    }
    for (start_idx = 0; start_idx < nuploads; start_idx++) {
        if (strcmp(uploads[start_idx].key, key_marker) > 0) {
            break;
        }
    }
    return start_idx;
}

/*
 * mpu_render_and_send — build the ListMultipartUploadsResult document and send it.
 *
 * WHAT: Allocates a right-sized buffer, writes the full XML response (header,
 *       Bucket/KeyMarker/MaxUploads/IsTruncated, optional NextKeyMarker /
 *       NextUploadIdMarker when truncated, and one <Upload> block per listed
 *       entry), copies it into an nginx temp buf and sends it as a 200
 *       application/xml response.  Returns the send result, or
 *       NGX_HTTP_INTERNAL_SERVER_ERROR on allocation / encode overflow.
 * WHY:  The XML assembly is the bulk of the handler's length; pulling it out
 *       leaves the handler as a short orchestration of parse → collect → sort →
 *       paginate → render+send.  Rendering and sending stay together because the
 *       XML_APPEND macros embed a `return NGX_HTTP_INTERNAL_SERVER_ERROR` on
 *       overflow — the caller must be a handler-returning (ngx_int_t) function.
 * HOW:  Buffer sizing, every XML_APPEND, and the temp-buf send are copied
 *       verbatim from the original inline tail, so the produced document and all
 *       status/error paths are byte-for-byte identical.
 */
static ngx_int_t
mpu_render_and_send(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf,
                    const mpu_page_t *pg)
{
    const mpu_upload_entry_t *uploads     = pg->uploads;
    const char               *key_marker  = pg->key_marker;
    int                       max_uploads = pg->max_uploads;
    int                       start_idx   = pg->start_idx;
    int                       end_idx     = pg->end_idx;
    int                       truncated   = pg->truncated;
    size_t     xml_capacity;
    u_char    *xml;
    size_t     xml_len = 0;
    char       iso_buf[32];
    int        i;
    ngx_buf_t *b;

    /* Size the XML buffer: header + per-upload block */
    xml_capacity = 512
                 + (size_t) cf->bucket.len * 6 + 32
                 + strlen(key_marker) * 6 + 32
                 + (end_idx - start_idx) * (NAME_MAX * 6 + 256)
                 + (truncated ? NAME_MAX * 6 + 128 : 0);

    xml = ngx_palloc(r->pool, xml_capacity);
    if (xml == NULL) {
        BRIX_S3_METRIC_INC(events_total[BRIX_S3_EVENT_INTERNAL_ERROR]);
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
        brix_format_iso8601(uploads[i].mtime, iso_buf, sizeof(iso_buf));
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
s3_handle_list_multipart_uploads(ngx_http_request_t *r,
                                  ngx_http_s3_loc_conf_t *cf)
{
    mpu_upload_entry_t *uploads;
    mpu_scan_t          scan;
    mpu_page_t          pg;
    int                 nuploads;
    char                key_marker[NAME_MAX + 1];
    int                 max_uploads;
    int                 start_idx;
    int                 end_idx;
    int                 truncated;

    if (cf->common.root.data == NULL || cf->common.root.len == 0) {
        BRIX_S3_METRIC_INC(events_total[BRIX_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Parse pagination query parameters */
    key_marker[0] = '\0';
    s3_get_query_param(r, "key-marker", key_marker, sizeof(key_marker));
    max_uploads = mpu_parse_max_uploads(r);

    /* Collect matching entries first so we can size the XML buffer accurately. */
    uploads = ngx_palloc(r->pool,
                         sizeof(mpu_upload_entry_t) * MPU_MAX_LISTED_UPLOADS);
    if (uploads == NULL) {
        BRIX_S3_METRIC_INC(events_total[BRIX_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /*
     * Recursively enumerate staging dirs across the whole bucket tree, opened
     * impersonation-confined as the mapped user.  Replaces the original flat
     * single-level bare-opendir(root) scan, which (a) only saw bucket-root-keyed
     * uploads and (b) under `brix_impersonation map` could not open the mapped
     * user's own 0700 key subdirs as the unprivileged worker.  A dir the mapped
     * user cannot traverse is skipped, so no cross-tenant upload is enumerated.
     */
    scan.r       = r;
    scan.cf      = cf;
    scan.uploads = uploads;
    scan.max     = MPU_MAX_LISTED_UPLOADS;
    scan.n       = 0;
    mpu_collect(&scan, (const char *) cf->common.root_canon, "", 0);
    nuploads = scan.n;

    /* Sort by key for deterministic pagination */
    if (nuploads > 1) {
        qsort(uploads, (size_t) nuploads, sizeof(mpu_upload_entry_t),
              mpu_upload_entry_cmp);
    }

    /* Apply key-marker: skip entries whose key <= marker */
    start_idx = mpu_marker_start_idx(uploads, nuploads, key_marker);

    end_idx = start_idx + max_uploads;
    if (end_idx > nuploads) {
        end_idx = nuploads;
    }
    truncated = (end_idx < nuploads);

    pg.uploads     = uploads;
    pg.key_marker  = key_marker;
    pg.max_uploads = max_uploads;
    pg.start_idx   = start_idx;
    pg.end_idx     = end_idx;
    pg.truncated   = truncated;

    return mpu_render_and_send(r, cf, &pg);
}
