/*
 * multipart_internal.h — shared declarations for the S3 multipart upload
 * implementation split across multipart.c and the multipart_complete_*.c units.
 */
#ifndef XROOTD_S3_MULTIPART_INTERNAL_H
#define XROOTD_S3_MULTIPART_INTERNAL_H

/* Maximum valid S3 part number (AWS limit). */
#define MPU_MAX_PART_NUMBER  10000

/* Validate that upload_id contains only hex digits and hyphens (no path chars).
 * Returns 1 if valid, 0 if invalid. */
int mpu_validate_upload_id(const char *upload_id);
/* Recursive directory removal used by abort and complete. */
int mpu_rmdir_recursive(ngx_log_t *log, const char *root_canon,
    const char *path);

/* Phase 39 (WS8/HTTP-2): reap abandoned ".<obj>.mpu-<id>" staging dirs in the
 * directory holding final_path that are idle longer than max_age_secs.  Bounded
 * to one readdir; no-op when max_age_secs <= 0.  Returns the count reaped. */
int s3_mpu_reap_stale(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf,
    const char *final_path, time_t max_age_secs);

#endif /* XROOTD_S3_MULTIPART_INTERNAL_H */
