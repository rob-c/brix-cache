/*
 * multipart_internal.h — shared declarations for the S3 multipart upload
 * implementation split across multipart.c and multipart_complete.c.
 */
#pragma once

/* Maximum valid S3 part number (AWS limit). */
#define MPU_MAX_PART_NUMBER  10000

/* Validate that upload_id contains only hex digits and hyphens (no path chars).
 * Returns 1 if valid, 0 if invalid. */
int mpu_validate_upload_id(const char *upload_id);
/* Recursive directory removal used by abort and complete. */
int mpu_rmdir_recursive(ngx_log_t *log, const char *root_canon,
    const char *path);
