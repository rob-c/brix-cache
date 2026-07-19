#ifndef NGX_HTTP_S3_OPS_H
#define NGX_HTTP_S3_OPS_H

/*
 * s3_ops.h — multipart / copy / delete-objects / checksum operation
 * declarations, split (phase-79 file-size burndown) out of the oversized s3.h
 * with zero behaviour change. This header is included at the END of s3.h and
 * DEPENDS on the types it defines (ngx_http_s3_loc_conf_t, brix_vfs_ctx_t,
 * the s3 request ctx, plus the nginx/openssl includes s3.h pulls). Do not
 * include it directly — include "s3.h", which pulls this in.
 */

/* multipart.c */

/* Return 1 if <key> is present as a bare flag (no '=') in r->args, else 0. */
int s3_has_query_flag(ngx_http_request_t *r, const char *key);
/* Copy query parameter <key>'s value into out (NUL-terminated, truncated to
 * outsz). Returns 1 on success, 0 if absent or value empty. */
int s3_get_query_param(ngx_http_request_t *r, const char *key, char *out, size_t outsz);
/* Build the hidden MPU staging dir path (".<basename>.mpu-<upload_id>" beside
 * fs_path) into out_dir; always NUL-terminates within outsz. */
void s3_get_mpu_dir(const char *fs_path, const char *upload_id, char *out_dir, size_t outsz);
/* InitiateMultipartUpload: mint an opaque hex upload_id, create the confined
 * 0700 staging dir, send the XML result. Returns HTTP status (500 on error). */
ngx_int_t s3_handle_multipart_initiate(ngx_http_request_t *r, const char *fs_path, ngx_http_s3_loc_conf_t *cf, const char *key_str);
/* AbortMultipartUpload: validate upload_id, recursively remove staging dir.
 * Returns 204; 400 invalid id, 404 NoSuchUpload, 500 on removal failure. */
ngx_int_t s3_handle_multipart_abort(ngx_http_request_t *r, const char *fs_path, ngx_http_s3_loc_conf_t *cf, const char *upload_id);
/* CompleteMultipartUpload async body callback: concatenate part.1..part.N in
 * ascending order into a temp file, atomically rename to the object, best-effort
 * clean staging, send CompleteMultipartUploadResult XML. Owns finalization. */
void s3_multipart_complete_body_handler(ngx_http_request_t *r);
/* ListParts: enumerate staged "part.<N>" files, sort, paginate (part-number-marker
 * + max-parts), emit ListPartsResult XML. Returns HTTP status. */
ngx_int_t s3_handle_list_parts(ngx_http_request_t *r, const char *fs_path, ngx_http_s3_loc_conf_t *cf, const char *key_str);
/* ListMultipartUploads: scan bucket root for ".<key>.mpu-<id>" staging dirs,
 * sort by key, paginate, emit ListMultipartUploadsResult XML. Returns status. */
ngx_int_t s3_handle_list_multipart_uploads(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf);
/* UploadPartCopy: copy a confined source (x-amz-copy-source) into staged
 * part.<part_num>, emit CopyPartResult XML. Returns HTTP status (500 unlinks
 * the partial part). */
ngx_int_t s3_handle_upload_part_copy(ngx_http_request_t *r, const char *fs_path, ngx_http_s3_loc_conf_t *cf, const char *upload_id, int part_num);

/* copy.c */

/* CopyObject: server-side copy of x-amz-copy-source (confined) to dst_fs_path
 * via copy_file_range (read/write fallback), staged temp+rename. Emits
 * CopyObjectResult XML. Returns HTTP status. */
ngx_int_t s3_handle_copy_object(ngx_http_request_t *r, const char *dst_fs_path, ngx_http_s3_loc_conf_t *cf);

/* delete_objects.c */

/* DeleteObjects (POST ?delete) async body callback: parse the <Delete> XML
 * (max 1000 keys, 1 MiB body), unlink each (rmdir fallback for dirs), emit a
 * DeleteResult with per-key Deleted/Error. Owns request finalization. */
void s3_delete_objects_body_handler(ngx_http_request_t *r);

/*
 * Populate an ETag string (format: "\"mtime-size\"") for a stat result.
 * buf must be at least 40 bytes.
 */
void s3_etag(const struct stat *st, char *buf, size_t bufsz);

/* Initialise *vctx as a transient (rootfd=-1) S3 VFS request descriptor for the
 * already-resolved confined path fs_path, taking pool/log/TLS/identity from r
 * and roots/write-gate from cf.  Shared by the PUT and POST-object write paths. */
void s3_build_vfs_ctx(ngx_http_request_t *r, const char *fs_path,
    ngx_http_s3_loc_conf_t *cf, brix_vfs_ctx_t *vctx);

/* Phase-70 §5.1/§5.4: bind the request's captured forwardable credential
 * (raw bearer JWT and/or user-supplied full x509 proxy PEM, both lifted onto the
 * S3 req ctx at the auth gate) onto an already-cred-bound VFS ctx, using the
 * export's resolved mode (cf->common.backend_delegation). A no-op on the default
 * SELECT path or when nothing forwardable was captured. Called at every S3
 * brix_vfs_ctx_bind_backend_cred site. */
void s3_vfs_bind_deleg(ngx_http_request_t *r,
    ngx_http_s3_loc_conf_t *cf, brix_vfs_ctx_t *vctx);

/* AWS S3 full-object checksum headers (this gateway supports CRC-64/NVME). */
#define S3_HDR_CHECKSUM_CRC64NVME  "x-amz-checksum-crc64nvme"
#define S3_HDR_CHECKSUM_TYPE       "x-amz-checksum-type"
/* base64 of 8 bytes = 12 chars + NUL; round up for safety. */
#define S3_CRC64NVME_B64_MAX       16

/*
 * Compute (or cache-read) an object's CRC-64/NVME for the open fd and base64-
 * encode the 8 big-endian bytes into out (>= S3_CRC64NVME_B64_MAX) — the AWS
 * x-amz-checksum-crc64nvme wire form. cache_only=1 returns NGX_DECLINED on a
 * cache miss instead of computing (read path). Returns NGX_OK / NGX_DECLINED /
 * NGX_ERROR.
 */
ngx_int_t s3_object_crc64nvme_b64(ngx_http_request_t *r, int fd,
    const char *path, ngx_flag_t cache_only, char *out, size_t outsz);

/* -------------------------------------------------------------------------
 * Multi-algorithm full-object checksums (checksum.c, phase-43 W1)
 * ---------------------------------------------------------------------- */

/* Declared request/echo headers for the additional AWS checksum algorithms. */
#define S3_HDR_SDK_CHECKSUM_ALGO  "x-amz-sdk-checksum-algorithm"
#define S3_HDR_CHECKSUM_MODE      "x-amz-checksum-mode"
/* base64(sha256)=44 chars + NUL; covers every supported algorithm. */
#define S3_CHECKSUM_B64_MAX       48

/* Outcome of s3_put_checksum_apply. */
typedef enum {
    S3_CKSUM_OK = 0,    /* verified or echoed                                  */
    S3_CKSUM_MISMATCH,  /* supplied value mismatched — object removed; 400     */
    S3_CKSUM_CONFLICT,  /* ambiguous / unsupported algorithm selection — 400   */
    S3_CKSUM_ERROR      /* our own compute failed — proceed without the header */
} s3_cksum_result_t;

/* Compute (or cache-read) alg_name for fd and base64-encode the raw digest into
 * out (>= S3_CHECKSUM_B64_MAX) — the AWS x-amz-checksum-* wire form.  Works for
 * crc32/crc32c/sha1/sha256/crc64nvme.  cache_only=1 → NGX_DECLINED on a miss. */
ngx_int_t s3_checksum_b64(ngx_http_request_t *r, int fd, const char *path,
    const char *alg_name, ngx_flag_t cache_only, char *out, size_t outsz);

/* Verify the client-selected full-object checksum (any supported algorithm) for
 * the just-committed object and echo it; see checksum.c for the result codes. */
s3_cksum_result_t s3_put_checksum_apply(ngx_http_request_t *r,
    const char *fs_path, const char *root_canon);

/* Verify+echo a checksum carried in an aws-chunked trailer (phase-43 W0); same
 * result contract as s3_put_checksum_apply. */
s3_cksum_result_t s3_put_trailer_checksum_apply(ngx_http_request_t *r,
    const char *fs_path, const char *root_canon, const char *algo_token,
    const char *value);

/* Verify a classic Content-MD5 (RFC 1864) over the just-committed object; same
 * result contract as s3_put_checksum_apply (MISMATCH → BadDigest, CONFLICT →
 * malformed/InvalidDigest, OK when absent or verified). */
s3_cksum_result_t s3_content_md5_verify(ngx_http_request_t *r,
    const char *fs_path, const char *root_canon);

/* GET/HEAD echo: always emits a cached crc64nvme; with x-amz-checksum-mode:
 * ENABLED also emits every other cached algorithm. */
void s3_echo_object_checksums(ngx_http_request_t *r, int fd, const char *path);

#endif /* NGX_HTTP_S3_OPS_H */
