#ifndef BRIX_FS_BACKEND_S3_SD_S3_INTERNAL_H
#define BRIX_FS_BACKEND_S3_SD_S3_INTERNAL_H

/*
 * sd_s3_internal.h — the S3 client's private layout, shared across the client's
 * translation units (sd_s3.c, sd_s3_meta.c).
 *
 * sd_s3_file is opaque to the driver adapter (only the typedef is in sd_s3.h);
 * the concrete struct + the tuning constants live here so the read/write path
 * and the object-metadata path can both see them without either re-declaring the
 * layout.  Also declares the SigV4 signing + error-mapping primitives (defined in
 * sd_s3.c) that every path shares.
 */

#include "sd_s3.h"                 /* opaque sd_s3_file, sd_s3_open_params */
#include "sd_s3_transport.h"       /* brix_s3_transport_t */

#include <stdint.h>
#include <stddef.h>

#define SD_S3_AUTH_HDRS_CAP  4096
#define SD_S3_PREAD_MAX      (7LL * 1024 * 1024)
#define SD_S3_KEY_MAX        4096
#define SD_S3_ETAG_LEN       96
#define SD_S3_UPLOAD_ID_LEN  128
#define SD_S3_ETAG_INIT_CAP  16
#define SD_S3_PUT_BUF_INIT   (64 * 1024)

typedef struct { char val[SD_S3_ETAG_LEN]; } sd_s3_part_etag;

struct sd_s3_file {
    char                         host[256];
    int                          port;
    int                          tls;
    char                         key[SD_S3_KEY_MAX];
    char                         ak[128];
    char                         sk[256];
    char                         region[64];
    const brix_s3_transport_t *transport;
    void                        *tctx;
    int                          timeout_ms;
    int64_t                      obj_size;   /* -1 until first HEAD */

    /* write state */
    int                          is_write;
    int                          is_mpu;
    int                          lazy_mpu;   /* PUT-buffered until the volume
                                              * exceeds part_size, then upgrade
                                              * to MPU mid-stream (P80.2) */
    int64_t                      part_size;
    /* single PUT */
    void                        *put_buf;
    size_t                       put_len;
    size_t                       put_cap;
    int64_t                      put_write_off;
    /* multipart */
    char                         upload_id[SD_S3_UPLOAD_ID_LEN];
    int                          part_count;
    sd_s3_part_etag             *etags;
    int                          etag_cap;
    int64_t                      mpu_write_off;
    void                        *part_buf;
    size_t                       part_buf_len;

    /* #12: when set, every PUT / UploadPart carries a signed x-amz-checksum-crc32
     * of its body so the ORIGIN validates the bytes and rejects a wire-corrupted
     * upload with 400 BadDigest (brix_backend_put_checksum). Off ⇒ UNSIGNED-PAYLOAD
     * with no body integrity — the stock behaviour. */
    int                          put_checksum;
};

/* ---- SigV4 signing + error mapping (sd_s3.c), shared by every path --------- */
void sd_s3_set_err(char *errbuf, size_t errcap, const char *fmt, ...);
void sd_s3_utc_now(char amzdate[20], char datestamp[12]);
void sd_s3_sha256_hex(const void *data, size_t len, char *out /* >=65 */);
int  sd_s3_sign(const sd_s3_file *f, const char *method, const char *canon_qs,
         char *hdrs, size_t hdrsz);
int  sd_s3_sign_ex(const sd_s3_file *f, const char *method, const char *canon_qs,
         const char *ck_name, const char *ck_val, char *hdrs, size_t hdrsz);
int  sd_s3_status_err(int status, const char *op, const char *key,
         char *errbuf, size_t errcap);

#endif /* BRIX_FS_BACKEND_S3_SD_S3_INTERNAL_H */
