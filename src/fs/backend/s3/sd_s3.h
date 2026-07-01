/*
 * sd_s3.h — shared S3 object-store storage driver (read path; write/MPU follow).
 *
 * WHAT: The S3 storage logic — SigV4 signing (shared kernels), HEAD/Range-GET,
 *       and (later) single-PUT + multipart upload — living once in
 *       src/fs/backend/, used by the userland clients (and any future server
 *       consumer) through an injected HTTP transport (sd_s3_transport.h).
 * WHY:  S3 was previously a client-only backend welded to client/lib's HTTP
 *       stack. The transport injection breaks that coupling so the protocol logic
 *       is shared, ngx-free, in libxrdproto.
 * HOW:  Endpoint + credentials + transport are bound at open into an opaque
 *       handle; ops build signed requests and run them through the transport. The
 *       error model is a neutral (int rc, errbuf) pair — no xrdc_status / ngx.
 */
#ifndef XROOTD_SD_S3_H
#define XROOTD_SD_S3_H

#include "sd_s3_transport.h"
#include "../meta_advisory.h"

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>   /* ssize_t, off_t */

typedef struct sd_s3_file sd_s3_file;   /* opaque read handle */

/* Endpoint + credentials + transport for one open. Strings are copied. */
typedef struct {
    const char                  *host;        /* S3 endpoint host */
    int                          port;
    int                          tls;
    const char                  *key;         /* object path "/bucket/key" */
    const char                  *ak;          /* access key id */
    const char                  *sk;          /* secret key */
    const char                  *region;      /* e.g. "us-east-1" */
    const xrootd_s3_transport_t *transport;   /* injected HTTP transport */
    void                        *tctx;        /* transport context */
    int                          timeout_ms;
} sd_s3_open_params;

/* Open an object for READ. Returns a handle, or NULL with a message in errbuf. */
sd_s3_file *sd_s3_open_read(const sd_s3_open_params *p,
                           char *errbuf, size_t errcap);

/* Object size via a signed HEAD (cached after the first call). 0 / -1. */
int sd_s3_size(sd_s3_file *f, int64_t *out_size, char *errbuf, size_t errcap);

/* Read up to n bytes at off via a signed Range GET. Returns bytes read (>=0,
 * may be short at EOF) or -1 with a message in errbuf. */
ssize_t sd_s3_pread(sd_s3_file *f, void *buf, size_t n, off_t off,
                    char *errbuf, size_t errcap);

/*
 * Open an object for WRITE. `expected_size` < 0 means unknown. When it is known
 * and <= `part_size` a single buffered PUT is used; otherwise a multipart upload
 * is created immediately (CreateMultipartUpload). Returns a handle or NULL
 * (errbuf). Writes must be sequential (S3 has no random write).
 */
sd_s3_file *sd_s3_open_write(const sd_s3_open_params *p, int64_t expected_size,
                            int64_t part_size, char *errbuf, size_t errcap);

/* Append n bytes (must be at the sequential offset). 0 / -1 (errbuf). */
int sd_s3_pwrite(sd_s3_file *f, const void *buf, size_t n, off_t off,
                 char *errbuf, size_t errcap);

/* Finalize the write: single PUT, or flush-last-part + CompleteMultipartUpload.
 * 0 / -1 (errbuf). */
int sd_s3_commit(sd_s3_file *f, char *errbuf, size_t errcap);

/* Discard a partial write (AbortMultipartUpload / drop buffer). Best-effort. */
void sd_s3_abort(sd_s3_file *f);

/* Bytes written so far (for fstat on a write handle). */
int64_t sd_s3_write_size(const sd_s3_file *f);

/* Free the handle. */
void sd_s3_close(sd_s3_file *f);

/* Delete the object (signed DELETE). Idempotent: a missing object (HTTP 404) is
 * success. 0 / -1 (errbuf; errno set to the POSIX class). */
int sd_s3_delete(const sd_s3_open_params *p, char *errbuf, size_t errcap);

/* ---- object metadata (x-amz-meta-*) ----------------------------------- *
 * S3 has no in-place metadata mutation: get is a HEAD that reads one user-meta
 * header; set is a copy-onto-self with x-amz-metadata-directive: REPLACE. The
 * advisory unix-attr blob (mode/uid/gid/mtime) rides in the reserved key
 * x-amz-meta-<XROOTD_META_ADVISORY_S3META>. Attribute names are lowercased to
 * match the S3 user-metadata contract.                                      */

/* Read user-metadata header x-amz-meta-<name> via a signed HEAD into buf[cap]
 * (NUL-terminated). Returns the value length (0 when the attribute is absent),
 * or -1 with errbuf on a transport/HTTP error. */
ssize_t sd_s3_get_meta(sd_s3_file *f, const char *name,
                       char *buf, size_t cap, char *errbuf, size_t errcap);

/* One x-amz-meta-<name>=value pair for sd_s3_set_meta. */
typedef struct { const char *name; const char *value; } sd_s3_meta_kv;

/* Replace the object's user metadata with kv[0..nkv) via a copy-onto-self (PUT
 * key + x-amz-copy-source: key + x-amz-metadata-directive: REPLACE), each pair
 * sent and SigV4-signed as x-amz-meta-<name>. 0 / -1 (errbuf). */
int sd_s3_set_meta(const sd_s3_open_params *p, const sd_s3_meta_kv *kv,
                   size_t nkv, char *errbuf, size_t errcap);

/* Advisory POSIX attrs carried in x-amz-meta-<S3META>. get returns 1 (present +
 * decoded) / 0 (absent) / -1 (error); set replaces the user metadata with the
 * single advisory blob. */
int sd_s3_get_unixattr(sd_s3_file *f, xrootd_meta_advisory_t *out,
                       char *errbuf, size_t errcap);
int sd_s3_set_unixattr(const sd_s3_open_params *p,
                       const xrootd_meta_advisory_t *a,
                       char *errbuf, size_t errcap);

#endif /* XROOTD_SD_S3_H */
