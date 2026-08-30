/*
 * sd_s3.h — shared S3 object-store storage driver (read + write/MPU paths).
 *
 * WHAT: The S3 storage logic — SigV4 signing (shared kernels), HEAD/Range-GET,
 *       and single-PUT + multipart upload (sd_s3_write.c) — living once in
 *       src/fs/backend/, used by the userland clients (and any future server
 *       consumer) through an injected HTTP transport (sd_s3_transport.h).
 * WHY:  S3 was previously a client-only backend welded to client/lib's HTTP
 *       stack. The transport injection breaks that coupling so the protocol logic
 *       is shared, ngx-free, in libxrdproto.
 * HOW:  Endpoint + credentials + transport are bound at open into an opaque
 *       handle; ops build signed requests and run them through the transport. The
 *       error model is a neutral (int rc, errbuf) pair — no xrdc_status / ngx.
 */
#ifndef BRIX_SD_S3_H
#define BRIX_SD_S3_H

#include "sd_s3_transport.h"
#include "fs/backend/meta_advisory.h"

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>   /* ssize_t, off_t */
#include <time.h>       /* time_t in the flat-listing callback */

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
    const char                  *session_token; /* STS X-Amz-Security-Token; NULL for a
                                                * static keypair (phase-70 §5.5). When
                                                * set it is signed into every request as
                                                * a canonical header. Never logged. */
    const brix_s3_transport_t *transport;   /* injected HTTP transport */
    void                        *tctx;        /* transport context */
    int                          timeout_ms;
    int                          put_checksum; /* #12: sign+send x-amz-checksum-crc32
                                                * on PUT/UploadPart (origin-enforced
                                                * body integrity). 0 = UNSIGNED. */
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
 * x-amz-meta-<BRIX_META_ADVISORY_S3META>. Attribute names are lowercased to
 * match the S3 user-metadata contract.                                      */

/* Destination buffer for sd_s3_get_meta: the value lands NUL-terminated in
 * buf[0..cap). */
typedef struct { char *buf; size_t cap; } sd_s3_meta_buf;

/* Read user-metadata header x-amz-meta-<name> via a signed HEAD into out
 * (NUL-terminated). Returns the value length (0 when the attribute is absent),
 * or -1 with errbuf on a transport/HTTP error. */
ssize_t sd_s3_get_meta(sd_s3_file *f, const char *name,
                       const sd_s3_meta_buf *out, char *errbuf, size_t errcap);

/* Read ONE checksum-bearing response header off a signed HEAD that asks the
 * origin to return the checksums it stored at upload time
 * (`x-amz-checksum-mode: ENABLED`). `hdr_name` is the header to extract — an
 * `x-amz-checksum-<algo>` (base64, per the S3 additional-checksum feature) or
 * `ETag` (hex, and an md5 of the object ONLY for a single-part upload). The
 * value lands NUL-terminated in out->buf; the ENCODING is the caller's to
 * interpret, so this layer stays free of any digest grammar. Returns the value
 * length, 0 when the origin sent no such header, or -1 with errbuf. */
ssize_t sd_s3_get_checksum(sd_s3_file *f, const char *hdr_name,
                           const sd_s3_meta_buf *out, char *errbuf,
                           size_t errcap);

/* Enumerate every user-metadata name on the object (signed HEAD + raw header
 * walk) into buf as a listxattr(2)-style NUL-separated block of "user.<name>"
 * entries; the reserved advisory key (BRIX_META_ADVISORY_S3META) is omitted —
 * it surfaces as POSIX attrs, not as a user xattr. cap==0 probes the required
 * size. Returns the byte count, or -1 with errbuf + errno (ERANGE when buf is
 * too small; ENOTSUP when the transport cannot enumerate headers). */
ssize_t sd_s3_list_meta(sd_s3_file *f, char *buf, size_t cap,
                        char *errbuf, size_t errcap);

/* One x-amz-meta-<name>=value pair for sd_s3_set_meta. */
typedef struct { const char *name; const char *value; } sd_s3_meta_kv;

/* Replace the object's user metadata with kv[0..nkv) via a copy-onto-self (PUT
 * key + x-amz-copy-source: key + x-amz-metadata-directive: REPLACE), each pair
 * sent and SigV4-signed as x-amz-meta-<name>. 0 / -1 (errbuf). */
int sd_s3_set_meta(const sd_s3_open_params *p, const sd_s3_meta_kv *kv,
                   size_t nkv, char *errbuf, size_t errcap);

/* Server-side CopyObject: copy `copy_source` (an "/bucket/key" object path) onto
 * the destination object addressed by `p->key`, signed with p's credential. The
 * bytes never traverse this host — S3 copies in-store via the x-amz-copy-source
 * header (default COPY metadata-directive, so the source's user metadata is
 * preserved). Returns 0, or -1 with errno mapped from the HTTP status
 * (ENOENT on a missing source, EACCES on auth, EIO otherwise) + errbuf. */
int sd_s3_copy(const sd_s3_open_params *p, const char *copy_source,
               char *errbuf, size_t errcap);

/* ---- object listing (ListObjectsV2, delimited) ----------------------------
 * Enumerate ONE page of the bucket under `prefix` with delimiter '/', so the
 * result is a single directory level: <Contents> keys directly under the prefix
 * (files) and <CommonPrefixes> (sub-directories). `p->key` MUST address the
 * bucket root ("/bucket/") — that is the canonical URI the request is signed
 * against; `prefix` (may be "") and the continuation token ride in the query
 * string. `cb` fires once per entry with the entry BASENAME (a sub-directory
 * carries no trailing slash) and `is_dir` distinguishing the two; the
 * directory-marker object (Key == prefix) is skipped. Returning non-zero from
 * `cb` stops enumeration of the current page early (reported as success). On
 * success *truncated says whether more pages remain and cont_out receives the
 * NextContinuationToken (empty when not truncated) to feed the next call's
 * cont_in. 0 / -1 (errbuf + errno mapped from the HTTP status). */
typedef int (*sd_s3_list_cb)(void *ud, const char *name, int is_dir);
int sd_s3_list_page(const sd_s3_open_params *p, const char *prefix,
                    const char *cont_in, sd_s3_list_cb cb, void *ud,
                    int *truncated, char *cont_out, size_t cont_cap,
                    char *errbuf, size_t errcap);

/* ---- flat object listing (ListObjectsV2, NO delimiter) --------------------
 * The same request without `delimiter`, so one page reports up to 1000 keys
 * under `prefix` at ANY depth — the shape driver->enumerate wants. `cb` fires
 * once per <Contents> entry with the FULL key (not a basename; there are no
 * <CommonPrefixes> in an undelimited listing) plus the size and mtime S3
 * reports in the listing itself, so a stat-bearing enumeration costs no extra
 * request. mtime is 0 when <LastModified> is absent or unparsable — never a
 * guessed epoch. Directory-marker objects (a key ending in '/') ARE reported;
 * they are real stored objects, and it is the caller's namespace model that
 * decides whether to skip them. Paging, early stop and the return contract are
 * identical to sd_s3_list_page. */
typedef int (*sd_s3_list_flat_cb)(void *ud, const char *key, uint64_t size,
                                  time_t mtime);
int sd_s3_list_flat_page(const sd_s3_open_params *p, const char *prefix,
                    const char *cont_in, sd_s3_list_flat_cb cb, void *ud,
                    int *truncated, char *cont_out, size_t cont_cap,
                    char *errbuf, size_t errcap);

/* ---- archive state + restore (sd_s3_archive.c) ----------------------------
 * The two verbs an object store offers about data AVAILABILITY rather than
 * data, and the pair the nearline SD slots are built from.
 */

/* Where sd_s3_archive_state writes the three headers it reads. Every buffer is
 * the caller's and every one is left "" when the origin sent no such header —
 * which is the normal answer for an object that was never archived. */
typedef struct {
    const sd_s3_meta_buf *storage_class;    /* x-amz-storage-class   */
    const sd_s3_meta_buf *restore;          /* x-amz-restore         */
    const sd_s3_meta_buf *archive_status;   /* x-amz-archive-status  */
} sd_s3_archive_buf_t;

/* Read the object's archive state off ONE signed HEAD. 0 (the buffers hold
 * whatever the origin sent, "" for each absent header), or -1 with errbuf and
 * errno set. An absent header is never an error — see the struct above. */
int sd_s3_archive_state(sd_s3_file *f, const sd_s3_archive_buf_t *out,
                        char *errbuf, size_t errcap);

/* RestoreObject: ask the store to bring the archived object addressed by p->key
 * back to the online tier for `days` (<=0 selects the driver's default), as a
 * POST to `?restore`. Returns 0 when the restore is under way OR already in
 * progress OR already complete — S3 spells those 202 / 409 / 200 and they are
 * one outcome to a caller that is going to poll the state anyway — and -1 with
 * errbuf + errno on anything else. Asynchronous by definition: 0 means
 * "accepted", never "the bytes are readable now". */
int sd_s3_restore(const sd_s3_open_params *p, int days, char *errbuf,
                  size_t errcap);

/* Advisory POSIX attrs carried in x-amz-meta-<S3META>. get returns 1 (present +
 * decoded) / 0 (absent) / -1 (error); set replaces the user metadata with the
 * single advisory blob. */
int sd_s3_get_unixattr(sd_s3_file *f, brix_meta_advisory_t *out,
                       char *errbuf, size_t errcap);
int sd_s3_set_unixattr(const sd_s3_open_params *p,
                       const brix_meta_advisory_t *a,
                       char *errbuf, size_t errcap);

#endif /* BRIX_SD_S3_H */
