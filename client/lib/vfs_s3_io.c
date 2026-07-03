/*
 * vfs_s3_io.c - extracted concern
 * Phase-38 split of vfs_s3.c; behavior-identical.
 */
#include "vfs_s3_internal.h"


/* HEAD to get object size */
/*
 * s3_load_size — issue a SigV4-signed HEAD and populate sf->obj_size.
 *
 * WHAT: sends HEAD /key, parses the Content-Length response header, stores the
 *       result in sf->obj_size (or -1 if Content-Length is absent).
 * WHY:  fstat() on a read handle needs the object size; the HEAD is deferred
 *       to the first fstat call (lazy) to avoid a round-trip on write handles.
 * HOW:  s3_sign + brix_http_req; parse Content-Length with brix_http_header.
 */
int
s3_load_size(vfs_s3_file *sf, brix_status *st)
{
    char errbuf[256] = "";

    /* Delegate to the shared S3 driver (HEAD-size lives in src/fs/backend/sd_s3.c). */
    if (sd_s3_size(sf->sd, &sf->obj_size, errbuf, sizeof(errbuf)) != 0) {
        brix_status_set(st, XRDC_EIO, 0, "%s", errbuf);
        return -1;
    }
    return 0;
}


/* vtable: pread */
/*
 * s3_pread — read n bytes at offset off from the S3 object into buf.
 *
 * WHAT: issues a SigV4-signed GET with a "Range: bytes=off-end\r\n" header;
 *       copies the 206 (or 200) response body into buf.
 * WHY:  VFS callers need seekable reads; S3 supports this via HTTP Range.
 * HOW:  cap n at S3_PREAD_MAX to stay within brix_http_req's 8 MiB body limit;
 *       build combined auth+range extra_headers string; issue GET; check status;
 *       memcpy body to buf; return bytes copied.
 */
ssize_t
s3_pread(brix_vfs_file *f, int64_t off, void *buf, size_t n, brix_status *st)
{
    vfs_s3_file *sf = (vfs_s3_file *) f;
    char         errbuf[256] = "";
    ssize_t      r;

    /* Delegate to the shared S3 driver (Range-GET lives in src/fs/backend/sd_s3.c). */
    r = sd_s3_pread(sf->sd, buf, n, (off_t) off, errbuf, sizeof(errbuf));
    if (r < 0) {
        brix_status_set(st, XRDC_EIO, 0, "%s", errbuf);
    }
    return r;
}


/* vtable: pwrite */



/*
 * s3_pwrite — write n bytes from buf at offset off.
 *
 * WHAT: dispatcher that routes to s3_pwrite_single or s3_pwrite_mpu based on
 *       the handle's write mode (sf->is_mpu).
 * WHY:  the vtable interface is uniform; mode dispatch is one place.
 * HOW:  cast f to vfs_s3_file; check is_write; delegate.
 */
int
s3_pwrite(brix_vfs_file *f, int64_t off, const void *buf, size_t n,
          brix_status *st)
{
    vfs_s3_file *sf = (vfs_s3_file *) f;
    char         errbuf[256] = "";

    /* Delegate to the shared S3 driver (single-PUT buffer / MPU part flush).
     * The driver sets errno at its error sites (EINVAL for a non-sequential
     * write, EACCES for an auth failure on a part flush); reset it first so a
     * stale value can't leak, then map it to the matching XRDC_* code. */
    errno = 0;
    if (sd_s3_pwrite(sf->sd, buf, n, (off_t) off, errbuf, sizeof(errbuf)) != 0) {
        int e = errno;
        brix_status_set(st, s3_brix_from_errno(e), e, "%s", errbuf);
        return -1;
    }
    return 0;
}


/* vtable: fstat */
/*
 * s3_fstat — fill *out with size metadata for the open handle.
 *
 * WHAT: for READ handles, issues a lazy HEAD if size not yet loaded; for WRITE
 *       handles returns the accumulated byte count as the current size.
 * WHY:  copy.c may call fstat after open to get the object size for progress.
 * HOW:  READ: lazy s3_load_size; WRITE single-PUT: put_len; WRITE MPU:
 *       mpu_write_off (total bytes written so far).
 */
int
s3_fstat(brix_vfs_file *f, brix_vfs_stat *out, brix_status *st)
{
    vfs_s3_file *sf = (vfs_s3_file *) f;

    out->is_dir = 0;
    out->mtime  = 0;
    out->exists = 1;

    if (sf->is_write) {
        out->size = sd_s3_write_size(sf->sd);
        return 0;
    }
    /* READ handle: load size lazily on first fstat. */
    if (sf->obj_size < 0) {
        if (s3_load_size(sf, st) != 0) {
            return -1;
        }
    }
    out->size = sf->obj_size;
    return 0;
}


/* vtable: truncate */
/*
 * s3_truncate — unsupported on S3 (not advertised in caps).
 *
 * WHAT: always returns XRDC_EUSAGE.
 * WHY:  S3 objects are immutable once committed; in-place truncation is not
 *       possible without re-uploading.  The backend does not advertise
 *       XRDC_VFS_CAP_TRUNCATE, so callers that check caps won't reach here.
 * HOW:  unconditional error return.
 */
int
s3_truncate(brix_vfs_file *f, int64_t size, brix_status *st)
{
    vfs_s3_file *sf = (vfs_s3_file *) f;
    (void) size;
    brix_status_set(st, XRDC_EUSAGE, 0,
                    "s3 backend does not support truncate on %s",
                    sf->key_path);
    return -1;
}


/* vtable: sync */
/*
 * s3_sync — no-op for the S3 backend.
 *
 * WHAT: returns 0 immediately.
 * WHY:  S3 object stores are synchronous by nature — a successful PUT or MPU
 *       part acknowledgement means the data is durable.  There is no separate
 *       flush step needed between pwrite calls.
 * HOW:  unconditional 0 return.
 */
int
s3_sync(brix_vfs_file *f, brix_status *st)
{
    (void) f;
    (void) st;
    return 0;
}


/* vtable: commit */


/*
 * s3_commit — finalise a write handle.
 *
 * WHAT: for single-PUT → PUT the buffer; for MPU → flush + CompleteMultipartUpload.
 *       No-op for READ handles.
 * WHY:  the vtable commit() is the single finalise point for all backends.
 * HOW:  dispatch on is_mpu; delegate.
 */
int
s3_commit(brix_vfs_file *f, brix_status *st)
{
    vfs_s3_file *sf = (vfs_s3_file *) f;
    char         errbuf[256] = "";

    if (sd_s3_commit(sf->sd, errbuf, sizeof(errbuf)) != 0) {
        brix_status_set(st, XRDC_EIO, 0, "%s", errbuf);
        return -1;
    }
    return 0;
}


/* vtable: abort */
/*
 * s3_abort — discard a partial write.
 *
 * WHAT: MPU → AbortMultipartUpload (removes server-side staging directory);
 *       single-PUT → discard the in-memory buffer (no server cleanup needed).
 *       READ handles → no-op.
 * WHY:  a failed transfer must not leave orphan server resources.
 * HOW:  is_mpu → s3_mpu_abort_upload (best-effort: errors are swallowed);
 *       single-PUT: put_len reset to 0 (buffer freed in close).
 */
void
s3_abort(brix_vfs_file *f)
{
    vfs_s3_file *sf = (vfs_s3_file *) f;

    sd_s3_abort(sf->sd);
}


/* vtable: close */
/*
 * s3_close — release all resources held by the handle.
 *
 * WHAT: frees all malloc'd buffers (put_buf, part_buf, etags) and the handle
 *       struct itself.  Must be called after commit() or abort().
 * WHY:  owns all resources allocated by s3_be_open(); one release point.
 * HOW:  free each field; free(sf).
 */
void
s3_close(brix_vfs_file *f)
{
    vfs_s3_file *sf = (vfs_s3_file *) f;

    /* All S3 byte/MPU buffers live in the shared driver handle now. */
    if (sf->sd != NULL) {
        sd_s3_close(sf->sd);
    }
    free(sf);
}
