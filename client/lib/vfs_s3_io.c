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
 * HOW:  s3_sign + xrdc_http_req; parse Content-Length with xrdc_http_header.
 */
int
s3_load_size(vfs_s3_file *sf, xrdc_status *st)
{
    char           auth_hdrs[S3_AUTH_HDRS_CAP];
    xrdc_http_resp resp;
    char           cl_buf[32];

    if (s3_sign(sf, "HEAD", "", auth_hdrs, sizeof(auth_hdrs), st) != 0) {
        return -1;
    }
    if (xrdc_http_req(sf->host, sf->port, sf->tls, "HEAD", sf->key_path,
                      auth_hdrs, NULL, 0, S3_REQ_TIMEOUT_MS, 0, NULL,
                      &resp, st) != 0) {
        return -1;
    }
    if (resp.status != 200) {
        int rc = s3_http_err(resp.status, "HEAD", sf->key_path, st);
        xrdc_http_resp_free(&resp);
        return rc;
    }
    sf->obj_size = -1;
    if (xrdc_http_header(&resp, "Content-Length", cl_buf, sizeof(cl_buf))) {
        sf->obj_size = strtoll(cl_buf, NULL, 10);
    }
    xrdc_http_resp_free(&resp);
    return 0;
}


/* vtable: pread */
/*
 * s3_pread — read n bytes at offset off from the S3 object into buf.
 *
 * WHAT: issues a SigV4-signed GET with a "Range: bytes=off-end\r\n" header;
 *       copies the 206 (or 200) response body into buf.
 * WHY:  VFS callers need seekable reads; S3 supports this via HTTP Range.
 * HOW:  cap n at S3_PREAD_MAX to stay within xrdc_http_req's 8 MiB body limit;
 *       build combined auth+range extra_headers string; issue GET; check status;
 *       memcpy body to buf; return bytes copied.
 */
ssize_t
s3_pread(xrdc_vfs_file *f, int64_t off, void *buf, size_t n, xrdc_status *st)
{
    vfs_s3_file   *sf = (vfs_s3_file *) f;
    char           auth_hdrs[S3_AUTH_HDRS_CAP];
    char           combined[S3_AUTH_HDRS_CAP + 80];
    xrdc_http_resp resp;
    int64_t        end;
    size_t         n_capped;
    ssize_t        copied;
    int            cn;

    if (n == 0) {
        return 0;
    }
    n_capped = (n > (size_t) S3_PREAD_MAX) ? (size_t) S3_PREAD_MAX : n;
    end = off + (int64_t) n_capped - 1;

    if (s3_sign(sf, "GET", "", auth_hdrs, sizeof(auth_hdrs), st) != 0) {
        return -1;
    }
    cn = snprintf(combined, sizeof(combined),
                  "Range: bytes=%lld-%lld\r\n%s",
                  (long long) off, (long long) end, auth_hdrs);
    if (cn < 0 || (size_t) cn >= sizeof(combined)) {
        xrdc_status_set(st, XRDC_EUSAGE, 0, "s3 pread: header too long");
        return -1;
    }
    if (xrdc_http_req(sf->host, sf->port, sf->tls, "GET", sf->key_path,
                      combined, NULL, 0, S3_REQ_TIMEOUT_MS, 0, NULL,
                      &resp, st) != 0) {
        return -1;
    }
    if (resp.status != 206 && resp.status != 200) {
        s3_http_err(resp.status, "GET", sf->key_path, st);
        xrdc_http_resp_free(&resp);
        return -1;
    }
    if (resp.body == NULL || resp.body_len == 0) {
        xrdc_http_resp_free(&resp);
        return 0;   /* EOF or empty range */
    }
    copied = (resp.body_len < n_capped) ? (ssize_t) resp.body_len
                                        : (ssize_t) n_capped;
    memcpy(buf, resp.body, (size_t) copied);
    xrdc_http_resp_free(&resp);
    return copied;
}


/* vtable: pwrite */
/*
 * s3_pwrite_check_sequential — verify that the write offset matches the expected
 * boundary for sequential S3 writes.
 *
 * WHAT: returns -1 with XRDC_EUSAGE if off != *expected_off.
 * WHY:  S3 requires sequential writes; a non-sequential offset cannot be satisfied
 *       without random-write support (which S3 does not have).
 * HOW:  simple integer comparison.
 */
int
s3_pwrite_check_sequential(int64_t off, int64_t expected_off,
                           const char *path, xrdc_status *st)
{
    if (off != expected_off) {
        xrdc_status_set(st, XRDC_EUSAGE, 0,
                        "s3 backend requires sequential writes "
                        "(got offset %lld, expected %lld) on %s",
                        (long long) off, (long long) expected_off, path);
        return -1;
    }
    return 0;
}


/*
 * s3_pwrite_single — append data to the single-PUT in-memory buffer.
 *
 * WHAT: copies data[0..n) into sf->put_buf, growing it via realloc if needed.
 * WHY:  single-PUT mode buffers the whole object in memory; the PUT is issued at
 *       commit() time so we know the Content-Length.
 * HOW:  check sequential offset; realloc if put_len + n > put_cap; memcpy; advance.
 */
int
s3_pwrite_single(vfs_s3_file *sf, int64_t off, const void *data, size_t n,
                 xrdc_status *st)
{
    size_t new_len;
    void  *new_buf;

    if (s3_pwrite_check_sequential(off, sf->put_write_off, sf->key_path,
                                   st) != 0) {
        return -1;
    }
    new_len = sf->put_len + n;
    if (new_len > sf->put_cap) {
        size_t new_cap = sf->put_cap * 2;
        while (new_cap < new_len) {
            new_cap *= 2;
        }
        new_buf = realloc(sf->put_buf, new_cap);
        if (new_buf == NULL) {
            xrdc_status_set(st, XRDC_EIO, ENOMEM,
                            "s3 single-put: out of memory");
            return -1;
        }
        sf->put_buf = new_buf;
        sf->put_cap = new_cap;
    }
    memcpy((char *) sf->put_buf + sf->put_len, data, n);
    sf->put_len      += n;
    sf->put_write_off = off + (int64_t) n;
    return 0;
}


/*
 * s3_pwrite_mpu — append data to the MPU part buffer, flushing full parts.
 *
 * WHAT: copies data[0..n) into sf->part_buf chunk by chunk; when part_buf fills
 *       (part_buf_len reaches part_size), uploads the part via
 *       s3_mpu_flush_part_buf() and resets for the next part.
 * WHY:  MPU requires fixed-size parts (except the last); this incrementally fills
 *       the buffer and uploads complete parts as they accumulate.
 * HOW:  sequential guard; copy-loop that fills the part buffer and flushes when
 *       full; advance mpu_write_off.
 */
int
s3_pwrite_mpu(vfs_s3_file *sf, int64_t off, const void *data, size_t n,
              xrdc_status *st)
{
    const char *src      = (const char *) data;
    size_t      remaining = n;

    if (s3_pwrite_check_sequential(off, sf->mpu_write_off, sf->key_path,
                                   st) != 0) {
        return -1;
    }
    while (remaining > 0) {
        size_t space  = (size_t) sf->part_size - sf->part_buf_len;
        size_t to_copy = (remaining < space) ? remaining : space;

        memcpy((char *) sf->part_buf + sf->part_buf_len, src, to_copy);
        sf->part_buf_len += to_copy;
        src              += to_copy;
        remaining        -= to_copy;

        if (sf->part_buf_len == (size_t) sf->part_size) {
            if (s3_mpu_flush_part_buf(sf, st) != 0) {
                return -1;
            }
        }
    }
    sf->mpu_write_off = off + (int64_t) n;
    return 0;
}


/*
 * s3_pwrite — write n bytes from buf at offset off.
 *
 * WHAT: dispatcher that routes to s3_pwrite_single or s3_pwrite_mpu based on
 *       the handle's write mode (sf->is_mpu).
 * WHY:  the vtable interface is uniform; mode dispatch is one place.
 * HOW:  cast f to vfs_s3_file; check is_write; delegate.
 */
int
s3_pwrite(xrdc_vfs_file *f, int64_t off, const void *buf, size_t n,
          xrdc_status *st)
{
    vfs_s3_file *sf = (vfs_s3_file *) f;

    if (!sf->is_write) {
        xrdc_status_set(st, XRDC_EUSAGE, 0,
                        "s3 pwrite: handle opened for read");
        return -1;
    }
    if (n == 0) {
        return 0;
    }
    if (sf->is_mpu) {
        return s3_pwrite_mpu(sf, off, buf, n, st);
    }
    return s3_pwrite_single(sf, off, buf, n, st);
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
s3_fstat(xrdc_vfs_file *f, xrdc_vfs_stat *out, xrdc_status *st)
{
    vfs_s3_file *sf = (vfs_s3_file *) f;

    out->is_dir = 0;
    out->mtime  = 0;
    out->exists = 1;

    if (sf->is_write) {
        out->size = sf->is_mpu ? sf->mpu_write_off : (int64_t) sf->put_len;
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
s3_truncate(xrdc_vfs_file *f, int64_t size, xrdc_status *st)
{
    vfs_s3_file *sf = (vfs_s3_file *) f;
    (void) size;
    xrdc_status_set(st, XRDC_EUSAGE, 0,
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
s3_sync(xrdc_vfs_file *f, xrdc_status *st)
{
    (void) f;
    (void) st;
    return 0;
}


/* vtable: commit */
/*
 * s3_commit_single — PUT the entire buffered object in a single request.
 *
 * WHAT: issues a SigV4-signed PUT with sf->put_buf as the body; checks 200.
 * WHY:  single-PUT mode defers the actual HTTP transfer until commit so that
 *       Content-Length is known at the time of the PUT.
 * HOW:  sign PUT (no query string); xrdc_http_req with put_buf; check 200.
 */
int
s3_commit_single(vfs_s3_file *sf, xrdc_status *st)
{
    char           auth_hdrs[S3_AUTH_HDRS_CAP];
    xrdc_http_resp resp;

    if (s3_sign(sf, "PUT", "", auth_hdrs, sizeof(auth_hdrs), st) != 0) {
        return -1;
    }
    if (xrdc_http_req(sf->host, sf->port, sf->tls, "PUT", sf->key_path,
                      auth_hdrs,
                      sf->put_buf, sf->put_len,
                      S3_REQ_TIMEOUT_MS, 0, NULL, &resp, st) != 0) {
        return -1;
    }
    if (resp.status != 200) {
        int rc = s3_http_err(resp.status, "PUT", sf->key_path, st);
        xrdc_http_resp_free(&resp);
        return rc;
    }
    xrdc_http_resp_free(&resp);
    return 0;
}


/*
 * s3_commit_mpu — flush the final partial part then CompleteMultipartUpload.
 *
 * WHAT: uploads any remaining data in sf->part_buf as the last part, then
 *       issues CompleteMultipartUpload with all part ETags.
 * WHY:  the MPU must be explicitly finalised; any unflushed partial part must be
 *       uploaded first (the last part is the only one allowed to be < 5 MiB on
 *       real S3; our server has no minimum size restriction).
 * HOW:  s3_mpu_flush_part_buf; s3_mpu_complete.
 */
int
s3_commit_mpu(vfs_s3_file *sf, xrdc_status *st)
{
    if (s3_mpu_flush_part_buf(sf, st) != 0) {
        return -1;
    }
    if (sf->part_count == 0) {
        /* Zero-byte MPU: upload an empty last part so complete has at least one
         * part; the server assembles an empty object. */
        if (s3_mpu_upload_part(sf, 1, NULL, 0, st) != 0) {
            return -1;
        }
    }
    return s3_mpu_complete(sf, st);
}


/*
 * s3_commit — finalise a write handle.
 *
 * WHAT: for single-PUT → PUT the buffer; for MPU → flush + CompleteMultipartUpload.
 *       No-op for READ handles.
 * WHY:  the vtable commit() is the single finalise point for all backends.
 * HOW:  dispatch on is_mpu; delegate.
 */
int
s3_commit(xrdc_vfs_file *f, xrdc_status *st)
{
    vfs_s3_file *sf = (vfs_s3_file *) f;

    if (!sf->is_write) {
        return 0;   /* READ handle — nothing to commit */
    }
    if (sf->is_mpu) {
        return s3_commit_mpu(sf, st);
    }
    return s3_commit_single(sf, st);
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
s3_abort(xrdc_vfs_file *f)
{
    vfs_s3_file *sf = (vfs_s3_file *) f;

    if (!sf->is_write) {
        return;
    }
    if (sf->is_mpu) {
        s3_mpu_abort_upload(sf);
    } else {
        sf->put_len = 0;   /* discard buffer; close() frees the allocation */
    }
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
s3_close(xrdc_vfs_file *f)
{
    vfs_s3_file *sf = (vfs_s3_file *) f;

    free(sf->put_buf);
    free(sf->part_buf);
    free(sf->etags);
    free(sf);
}
