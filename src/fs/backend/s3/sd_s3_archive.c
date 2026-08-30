/*
 * sd_s3_archive.c — the S3 archive (GLACIER / DEEP_ARCHIVE) primitives: read an
 * object's archive state, and ask the store to restore it.
 *
 * WHAT: sd_s3_archive_state() — one signed HEAD returning the three response
 *       headers that between them say whether an object's bytes are readable
 *       right now; sd_s3_restore() — the RestoreObject POST that starts a
 *       temporary copy coming back to the online tier.
 *
 * WHY:  These are the two halves the nearline SD slots (residency / recall) need
 *       from an object store, and they are the only S3 verbs in the whole client
 *       that concern data AVAILABILITY rather than data. Keeping them out of
 *       sd_s3_meta.c (which is about an object's user metadata) and out of
 *       sd_s3_write.c (which is about putting bytes) leaves each file with one
 *       subject — and, less tidily but more importantly, both of these are
 *       failure-tolerant advisory operations, which is a different contract from
 *       everything either neighbour does.
 *
 * HOW:  Both are ordinary SigV4 requests. The state read shares the metadata
 *       path's HEAD leg (sd_s3_head_send) so three headers cost ONE round trip
 *       and the status verdict is not restated. The restore is a POST to
 *       `?restore` with an XML RestoreRequest body, signed through the extended
 *       signer for the same reason CreateMPU is: the canonical query string is
 *       part of the signature.
 *
 * NOTE ON `errno`: sd_s3_status_err maps the HTTP status onto errno for the
 *       caller, and every path here preserves it across the resp_free cleanup.
 *       The nearline slots decide policy from errno alone, so losing it to a
 *       cleanup call would turn "the object is not there" into "something went
 *       wrong".
 */

#include "sd_s3_internal.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

/* The restored-copy lifetime the driver asks for when the operator configured
 * none. One day is the smallest value AWS accepts and the right default for a
 * read-through cache: the cache tier owns the copy's usefulness from the moment
 * the recall lands, so paying for archive-tier storage beyond that is the
 * operator's deliberate choice, not ours. */
#define SD_S3_RESTORE_DAYS_DEFAULT  1

/* An x-amz-restore value is short and fixed-shape ("ongoing-request=\"false\",
 * expiry-date=\"Fri, 01 Jan 2027 00:00:00 GMT\""); a storage class is one token.
 * Anything longer is not something this build can classify, and the buffers
 * below are the caller's, so this only bounds what we ask the transport for. */

int
sd_s3_archive_state(sd_s3_file *f, const sd_s3_archive_buf_t *out,
                    char *errbuf, size_t errcap)
{
    brix_s3_resp_t resp;
    char           auth[SD_S3_AUTH_HDRS_CAP];
    int            e;

    if (f == NULL || out == NULL || out->storage_class == NULL
        || out->restore == NULL || out->archive_status == NULL)
    {
        sd_s3_set_err(errbuf, errcap, "s3 archive-state: bad parameters");
        return -1;
    }
    out->storage_class->buf[0]  = '\0';
    out->restore->buf[0]        = '\0';
    out->archive_status->buf[0] = '\0';

    if (sd_s3_sign(f, "HEAD", "", auth, sizeof(auth)) != 0) {
        sd_s3_set_err(errbuf, errcap, "s3 HEAD: SigV4 sign failed on %s",
                      f->key);
        return -1;
    }
    if (sd_s3_head_send(f, auth, &resp, errbuf, errcap) != 0) {
        return -1;
    }
    /* Each header is optional: a STANDARD object carries none of the three, and
     * an absent header is an ANSWER here ("not archived"), never a failure. The
     * buffers were emptied above, so a missed lookup leaves "" behind. */
    (void) f->transport->resp_header(&resp, "x-amz-storage-class",
                                     out->storage_class->buf,
                                     out->storage_class->cap);
    (void) f->transport->resp_header(&resp, "x-amz-restore",
                                     out->restore->buf, out->restore->cap);
    (void) f->transport->resp_header(&resp, "x-amz-archive-status",
                                     out->archive_status->buf,
                                     out->archive_status->cap);
    e = errno;
    f->transport->resp_free(&resp);
    errno = e;
    return 0;
}

int
sd_s3_restore(const sd_s3_open_params *p, int days, char *errbuf, size_t errcap)
{
    sd_s3_file          *f;
    const sd_s3_sign_req_t req = { "POST", "restore=", NULL, 0 };
    brix_s3_resp_t       resp;
    char                 wire[SD_S3_KEY_MAX + 16];
    char                 auth[SD_S3_AUTH_HDRS_CAP];
    char                 body[256];
    int                  blen, pn, rc = 0, e;

    if (p == NULL) {
        sd_s3_set_err(errbuf, errcap, "s3 restore: bad parameters");
        errno = EINVAL;
        return -1;
    }
    if (days <= 0) {
        days = SD_S3_RESTORE_DAYS_DEFAULT;
    }
    /* A read handle is how this client addresses an object; opening one signs
     * nothing and issues no request, so this costs a struct, not a round trip. */
    f = sd_s3_open_read(p, errbuf, errcap);
    if (f == NULL) {
        return -1;
    }
    pn = snprintf(wire, sizeof(wire), "%s?restore", f->key);
    if (pn < 0 || (size_t) pn >= sizeof(wire)) {
        sd_s3_set_err(errbuf, errcap, "s3 restore: key path too long");
        sd_s3_close(f);
        errno = ENAMETOOLONG;
        return -1;
    }
    /* Tier Standard, not Expedited: Expedited is a paid capacity reservation
     * that AWS can refuse outright with InsufficientCapacityError, and a recall
     * this layer starts is a cache fill, not a user-visible latency promise. */
    blen = snprintf(body, sizeof(body),
                    "<RestoreRequest><Days>%d</Days>"
                    "<GlacierJobParameters><Tier>Standard</Tier>"
                    "</GlacierJobParameters></RestoreRequest>", days);
    if (sd_s3_sign_ext(f, &req, auth, sizeof(auth)) != 0) {
        sd_s3_set_err(errbuf, errcap, "s3 RestoreObject: sign failed on %s",
                      f->key);
        sd_s3_close(f);
        return -1;
    }
    if (f->transport->request(f->tctx, f->host, f->port, f->tls, "POST", wire,
                              auth, body, (size_t) blen, f->timeout_ms, &resp,
                              errbuf, errcap) != 0)
    {
        sd_s3_close(f);
        return -1;
    }
    /* 202 = restore started. 200 = a restored copy already exists (S3 answers
     * OK and extends nothing). 409 = RestoreAlreadyInProgress, which is the
     * SAME outcome as 202 from the caller's side — the object is on its way —
     * and treating it as an error would make every concurrent reader of one
     * archived object fail all but the first. */
    if (resp.status != 200 && resp.status != 202 && resp.status != 409) {
        rc = sd_s3_status_err(resp.status, "RestoreObject", f->key, errbuf,
                              errcap);
    }
    e = errno;
    f->transport->resp_free(&resp);
    sd_s3_close(f);
    errno = e;
    return rc;
}
