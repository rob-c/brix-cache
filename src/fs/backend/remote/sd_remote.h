#ifndef BRIX_SD_REMOTE_H
#define BRIX_SD_REMOTE_H

/*
 * sd_remote.h — remote-origin (s3://) storage driver: ranged reads plus staged
 * whole-object writes.
 *
 * WHAT: A capability-typed SD driver (CAP_RANGE_READ|CAP_MEMFILE) serving
 *       open/stat/pread/preadv/fstat/close against a REMOTE object store, plus
 *       staged whole-object writes (.staged_* → single PUT or multipart upload)
 *       and .unlink (DELETE). The read-through cache fill drives it
 *       driver→driver: open the origin object, pread sequential ranges into the
 *       cache's staged-write sink; as a primary it also accepts uploads.
 *
 * WHY:  It folds the origin onto the SAME SD seam as the local cache and
 *       export, so fills and uploads are origin-agnostic. There is deliberately
 *       no .pwrite slot — random in-place writes are impossible on an object
 *       store, so they are rejected at the cap layer while sequential uploads
 *       go through the staged path. Dir/xattr/namespace slots stay NULL.
 *
 * HOW:  s3:// delegates to the shared S3 driver (sd_s3): the per-open object wraps
 *       an sd_s3_file*, pread is a signed Range GET. The HTTP transport is INJECTED
 *       by the cache (kept transport-agnostic, exactly like sd_s3), so no cache or
 *       libcurl dependency leaks into the backend layer. Blocking ops run only on
 *       the cache-fill worker thread. The instance + objects are malloc-owned
 *       (no nginx pool), so they are safe to build and use off the event loop.
 */

#include "fs/backend/sd.h"
#include "fs/backend/s3/sd_s3_transport.h"

/* Remote-origin schemes the driver can serve. */
typedef enum {
    BRIX_SD_REMOTE_S3 = 1
} brix_sd_remote_scheme_t;

/* Origin endpoint + credentials + injected transport. Strings are copied. */
typedef struct {
    brix_sd_remote_scheme_t    scheme;
    char                         host[256];
    int                          port;
    int                          tls;
    char                         bucket[256];      /* S3 bucket (path-style) */
    char                         access_key[256];
    char                         secret_key[256];
    char                         region[64];
    int                          timeout_ms;
    int                          put_checksum;    /* #12: sign+send x-amz-checksum-crc32
                                                   * on every PUT/UploadPart so the origin
                                                   * rejects a corrupted body (BadDigest).
                                                   * 0 = UNSIGNED-PAYLOAD (stock). */
    const brix_s3_transport_t *transport;        /* injected by the cache */
    void                        *tctx;
} brix_sd_remote_cfg_t;

/* Build a remote-origin instance from cfg (deep-copied). Returns a malloc-owned
 * instance whose ->driver is the read-only remote driver, or NULL (errno set).
 * Destroy with brix_sd_remote_destroy. Worker-thread safe (no nginx pool). */
brix_sd_instance_t *brix_sd_remote_create(
    const brix_sd_remote_cfg_t *cfg, ngx_log_t *log);

/* Free a remote instance built by brix_sd_remote_create. NULL-safe. */
void brix_sd_remote_destroy(brix_sd_instance_t *inst);

#endif /* BRIX_SD_REMOTE_H */
