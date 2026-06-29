#ifndef XROOTD_SD_XROOT_H
#define XROOTD_SD_XROOT_H

/*
 * sd_xroot.h — remote root:// origin storage driver (read + write data path).
 *
 * WHAT: A capability-typed SD driver against a REMOTE XRootD (root:// / roots://)
 *       server. Read slots (open/stat/pread/fstat/close) plus, as of Phase 1 of
 *       the writable-remote-backend work, the WRITE DATA PATH (pwrite/ftruncate/
 *       fsync over kXR_write/_truncate/_sync; caps RANGE_READ|RANDOM_WRITE|
 *       TRUNCATE). It is the root:// sibling of the S3 sd_remote driver: the cache
 *       fill drives the read side driver→driver (open the origin file, pread
 *       ranges into the staged-write sink).
 *
 * WHY:  It folds the root:// origin onto the SAME SD seam as S3, the local cache,
 *       and the export, so storage is origin-agnostic. The write slots are the
 *       foundation for making a remote root:// a first-class writable backend with
 *       optional local staging (see docs/superpowers/specs/2026-06-29-writable-
 *       remote-root-staged-write-design.md); staged-write and namespace (mkdir/
 *       rename) slots are later phases. Not yet registry-selectable as a primary
 *       export backend (Phase 2 wires that) — today it is cache-constructed only.
 *
 * HOW:  It wraps the in-process XRootD origin wire client (cache/origin_*.c) —
 *       which needs only a server conf + a logical path — behind the SD vtable.
 *       The per-open object holds a live origin connection + open file handle;
 *       pread issues a kXR_read range into a memory sink. AUTH: anonymous login
 *       (the wire client's native mode). Authenticated root:// origins (bearer
 *       token / GSI X.509 proxy) are filled by the cache's native-client
 *       delegation (xrootd_cache_origin_proxy / _token), not this in-process
 *       driver — a full in-process root:// token/GSI client is a follow-on (that
 *       auth logic lives in libxrdc, which src/ cannot link). Blocking; runs only
 *       on the cache-fill worker thread. Instance/objects are malloc-owned.
 *
 * NOTE: This driver intentionally depends on the cache's origin wire client
 *       (cache/cache_internal.h) — it exists to expose that client as an SD
 *       backend, so the dependency is inherent rather than a layering slip.
 */

#include "../sd.h"

/* Build a remote root:// instance bound to `conf` (an ngx_stream_xrootd_srv_conf_t*,
 * read for cache_origin_host/port/tls/ssl_ctx). Returns a malloc-owned instance
 * whose ->driver is the remote root:// driver, or NULL (errno set). Destroy
 * with xrootd_sd_xroot_destroy. Worker-thread safe (no nginx pool). */
xrootd_sd_instance_t *xrootd_sd_xroot_create(void *conf, ngx_log_t *log);

/* Build a remote root:// instance from EXPLICIT origin params (host/port/tls),
 * synthesizing the minimal conf the wire client needs. Used to make a remote
 * root:// the registry-selectable PRIMARY backend of any export (stream OR http,
 * which has no stream conf). Anonymous; tls!=0 needs trusted-CA wiring (follow-on).
 * Returns a malloc-owned instance, or NULL (errno set). Destroy with
 * xrootd_sd_xroot_destroy. */
xrootd_sd_instance_t *xrootd_sd_xroot_create_origin(const char *host, int port,
    int tls, ngx_log_t *log);

/* Free a root:// instance built by xrootd_sd_xroot_create. NULL-safe. */
void xrootd_sd_xroot_destroy(xrootd_sd_instance_t *inst);

/* Query the origin's content checksum (kXR_Qcksum) for an OPEN object, so the
 * cache's commit-then-verify path can compare the filled bytes against the
 * origin's advertised digest (preserving root:// checksum-on-fill when the fill
 * runs through this driver). Writes alg/hex (empty when the origin advertises
 * none). Best-effort: a failure leaves them empty. The object must be one
 * returned by this driver's ->open. */
void xrootd_sd_xroot_query_checksum(xrootd_sd_obj_t *obj,
    char *alg, size_t algsz, char *hex, size_t hexsz);

#endif /* XROOTD_SD_XROOT_H */
