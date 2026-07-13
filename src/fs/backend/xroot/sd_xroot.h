#ifndef BRIX_SD_XROOT_H
#define BRIX_SD_XROOT_H

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
 *       delegation (brix_cache_origin_proxy / _token), not this in-process
 *       driver — a full in-process root:// token/GSI client is a follow-on (that
 *       auth logic lives in libxrdc, which src/ cannot link). Blocking; runs only
 *       on the cache-fill worker thread. Instance/objects are malloc-owned.
 *
 * NOTE: This driver intentionally depends on the cache's origin wire client
 *       (cache/cache_internal.h) — it exists to expose that client as an SD
 *       backend, so the dependency is inherent rather than a layering slip.
 */

#include "fs/backend/sd.h"
#include "core/compat/af_policy.h"   /* BRIX_AF_* for create_origin af_policy */

/* Build a remote root:// instance bound to `conf` (an ngx_stream_brix_srv_conf_t*,
 * read for cache_origin_host/port/tls/ssl_ctx). Returns a malloc-owned instance
 * whose ->driver is the remote root:// driver, or NULL (errno set). Destroy
 * with brix_sd_xroot_destroy. Worker-thread safe (no nginx pool). */
brix_sd_instance_t *brix_sd_xroot_create(void *conf, ngx_log_t *log);

/* brix_sd_xroot_origin_cfg_t — the EXPLICIT origin parameters for a
 * registry/cache-built remote root:// instance.
 *
 * WHAT: One value carrying every input `brix_sd_xroot_create_origin()` needs to
 *       synthesize the minimal wire-client conf: the endpoint (host/port/tls/
 *       af_policy), the optional §14 credential set (bearer / x509_proxy /
 *       x509_key / sss_keytab), and the CA store source (ca_dir). Every string
 *       field may be NULL/"" (unset); the pointed-at bytes need only outlive the
 *       create call (they are copied onto instance-owned storage).
 * WHY:  It collapses the nine loose create arguments to a single struct pointer,
 *       keeping the create function under the parameter gate and giving each
 *       caller one named-field literal instead of a positional argument stack —
 *       the credential/endpoint fields are easy to transpose positionally.
 * HOW:  `host` (required, non-empty) + `port` (1..65535, required) + `tls` +
 *       `af_policy` (brix_af_policy_t: BRIX_AF_AUTO tries all, _INET/_INET6 force
 *       IPv4/IPv6) name the endpoint. `bearer` is presented via ztn (XrdSecztn),
 *       `x509_proxy` (a PEM path) + optional separate `x509_key` via the
 *       in-process XrdSecgsi handshake, and `sss_keytab` via SSS, when the origin
 *       demands authentication. `ca_dir` (a CA file or hashed dir) builds the
 *       store that VERIFIES the origin's server cert during the GSI handshake
 *       (MITM protection). */
typedef struct {
    const char *host;        /* required: origin hostname (non-empty) */
    int         port;        /* required: origin port (1..65535) */
    int         tls;         /* non-zero: connect via roots:// (TLS) */
    int         af_policy;   /* brix_af_policy_t: address-family constraint */
    const char *bearer;      /* §14/C-3 ztn bearer token text (NULL/"" = anon) */
    const char *x509_proxy;  /* §14/C-3 GSI proxy (or cert) PEM path */
    const char *x509_key;    /* §14/C-3 separate GSI private key path */
    const char *ca_dir;      /* CA file or hashed dir verifying the origin cert */
    const char *sss_keytab;  /* §14 SSS shared-secret keytab path */
} brix_sd_xroot_origin_cfg_t;

/* Build a remote root:// instance from the EXPLICIT origin params in `cfg`,
 * synthesizing the minimal conf the wire client needs. Used to make a remote
 * root:// the registry-selectable PRIMARY backend of any export (stream OR http,
 * which has no stream conf). Returns a malloc-owned instance, or NULL (errno set).
 * Destroy with brix_sd_xroot_destroy. */
brix_sd_instance_t *brix_sd_xroot_create_origin(
    const brix_sd_xroot_origin_cfg_t *cfg, ngx_log_t *log);

/* Free a root:// instance built by brix_sd_xroot_create. NULL-safe. */
void brix_sd_xroot_destroy(brix_sd_instance_t *inst);

/* Query the origin's content checksum (kXR_Qcksum) for an OPEN object, so the
 * cache's commit-then-verify path can compare the filled bytes against the
 * origin's advertised digest (preserving root:// checksum-on-fill when the fill
 * runs through this driver). Writes alg/hex (empty when the origin advertises
 * none). Best-effort: a failure leaves them empty. The object must be one
 * returned by this driver's ->open. */
void brix_sd_xroot_query_checksum(brix_sd_obj_t *obj,
    char *alg, size_t algsz, char *hex, size_t hexsz);

#endif /* BRIX_SD_XROOT_H */
