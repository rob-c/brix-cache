/*
 * oci_module_internal.h — seams internal to src/protocols/oci/.
 *
 * WHAT: the declarations the OCI module's own translation units share and
 *       nobody outside the directory may call: the merge orchestrator the
 *       module context installs, the finalize observer that charges the
 *       metric families exactly once, the guard-line emitter, and the small
 *       response helpers the gate and the mirror handler both need.
 * WHY:  oci.h is the plane's PUBLIC face (the handler entry point, the loc
 *       conf, the classified ctx) — it is included from ./config-listed
 *       siblings such as the metrics exporter. Keeping the intra-module
 *       wiring out of it means a change to the file split never ripples
 *       past this directory, which is exactly how src/protocols/cvmfs/
 *       separates cvmfs.h from cvmfs_module_internal.h.
 * HOW:  declarations only; every definition lives in the .c named in the
 *       comment above it.
 */
#ifndef BRIX_PROTOCOLS_OCI_MODULE_INTERNAL_H
#define BRIX_PROTOCOLS_OCI_MODULE_INTERNAL_H

#include "oci.h"
#include "fs/vfs/vfs.h"
#include "net/guard/guard.h"
#include "protocols/shared/file_serve.h"

/* ---- oci_merge.c --------------------------------------------------------- */

char *ngx_http_brix_oci_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);

/* ---- oci_token_cache.c --------------------------------------------------- */

/* The SHM token cache the dance and the D16 proof gate share. `cred` is a raw
 * 32-byte credential hash joining the key, or NULL for the credential-blind
 * entry the fill-side provider probes. get: 0 = hit (tok NUL-terminated);
 * put: expiry is expires_in seconds less the renewal skew, floored. */
int brix_oci_token_cache_get(brix_oci_upstream_t *up, const char *scope,
    const u_char *cred, char *tok, size_t toklen);
void brix_oci_token_cache_put(brix_oci_upstream_t *up, const char *scope,
    const u_char *cred, const char *tok, long expires_in);

/* sha256 of [data, data+len) as 32 RAW bytes — the one primitive every SHM
 * key in this plane (token, proof, challenge memo, credential digest) is
 * derived with. 0 = key written / -1 = EVP failure. */
int brix_oci_sha256_key(const void *data, size_t len, u_char key[32]);

/* ---- oci_tags.c ---------------------------------------------------------- */

/* The location's thread pool, resolved lazily on first use (post-fork only).
 * Shared by the listing relay and the D16 proof gate so both blocking relays
 * ride one pool and one back-pressure story. NULL = no pool configured. */
ngx_thread_pool_t *brix_oci_thread_pool(ngx_http_brix_oci_loc_conf_t *lcf);

/* ---- oci_errors.c -------------------------------------------------------- */

/* One unified guard-core audit line (the fail2ban contract, proto="oci").
 * The request URI rides the path field, sanitized here. */
void brix_oci_guard_emit(ngx_http_request_t *r, guard_reason_t reason,
    guard_op_class_t op, ngx_uint_t status);

/* Every OCI response carries the API-version header the client uses to
 * confirm it is talking to a v2 registry (§0.7.1). */
ngx_int_t brix_oci_api_version_header(ngx_http_request_t *r);

/* Send `len` bytes of `body` as the complete response with `status` and
 * `ctype`; `body` must outlive the request (a pool allocation or a literal).
 * HEAD is honoured: the header goes out, the body does not. */
ngx_int_t brix_oci_send_body(ngx_http_request_t *r, ngx_uint_t status,
    const char *ctype, const u_char *body, size_t len);

/* ---- oci_present.c ------------------------------------------------------- */

/* Everything the response says ABOUT the object, as opposed to the object.
 * Request-pool allocated and handed to the serve pipeline as pre_header_ud,
 * so its buffers outlive the header filter. */
typedef struct {
    brix_oci_meta_t  meta;
    unsigned         stale:1;      /* served past brix_oci_manifest_ttl */
} brix_oci_present_t;

/* Resolve the media type + content digest for the object open on `fh`,
 * deriving and memoizing them when the sidecar cannot answer. `meta_base` is
 * the body's own on-disk path — the sidecar is written beside it — or NULL
 * when the object has no local path to sit beside (a remote cache store), in
 * which case every hit derives instead. NGX_OK, or NGX_ERROR on an unusable
 * classification. */
ngx_int_t brix_oci_present_prepare(ngx_http_request_t *r,
    ngx_http_brix_oci_loc_conf_t *lcf, ngx_http_brix_oci_ctx_t *ctx,
    brix_vfs_file_t *fh, const brix_vfs_stat_t *vst, const char *meta_base,
    brix_oci_present_t *pres);

/* Format this object's strong validator ("\"sha256:...\"") into `buf`.
 * 1 = written, 0 = no digest is known and the caller must fall back to the
 * pipeline's mtime+size ETag. */
int brix_oci_present_etag(const brix_oci_present_t *pres, char *buf,
    size_t buflen);

/* brix_http_pre_header_fn: attach those headers to the outgoing response. */
void brix_oci_present_headers(ngx_http_request_t *r, ngx_fd_t fd,
    off_t file_size, void *userdata);

/* The serve options both surfaces hand the ranged file pipeline. Identical on
 * purpose: a pull from the mirror and a pull from the local registry are the
 * same response to the client, and the ONE thing neither may do is transcode. */
void brix_oci_present_serve_opts(brix_http_serve_opts_t *opts,
    brix_oci_present_t *pres);

/* ---- oci_mirror.c -------------------------------------------------------- */

/* The pool-cleanup observer: charges requests_total / upstream_errors_total
 * for this request once its final status is known. `data` is the request. */
void brix_oci_finalize_observe(void *data);

#endif /* BRIX_PROTOCOLS_OCI_MODULE_INTERNAL_H */
