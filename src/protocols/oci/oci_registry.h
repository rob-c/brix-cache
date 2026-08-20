/*
 * oci_registry.h — seams internal to the local registry (push) surface (D4).
 *
 * WHAT: the store layout primitives, the authorization gate and the two
 *       write engines (upload sessions, manifest PUT) that `brix_oci_registry`
 *       composes. Nothing here is reachable from a mirror-only build path:
 *       the surfaces share a module, a classifier and an error envelope, and
 *       nothing else.
 * WHY:  the push surface is the one place in this plane where wire bytes
 *       become STORED objects, so its seams want to be visible in one header
 *       rather than discovered per file: every path in the store is built by
 *       oci_store.c from an already-validated name/digest (§0.7.2), every
 *       write lands through a staged temp, and every request has passed the
 *       one authorization gate before any of it runs. Splitting these into
 *       four translation units keeps each under the size cap and keeps the
 *       state machine (App. J.7) readable as a state machine.
 * HOW:  declarations only. The store speaks NUL-terminated C paths because
 *       that is what the VFS seam and the staged-file helpers take; the
 *       handlers speak nginx rcs.
 */
#ifndef BRIX_PROTOCOLS_OCI_REGISTRY_H
#define BRIX_PROTOCOLS_OCI_REGISTRY_H

#include "oci.h"
#include "oci_module_internal.h"

#include <limits.h>

/* A manifest body is JSON describing an image; real ones are single-digit
 * KiB. The cap is the spec's own guidance, and it is enforced BEFORE the
 * body is read, so a hostile 100 MiB "manifest" never reaches jansson. */
#define BRIX_OCI_MANIFEST_MAX   (4 * 1024 * 1024)

/* An image index may name this many manifests, an image manifest this many
 * layers. Both are far past anything a real build produces and bound the
 * existence walk a single PUT can ask us to perform. */
#define BRIX_OCI_MAX_REFS       512

/* ---- oci_store.c — the on-disk store (App. B.3) -------------------------- */

/* Every store path is built from this: the canonical registry root, resolved
 * once at request entry so the per-request builders stay pure. */
typedef struct {
    char        root[PATH_MAX];             /* brix_oci_registry_root        */
    size_t      root_len;
} brix_oci_store_t;

/* Resolve the store root for this location. NGX_OK, or NGX_ERROR when the
 * location configured no usable root (the merge already warned). */
ngx_int_t brix_oci_store_init(brix_oci_store_t *st,
    ngx_http_brix_oci_loc_conf_t *lcf);

/* <root>/blobs/<alg>/<hex[0:2]>/<hex> — the global CAS body path. Takes the
 * parsed digest, not a bare hex string: the algorithm names a directory, so a
 * caller that has only the hex does not yet know where the blob lives. */
int brix_oci_store_blob_path(const brix_oci_store_t *st,
    const brix_oci_digest_t *d, char *out, size_t outsz);

/* <root>/repos/<name>/<rest>. `rest` is a caller-built suffix that has
 * already been validated (a digest hex, a tag, or a fixed literal). */
int brix_oci_store_repo_path(const brix_oci_store_t *st, const char *name,
    size_t name_len, const char *rest, char *out, size_t outsz);

/* <root>/_uploads/<session> — the session directory. `session` must have
 * classified (BRIX_OCI_SESSION_MAX-bounded, no separators). */
int brix_oci_store_upload_path(const brix_oci_store_t *st,
    const char *session, size_t session_len, const char *rest,
    char *out, size_t outsz);

/* mkdir -p every component of `path`'s PARENT directory beneath the store
 * root. NGX_OK / NGX_ERROR (errno set). */
ngx_int_t brix_oci_store_mkparent(const char *path, ngx_log_t *log);

/* Does the regular file at `path` exist? Size lands in *size_out when
 * non-NULL. 1 present / 0 absent. */
int brix_oci_store_exists(const char *path, off_t *size_out);

/* Stream the file at `path` through `want`'s algorithm, comparing against it.
 * NGX_OK on match, NGX_DECLINED on mismatch, NGX_ERROR on I/O failure. */
ngx_int_t brix_oci_store_verify(const char *path,
    const brix_oci_digest_t *want, ngx_log_t *log);

/* Publish `tmp_path` (a staged sibling) onto `final_path`, creating parents.
 * Atomic: readers see the old object or the new one, never a partial. */
ngx_int_t brix_oci_store_publish(const char *tmp_path, const char *final_path,
    ngx_log_t *log);

/* Write `text` into `final_path` atomically (tag files, ref marks). */
ngx_int_t brix_oci_store_put_text(const char *final_path, const char *text,
    size_t len, ngx_log_t *log);

/* Read at most `outsz-1` bytes of `path` into `out` (NUL-terminated).
 * Bytes read, or -1. */
ssize_t brix_oci_store_get_text(const char *path, char *out, size_t outsz);

/* <root>/repos/<name>/manifests/<alg>/<hex>[<suffix>] — the manifest body,
 * or its sidecar when `suffix` is ".meta". */
int brix_oci_store_manifest_path(const brix_oci_store_t *st, const char *name,
    size_t name_len, const brix_oci_digest_t *d, const char *suffix,
    char *out, size_t outsz);

/* <root>/repos/<name>/tags/<tag> — the one-line pointer file. */
int brix_oci_store_tag_path(const brix_oci_store_t *st,
    const brix_oci_req_t *req, char *out, size_t outsz);

/* <root>/repos/<name>/layers/<hex> — this repo's reference mark. No algorithm
 * component, unlike the blob and manifest paths: the hex WIDTH already
 * separates the algorithms (64 vs 128 chars), so a directory level here would
 * buy no disambiguation and would move every existing mark. */
int brix_oci_store_layer_path(const brix_oci_store_t *st, const char *name,
    size_t name_len, const brix_oci_digest_t *d, char *out, size_t outsz);

/* Point `req`'s tag at `digest_str` ("<alg>:<hex>"), atomically. */
ngx_int_t brix_oci_store_tag_set(const brix_oci_store_t *st,
    const brix_oci_req_t *req, const char *digest_str, ngx_log_t *log);

/* Every tag this repository holds, newline-joined into `out` (the local
 * answer to GET /v2/<name>/tags/list). Count, or -1. */
int brix_oci_store_tag_list(const brix_oci_store_t *st, const char *name,
    size_t name_len, char *out, size_t outsz);

/* Record that repo `name` references blob `d` (an empty mark file). */
ngx_int_t brix_oci_store_mark_layer(const brix_oci_store_t *st,
    const char *name, size_t name_len, const brix_oci_digest_t *d,
    ngx_log_t *log);

/* Remove one path; NGX_OK also when it was already gone. */
ngx_int_t brix_oci_store_remove(const char *path, ngx_log_t *log);

/* Recursively remove a session directory (two known children + the dir). */
void brix_oci_store_drop_dir(const char *dir, ngx_log_t *log);

/* ---- oci_upload.c — small shared answers -------------------------------- */

/* A status with no body at all — the 202/204 answers on this surface carry
 * their whole meaning in their headers. */
ngx_int_t brix_oci_reply_empty(ngx_http_request_t *r, ngx_uint_t status);

/* ---- oci_authz.c — the D4.5 gate ---------------------------------------- */

/* Decide whether this request may proceed on the registry surface, and with
 * what identity. NGX_OK = allowed (`principal` filled, possibly "anonymous");
 * NGX_DONE = refused, with the 401/403 envelope already written; any other rc
 * is a failure to return as-is. NGX_OK never means "answered" here — see
 * brix_oci_refuse(). */
ngx_int_t brix_oci_registry_authz(ngx_http_request_t *r,
    ngx_http_brix_oci_loc_conf_t *lcf, ngx_http_brix_oci_ctx_t *ctx,
    char *principal, size_t principal_len);

/* ---- oci_upload.c — the J.7 state machine ------------------------------- */

/* POST /v2/<name>/blobs/uploads/[?digest=|?mount=&from=] */
ngx_int_t brix_oci_upload_start(ngx_http_request_t *r,
    ngx_http_brix_oci_loc_conf_t *lcf, ngx_http_brix_oci_ctx_t *ctx,
    brix_oci_store_t *st);

/* PATCH / PUT / GET / DELETE on /v2/<name>/blobs/uploads/<session> */
ngx_int_t brix_oci_upload_session(ngx_http_request_t *r,
    ngx_http_brix_oci_loc_conf_t *lcf, ngx_http_brix_oci_ctx_t *ctx,
    brix_oci_store_t *st);

/* Sweep sessions idle longer than brix_oci_upload_grace. Cheap enough to run
 * on the way into a session-creating request; returns the number reaped. */
ngx_uint_t brix_oci_upload_reap(const brix_oci_store_t *st, time_t grace,
    ngx_log_t *log);

/* ---- oci_manifest_put.c -------------------------------------------------- */

/* GET/HEAD /v2/<name>/tags/list answered from the local store (§D4.3). */
ngx_int_t brix_oci_registry_tags(ngx_http_request_t *r,
    ngx_http_brix_oci_ctx_t *ctx, brix_oci_store_t *st);

/* PUT /v2/<name>/manifests/<reference> */
ngx_int_t brix_oci_manifest_put(ngx_http_request_t *r,
    ngx_http_brix_oci_loc_conf_t *lcf, ngx_http_brix_oci_ctx_t *ctx,
    brix_oci_store_t *st);

/* ---- oci_registry.c ------------------------------------------------------ */

/* The registry surface's whole request path: gate → authorize → dispatch.
 * Called from ngx_http_brix_oci_handler when the location is a registry. */
ngx_int_t brix_oci_registry_handle(ngx_http_request_t *r,
    ngx_http_brix_oci_loc_conf_t *lcf, ngx_http_brix_oci_ctx_t *ctx);

/* DELETE on manifests/<digest> and blobs/<digest> (§D4.4). */
ngx_int_t brix_oci_registry_delete(ngx_http_request_t *r,
    ngx_http_brix_oci_ctx_t *ctx, brix_oci_store_t *st);

#endif /* BRIX_PROTOCOLS_OCI_REGISTRY_H */
