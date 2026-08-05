/*
 * sd_http_mutate.c — namespace mutations for the HTTP-origin storage driver:
 * DELETE / MKCOL / MOVE against the WebDAV origin.
 *
 * WHAT: The namespace-facing vtable slots — unlink/unlink_cred (DELETE behind
 *       the POSIX delete gate), mkdir/mkdir_cred (MKCOL), rename/rename_cred
 *       (MOVE with Overwrite semantics) — plus the shared request path
 *       (sd_http_ns_send), the WebDAV-status→errno map, and the delete gate
 *       (type + emptiness probes) that keeps a recursive WebDAV DELETE from
 *       ever being issued where POSIX would refuse ENOTEMPTY.
 *
 * WHY:  Split out of sd_http_write.c (600-line ratchet): the staged-upload
 *       path (buffer + one PUT) and the namespace mutations are two concepts;
 *       this file owns the latter. Writes never fail over — a mutation on a
 *       non-primary origin would split-brain the store — so every request here
 *       targets endpoint 0 via sd_http_write_path, exactly like the commit PUT.
 *
 * HOW:  A `cred` presents the requesting user's bearer (Authorization header)
 *       or x509 proxy (mutual-TLS client cert) to the origin; cred==NULL falls
 *       back to the instance static header / anonymous. The same cred_gate the
 *       read/write legs use refuses a proxy-only cred the transport cannot
 *       present in deny mode.
 */

#include "sd_http_internal.h"    /* endpoint + inst_state layout */

#include <errno.h>
#include <stdio.h>

/* sd_http_ns_send — issue a body-less namespace request (DELETE/MKCOL/MOVE) on
 * endpoint 0. When `cert_pem` is set AND the transport can present a client cert
 * (request_cred), the request goes over a mutual-TLS leg carrying the per-user
 * x509 proxy; otherwise the plain request (whose `hdrs` already carries any
 * Authorization/Destination lines). Shared by the plain and credential-scoped
 * namespace slots so the transport selection lives in exactly one place, mirroring
 * sd_http_staged_commit's PUT selection. Returns the transport rc (0 = wire OK). */
static int
sd_http_ns_send(sd_http_inst_state *is, const char *method, const char *path,
    const char *hdrs, const char *cert_pem, brix_s3_resp_t *resp,
    char *errbuf, size_t errcap)
{
    if (cert_pem != NULL && cert_pem[0] != '\0'
        && is->transport->request_cred != NULL)
    {
        return is->transport->request_cred(is->tctx, is->eps[0].host,
                   is->eps[0].port, is->eps[0].tls, method, path, hdrs,
                   NULL, 0, is->timeout_ms, cert_pem, resp, errbuf, errcap);
    }
    return is->transport->request(is->tctx, is->eps[0].host, is->eps[0].port,
               is->eps[0].tls, method, path, hdrs, NULL, 0, is->timeout_ms,
               resp, errbuf, errcap);
}

/* sd_http_status_to_errno — map a WebDAV mutation status to a POSIX errno for the
 * delete/mkdir/rename slots. 401/403 → EACCES, 404/409 → ENOENT (target or its parent
 * absent), 405 → EEXIST (method not allowed on an existing collection), 412 →
 * EEXIST (Overwrite:F precondition — dst already present), anything else → EIO.
 * The caller decides which codes count as success before calling this. */
static int
sd_http_status_to_errno(long status)
{
    switch (status) {
    case 401:
    case 403: return EACCES;
    case 404:
    case 409: return ENOENT;
    case 405:
    case 412: return EEXIST;
    default:  return EIO;
    }
}

/* sd_http_coll_empty — 1 iff the collection at `path` has no children, 0 if it
 * has at least one, -1 (errno set) if the question could not be answered.
 *
 * A WebDAV DELETE of a collection is RECURSIVE (RFC 4918 §9.6), while the VFS
 * only ever calls this slot non-recursively (a recursive delete is walked by
 * brix_vfs_driver_rmtree). Without an emptiness gate the two disagree in the
 * most expensive possible direction: `xrdfs rmdir` of a populated collection —
 * an operation POSIX refuses with ENOTEMPTY — would erase the entire subtree on
 * any origin that implements DELETE to spec. Asking first makes the answer the
 * origin's dialect-independent one. */
static int
sd_http_coll_empty(brix_sd_instance_t *inst, const char *path)
{
    brix_sd_dir_t     *d;
    brix_sd_dirent_t   ent;
    int                err = EIO, rc;

    d = sd_http_opendir(inst, path, &err);
    if (d == NULL) {
        errno = err ? err : EIO;
        return -1;
    }
    rc = sd_http_readdir(d, &ent);
    sd_http_closedir(d);
    return (rc == NGX_DONE) ? 1 : 0;
}

/* sd_http_delete_gate — decide whether `path` may be deleted by this slot, given
 * the caller's `is_dir` (VFS require_empty_dir) request. 0 = proceed, -1 with
 * errno set = refuse without issuing anything.
 *
 * The rules are the POSIX ones the default backend applies, expressed over
 * WebDAV's single DELETE method:
 *   absent                 → ENOENT (a delete that removed nothing is not success)
 *   rmdir of a non-dir     → ENOTDIR
 *   any non-empty coll     → ENOTEMPTY (rm and rmdir alike; see sd_http_coll_empty)
 *   empty collection       → allowed for BOTH spellings, matching brix_ns_delete,
 *                            which removes an empty directory on a plain rm
 *   no WebDAV at the origin (PROPFIND 405/501) → a file delete proceeds (such an
 *                            origin has no collections); an rmdir is ENOTSUP
 *                            rather than a guess. */
static int
sd_http_delete_gate(brix_sd_instance_t *inst, sd_http_inst_state *is,
    const char *path, int is_dir, const char *auth_hdr, const char *cert_pem)
{
    int is_coll = 0, perr = 0, empty;

    if (sd_http_probe_type(is, path, auth_hdr, cert_pem,
                           &is_coll, &perr) != 0) {
        if (perr != ENOTSUP) { errno = perr; return -1; }
        if (is_dir)          { errno = ENOTSUP; return -1; }
        return 0;
    }
    if (is_dir && !is_coll) {
        errno = ENOTDIR;
        return -1;
    }
    if (!is_coll) {
        return 0;
    }
    empty = sd_http_coll_empty(inst, path);
    if (empty < 0) {
        return -1;                              /* errno set by the probe */
    }
    if (!empty) {
        errno = ENOTEMPTY;
        return -1;
    }
    return 0;
}

/* sd_http_unlink_common — shared DELETE path for the plain and credential-scoped
 * unlink slots. The type/emptiness rules live in sd_http_delete_gate; nothing
 * reaches the origin until they pass, so a mis-typed or over-broad delete can
 * never be issued at all. Three behaviours this replaced were each a way of
 * destroying or mis-reporting data: `is_dir` was discarded (an rmdir of a
 * regular FILE deleted it), a 404 was reported as success (a delete of a
 * missing object looked like a delete of a real one), and a non-empty
 * collection was handed to DELETE (a recursive wipe where POSIX refuses
 * ENOTEMPTY — this origin answers 409, which the shared status map read as
 * ENOENT and the root layer then treated as idempotent rmdir SUCCESS).
 *
 * A `cred` presents the requesting user's bearer (Authorization header) or x509
 * proxy (mutual-TLS client cert) to the origin — the gate probes and the DELETE
 * is issued under the same identity; cred==NULL falls back to the instance
 * static header / anonymous, exactly as before. The same cred_gate the
 * read/write legs use refuses a proxy-only cred the transport cannot present in
 * deny mode. */
static ngx_int_t
sd_http_unlink_common(brix_sd_instance_t *inst, const char *path, int is_dir,
    const brix_sd_cred_t *cred)
{
    sd_http_inst_state *is = inst->state;
    brix_s3_resp_t    resp;
    char                errbuf[256], full[SD_HTTP_PATH_MAX];
    char                open_auth[SD_HTTP_AUTH_MAX];
    const char         *open_cert, *auth_hdr;

    if (sd_http_cred_gate(is, cred) != 0) {
        return NGX_ERROR;                       /* errno = EACCES (set by gate) */
    }
    open_cert = sd_http_resolve_open_cred(is, cred, open_auth, sizeof(open_auth));
    auth_hdr  = open_auth[0] ? open_auth
                             : (is->auth_hdr[0] ? is->auth_hdr : NULL);

    if (sd_http_delete_gate(inst, is, path, is_dir, auth_hdr, open_cert) != 0) {
        return NGX_ERROR;                       /* errno set by the gate */
    }

    sd_http_write_path(is, path, full, sizeof(full));

    if (sd_http_ns_send(is, "DELETE", full, auth_hdr, open_cert, &resp,
                        errbuf, sizeof(errbuf)) != 0)
    {
        errno = EIO;
        return NGX_ERROR;
    }
    if (resp.status != 204 && resp.status != 200) {
        int status = (int) resp.status;

        is->transport->resp_free(&resp);
        /* 404 here means the entry the gate saw was removed underneath us — a
         * concurrent delete, which is still "it is not there and I did not
         * remove it": ENOENT, same as unlink(2) losing that race. 409 on a
         * DELETE is the collection-not-empty conflict (the gate's race window:
         * a child appeared after the emptiness probe), NOT the missing-parent
         * ENOENT the shared status map assumes for MKCOL/MOVE. */
        errno = (status == 404) ? ENOENT
              : (status == 409) ? ENOTEMPTY
              : sd_http_status_to_errno(status);
        return NGX_ERROR;
    }
    is->transport->resp_free(&resp);
    return NGX_OK;
}

ngx_int_t
sd_http_unlink(brix_sd_instance_t *inst, const char *path, int is_dir)
{
    return sd_http_unlink_common(inst, path, is_dir, NULL);
}

/* sd_http_unlink_cred — vtable unlink_cred slot: per-user credential-scoped DELETE. */
ngx_int_t
sd_http_unlink_cred(brix_sd_instance_t *inst, const char *path, int is_dir,
    const brix_sd_cred_t *cred)
{
    return sd_http_unlink_common(inst, path, is_dir, cred);
}

/* sd_http_mkdir — create a collection at `path` via WebDAV MKCOL (RFC 4918 §9.3).
 * `mode` is ignored: a WebDAV collection has no POSIX mode, and the VFS treats a
 * best-effort chmod as a no-op success (sd.h setattr contract). Writes never fail
 * over (a mutation on a non-primary origin would split-brain the store), so this
 * targets endpoint 0 exactly like unlink/commit. 201 Created is success; 405 means
 * the collection already exists (→ EEXIST); 409 means the parent is missing. */
/* sd_http_mkdir_common — shared MKCOL path for the plain and credential-scoped
 * mkdir slots (see sd_http_mkdir for the WebDAV semantics). A `cred` presents the
 * requesting user's bearer / x509 proxy to the origin; cred==NULL falls back to the
 * instance static header, exactly as before. */
static ngx_int_t
sd_http_mkdir_common(brix_sd_instance_t *inst, const char *path, mode_t mode,
    const brix_sd_cred_t *cred)
{
    sd_http_inst_state *is = inst->state;
    brix_s3_resp_t      resp;
    char                errbuf[256], full[SD_HTTP_PATH_MAX];
    char                open_auth[SD_HTTP_AUTH_MAX];
    const char         *open_cert, *auth_hdr;

    (void) mode;
    if (sd_http_cred_gate(is, cred) != 0) {
        return NGX_ERROR;                       /* errno = EACCES (set by gate) */
    }
    open_cert = sd_http_resolve_open_cred(is, cred, open_auth, sizeof(open_auth));
    auth_hdr  = open_auth[0] ? open_auth
                             : (is->auth_hdr[0] ? is->auth_hdr : NULL);

    sd_http_write_path(is, path, full, sizeof(full));
    if (sd_http_ns_send(is, "MKCOL", full, auth_hdr, open_cert, &resp,
                        errbuf, sizeof(errbuf)) != 0)
    {
        errno = EIO;
        return NGX_ERROR;
    }
    if (resp.status != 201 && resp.status != 200) {
        errno = sd_http_status_to_errno(resp.status);
        is->transport->resp_free(&resp);
        return NGX_ERROR;
    }
    is->transport->resp_free(&resp);
    return NGX_OK;
}

ngx_int_t
sd_http_mkdir(brix_sd_instance_t *inst, const char *path, mode_t mode)
{
    return sd_http_mkdir_common(inst, path, mode, NULL);
}

/* sd_http_mkdir_cred — vtable mkdir_cred slot: per-user credential-scoped MKCOL. */
ngx_int_t
sd_http_mkdir_cred(brix_sd_instance_t *inst, const char *path, mode_t mode,
    const brix_sd_cred_t *cred)
{
    return sd_http_mkdir_common(inst, path, mode, cred);
}

/* sd_http_rename — rename/move `src` to `dst` via WebDAV MOVE (RFC 4918 §9.9).
 * The Destination header must be a full absolute URI on this origin, so it is
 * composed from endpoint 0's scheme/host/port and the write-path of `dst`.
 * `noreplace` sends Overwrite: F so an existing destination fails 412 (→ EEXIST)
 * rather than being clobbered; otherwise Overwrite: T replaces it. 201 (created)
 * and 204 (replaced) are success. Any per-instance auth header is preserved
 * alongside the MOVE-specific headers. Endpoint 0 only (writes never fail over). */
/* sd_http_rename_common — shared MOVE path for the plain and credential-scoped
 * rename slots (see sd_http_rename for the WebDAV semantics). A `cred` presents the
 * requesting user's bearer (folded into the MOVE header block, so the origin
 * authorizes BOTH the source and the Destination leg as the user) or x509 proxy
 * (mutual-TLS client cert); cred==NULL falls back to the instance static header.
 * The header block is sized for a full Destination URI PLUS a forwarded bearer
 * (SD_HTTP_AUTH_MAX) so a large JWT never truncates to a spurious ENAMETOOLONG. */
static ngx_int_t
sd_http_rename_common(brix_sd_instance_t *inst, const char *src, const char *dst,
    int noreplace, const brix_sd_cred_t *cred)
{
    sd_http_inst_state *is = inst->state;
    brix_s3_resp_t      resp;
    char                errbuf[256], srcfull[SD_HTTP_PATH_MAX];
    char                dstfull[SD_HTTP_PATH_MAX];
    char                hdrs[SD_HTTP_PATH_MAX + SD_HTTP_AUTH_MAX + 128];
    char                open_auth[SD_HTTP_AUTH_MAX];
    const char         *open_cert, *eff_auth;
    int                 n;

    if (sd_http_cred_gate(is, cred) != 0) {
        return NGX_ERROR;                       /* errno = EACCES (set by gate) */
    }
    open_cert = sd_http_resolve_open_cred(is, cred, open_auth, sizeof(open_auth));
    /* The per-user bearer header (open_auth) wins over the instance static; "" =
     * anonymous/static. Folded into the MOVE header block below. */
    eff_auth  = open_auth[0] ? open_auth
                             : (is->auth_hdr[0] ? is->auth_hdr : "");

    sd_http_write_path(is, src, srcfull, sizeof(srcfull));
    sd_http_write_path(is, dst, dstfull, sizeof(dstfull));

    /* Destination is an absolute URI on this origin; append Overwrite and the
     * resolved auth header. A default HTTP/HTTPS port is emitted explicitly — it is
     * always valid in an authority and keeps the composition branch-free. */
    n = snprintf(hdrs, sizeof(hdrs),
                 "Destination: %s://%s:%d%s\r\nOverwrite: %c\r\n%s",
                 is->eps[0].tls ? "https" : "http",
                 is->eps[0].host, is->eps[0].port, dstfull,
                 noreplace ? 'F' : 'T', eff_auth);
    if (n <= 0 || (size_t) n >= sizeof(hdrs)) {
        errno = ENAMETOOLONG;
        return NGX_ERROR;
    }

    if (sd_http_ns_send(is, "MOVE", srcfull, hdrs, open_cert, &resp,
                        errbuf, sizeof(errbuf)) != 0)
    {
        errno = EIO;
        return NGX_ERROR;
    }
    if (resp.status != 201 && resp.status != 204) {
        errno = sd_http_status_to_errno(resp.status);
        is->transport->resp_free(&resp);
        return NGX_ERROR;
    }
    is->transport->resp_free(&resp);
    return NGX_OK;
}

ngx_int_t
sd_http_rename(brix_sd_instance_t *inst, const char *src, const char *dst,
    int noreplace)
{
    return sd_http_rename_common(inst, src, dst, noreplace, NULL);
}

/* sd_http_rename_cred — vtable rename_cred slot: per-user credential-scoped MOVE. */
ngx_int_t
sd_http_rename_cred(brix_sd_instance_t *inst, const char *src, const char *dst,
    int noreplace, const brix_sd_cred_t *cred)
{
    return sd_http_rename_common(inst, src, dst, noreplace, cred);
}
