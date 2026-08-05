/*
 * sd_http_write.c — write path for the HTTP-origin storage driver (SP3): the
 * HTTP/WebDAV origin as a writable cache_store / stage_store.
 *
 * WHAT: The write-facing vtable slots — staged_open/staged_open_cred (buffer a
 *       whole object, capturing the per-user credential for the commit),
 *       staged_write (sequential append into the growable buffer), staged_commit
 *       (one PUT of the whole object — atomic from the reader's view),
 *       staged_abort, and unlink (a DELETE: eviction + post-flush stage cleanup).
 *
 * WHY:  Split out of sd_http.c (phase-79 file-size split): the write path is one
 *       concept, distinct from the read/credential path (sd_http_read.c),
 *       selection/failover (sd_http_select.c), and the driver vtable/lifecycle
 *       (sd_http.c). Writes never fail over — a write to a non-primary origin
 *       would split-brain the store — so they always target endpoint 0 via
 *       sd_http_write_path (sd_http_select.c) rather than sd_http_request_fo.
 *
 * HOW:  The per-user identity (bearer header / x509 client-cert path) is captured
 *       at staged_open and applied at commit — mirroring the read leg exactly,
 *       because an HTTP origin has no kernel fd / session to re-scope per user.
 *       cred_gate (sd_http_read.c) refuses a proxy-only cred the transport cannot
 *       present in deny mode, just like the read leg.
 */

#include "sd_http_internal.h"    /* endpoint + inst_state layout */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>         /* #12: MD5 + base64 for the Content-MD5 PUT header */

/* #12 outbound integrity: base64(MD5(buf,len)) → out[25] ("" on failure). The
 * classic RFC 1864 Content-MD5 the origin re-computes over the received body and
 * rejects on mismatch (400/412) — the outbound analogue of the ingest
 * s3_content_md5_verify gate. ngx-free (this backend layer builds into
 * libxrdproto): OpenSSL EVP only, no ngx_* / ngx pool. */
static void
sd_http_content_md5(const void *buf, size_t len, char out[25])
{
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int  mdlen = 0;

    out[0] = '\0';
    if (EVP_Digest(buf, len, md, &mdlen, EVP_md5(), NULL) != 1 || mdlen != 16) {
        return;
    }
    EVP_EncodeBlock((unsigned char *) out, md, 16);   /* 16 → 24 chars + NUL */
}

/* Per-staged-write state: HTTP has no streaming PUT through this transport, so the
 * object is buffered and PUT whole at commit (a remote stage/cache store of typical
 * file sizes; very large objects are a multipart follow-up).
 *
 * auth_hdr / cert_pem carry the per-open (per-user) credential captured at
 * staged_open_cred so the commit PUT authenticates to the origin AS the requesting
 * user rather than the static service credential (phase-70 §5.1, write leg). Both
 * are COPIES — the cred fields are borrowed only for the staged_open() call. "" in
 * either falls back to the instance static (is->auth_hdr) / no client cert. Exactly
 * one kind is ever set (the VFS gate populates one of bearer / x509_proxy). */
typedef struct {
    char     path[SD_HTTP_PATH_MAX];
    u_char  *buf;
    size_t   len;
    size_t   cap;
    char     auth_hdr[SD_HTTP_AUTH_MAX];
    char     cert_pem[SD_HTTP_PATH_MAX];
} sd_http_staged_state;

/* sd_http_staged_open_common — shared staged-open path for the plain and
 * credential-scoped staged-open slots.
 *
 * WHAT: Allocates the staged buffer state, composes the write-target URL path
 *       and, when a `cred` is present, captures the per-user credential (bearer →
 *       Authorization header; x509 proxy → mutual-TLS client-cert PATH) into the
 *       staged state so the commit PUT presents THAT identity, not the static
 *       service credential.
 * WHY:  Phase-70 §5.1 write leg — an HTTP/WebDAV origin authenticates a PUT purely
 *       on the request credential, and this driver has no kernel fd / session to
 *       re-scope per user, so the per-user identity travels as staged state copied
 *       at open time (mirroring the read-leg sd_http_open_common exactly).
 * HOW:  cred==NULL (plain .staged_open) leaves auth_hdr AND cert_pem empty, so the
 *       commit falls back to the instance static header and no client cert. The
 *       same cred_gate the read path uses refuses a proxy-only cred in deny mode
 *       when the transport cannot mutual-TLS (request_cred==NULL) → EACCES. A
 *       bearer is snprintf'd into the staged auth_hdr; an x509 proxy path is copied
 *       into cert_pem only when the transport can present it (request_cred!=NULL).
 *       Both are COPIES — cred fields are borrowed only for this call. */
static brix_sd_staged_t *
sd_http_staged_open_common(brix_sd_instance_t *inst, const char *final_path,
    mode_t mode, const brix_sd_cred_t *cred, int *err_out)
{
    sd_http_inst_state   *is = inst->state;
    sd_http_staged_state *ss;
    brix_sd_staged_t   *h;

    (void) mode;

    /* Same credential gate the read leg applies: a proxy-only cred that cannot be
     * presented as a client cert must be refused in deny mode rather than served
     * on the anonymous/service credential. */
    if (sd_http_cred_gate(is, cred) != 0) {
        if (err_out) { *err_out = errno; }
        return NULL;
    }

    ss = calloc(1, sizeof(*ss));
    h  = calloc(1, sizeof(*h));
    if (ss == NULL || h == NULL) {
        free(ss);
        free(h);
        if (err_out) { *err_out = ENOMEM; }
        return NULL;
    }
    sd_http_write_path(is, final_path, ss->path, sizeof(ss->path));

    /* Capture the per-open credential for the commit PUT: bearer → header;
     * x509 proxy → cert path (only when the transport can present it). Empty
     * leaves the commit on the instance static / anonymous credential. */
    if (cred != NULL && cred->bearer != NULL && cred->bearer[0] != '\0') {
        snprintf(ss->auth_hdr, sizeof(ss->auth_hdr),
                 "Authorization: Bearer %s\r\n", cred->bearer);
    }
    if (cred != NULL && cred->x509_proxy != NULL && cred->x509_proxy[0] != '\0'
        && is->transport->request_cred != NULL)
    {
        snprintf(ss->cert_pem, sizeof(ss->cert_pem), "%s", cred->x509_proxy);
    }

    h->inst  = inst;
    h->state = ss;
    return h;
}

/* sd_http_staged_open — vtable staged_open slot: service credential / anonymous. */
brix_sd_staged_t *
sd_http_staged_open(brix_sd_instance_t *inst, const char *final_path,
    mode_t mode, int *err_out)
{
    return sd_http_staged_open_common(inst, final_path, mode, NULL, err_out);
}

/* sd_http_staged_open_cred — vtable staged_open_cred slot: per-user credential.
 *
 * WHAT: Credential-scoped staged open that binds the requesting user's bearer
 *       token or x509 proxy to the staged object so the commit PUT authenticates
 *       to the origin AS that user (phase-70 §5.1 write leg — the two-hop PUT over
 *       an https backend leg).
 * WHY:  Without this slot the write/commit leg always PUT with the static service
 *       credential, so per-user forwarding failed for two-hop PUT over an https
 *       backend leg (the "C HH/RH gsi/token" cells in run_fwd_brix_brix.sh).
 * HOW:  Delegates to sd_http_staged_open_common with the supplied cred. */
brix_sd_staged_t *
sd_http_staged_open_cred(brix_sd_instance_t *inst, const char *final_path,
    mode_t mode, const brix_sd_cred_t *cred, int *err_out)
{
    return sd_http_staged_open_common(inst, final_path, mode, cred, err_out);
}

ssize_t
sd_http_staged_write(brix_sd_staged_t *h, const void *buf, size_t len,
    off_t off)
{
    sd_http_staged_state *ss = h->state;

    /* Sequential append only (whole-object PUT has no random write). */
    if ((size_t) off != ss->len) {
        errno = ESPIPE;
        return -1;
    }
    if (ss->len + len > ss->cap) {
        size_t  ncap = ss->cap ? ss->cap * 2 : (1u << 20);
        u_char *nbuf;

        while (ncap < ss->len + len) {
            ncap *= 2;
        }
        nbuf = realloc(ss->buf, ncap);
        if (nbuf == NULL) {
            errno = ENOMEM;
            return -1;
        }
        ss->buf = nbuf;
        ss->cap = ncap;
    }
    ngx_memcpy(ss->buf + ss->len, buf, len);
    ss->len += len;
    return (ssize_t) len;
}

ngx_int_t
sd_http_staged_commit(brix_sd_staged_t *h, int noreplace)
{
    sd_http_staged_state *ss = h->state;
    sd_http_inst_state   *is = h->inst->state;
    brix_s3_resp_t      resp;
    char                  errbuf[256];
    const char           *auth_hdr;
    const char           *hdrs;
    char                  hdr_block[SD_HTTP_AUTH_MAX + 64];
    int                   rq;
    ngx_int_t             rc = NGX_OK;

    (void) noreplace;                          /* HTTP PUT always replaces */

    /* Per-user commit: a per-open bearer (staged_open_cred) wins over the
     * instance's static bearer_token; "" (plain staged_open, or no usable cred)
     * falls back. A per-open x509 proxy path (ss->cert_pem) is presented as the
     * mutual-TLS client cert on the PUT via the transport's request_cred slot —
     * exactly mirroring the read leg (sd_http_request_fo / sd_http_pread). The
     * cred gate at staged_open already refused a proxy-only cred that cannot be
     * presented in deny mode, so reaching here with a cert path guarantees a
     * request_cred-capable transport. */
    auth_hdr = ss->auth_hdr[0] ? ss->auth_hdr
                               : (is->auth_hdr[0] ? is->auth_hdr : NULL);

    /* #12 outbound integrity: when put_checksum is on, prepend a Content-MD5 line
     * (base64 MD5 of the whole staged object) to the header block so the origin
     * re-computes it over the received body and rejects a wire-corrupted PUT with
     * 400/412 rather than silently committing poison. The transport splits this
     * CRLF block into request headers (s3o_build_slist). Off ⇒ the auth header
     * passes through unchanged (byte-frozen prior behaviour). */
    hdrs = auth_hdr;
    if (is->put_checksum) {
        char md5b64[25];

        sd_http_content_md5(ss->buf, ss->len, md5b64);
        if (md5b64[0] != '\0') {
            snprintf(hdr_block, sizeof(hdr_block), "Content-MD5: %s\r\n%s",
                     md5b64, auth_hdr ? auth_hdr : "");
            hdrs = hdr_block;
        }
    }

    if (ss->cert_pem[0] != '\0' && is->transport->request_cred != NULL) {
        rq = is->transport->request_cred(is->tctx, is->eps[0].host,
                               is->eps[0].port, is->eps[0].tls, "PUT",
                               ss->path, hdrs, ss->buf, ss->len,
                               is->timeout_ms, ss->cert_pem, &resp,
                               errbuf, sizeof(errbuf));
    } else {
        rq = is->transport->request(is->tctx, is->eps[0].host, is->eps[0].port,
                               is->eps[0].tls, "PUT",
                               ss->path, hdrs,
                               ss->buf, ss->len, is->timeout_ms, &resp,
                               errbuf, sizeof(errbuf));
    }
    /* Ownership contract (brix_vfs_staged_commit / sd_remote_staged_commit):
     * free the handle ONLY on success. On failure it stays valid for the
     * caller's staged_abort — freeing here would double-free. */
    if (rq != 0) {
        errno = EIO;
        return NGX_ERROR;
    }
    if (resp.status != 200 && resp.status != 201 && resp.status != 204) {
        errno = (resp.status == 403 || resp.status == 401) ? EACCES : EIO;
        rc = NGX_ERROR;
    }
    is->transport->resp_free(&resp);
    if (rc != NGX_OK) {
        return rc;
    }
    free(ss->buf);
    free(ss);
    free(h);
    return NGX_OK;
}

void
sd_http_staged_abort(brix_sd_staged_t *h)
{
    sd_http_staged_state *ss = h->state;

    free(ss->buf);
    free(ss);
    free(h);
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
    const char *path, int is_dir)
{
    int is_coll = 0, perr = 0, empty;

    if (sd_http_probe_type(is, path, is->auth_hdr[0] ? is->auth_hdr : NULL,
                           NULL, &is_coll, &perr) != 0) {
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

/* sd_http_unlink — vtable unlink/rmdir slot. The type/emptiness rules live in
 * sd_http_delete_gate; nothing reaches the origin until they pass, so a
 * mis-typed or over-broad delete can never be issued at all. Three behaviours
 * this replaced were each a way of destroying or mis-reporting data: `is_dir`
 * was discarded (an rmdir of a regular FILE deleted it), a 404 was reported as
 * success (a delete of a missing object looked like a delete of a real one), and
 * a non-empty collection was handed to DELETE (a recursive wipe where POSIX
 * refuses ENOTEMPTY — this origin answers 409, which the shared status map read
 * as ENOENT and the root layer then treated as idempotent rmdir SUCCESS). */
ngx_int_t
sd_http_unlink(brix_sd_instance_t *inst, const char *path, int is_dir)
{
    sd_http_inst_state *is = inst->state;
    brix_s3_resp_t    resp;
    char                errbuf[256], full[SD_HTTP_PATH_MAX];

    if (sd_http_delete_gate(inst, is, path, is_dir) != 0) {
        return NGX_ERROR;                       /* errno set by the gate */
    }

    sd_http_write_path(is, path, full, sizeof(full));

    if (is->transport->request(is->tctx, is->eps[0].host, is->eps[0].port,
                               is->eps[0].tls, "DELETE",
                               full, is->auth_hdr[0] ? is->auth_hdr : NULL,
                               NULL, 0, is->timeout_ms, &resp,
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

/* sd_http_mkdir — create a collection at `path` via WebDAV MKCOL (RFC 4918 §9.3).
 * `mode` is ignored: a WebDAV collection has no POSIX mode, and the VFS treats a
 * best-effort chmod as a no-op success (sd.h setattr contract). Writes never fail
 * over (a mutation on a non-primary origin would split-brain the store), so this
 * targets endpoint 0 exactly like unlink/commit. 201 Created is success; 405 means
 * the collection already exists (→ EEXIST); 409 means the parent is missing. */
ngx_int_t
sd_http_mkdir(brix_sd_instance_t *inst, const char *path, mode_t mode)
{
    sd_http_inst_state *is = inst->state;
    brix_s3_resp_t      resp;
    char                errbuf[256], full[SD_HTTP_PATH_MAX];

    (void) mode;
    sd_http_write_path(is, path, full, sizeof(full));
    if (is->transport->request(is->tctx, is->eps[0].host, is->eps[0].port,
                               is->eps[0].tls, "MKCOL",
                               full, is->auth_hdr[0] ? is->auth_hdr : NULL,
                               NULL, 0, is->timeout_ms, &resp,
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

/* sd_http_rename — rename/move `src` to `dst` via WebDAV MOVE (RFC 4918 §9.9).
 * The Destination header must be a full absolute URI on this origin, so it is
 * composed from endpoint 0's scheme/host/port and the write-path of `dst`.
 * `noreplace` sends Overwrite: F so an existing destination fails 412 (→ EEXIST)
 * rather than being clobbered; otherwise Overwrite: T replaces it. 201 (created)
 * and 204 (replaced) are success. Any per-instance auth header is preserved
 * alongside the MOVE-specific headers. Endpoint 0 only (writes never fail over). */
ngx_int_t
sd_http_rename(brix_sd_instance_t *inst, const char *src, const char *dst,
    int noreplace)
{
    sd_http_inst_state *is = inst->state;
    brix_s3_resp_t      resp;
    char                errbuf[256], srcfull[SD_HTTP_PATH_MAX];
    char                dstfull[SD_HTTP_PATH_MAX];
    char                hdrs[SD_HTTP_PATH_MAX + 512];
    int                 n;

    sd_http_write_path(is, src, srcfull, sizeof(srcfull));
    sd_http_write_path(is, dst, dstfull, sizeof(dstfull));

    /* Destination is an absolute URI on this origin; append Overwrite and any
     * static auth header. A default HTTP/HTTPS port is emitted explicitly — it is
     * always valid in an authority and keeps the composition branch-free. */
    n = snprintf(hdrs, sizeof(hdrs),
                 "Destination: %s://%s:%d%s\r\nOverwrite: %c\r\n%s",
                 is->eps[0].tls ? "https" : "http",
                 is->eps[0].host, is->eps[0].port, dstfull,
                 noreplace ? 'F' : 'T',
                 is->auth_hdr[0] ? is->auth_hdr : "");
    if (n <= 0 || (size_t) n >= sizeof(hdrs)) {
        errno = ENAMETOOLONG;
        return NGX_ERROR;
    }

    if (is->transport->request(is->tctx, is->eps[0].host, is->eps[0].port,
                               is->eps[0].tls, "MOVE",
                               srcfull, hdrs, NULL, 0, is->timeout_ms, &resp,
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
