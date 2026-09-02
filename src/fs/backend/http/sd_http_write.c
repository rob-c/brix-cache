/*
 * sd_http_write.c — write path for the HTTP-origin storage driver (SP3): the
 * HTTP/WebDAV origin as a writable cache_store / stage_store.
 *
 * WHAT: The staged-upload vtable slots — staged_open/staged_open_cred (buffer a
 *       whole object, capturing the per-user credential for the commit),
 *       staged_write (sequential append into the growable buffer), staged_commit
 *       (one PUT of the whole object — atomic from the reader's view), and
 *       staged_abort.
 *
 * WHY:  Split out of sd_http.c (phase-79 file-size split): the write path is one
 *       concept, distinct from the read/credential path (sd_http_read.c),
 *       selection/failover (sd_http_select.c), the driver vtable/lifecycle
 *       (sd_http.c), and the namespace mutations DELETE/MKCOL/MOVE
 *       (sd_http_mutate.c). Writes never fail over — a write to a non-primary
 *       origin would split-brain the store — so they always target endpoint 0
 *       via sd_http_write_path (sd_http_select.c) rather than sd_http_request_fo.
 *
 * HOW:  The per-user identity (bearer header / x509 client-cert path) is captured
 *       at staged_open and applied at commit — mirroring the read leg exactly,
 *       because an HTTP origin has no kernel fd / session to re-scope per user.
 *       cred_gate (sd_http_read.c) refuses a proxy-only cred the transport cannot
 *       present in deny mode, just like the read leg.
 */

#include "sd_http_internal.h"    /* endpoint + inst_state layout */

#include <errno.h>
#include <stdatomic.h>
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

/* Memory-safety cap on the whole-object staged buffer (phase-107 C1, W2): this
 * transport PUTs from memory, so the buffer holds the ENTIRE object — before this
 * cap a large upload grew worker heap without bound. Past it the append refuses
 * ENOSPC (capacity error -> kXR_NoSpace / 507), never a truncated object. Reorder
 * absorption does NOT live here — that is the VFS spill (vfs_writer_spill.c),
 * which drains sequentially and is disk-backed; this bounds what one commit PUT
 * may hold in heap. A streaming/multipart PUT lifting the limit is a transport
 * follow-up. */
#define SD_HTTP_STAGED_MAX  (1u << 30)   /* 1 GiB */

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
    mode_t mode, off_t declared_size, const brix_sd_cred_t *cred, int *err_out)
{
    sd_http_inst_state   *is = inst->state;
    sd_http_staged_state *ss;
    brix_sd_staged_t   *h;

    (void) mode;

    /* Phase-107 C5: this driver stages the WHOLE object in one heap buffer, so
     * a declared final size past the buffer cap can only end in ENOSPC after
     * the client streams a gigabyte — refuse it at open instead. */
    if (declared_size > (off_t) SD_HTTP_STAGED_MAX) {
        if (err_out) { *err_out = ENOSPC; }
        errno = ENOSPC;
        return NULL;
    }

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
    mode_t mode, off_t declared_size, int *err_out)
{
    return sd_http_staged_open_common(inst, final_path, mode, declared_size,
                                      NULL, err_out);
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
    mode_t mode, off_t declared_size, const brix_sd_cred_t *cred, int *err_out)
{
    return sd_http_staged_open_common(inst, final_path, mode, declared_size,
                                      cred, err_out);
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
    if (ss->len + len > SD_HTTP_STAGED_MAX) {
        errno = ENOSPC;      /* whole-object buffer cap — see SD_HTTP_STAGED_MAX */
        return -1;
    }
    if (ss->len + len > ss->cap) {
        size_t  ncap = ss->cap ? ss->cap * 2 : (1u << 20);
        u_char *nbuf;

        while (ncap < ss->len + len) {
            ncap *= 2;
        }
        if (ncap > SD_HTTP_STAGED_MAX) {
            ncap = SD_HTTP_STAGED_MAX;   /* never allocate past the cap */
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

/* One origin request presenting the staged handle's identity — the commit's
 * dispatch (per-open mutual-TLS cert via request_cred when captured, else the
 * plain transport slot), shared with the conditional-PUT probe below so the
 * probe authenticates exactly as the commit it gates. Writes never fail over
 * (endpoint 0 only — see the file banner). */
static int
sd_http_staged_request(sd_http_inst_state *is, sd_http_staged_state *ss,
    const char *method, const char *path, const char *hdrs, const void *body,
    size_t blen, brix_s3_resp_t *resp, char *errbuf, size_t errcap)
{
    if (ss->cert_pem[0] != '\0' && is->transport->request_cred != NULL) {
        return is->transport->request_cred(is->tctx, is->eps[0].host,
                               is->eps[0].port, is->eps[0].tls, method,
                               path, hdrs, body, blen, is->timeout_ms,
                               ss->cert_pem, resp, errbuf, errcap);
    }
    return is->transport->request(is->tctx, is->eps[0].host, is->eps[0].port,
                               is->eps[0].tls, method, path, hdrs, body, blen,
                               is->timeout_ms, resp, errbuf, errcap);
}

/* Does the write origin HONOUR RFC 7232 conditional PUT (phase-107 C6)?
 * Lazily probed once per instance and latched in is->cond_probe: PUT an empty
 * body to a driver-private probe key with an If-Match etag that can never
 * hold. 412 ⇒ the origin evaluates preconditions (1). 2xx ⇒ it IGNORED the
 * header — it published the probe object unconditionally (deleted again
 * best-effort) — so a real precondition would be a silent lie there (-1).
 * Any other outcome (auth refusal, transport error) is NOT latched: the
 * verdict stays unknown and this commit refuses without condemning the
 * origin. Returns the verdict for this call: 1 / -1 / 0 (unknown). */
static int
sd_http_cond_probe(sd_http_inst_state *is, sd_http_staged_state *ss,
    const char *auth_hdr)
{
    char             probe_path[SD_HTTP_PATH_MAX];
    char             hdrs[SD_HTTP_AUTH_MAX + 64];
    brix_s3_resp_t resp;
    char             errbuf[256];
    int              verdict = atomic_load(&is->cond_probe);

    if (verdict != 0) {
        return verdict;
    }
    sd_http_write_path(is, "/.brix-cond-probe", probe_path,
                       sizeof(probe_path));
    snprintf(hdrs, sizeof(hdrs), "If-Match: \"brix-cond-probe-never\"\r\n%s",
             auth_hdr ? auth_hdr : "");
    if (sd_http_staged_request(is, ss, "PUT", probe_path, hdrs, "", 0,
                               &resp, errbuf, sizeof(errbuf)) != 0)
    {
        return 0;                              /* transport: unknown, unlatched */
    }
    if (resp.status == 412) {
        verdict = 1;
    } else if (resp.status >= 200 && resp.status < 300) {
        verdict = -1;                          /* ignored — and it published */
    }
    is->transport->resp_free(&resp);
    if (verdict == -1) {
        /* best-effort cleanup of the probe object the origin let through */
        if (sd_http_staged_request(is, ss, "DELETE", probe_path, auth_hdr,
                                   NULL, 0, &resp, errbuf,
                                   sizeof(errbuf)) == 0)
        {
            is->transport->resp_free(&resp);
        }
    }
    if (verdict != 0) {
        atomic_store(&is->cond_probe, verdict);
    }
    return verdict;
}

/* Build the RFC 7232 conditional line for the commit PUT (phase-107 C6). The
 * typed precondition is carried on the one commit PUT so the ORIGIN decides
 * atomically — but only after the lazy probe has seen this origin answer 412.
 * An origin that ignores the header would publish unconditionally, so anything
 * short of a positive probe refuses ENOTSUP (§3.5 — a refusal over an
 * emulation that lies). MATCH_META is np: HTTP has no size/mtime conditional.
 * Leaves cond_line empty for an unconditional commit. */
static ngx_int_t
sd_http_cond_line(sd_http_inst_state *is, sd_http_staged_state *ss,
    const brix_sd_precond_t *pre, const char *auth_hdr,
    char *cond_line, size_t cap)
{
    cond_line[0] = '\0';
    if (pre == NULL || pre->kind == BRIX_SD_PRECOND_NONE) {
        return NGX_OK;
    }
    if (pre->kind == BRIX_SD_PRECOND_ABSENT) {
        snprintf(cond_line, cap, "If-None-Match: *\r\n");
    } else if (pre->kind == BRIX_SD_PRECOND_MATCH_ETAG
               && pre->etag != NULL && pre->etag_len > 0
               && pre->etag_len < cap - 16)
    {
        snprintf(cond_line, cap, "If-Match: %.*s\r\n",
                 (int) pre->etag_len, pre->etag);
    } else {
        errno = (pre->kind == BRIX_SD_PRECOND_MATCH_ETAG) ? EINVAL : ENOTSUP;
        return NGX_ERROR;
    }
    if (sd_http_cond_probe(is, ss, auth_hdr) != 1) {
        errno = ENOTSUP;
        return NGX_ERROR;
    }
    return NGX_OK;
}

/* Map the commit PUT's terminal status to the staged-commit contract. A 412 on
 * a conditional commit is the origin refusing the precondition — ECANCELED is
 * the typed verdict, an ABSENT refusal the contract's EEXIST — and the refusal
 * was decided AT the origin, so it is atomic (C6 advisory metric). */
static ngx_int_t
sd_http_commit_status(long status, int conditional, brix_sd_precond_t *pre)
{
    if (status == 412 && conditional) {
        errno = brix_sd_precond_absent(pre) ? EEXIST : ECANCELED;
        pre->atomic = 1;
        return NGX_ERROR;
    }
    if (status != 200 && status != 201 && status != 204) {
        errno = (status == 403 || status == 401) ? EACCES : EIO;
        return NGX_ERROR;
    }
    return NGX_OK;
}

ngx_int_t
sd_http_staged_commit(brix_sd_staged_t *h, brix_sd_precond_t *pre)
{
    sd_http_staged_state *ss = h->state;
    sd_http_inst_state   *is = h->inst->state;
    brix_s3_resp_t      resp;
    char                  errbuf[256];
    const char           *auth_hdr;
    const char           *hdrs;
    char                  hdr_block[SD_HTTP_AUTH_MAX + 256];
    char                  cond_line[160];
    int                   rq;
    ngx_int_t             rc = NGX_OK;

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

    /* Typed publish precondition (phase-107 C6): the RFC 7232 line for the
     * commit PUT, probe-gated — see sd_http_cond_line. */
    if (sd_http_cond_line(is, ss, pre, auth_hdr, cond_line,
                          sizeof(cond_line)) != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* #12 outbound integrity: when put_checksum is on, prepend a Content-MD5 line
     * (base64 MD5 of the whole staged object) to the header block so the origin
     * re-computes it over the received body and rejects a wire-corrupted PUT with
     * 400/412 rather than silently committing poison. The transport splits this
     * CRLF block into request headers (s3o_build_slist). Off ⇒ the auth header
     * passes through unchanged (byte-frozen prior behaviour). The C6 conditional
     * line joins the same block. */
    hdrs = auth_hdr;
    {
        char md5b64[25];

        md5b64[0] = '\0';
        if (is->put_checksum) {
            sd_http_content_md5(ss->buf, ss->len, md5b64);
        }
        if (md5b64[0] != '\0' || cond_line[0] != '\0') {
            snprintf(hdr_block, sizeof(hdr_block), "%s%s%s%s%s",
                     cond_line,
                     md5b64[0] ? "Content-MD5: " : "", md5b64,
                     md5b64[0] ? "\r\n" : "",
                     auth_hdr ? auth_hdr : "");
            hdrs = hdr_block;
        }
    }

    rq = sd_http_staged_request(is, ss, "PUT", ss->path, hdrs, ss->buf,
                                ss->len, &resp, errbuf, sizeof(errbuf));
    /* Ownership contract (brix_vfs_staged_commit / sd_remote_staged_commit):
     * free the handle ONLY on success. On failure it stays valid for the
     * caller's staged_abort — freeing here would double-free. */
    if (rq != 0) {
        errno = EIO;
        return NGX_ERROR;
    }
    rc = sd_http_commit_status(resp.status, cond_line[0] != '\0', pre);
    is->transport->resp_free(&resp);
    if (rc != NGX_OK) {
        return rc;
    }
    if (cond_line[0] != '\0') {
        pre->atomic = 1;                       /* the probed origin decided */
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
