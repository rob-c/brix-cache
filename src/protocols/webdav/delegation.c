/*
 * delegation.c - authenticated proxy delegation endpoints: the simple
 * proxy-UPLOAD form (phase-2 T8) plus the shared cert-chain / storage
 * helpers used by every delegation entry point.
 *
 * This translation unit holds the Phase-2 T8 upload handler
 * (webdav_delegation_handle) and the cross-file helpers declared in
 * delegation_internal.h (chain parse/expiry/DN/trust checks, the atomic
 * credential store, and the reject choke point).  The Phase-3 T4 two-step
 * GridSite flow lives in delegation_gridsite_req.c (getProxyReq) and
 * delegation_gridsite_put.c (putProxy), and its per-worker pending-
 * delegation store in delegation_store.c — see those files for the
 * two-step WHAT/WHY/HOW.
 *
 * ============================ Phase-2 T8: upload ==========================
 * WHAT: PUT/POST /.well-known/brix-delegation, body = the client's own
 *       RFC-3820 x.509 proxy chain (PEM).  Requires GSI-cert-authenticated
 *       TLS (the request must already carry a verified client-certificate
 *       identity — see auth_cert.c), validates the uploaded proxy, and
 *       atomically stores it at <storage_credential_dir>/<key>.pem so
 *       Phase-1 credential selection (brix_sd_ucred_select) picks it up
 *       for that user's subsequent davs/S3 origin sessions.
 *
 * WHY: Phase-1 per-user backend credentials require a proxy to already
 *      exist under storage_credential_dir before a user's first origin
 *      request.  Operationally that means out-of-band provisioning.  This
 *      endpoint lets an already-authenticated client "capture" its own
 *      delegation over the wire (proxy-UPLOAD, not the full GridSite
 *      getProxyReq/putProxy two-step) so no pre-provisioning is required.
 *
 * HOW: 1. Gate on brix_delegation_endpoint + the well-known path.
 *      2. Require ctx->verified && ctx->auth_source == "cert"/"nginx"/
 *         "manual" (GSI/client-cert path — never a bearer token) and a
 *         non-empty ctx->dn.
 *      3. Read the whole body via brix_http_body_read_all (bounded, small).
 *      4. Parse the PEM chain (PEM_read_bio_X509 loop, mirrors the pattern
 *         in src/auth/gsi/parse_x509.c); find the end-entity cert (the one
 *         brix_px_classify() reports as BRIX_PX_NONE — proxies in the
 *         uploaded chain are excluded by construction).
 *      5. Check every cert in the chain (proxy and EEC) has a notAfter
 *         still in the future, and the EEC's subject DN (brix_x509_oneline,
 *         same normalisation as ctx->dn) equals the authenticated client's
 *         DN — a client may only upload a proxy for its own identity.
 *      6. Derive the credential key (brix_sd_ucred_key) and atomically
 *         write the whole uploaded PEM to <cred_dir>/<key>.pem: open a
 *         temp file in the same directory (O_CREAT|O_EXCL|O_WRONLY, 0600),
 *         write, fsync, close, then rename() over the final path.  This is
 *         a raw filesystem write to a service-owned config directory (not
 *         an export), so it is marked vfs-seam-allow rather than routed
 *         through the VFS, which confines to the export root only.
 */

#include "webdav.h"
#include "delegation.h"
#include "delegation_internal.h"
#include "fs/backend/ucred.h"
#include "auth/crypto/store_policy.h"
#include "auth/crypto/gsi_verify.h"
#include "core/compat/log_diag.h"
#include "core/http/http_body.h"

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* CSR responses (a single proxy-request cert, no chain) are small too. */
#define BRIX_DELEGATION_CSR_MAX  (16 * 1024)

/*
 * delegation_client_authenticated - true iff the request carries a verified
 * GSI/x.509 client-certificate identity (never a bearer token — those have
 * no certificate chain to delegate from).
 */
int
delegation_client_authenticated(const ngx_http_brix_webdav_req_ctx_t *ctx)
{
    return ctx != NULL
        && ctx->verified
        && !ctx->token_auth
        && ctx->dn[0] != '\0';
}

/*
 * delegation_find_eec - scan a parsed proxy chain for the end-entity
 * certificate (the one cert that is NOT itself a proxy per
 * brix_px_classify()).  Returns a borrowed reference (still owned by
 * `chain`) or NULL if every cert in the chain is a proxy (malformed
 * upload — no EEC present).
 */
X509 *
delegation_find_eec(STACK_OF(X509) *chain)
{
    int i, n;

    n = sk_X509_num(chain);
    for (i = 0; i < n; i++) {
        X509 *cert = sk_X509_value(chain, i);

        if (brix_px_classify(cert) == BRIX_PX_NONE) {
            return cert;
        }
    }
    return NULL;
}

/*
 * delegation_parse_chain - parse a PEM-concatenated cert chain from a
 * NUL-terminated buffer.  Mirrors the BIO+loop pattern in
 * src/auth/gsi/parse_x509.c (gsi_chain_from_plaintext).  Returns a
 * non-empty STACK_OF(X509) (caller must sk_X509_pop_free(chain, X509_free))
 * or NULL on any parse failure.
 */
STACK_OF(X509) *
delegation_parse_chain(const u_char *pem, size_t pem_len)
{
    BIO            *bio;
    STACK_OF(X509) *chain;
    X509           *cert;

    bio = BIO_new_mem_buf(pem, (int) pem_len);
    if (bio == NULL) {
        return NULL;
    }

    chain = sk_X509_new_null();
    if (chain == NULL) {
        BIO_free(bio);
        return NULL;
    }

    while ((cert = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != NULL) {
        sk_X509_push(chain, cert);
    }
    BIO_free(bio);

    if (sk_X509_num(chain) == 0) {
        sk_X509_pop_free(chain, X509_free);
        return NULL;
    }
    return chain;
}

/*
 * delegation_chain_expired - true iff ANY certificate in the uploaded chain
 * (proxy or EEC) has a notAfter that is not in the future.  A delegation is
 * only as strong as its weakest link: an expired proxy cert grants no
 * authority even if the EEC underneath it is still valid, so the whole
 * chain must check out.
 */
int
delegation_chain_expired(STACK_OF(X509) *chain)
{
    int i, n = sk_X509_num(chain);

    for (i = 0; i < n; i++) {
        if (X509_cmp_current_time(X509_get0_notAfter(sk_X509_value(chain, i)))
            <= 0)
        {
            return 1;
        }
    }
    return 0;
}

/*
 * delegation_eec_dn_matches - true iff `eec`'s subject DN
 * (brix_x509_oneline — the same normalisation ctx->dn uses) equals `want_dn`
 * exactly.  A client may only upload a proxy that delegates its own identity.
 */
int
delegation_eec_dn_matches(X509 *eec, const char *want_dn)
{
    char eec_dn[1024];

    brix_x509_oneline(X509_get_subject_name(eec), eec_dn, sizeof(eec_dn));
    return strcmp(eec_dn, want_dn) == 0;
}

/*
 * delegation_chain_trusted - cryptographically verify that a delegated proxy
 * chain actually chains to a CA in the frontend's trust store.
 *
 * WHAT: run the same PKIX + RFC-3820 proxy verification the WebDAV
 *       client-certificate auth path uses (brix_gsi_verify_chain against
 *       conf->ca_store), treating the topmost proxy (chain[0]) as the leaf
 *       and the whole parsed chain as the untrusted intermediate set.
 *
 * WHY: the DN-equality check (delegation_eec_dn_matches) alone compares the
 *      EEC's *self-asserted* subject string against the authenticated client
 *      DN — it proves nothing about issuance.  A credential-writing endpoint
 *      must not store a proxy it cannot anchor to a trusted CA, otherwise the
 *      authenticated owner could plant a self-signed cert whose subject string
 *      is spoofed to equal their own DN.  Running full chain verification
 *      first turns the subsequent DN string compare into an identity check on
 *      a cryptographically-anchored EEC rather than an attacker-controlled
 *      string.  Mirrors auth_cert.c: a NULL ca_store means we cannot verify,
 *      so we refuse (caller maps to 403) rather than trust blindly.
 *
 * HOW: NULL store -> NGX_ERROR (refuse, logged).  Otherwise leaf = chain[0]
 *      (assemble/upload order is proxy-first), untrusted = the full chain
 *      (OpenSSL tolerates the leaf appearing in the untrusted stack), and
 *      client_purpose = 0 so RFC-3820 proxy chains are accepted (the davs://
 *      GSI mode, not the TLS-leaf mode).  Returns NGX_OK iff the chain
 *      verifies to the trust store; brix_gsi_verify_chain has already logged
 *      the specific reason on failure.  Owns nothing.
 */
ngx_int_t
delegation_chain_trusted(ngx_http_request_t *r,
    const ngx_http_brix_webdav_loc_conf_t *conf, STACK_OF(X509) *chain)
{
    brix_gsi_verify_result_t verify_res;
    X509                    *leaf;

    if (conf->ca_store == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "brix_delegation: no trusted CA store configured — cannot verify"
            " delegated proxy; refusing to store an unverifiable credential"
            " (set brix_webdav_auth required with a CA on this location)");
        return NGX_ERROR;
    }

    leaf = sk_X509_value(chain, 0);
    if (leaf == NULL) {
        return NGX_ERROR;
    }

    if (brix_gsi_verify_chain(r->connection->log, conf->ca_store, leaf, chain,
            conf->verify_depth, &verify_res, 0 /* GSI: accept RFC-3820 proxy */)
        != NGX_OK)
    {
        /* brix_gsi_verify_chain already logged the specific error. */
        return NGX_ERROR;
    }

    return NGX_OK;
}

/*
 * delegation_store_pem - atomically write `pem`/`pem_len` to
 * <dir>/<key>.pem: temp file in the same directory (O_CREAT|O_EXCL|
 * O_WRONLY, 0600), write, fsync, close, rename() over the final path.
 * vfs-seam-allow: storage_credential_dir is service-owned server config,
 * not export storage — the VFS confines to the export root only, the
 * wrong root for this write.
 *
 * Returns NGX_OK on success, NGX_ERROR on any I/O failure (temp file is
 * best-effort unlinked on the way out; caller maps failure to 507).
 */
ngx_int_t
delegation_store_pem(ngx_log_t *log, const ngx_str_t *dir, const char *key,
    const u_char *pem, size_t pem_len)
{
    char    final_path[1024];
    char    tmp_path[1024];
    int     fd;
    ssize_t written;

    if (dir->len == 0
        || dir->len + 1 + strlen(key) + sizeof(".pem") >= sizeof(final_path)
        || dir->len + 1 + strlen(key) + sizeof(".pem.XXXXXX") >= sizeof(tmp_path))
    {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "brix_delegation: credential dir/key too long");
        return NGX_ERROR;
    }

    (void) ngx_snprintf((u_char *) final_path, sizeof(final_path) - 1,
        "%V/%s.pem%Z", dir, key);
    (void) snprintf(tmp_path, sizeof(tmp_path), "%.*s/.%s.pem.upload.%ld",
        (int) dir->len, dir->data, key, (long) getpid());

    fd = open(tmp_path, /* vfs-seam-allow: cred dir is svc-owned config, not an export */
              O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0 && ngx_errno == NGX_ENOENT) {
        /* Store dir vanished (tmpfs default is wiped by a reboot without a
         * config reload, or an admin rm'd it) — recreate it 0700 as the
         * worker uid and retry once before shouting. */
        if (mkdir((const char *) dir->data, 0700) == 0 /* vfs-seam-allow: cred dir is svc-owned config, not an export */
            || ngx_errno == NGX_EEXIST)
        {
            fd = open(tmp_path, /* vfs-seam-allow: cred dir is svc-owned config, not an export */
                      O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
        }
    }
    if (fd < 0) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                      "brix_delegation: open(\"%s\") temp cred file failed — "
                      "credential store \"%V\" is missing or not writable; "
                      "delegation will not work until "
                      "brix_storage_credential_dir is fixed",
                      tmp_path, dir);
        return NGX_ERROR;
    }

    written = write(fd, pem, pem_len);
    if (written < 0 || (size_t) written != pem_len || fsync(fd) != 0) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                      "brix_delegation: write/fsync(\"%s\") failed", tmp_path);
        close(fd);
        unlink(tmp_path); /* vfs-seam-allow: cred dir is svc-owned config, not an export */
        return NGX_ERROR;
    }
    close(fd);

    if (rename(tmp_path, final_path) != 0) { /* vfs-seam-allow: cred dir is svc-owned config, not an export */
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                      "brix_delegation: rename(\"%s\" -> \"%s\") failed",
                      tmp_path, final_path);
        unlink(tmp_path); /* vfs-seam-allow: cred dir is svc-owned config, not an export */
        return NGX_ERROR;
    }
    return NGX_OK;
}

/*
 * delegation_reject - send a small plain-text error body and finalize the
 * request.  Single choke point so every failure branch below is one line.
 */
void
delegation_reject(ngx_http_request_t *r, ngx_uint_t status, const char *msg)
{
    ngx_buf_t   *b;
    ngx_chain_t  out;
    size_t       len = strlen(msg);
    u_char      *buf = ngx_pnalloc(r->pool, len);

    if (buf == NULL) {
        webdav_metrics_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }
    ngx_memcpy(buf, msg, len);

    b = ngx_pcalloc(r->pool, sizeof(*b));
    if (b == NULL) {
        webdav_metrics_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }
    b->pos = buf;
    b->last = buf + len;
    b->memory = 1;
    b->last_buf = 1;
    out.buf = b;
    out.next = NULL;

    r->headers_out.status = status;
    r->headers_out.content_length_n = (off_t) len;
    r->headers_out.content_type.data = (u_char *) "text/plain";
    r->headers_out.content_type.len = sizeof("text/plain") - 1;
    r->headers_out.content_type_len = r->headers_out.content_type.len;

    if (ngx_http_send_header(r) == NGX_ERROR || r->header_only) {
        webdav_metrics_finalize_request(r, status);
        return;
    }
    webdav_metrics_finalize_request(r, ngx_http_output_filter(r, &out));
}

/*
 * delegation_validate_and_store - body is in hand; parse/validate/store.
 * Split out of webdav_delegation_handle so each early-return failure path
 * stays a single statement in the caller (no goto, no nested cleanup
 * ladders — chain ownership lives entirely in this function).
 */
static void
delegation_validate_and_store(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf,
    const ngx_http_brix_webdav_req_ctx_t *ctx,
    const u_char *body, size_t body_len)
{
    STACK_OF(X509) *chain;
    X509            *eec;
    char             key[BRIX_UCRED_KEY_MAX];

    chain = delegation_parse_chain(body, body_len);
    if (chain == NULL) {
        delegation_reject(r, NGX_HTTP_BAD_REQUEST,
                          "unparseable proxy PEM\n");
        return;
    }

    eec = delegation_find_eec(chain);
    if (eec == NULL) {
        sk_X509_pop_free(chain, X509_free);
        delegation_reject(r, NGX_HTTP_BAD_REQUEST,
                          "no end-entity certificate in chain\n");
        return;
    }

    /* Expiry checked before identity: an expired-and-mismatched upload
     * should not leak whether it also happens to name another identity. */
    if (delegation_chain_expired(chain)) {
        sk_X509_pop_free(chain, X509_free);
        delegation_reject(r, NGX_HTTP_BAD_REQUEST, "proxy is expired\n");
        return;
    }

    /* Chain-of-trust before identity: the EEC DN string compare below is only
     * meaningful once the EEC is proven to chain to a trusted CA.  A failure
     * here (self-signed / wrong-CA / untrusted issuer) and a DN mismatch both
     * report the same 403 so we never reveal which check the upload failed. */
    if (delegation_chain_trusted(r, conf, chain) != NGX_OK) {
        sk_X509_pop_free(chain, X509_free);
        delegation_reject(r, NGX_HTTP_FORBIDDEN,
                          "proxy chain does not verify against a trusted"
                          " CA\n");
        return;
    }

    if (!delegation_eec_dn_matches(eec, ctx->dn)) {
        char dn_log[1024];

        brix_sanitize_log_string(ctx->dn, dn_log, sizeof(dn_log));
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
            "brix_delegation: DN mismatch — authenticated as \"%s\","
            " uploaded proxy is for a different identity", dn_log);
        sk_X509_pop_free(chain, X509_free);
        delegation_reject(r, NGX_HTTP_FORBIDDEN,
                          "proxy identity does not match authenticated"
                          " client\n");
        return;
    }

    sk_X509_pop_free(chain, X509_free);

    if (brix_sd_ucred_key(ctx->dn, key, sizeof(key)) != NGX_OK) {
        delegation_reject(r, NGX_HTTP_INTERNAL_SERVER_ERROR,
                          "credential key derivation failed\n");
        return;
    }

    if (delegation_store_pem(r->connection->log,
            &conf->common.storage_credential_dir, key, body, body_len)
        != NGX_OK)
    {
        delegation_reject(r, NGX_HTTP_INSUFFICIENT_STORAGE,
                          "failed to store credential\n");
        return;
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
        "brix_delegation: stored proxy for key=%s", key);
    delegation_reject(r, NGX_HTTP_CREATED, "OK\n");
}

void
webdav_delegation_handle(ngx_http_request_t *r)
{
    ngx_http_brix_webdav_loc_conf_t *conf =
        ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);
    ngx_http_brix_webdav_req_ctx_t  *ctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
    u_char *body = NULL;
    size_t  body_len = 0;

    if (!delegation_client_authenticated(ctx)) {
        delegation_reject(r, NGX_HTTP_UNAUTHORIZED,
                          "GSI client-certificate authentication"
                          " required\n");
        return;
    }

    if (brix_http_body_read_all(r, BRIX_DELEGATION_BODY_MAX, &body, &body_len)
            != NGX_OK
        || body == NULL || body_len == 0)
    {
        delegation_reject(r, NGX_HTTP_BAD_REQUEST,
                          "missing or oversized proxy body\n");
        return;
    }

    delegation_validate_and_store(r, conf, ctx, body, body_len);
}
