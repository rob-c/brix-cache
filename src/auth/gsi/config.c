#include "core/config/config.h"
#include "auth/crypto/pki_build.h"
#include "core/compat/lifecycle_timing.h"

/*
 * Build (or rebuild) the X509_STORE used for GSI certificate verification.
 *
 * Loads the trusted CA from xcf->trusted_ca, then loads CRLs from xcf->crl.
 * Sets X509_V_FLAG_ALLOW_PROXY_CERTS so GSI proxy certificate chains verify.
 *
 * On success the new store is atomically swapped into xcf->gsi_store and any
 * previous store is freed.  On failure the old store is left intact so
 * existing connections are not disrupted.
 */
ngx_int_t
brix_rebuild_gsi_store(ngx_stream_brix_srv_conf_t *xcf, ngx_log_t *log,
    void *cache_scope)
{
    X509_STORE *store;
    X509_STORE *old_store;
    int         crl_count = 0;
    struct stat ca_st;
    int         ca_is_dir;

    /* brix_trusted_ca may name a single CA bundle file OR a hashed CA
     * directory (e.g. /etc/grid-security/certificates).  A directory is loaded
     * as an OpenSSL CApath so on-demand hash lookup verifies real grid proxy
     * chains (any CA under the dir), which a single-file bundle cannot cover. */
    ca_is_dir = (stat((char *) xcf->trusted_ca.data, &ca_st) == 0
                 && S_ISDIR(ca_st.st_mode));

    store = brix_build_ca_store_cached(cache_scope, log,
                                   ca_is_dir ? (char *) xcf->trusted_ca.data
                                             : NULL,
                                   ca_is_dir ? NULL
                                             : (char *) xcf->trusted_ca.data,
                                   xcf->crl.len > 0
                                       ? (char *) xcf->crl.data : NULL,
                                   X509_V_FLAG_ALLOW_PROXY_CERTS,
                                   &crl_count,
                                   (brix_sp_mode_t) xcf->signing_policy_mode,
                                   (int) xcf->crl_mode);
    if (store == NULL) {
        return NGX_ERROR;
    }

    if (xcf->crl.len > 0) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
                      "brix: loaded %d CRL(s) from \"%s\"",
                      crl_count, xcf->crl.data);
    }

    /* Atomic swap */
    old_store = xcf->gsi_store;
    xcf->gsi_store = store;
    if (old_store != NULL) {
        X509_STORE_free(old_store);
    }

    return NGX_OK;
}

/*
 * Compute the CA name-hash list advertised in the kXGS_init sec token
 * ("ca:hash1|hash2").
 *
 * WHY: stock XrdSecgsi clients look the advertised hashes up in their own CA
 * directory and abort the handshake with "unknown CA: cannot verify server
 * certificate" when none match, so the list must name the REAL issuer chain
 * of our server certificate.  (An earlier version PEM-parsed brix_trusted_ca
 * directly — wrong for a multi-CA bundle and silently empty when the
 * directive names a Grid CA DIRECTORY, which advertised ca:00000000 and broke
 * every stock client whose host cert hangs off a real CA chain.)
 *
 * HOW: verify our own certificate against the freshly built trust store and
 * hash every CA in the resulting chain (intermediates + root).  Falls back to
 * the leaf's issuer-name hash when chain building fails (e.g. a CRL gap), and
 * to "00000000" only when there is no certificate at all.
 */
static void
brix_gsi_compute_ca_hashes(ngx_stream_brix_srv_conf_t *xcf)
{
    X509_STORE_CTX  *sctx;
    STACK_OF(X509)  *chain;
    size_t           off = 0;
    int              i, n, w;

    xcf->gsi_ca_hashes[0] = '\0';

    sctx = X509_STORE_CTX_new();
    if (sctx != NULL && xcf->gsi_store != NULL && xcf->gsi_cert != NULL
        && X509_STORE_CTX_init(sctx, xcf->gsi_store, xcf->gsi_cert, NULL) == 1
        && X509_verify_cert(sctx) == 1)
    {
        chain = X509_STORE_CTX_get1_chain(sctx);
        if (chain != NULL) {
            n = sk_X509_num(chain);
            for (i = 1; i < n; i++) {              /* skip the leaf itself */
                w = snprintf(xcf->gsi_ca_hashes + off,
                             sizeof(xcf->gsi_ca_hashes) - off,
                             off > 0 ? "|%08lx" : "%08lx",
                             X509_subject_name_hash(sk_X509_value(chain, i)));
                if (w <= 0
                    || off + (size_t) w >= sizeof(xcf->gsi_ca_hashes))
                {
                    break;
                }
                off += (size_t) w;
            }
            sk_X509_pop_free(chain, X509_free);
        }
    }
    if (sctx != NULL) {
        X509_STORE_CTX_free(sctx);
    }

    if (xcf->gsi_ca_hashes[0] == '\0' && xcf->gsi_cert != NULL) {
        (void) snprintf(xcf->gsi_ca_hashes, sizeof(xcf->gsi_ca_hashes),
                        "%08lx", X509_issuer_name_hash(xcf->gsi_cert));
    }
    if (xcf->gsi_ca_hashes[0] == '\0') {
        (void) snprintf(xcf->gsi_ca_hashes, sizeof(xcf->gsi_ca_hashes),
                        "%08x", 0u);
    }
}

/* ---- Validate that all GSI trust inputs are present and path-usable ----
 *
 * WHAT: Returns NGX_OK when the certificate, private key, trusted CA and
 * (optional) CRL directives all point at readable filesystem paths of the
 * expected kind; returns NGX_ERROR after logging an NGX_LOG_EMERG line when a
 * mandatory directive is absent or any path fails validation.
 *
 * WHY: GSI mode is only meaningful when the certificate, private key and
 * trusted CA are all present simultaneously — missing any one makes GSI auth
 * meaningless, so the presence check must reject the config before any file is
 * touched.  Path validation is grouped here so the loader body stays a flat
 * sequence of load steps.
 *
 * HOW:
 *   1. Reject the config when any of certificate/certificate_key/trusted_ca is
 *      empty, with the combined "requires ..." emergency message.
 *   2. Validate certificate and certificate_key as readable regular files.
 *   3. Validate trusted_ca and crl as readable file-or-directory paths (crl may
 *      be empty; brix_validate_path treats an unset directive as a pass).
 */
static ngx_int_t
brix_gsi_require_trust_inputs(ngx_conf_t *cf, ngx_stream_brix_srv_conf_t *xcf)
{
    if (xcf->certificate.len == 0 || xcf->certificate_key.len == 0
        || xcf->trusted_ca.len == 0)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_auth gsi requires brix_certificate, "
            "brix_certificate_key and brix_trusted_ca");
        return NGX_ERROR;
    }

    if (brix_validate_path(cf, "brix_certificate", &xcf->certificate,
                             BRIX_PATH_REGULAR_FILE, R_OK) != NGX_OK
        || brix_validate_path(cf, "brix_certificate_key",
                                &xcf->certificate_key,
                                BRIX_PATH_REGULAR_FILE, R_OK) != NGX_OK
        || brix_validate_path(cf, "brix_trusted_ca", &xcf->trusted_ca,
                                BRIX_PATH_FILE_OR_DIRECTORY, R_OK) != NGX_OK
        || brix_validate_path(cf, "brix_crl", &xcf->crl,
                                BRIX_PATH_FILE_OR_DIRECTORY, R_OK) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}

/* ---- Load the server certificate PEM into xcf->gsi_cert ----
 *
 * WHAT: Opens xcf->certificate, parses the first X509 with PEM_read_X509() and
 * stores it in xcf->gsi_cert; returns NGX_OK on success or NGX_ERROR after an
 * NGX_LOG_EMERG line when the file cannot be opened or parsed.
 *
 * WHY: The parsed certificate is needed both to answer kXGS_cert and to build
 * the CA-hash advertisement, so it is loaded once at config time and kept.
 *
 * HOW:
 *   1. fopen the certificate path; on failure log with ngx_errno and return.
 *   2. Mark the descriptor FD_CLOEXEC so it does not leak across exec.
 *   3. PEM_read_X509 into xcf->gsi_cert and close the read-only stream.
 *   4. Reject when parsing yields no certificate.
 */
static ngx_int_t
brix_gsi_load_certificate(ngx_conf_t *cf, ngx_stream_brix_srv_conf_t *xcf)
{
    FILE *fp = fopen((char *) xcf->certificate.data, "r");
    if (fp == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
            "brix: cannot open certificate \"%s\"",
            xcf->certificate.data);
        return NGX_ERROR;
    }
    fcntl(fileno(fp), F_SETFD, FD_CLOEXEC);
    xcf->gsi_cert = PEM_read_X509(fp, NULL, NULL, NULL);
    (void) fclose(fp); /* phase74-fp: read-only stream, close failure cannot lose data */
    if (xcf->gsi_cert == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix: cannot parse certificate \"%s\"",
            xcf->certificate.data);
        return NGX_ERROR;
    }

    return NGX_OK;
}

/* ---- Cache the certificate PEM serialization for kXGS_cert replies ----
 *
 * WHAT: Serializes xcf->gsi_cert back to PEM into a pool-allocated buffer at
 * xcf->gsi_cert_pem (length xcf->gsi_cert_pem_len); returns NGX_OK on success,
 * NGX_ERROR on any OpenSSL/allocation failure (with an NGX_LOG_EMERG line for a
 * serialization failure).
 *
 * WHY: kXGS_cert sends the certificate on every GSI login, so encoding it once
 * at config time avoids per-request PEM encoding overhead on the hot path.
 *
 * HOW:
 *   1. Allocate a memory BIO; bail on allocation failure.
 *   2. PEM_write_bio_X509 the loaded certificate into it.
 *   3. Copy the BIO's bytes into a pool buffer and record the length.
 *   4. Free the BIO on every exit so no OpenSSL memory leaks.
 */
static ngx_int_t
brix_gsi_cache_cert_pem(ngx_conf_t *cf, ngx_stream_brix_srv_conf_t *xcf)
{
    BIO     *bio;
    BUF_MEM *bptr;

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        return NGX_ERROR;
    }

    if (!PEM_write_bio_X509(bio, xcf->gsi_cert)) {
        BIO_free(bio);
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix: cannot serialize certificate \"%s\"",
            xcf->certificate.data);
        return NGX_ERROR;
    }

    BIO_get_mem_ptr(bio, &bptr);
    xcf->gsi_cert_pem = ngx_pnalloc(cf->pool, bptr->length);
    if (xcf->gsi_cert_pem == NULL) {
        BIO_free(bio);
        return NGX_ERROR;
    }

    ngx_memcpy(xcf->gsi_cert_pem, bptr->data, bptr->length);
    xcf->gsi_cert_pem_len = bptr->length;
    BIO_free(bio);

    return NGX_OK;
}

/* ---- Load the server private key PEM into xcf->gsi_key ----
 *
 * WHAT: Opens xcf->certificate_key, parses it with PEM_read_PrivateKey() and
 * stores it in xcf->gsi_key; returns NGX_OK on success or NGX_ERROR after an
 * NGX_LOG_EMERG line when the file cannot be opened or parsed.
 *
 * WHY: The private key backs every GSI DH exchange, so like the certificate it
 * is loaded once at config time and cached on the server conf.
 *
 * HOW:
 *   1. fopen the key path; on failure log with ngx_errno and return.
 *   2. Mark the descriptor FD_CLOEXEC.
 *   3. PEM_read_PrivateKey into xcf->gsi_key and close the read-only stream.
 *   4. Reject when parsing yields no key.
 */
static ngx_int_t
brix_gsi_load_private_key(ngx_conf_t *cf, ngx_stream_brix_srv_conf_t *xcf)
{
    FILE *fp = fopen((char *) xcf->certificate_key.data, "r");
    if (fp == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
            "brix: cannot open private key \"%s\"",
            xcf->certificate_key.data);
        return NGX_ERROR;
    }
    fcntl(fileno(fp), F_SETFD, FD_CLOEXEC);
    xcf->gsi_key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    (void) fclose(fp); /* phase74-fp: read-only stream, close failure cannot lose data */
    if (xcf->gsi_key == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix: cannot parse private key \"%s\"",
            xcf->certificate_key.data);
        return NGX_ERROR;
    }

    return NGX_OK;
}

/* ---- Build the trusted-CA X509_STORE and run the PKI consistency check ----
 *
 * WHAT: Builds xcf->gsi_store from trusted_ca + CRLs via brix_rebuild_gsi_store,
 * runs the lightweight PKI/CRL consistency check, and logs the build duration;
 * returns NGX_OK, or NGX_ERROR when the store cannot be built.
 *
 * WHY: The store parse walks every CA (and CRL) under the trusted-CA path, so
 * its cost scales with the bundle size — on a full grid CA distribution
 * (hundreds of CAs + CRLs) it dominates GSI config time.  It is timed
 * independently so a slow startup is attributable at a glance.
 *
 * HOW:
 *   1. Snapshot a start timestamp.
 *   2. Rebuild the store scoped to cf->cycle so sibling GSI server blocks
 *      sharing the same trusted_ca/CRL dir load the IGTF CRLs once, not per
 *      block; bail on failure.
 *   3. Run brix_check_pki_consistency_stream to surface CRL gaps as warnings.
 *   4. Log the elapsed build time in microseconds.
 */
static ngx_int_t
brix_gsi_build_trust_store(ngx_conf_t *cf, ngx_stream_brix_srv_conf_t *xcf)
{
    uint64_t t0 = brix_phase_now_ns();

    if (brix_rebuild_gsi_store(xcf, cf->log, cf->cycle) != NGX_OK) {
        return NGX_ERROR;
    }

    (void) brix_check_pki_consistency_stream(cf->log, xcf);

    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0,
                  "brix: GSI trust store built from \"%V\" in %uLus",
                  &xcf->trusted_ca,
                  (brix_phase_now_ns() - t0) / 1000ull);

    return NGX_OK;
}

/* ---- Full GSI authentication configuration loader ----
 *
 * WHAT: When the auth mode selects GSI (or BOTH), validates the trust inputs,
 * loads and caches the server certificate + private key, builds the trusted-CA
 * store, and computes the advertised CA hashes; returns NGX_OK (also for a
 * non-GSI auth mode, a no-op) or NGX_ERROR on any validation/load failure.
 *
 * WHY: All three trust inputs must be present simultaneously — missing any one
 * makes GSI auth meaningless.  Cert serialization caching avoids per-request
 * PEM encoding on every client login, CRL checking enables revocation detection
 * across the full chain, and the CA hash lets clients confirm which CA the
 * server trusts before initiating the DH exchange.
 *
 * HOW:
 *   1. Return early when auth is neither GSI nor BOTH.
 *   2. Validate that all trust-input directives are present and path-usable.
 *   3. Load the certificate, cache its PEM, and load the private key.
 *   4. Build the trusted-CA store (with the PKI consistency check).
 *   5. Compute the CA-hash advertisement and log the configured summary.
 */
ngx_int_t
brix_configure_gsi(ngx_conf_t *cf, ngx_stream_brix_srv_conf_t *xcf)
{
    if (xcf->auth != BRIX_AUTH_GSI && xcf->auth != BRIX_AUTH_BOTH) {
        return NGX_OK;
    }

    if (brix_gsi_require_trust_inputs(cf, xcf) != NGX_OK) {
        return NGX_ERROR;
    }

    if (brix_gsi_load_certificate(cf, xcf) != NGX_OK) {
        return NGX_ERROR;
    }

    if (brix_gsi_cache_cert_pem(cf, xcf) != NGX_OK) {
        return NGX_ERROR;
    }

    if (brix_gsi_load_private_key(cf, xcf) != NGX_OK) {
        return NGX_ERROR;
    }

    if (brix_gsi_build_trust_store(cf, xcf) != NGX_OK) {
        return NGX_ERROR;
    }

    brix_gsi_compute_ca_hashes(xcf);

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
        "brix: GSI auth configured - cert=%s ca_hashes=%s",
        xcf->certificate.data, xcf->gsi_ca_hashes);

    return NGX_OK;
}
