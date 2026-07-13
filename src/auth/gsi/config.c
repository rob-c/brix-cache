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

/*
 * WHAT: Full GSI authentication configuration loader — validates auth method (GSI or BOTH), checks all three trust inputs (certificate, private key, trusted CA) are present and path-valid, loads server certificate via PEM_read_X509(), serializes it into cached PEM buffer for kXGS_cert responses on every GSI login, loads private key via PEM_read_PrivateKey(), builds X509_STORE with trusted CA + CRLs via brix_rebuild_gsi_store() (with proxy cert flag and CRL_CHECK_ALL), runs PKI/CRL consistency check, computes CA hash via X509_subject_name_hash() for kXRS_issuer_hash advertisement during GSI bootstrap.
 * WHY: All three trust inputs must be present simultaneously — missing any one makes GSI auth meaningless. Cert serialization caching avoids per-request PEM encoding overhead on every client login. CRL checking enables revocation detection across the full certificate chain. CA hash allows clients to confirm which CA the server trusts before initiating DH exchange.
 */
ngx_int_t
brix_configure_gsi(ngx_conf_t *cf, ngx_stream_brix_srv_conf_t *xcf)
{
    if (xcf->auth != BRIX_AUTH_GSI && xcf->auth != BRIX_AUTH_BOTH) {
        return NGX_OK;
    }

    /* GSI mode is only meaningful when all three trust inputs are present. */
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

    /* Load server certificate */
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
    }

    /* Cache the PEM serialization once; kXGS_cert sends it on every GSI login. */
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
    }

    /* Load server private key */
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
    }

    /* Build trusted CA X509_STORE.  This parses every CA (and CRL) under the
     * trusted-CA path, so its cost scales with the bundle size — on a full grid
     * CA distribution (hundreds of CAs + CRLs) it dominates GSI config time.
     * Time it independently so a slow startup is attributable at a glance. */
    {
        uint64_t t0 = brix_phase_now_ns();

        /* cf->cycle scopes the CA/CRL-store memo to THIS config parse, so
         * multiple GSI server blocks (root://, davs://, …) sharing the same
         * trusted_ca/CRL dir load the IGTF CRLs once, not once per block. */
        if (brix_rebuild_gsi_store(xcf, cf->log, cf->cycle) != NGX_OK) {
            return NGX_ERROR;
        }

        /* Run a lightweight PKI/CRL consistency check and log any problems. */
        (void) brix_check_pki_consistency_stream(cf->log, xcf);

        ngx_log_error(NGX_LOG_NOTICE, cf->log, 0,
                      "brix: GSI trust store built from \"%V\" in %uLus",
                      &xcf->trusted_ca,
                      (brix_phase_now_ns() - t0) / 1000ull);
    }

    brix_gsi_compute_ca_hashes(xcf);

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
        "brix: GSI auth configured - cert=%s ca_hashes=%s",
        xcf->certificate.data, xcf->gsi_ca_hashes);

    return NGX_OK;
}
