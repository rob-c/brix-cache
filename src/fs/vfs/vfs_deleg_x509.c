/* vfs_deleg_x509.c — RFC-3820 proxy-chain trust gate for delegated creds.
 *
 * WHAT: The X.509 half of the delegation live-cred materialiser: parse the
 *       captured proxy PEM into a certificate chain, re-verify it against the
 *       CA store bound on the bag (phase-70 §5.1 / P90-70.4), and stage the
 *       PEM into a request-scoped temp file for the backend driver.
 *
 * WHY:  Split out of vfs_deleg.c, which crossed the 600-line cap
 *       (coding-standards §1). The chain-trust trio is a self-contained
 *       OpenSSL-facing unit; the parent TU keeps the strategy dispatch and the
 *       SSS/krb5/STS arms, which need no X509 machinery.
 *
 * HOW:  Seam declarations live in vfs_deleg_internal.h — the parent lends
 *       brix_vfs_deleg_pem_is_valid()/_temp_cleanup(), this TU lends
 *       brix_vfs_deleg_proxy() back. brix_vfs_deleg_deny() is the shared
 *       failure terminal already exported from vfs_internal.h. */

#include "vfs_internal.h"
#include "net/proxy/gsi_upstream.h"
#include "auth/crypto/gsi_verify.h"      /* in-gate chain re-verify (P90-70.4)     */
#include "auth/token/exchange_cache.h"   /* §5.4 minted-token cache (P90-70.9)     */

#include <time.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include "vfs_deleg_internal.h"


/* ---- brix_vfs_deleg_chain_is_trusted ---------------------------------------
 *
 * WHAT: In-gate RFC-3820 chain-trust re-verify of the PASSTHROUGH proxy PEM
 *       against the CA store bound on the bag (phase-70 §5.1, P90-70.4).
 *
 * WHY:  The capture sites enforce transport + leaf-DN identity, but chain trust
 *       must also hold at the one seam where captured bytes become a backend
 *       credential — with a store bound this gate fails closed even if a future
 *       capture site forgets its own check.
 *
 * HOW:  No store bound → pass (the setter was never wired on this protocol; the
 *       capture-side gate applies alone). Otherwise parse the PEM into a
 *       STACK_OF(X509) via brix_vfs_deleg_chain_parse, take cert 0 as the leaf,
 *       and run brix_gsi_verify_chain with client_purpose=0 — the same call
 *       shape as webdav's delegation_chain_trusted (RFC-3820 proxies accepted;
 *       the helper logs the specific failure). Certs are freed either way. */

/* Parse every CERTIFICATE block out of `pem` into a new non-empty
 * STACK_OF(X509) (caller sk_X509_pop_free's it), or NULL. A forwarded grid
 * proxy is "proxy cert, PRIVATE KEY, issuing chain" — a bare
 * PEM_read_bio_X509 loop (delegation_parse_chain's shape) would stop at the
 * key block and lose the chain, so generic PEM blocks are read and only the
 * certificates kept; the key bytes are never copied out of the bag. */
static STACK_OF(X509) *
brix_vfs_deleg_chain_parse(const u_char *pem, size_t len)
{
    BIO            *bio;
    STACK_OF(X509) *chain;
    char           *name = NULL;
    char           *header = NULL;
    unsigned char  *der = NULL;
    long            der_len = 0;

    bio = BIO_new_mem_buf(pem, (int) len);
    if (bio == NULL) {
        return NULL;
    }

    chain = sk_X509_new_null();
    if (chain == NULL) {
        BIO_free(bio);
        return NULL;
    }

    while (PEM_read_bio(bio, &name, &header, &der, &der_len) == 1) {
        if (ngx_strcmp(name, PEM_STRING_X509) == 0) {
            const unsigned char *p = der;
            X509 *cert = d2i_X509(NULL, &p, der_len);

            if (cert != NULL && sk_X509_push(chain, cert) <= 0) {
                X509_free(cert);   /* partial chain → verify fails closed */
            }
        }
        OPENSSL_free(name);
        OPENSSL_free(header);
        OPENSSL_free(der);
        name = header = NULL;
        der = NULL;
    }
    ERR_clear_error();   /* the terminating PEM_read failure is expected */
    BIO_free(bio);

    if (sk_X509_num(chain) == 0) {
        sk_X509_pop_free(chain, X509_free);
        return NULL;
    }

    return chain;
}

static int
brix_vfs_deleg_chain_is_trusted(brix_vfs_ctx_t *ctx)
{
    brix_deleg_live_t        *live = ctx->deleg_live;
    X509                     *leaf;
    STACK_OF(X509)           *chain;
    brix_gsi_verify_result_t  res;
    ngx_int_t                 rc;

    if (live->ca_store == NULL) {
        return 1;
    }

    chain = brix_vfs_deleg_chain_parse(live->proxy_pem.data,
                                       live->proxy_pem.len);
    if (chain == NULL) {
        return 0;
    }

    leaf = sk_X509_value(chain, 0);

    rc = brix_gsi_verify_chain(ctx->log, (X509_STORE *) live->ca_store, leaf,
             chain, live->ca_verify_depth, &res,
             0 /* GSI: accept RFC-3820 proxies */);
    sk_X509_pop_free(chain, X509_free);

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
            "brix: PASSTHROUGH proxy chain failed CA re-verify at the "
            "delegation gate - denying");
        return 0;
    }

    return 1;
}

/* ---- brix_vfs_deleg_proxy --------------------------------------------------
 *
 * WHAT: Materialise a PASSTHROUGH full x509 proxy: validate the PEM, write it to
 *       a 0600 temp, register the unlink+zero cleanup, and point cred->x509_proxy
 *       at the temp path.
 *
 * WHY:  brix_cache_origin_auth_gsi() authenticates from a proxy FILE path, so
 *       any strategy that materialises a proxy PEM at a 0600 path reuses the
 *       origin leg unchanged (§5.1). The private key must never be logged and
 *       must be unlinked on pool teardown.
 *
 * HOW:  brix_vfs_deleg_pem_is_valid() rejects non-PEM bytes → deny;
 *       brix_vfs_deleg_chain_is_trusted() re-runs the RFC-3820 chain-trust gate
 *       when the capture site bound a CA store → deny on failure. Then
 *       brix_proxy_gsi_write_pem_temp() creates the owner-only temp; the path is
 *       copied onto the pool and a cleanup registered to unlink+zero it.
 *
 * RFC-3820 chain-trust (phase-70 §5.1): the full gate is (1) chain parses AND is
 *       unexpired; (2) leaf DN EQUALS the front-door authenticated DN (no
 *       privilege swap); (3) chain is RFC-3820-valid AND trusted by the export's
 *       CA store via brix_gsi_verify_chain(..., client_purpose=0); (4) TLS-only
 *       transport. (2) and (4) are enforced at CAPTURE (deleg_capture.c matches
 *       the leaf DN against the authenticated identity over TLS;
 *       gsi_promote_fullproxy DN-matches the root:// push); (1)+(3) are enforced
 *       HERE whenever the capture site stamped the export's CA store via
 *       brix_vfs_deleg_set_ca_store (P90-70.4 — webdav binds conf->ca_store,
 *       root:// binds conf->gsi_store). With no store bound the seam enforces
 *       PEM well-formedness and relies on the capture-side gate. */
ngx_int_t
brix_vfs_deleg_proxy(brix_vfs_ctx_t *ctx, brix_sd_cred_t *cred,
    int *use_cred, int *err_out)
{
    brix_deleg_live_t   *live = ctx->deleg_live;
    char                  tmp[NGX_MAX_PATH];
    char                 *path;
    size_t                path_len;
    brix_deleg_temp_t   *payload;
    ngx_pool_cleanup_t   *cln;
    ngx_str_t             princ = ngx_string("");

    if (!brix_vfs_deleg_pem_is_valid(live->proxy_pem.data,
                                     live->proxy_pem.len)) {
        return brix_vfs_deleg_deny(ctx, use_cred, err_out,
                                   BRIX_CRED_FAIL_PEM);
    }

    if (!brix_vfs_deleg_chain_is_trusted(ctx)) {
        return brix_vfs_deleg_deny(ctx, use_cred, err_out,
                                   BRIX_CRED_FAIL_CHAIN);
    }

    if (brix_proxy_gsi_write_pem_temp(live->proxy_pem.data,
            live->proxy_pem.len, tmp, sizeof(tmp)) != 0) {
        if (ctx->identity != NULL) {
            princ = ctx->identity->subject;
        }
        ngx_log_error(NGX_LOG_ERR, ctx->log, ngx_errno,
            "brix: failed to materialise PASSTHROUGH proxy temp for "
            "principal=\"%V\"", &princ);
        return brix_vfs_deleg_deny(ctx, use_cred, err_out,
                                   BRIX_CRED_FAIL_MATERIALISE);
    }

    path_len = ngx_strlen(tmp);
    path = ngx_pnalloc(ctx->pool, path_len + 1);
    if (path == NULL) {
        (void) unlink(tmp);   /* vfs-seam-allow: config-domain PASSTHROUGH proxy credential temp (not export storage) */
        brix_metric_cred_fail(brix_vfs_metrics_proto(ctx),
                              BRIX_CRED_FAIL_MATERIALISE);
        errno = ENOMEM;
        if (err_out != NULL) {
            *err_out = ENOMEM;
        }
        *use_cred = 0;
        return NGX_ERROR;
    }
    ngx_memcpy(path, tmp, path_len);
    path[path_len] = '\0';

    cln = ngx_pool_cleanup_add(ctx->pool, sizeof(*payload));
    if (cln == NULL) {
        (void) unlink(path);  /* vfs-seam-allow: config-domain PASSTHROUGH proxy credential temp (not export storage) */
        ngx_memzero(path, path_len);
        brix_metric_cred_fail(brix_vfs_metrics_proto(ctx),
                              BRIX_CRED_FAIL_MATERIALISE);
        errno = ENOMEM;
        if (err_out != NULL) {
            *err_out = ENOMEM;
        }
        *use_cred = 0;
        return NGX_ERROR;
    }
    payload = cln->data;
    payload->path = path;
    cln->handler = brix_vfs_deleg_temp_cleanup;

    cred->x509_proxy = path;
    cred->mode       = BRIX_CRED_PASSTHROUGH;
    *use_cred        = 1;

    brix_metric_cred_deleg(brix_vfs_metrics_proto(ctx),
        (ngx_uint_t) brix_vfs_backend_mode(ctx), BRIX_CRED_OUTCOME_USER);
    return NGX_OK;
}
