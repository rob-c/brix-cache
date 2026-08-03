/*
 * cvmfs/secure_x509.c — X.509 / VOMS client-certificate authz for CVMFS.
 *
 * WHAT: The `brix_scvmfs_authz x509` and `authz voms` back-ends — locate the
 *       end-entity cert behind any RFC 3820 proxy chain, glob-gate its subject
 *       DN (brix_scvmfs_x509_dn), and, in VOMS mode, glob-gate the extracted
 *       VO/FQAN set (brix_scvmfs_voms).  Both fail CLOSED when TLS is absent or
 *       the peer presented no VERIFIED cert.
 *
 * WHY:  Split out of secure.c (coding-standards §1, 600-line cap). secure.c
 *       keeps the bearer-token path, the repo-authz directive plumbing, the
 *       preamble that dispatches between modes, and the QoS class glue; the
 *       OpenSSL chain-walking lives here so the crypto surface is one
 *       reviewable unit and the #if (NGX_HTTP_SSL) fencing stays in one place.
 */

#include "cvmfs.h"
#include "secure_internal.h"
#include "cvmfs_module_internal.h"
#include "core/ngx_brix_module.h"           /* brix_extract_voms_info (voms) */
#include "auth/token/issuer_registry.h"
#include "auth/crypto/store_policy.h"       /* brix_x509_oneline, brix_px_classify */
#include "auth/crypto/signing_policy.h"     /* brix_sp_glob_match (DN allow-glob) */
#include "core/compat/cstr.h"
#include "core/types/tunables.h"

#include <limits.h>


/* ---- x509 client-cert authz (phase-92) -----------------------------------
 * Authenticate the TLS-verified peer by its end-entity subject DN. nginx's
 * ssl_verify_client chain does the crypto; we require a peer cert that VERIFIED
 * (X509_V_OK) — a location that forgot ssl_verify_client presents no cert and
 * fails CLOSED here. The EEC is the leaf when the client used a bare cert, else
 * the first non-proxy cert in the presented chain (RFC 3820 proxies chain
 * leaf → EEC), so a GSI proxy authenticates as its issuing identity. An
 * optional brix_scvmfs_x509_dn glob list gates the DN; an empty list accepts
 * any verified client. The validated DN becomes the F9 QoS / attest subject. */
#if (NGX_HTTP_SSL)
static X509 *
scvmfs_find_eec(SSL *sc, X509 *leaf)
{
    STACK_OF(X509)  *chain;
    int              i, n;

    if (brix_px_classify(leaf) == BRIX_PX_NONE) {
        return leaf;
    }
    chain = SSL_get_peer_cert_chain(sc);      /* server side: excludes leaf */
    n = (chain != NULL) ? sk_X509_num(chain) : 0;
    for (i = 0; i < n; i++) {
        X509 *cert = sk_X509_value(chain, i);
        if (brix_px_classify(cert) == BRIX_PX_NONE) {
            return cert;
        }
    }
    return NULL;
}

static ngx_int_t
scvmfs_dn_allowed(ngx_array_t *globs, const char *dn)
{
    ngx_str_t  *g;
    ngx_uint_t  i;

    if (globs == NULL || globs->nelts == 0) {
        return 1;                             /* no list = any verified peer */
    }
    g = globs->elts;
    for (i = 0; i < globs->nelts; i++) {
        char pat[SCVMFS_DN_MAX];

        if (g[i].len >= sizeof(pat)) {
            continue;                         /* pathological glob; skip */
        }
        ngx_memcpy(pat, g[i].data, g[i].len);
        pat[g[i].len] = '\0';
        if (brix_sp_glob_match(pat, dn)) {
            return 1;
        }
    }
    return 0;
}

/* voms mode: gate the proxy's carried VO name(s) against an allow-glob list.
 * vo_csv is the comma-separated VO list lifted by brix_extract_voms_info; an
 * empty glob list admits any client carrying at least one VO, otherwise one
 * glob must match one carried VO. Fails CLOSED (0) on the empty-VO case — the
 * caller has already rejected a proxy with no VOMS AC. */
static ngx_int_t
scvmfs_vo_allowed(ngx_array_t *globs, const char *vo_csv)
{
    ngx_str_t   *g;
    ngx_uint_t   i;
    const char  *tok;

    if (globs == NULL || globs->nelts == 0) {
        return 1;                             /* no list = any carried VO */
    }
    g = globs->elts;
    for (tok = vo_csv; tok != NULL && *tok != '\0'; ) {
        const char *comma = strchr(tok, ',');
        size_t      tlen  = (comma != NULL) ? (size_t) (comma - tok)
                                            : ngx_strlen(tok);
        char        vo[256];

        if (tlen < sizeof(vo)) {
            ngx_memcpy(vo, tok, tlen);
            vo[tlen] = '\0';
            for (i = 0; i < globs->nelts; i++) {
                char pat[256];

                if (g[i].len >= sizeof(pat)) {
                    continue;                 /* pathological glob; skip */
                }
                ngx_memcpy(pat, g[i].data, g[i].len);
                pat[g[i].len] = '\0';
                if (brix_sp_glob_match(pat, vo)) {
                    return 1;
                }
            }
        }
        tok = (comma != NULL) ? comma + 1 : NULL;
    }
    return 0;
}
#endif

ngx_int_t
scvmfs_check_x509(ngx_http_request_t *r,
    ngx_http_brix_cvmfs_loc_conf_t *lcf)
{
#if (NGX_HTTP_SSL)
    ngx_connection_t *c = r->connection;
    X509             *leaf, *eec;
    char              dn[SCVMFS_DN_MAX];

    if (c->ssl == NULL
        || SSL_get_verify_result(c->ssl->connection) != X509_V_OK)
    {
        return NGX_HTTP_UNAUTHORIZED;         /* no verified client chain */
    }

    leaf = SSL_get_peer_certificate(c->ssl->connection);
    if (leaf == NULL) {
        return NGX_HTTP_UNAUTHORIZED;         /* verify off / no cert presented */
    }

    dn[0] = '\0';
    eec = scvmfs_find_eec(c->ssl->connection, leaf);
    if (eec != NULL) {
        brix_x509_oneline(X509_get_subject_name(eec), dn, sizeof(dn));
    }
    X509_free(leaf);

    if (dn[0] == '\0') {
        return NGX_HTTP_UNAUTHORIZED;         /* every presented cert a proxy */
    }
    if (!scvmfs_dn_allowed(lcf->scvmfs_x509_dn, dn)) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
            "scvmfs: client DN \"%s\" not in brix_scvmfs_x509_dn allow-list "
            "- 403", dn);
        return NGX_HTTP_FORBIDDEN;            /* verified, but out of policy */
    }

    {
        ngx_http_brix_cvmfs_ctx_t *ctx =
            ngx_http_get_module_ctx(r, ngx_http_brix_cvmfs_module);

        if (ctx != NULL) {
            ngx_cpystrn((u_char *) ctx->token_sub, (u_char *) dn,
                        sizeof(ctx->token_sub));
        }
    }
    return NGX_DECLINED;                       /* authenticated: proceed */
#else
    (void) r; (void) lcf;
    return NGX_HTTP_UNAUTHORIZED;              /* no TLS built in: fail closed */
#endif
}

/* voms mode = x509 authentication PLUS a VOMS-FQAN authorisation gate. The
 * TLS-verified peer is authenticated by its EEC DN exactly as x509 mode, then
 * brix_extract_voms_info lifts+verifies the proxy's VOMS VO(s) against the
 * per-VO LSC dir (vomsdir) and VOMS signing-CA trust (voms_cert_dir); the VO(s)
 * are gated by the brix_scvmfs_voms allow-glob list. Fails CLOSED: a plain GSI
 * proxy carrying no VOMS AC is 403, never admitted. The crypto is nginx's
 * ssl_verify_client chain plus the shared brix_extract_voms_info engine — this
 * TU stays policy glue. */
ngx_int_t
scvmfs_check_voms(ngx_http_request_t *r,
    ngx_http_brix_cvmfs_loc_conf_t *lcf)
{
#if (NGX_HTTP_SSL)
    ngx_connection_t *c = r->connection;
    X509             *leaf, *eec;
    STACK_OF(X509)   *chain;
    char              dn[SCVMFS_DN_MAX];
    char              primary_vo[256] = "";
    char              vo_list[1024]   = "";

    if (c->ssl == NULL
        || SSL_get_verify_result(c->ssl->connection) != X509_V_OK)
    {
        return NGX_HTTP_UNAUTHORIZED;         /* no verified client chain */
    }
    leaf = SSL_get_peer_certificate(c->ssl->connection);
    if (leaf == NULL) {
        return NGX_HTTP_UNAUTHORIZED;         /* verify off / no cert presented */
    }
    chain = SSL_get_peer_cert_chain(c->ssl->connection);   /* borrowed */

    dn[0] = '\0';
    eec = scvmfs_find_eec(c->ssl->connection, leaf);
    if (eec != NULL) {
        brix_x509_oneline(X509_get_subject_name(eec), dn, sizeof(dn));
    }
    (void) brix_extract_voms_info(c->log, leaf, chain,
                                  &lcf->scvmfs_vomsdir,
                                  &lcf->scvmfs_voms_cert_dir,
                                  primary_vo, sizeof(primary_vo),
                                  vo_list, sizeof(vo_list));
    X509_free(leaf);

    if (dn[0] == '\0') {
        return NGX_HTTP_UNAUTHORIZED;         /* every presented cert a proxy */
    }
    if (vo_list[0] == '\0') {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
            "scvmfs: client DN \"%s\" carries no VOMS attribute - 403", dn);
        return NGX_HTTP_FORBIDDEN;            /* voms mode requires a VO */
    }
    if (!scvmfs_vo_allowed(lcf->scvmfs_voms, vo_list)) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
            "scvmfs: client VO(s) \"%s\" not in brix_scvmfs_voms allow-list "
            "- 403", vo_list);
        return NGX_HTTP_FORBIDDEN;            /* verified, but out of policy */
    }

    {
        ngx_http_brix_cvmfs_ctx_t *ctx =
            ngx_http_get_module_ctx(r, ngx_http_brix_cvmfs_module);

        if (ctx != NULL) {
            ngx_cpystrn((u_char *) ctx->token_sub, (u_char *) dn,
                        sizeof(ctx->token_sub));
        }
    }
    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                  "scvmfs: x509+voms admit DN=\"%s\" primary_vo=\"%s\"",
                  dn, primary_vo);
    return NGX_DECLINED;                       /* authenticated + authorised */
#else
    (void) r; (void) lcf;
    return NGX_HTTP_UNAUTHORIZED;              /* no TLS built in: fail closed */
#endif
}

