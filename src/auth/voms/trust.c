/*
 * src/auth/voms/trust.c — trust stores for VOMS server certificate chains
 *
 * WHAT: brix_voms_init / brix_voms_available / brix_voms_warm from
 *       ngx_brix_module.h and brix_voms_trust_store from voms_internal.h.
 * WHY:  Verifying an attribute certificate means chaining the embedded VOMS
 *       server certificate to the CA directory named by brix_voms_cert_dir.
 *       Loading an IGTF directory's CRLs takes about a second, so the store
 *       is built once per directory by the module's CA-store cache
 *       (auth/crypto/pki_build.c) at configuration time — brix_voms_warm —
 *       and inherited by the workers; a request only looks it up.
 * HOW:  One trust policy for every VOMS store: CRLs checked where present
 *       (try mode), signing policy off (as libvoms behaved). Both entry
 *       points return an owned reference the caller frees.
 */

#include "voms_internal.h"
#include "auth/crypto/pki_build.h"
#include "auth/crypto/store_policy.h"
#include <limits.h>

ngx_flag_t
brix_voms_available(void)
{
    return 1;   /* the verifier is compiled in: shared/voms/ */
}

ngx_int_t
brix_voms_init(ngx_log_t *log)
{
    ngx_log_error(NGX_LOG_NOTICE, log, 0,
                  "brix: native VOMS attribute-certificate verifier enabled");
    return NGX_OK;
}

static void
voms_trust_policy(brix_trust_policy_t *pol)
{
    brix_trust_policy_t init = BRIX_TRUST_POLICY_INIT;

    *pol = init;
    pol->sp_mode = BRIX_SP_MODE_OFF;
    pol->crl_mode = BRIX_CRL_MODE_TRY;
}

static int
voms_dir_cstr(const ngx_str_t *cert_dir, char *dir, size_t cap)
{
    if (cert_dir == NULL || cert_dir->len == 0 || cert_dir->len >= cap) {
        return 0;
    }
    ngx_memcpy(dir, cert_dir->data, cert_dir->len);
    dir[cert_dir->len] = '\0';
    return 1;
}

X509_STORE *
brix_voms_trust_store(ngx_log_t *log, const ngx_str_t *cert_dir)
{
    brix_trust_policy_t pol;
    char                dir[PATH_MAX];
    X509_STORE         *store;
    int                 crl_count = 0;

    if (!voms_dir_cstr(cert_dir, dir, sizeof(dir))) {
        return NULL;
    }
    voms_trust_policy(&pol);
    store = brix_build_ca_store_peek(dir, NULL, NULL, 0, &pol);
    if (store != NULL) {
        return store;
    }
    /* not warmed at configuration time (a directory no gate validated):
     * build it now and let the cache keep it for the next request */
    store = brix_build_ca_store_cached((void *) 1, log, dir, NULL, NULL, 0,
                                       &crl_count, &pol);
    if (store == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "brix: VOMS trust store: cannot load CA directory \"%s\"", dir);
    }
    return store;
}

ngx_int_t
brix_voms_warm(ngx_log_t *log, const ngx_str_t *cert_dir)
{
    brix_trust_policy_t pol;
    char                dir[PATH_MAX];
    X509_STORE         *store;
    int                 crl_count = 0;

    if (!voms_dir_cstr(cert_dir, dir, sizeof(dir))) {
        return NGX_ERROR;
    }
    voms_trust_policy(&pol);
    store = brix_build_ca_store_cached((void *) 1, log, dir, NULL, NULL, 0,
                                       &crl_count, &pol);
    if (store == NULL) {
        return NGX_ERROR;
    }
    X509_STORE_free(store);   /* the cache holds its own reference */
    ngx_log_error(NGX_LOG_NOTICE, log, 0,
                  "brix: VOMS trust store ready for \"%s\" (%d CRL(s))",
                  dir, crl_count);
    return NGX_OK;
}
