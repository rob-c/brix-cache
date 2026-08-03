/* http_common_setters.c — hand-written directive setters for the shared HTTP
 * preamble.
 *
 * WHAT: The three brix_conf_set_* handlers that need more than a generic
 *       ngx_conf_set_*_slot: the mint-CA pair (config-time PEM parse of both
 *       cert and key), the cache-peer list, and the backend token-exchange
 *       endpoint (URL shape validation).
 *
 * WHY:  Split out of http_common.c, which crossed the 600-line cap
 *       (coding-standards §1). The parent TU is the directive TABLE plus the
 *       module/conf lifecycle; these setters are directive SEMANTICS, and each
 *       one fails `nginx -t` loudly rather than deferring to runtime.
 *
 * HOW:  Declared in http_common.h so the command table in http_common.c can
 *       name them; each stores into the shared preamble conf it is handed. */

#include "core/config/http_common.h"
#include "core/seccomp/seccomp.h"            /* brix_conf_set_seccomp */
#include "auth/impersonate/lifecycle.h"      /* brix_conf_set_worker_user */
#include "protocols/root/stream/module_enums.h" /* brix_seccomp_modes */
#include "fs/cache/verify.h"               /* brix_cache_verify_mode_e */
#include "fs/backend/sd.h"                 /* BRIX_CRED_* (phase-70 §4) */
#include "auth/s3/sts.h"                   /* BRIX_STS_FLAVOR_* (phase-70 §5.5) */
#include "core/config/config.h"            /* brix_conf_set_backend_sss_keytab */

#include <stdio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>                   /* phase-2 T9 mint-CA config-time validation */
#include "auth/crypto/scoped.h"   /* W3 NULL-safe destroyers (P90-27.1) */


/*
 * brix_conf_set_mint_ca — setter for "brix_storage_credential_mint_ca <cert>
 * <key>" (phase-2 T9). Validates both PEM files load-parse at config time
 * (nginx -t fails loudly on a bad mint CA instead of every mint request
 * failing at runtime) and stores their paths into the shared preamble's
 * storage_credential_mint_ca_cert / _key fields. TRUST NOTE: configuring this
 * directive means the frontend will sign per-user x509 proxies with this CA
 * key — the ORIGIN must trust this CA for minted credentials to be usable;
 * see src/fs/backend/cred_mint.h for the full trust-model note.
 */
char *
brix_conf_set_mint_ca(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_brix_common_conf_t *c = conf;
    ngx_str_t                   *value = cf->args->elts;
    FILE                         *f;
    X509                         *cert;
    EVP_PKEY                     *key;

    (void) cmd;

    f = fopen((const char *) value[1].data, "r");
    cert = (f != NULL) ? PEM_read_X509(f, NULL, NULL, NULL) : NULL;
    if (f != NULL) {
        (void) fclose(f);   /* read-only stream: close failure cannot lose data */
    }
    if (cert == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_storage_credential_mint_ca: cannot parse CA cert \"%V\"",
            &value[1]);
        return NGX_CONF_ERROR;
    }
    X509_free(cert);

    f = fopen((const char *) value[2].data, "r");
    key = (f != NULL) ? PEM_read_PrivateKey(f, NULL, NULL, NULL) : NULL;
    if (f != NULL) {
        (void) fclose(f);   /* read-only stream: close failure cannot lose data */
    }
    if (key == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_storage_credential_mint_ca: cannot parse CA key \"%V\"",
            &value[2]);
        return NGX_CONF_ERROR;
    }
    brix_evp_pkey_free(key);

    c->common.storage_credential_mint_ca_cert = value[1];
    c->common.storage_credential_mint_ca_key  = value[2];
    return NGX_CONF_OK;
}

/*
 * brix_conf_set_peers — setter for "brix_cache_peers <member> <member> ..."
 * (phase-85 F8 sibling mesh). Each member is "host:port", with this node's own
 * ring slot written "self=host:port". The tokens are only COLLECTED here (into
 * an ngx_str_t array on the shared preamble); shape validation — exactly one
 * self=, ≥2 members, well-formed authorities — runs at tier registration where
 * the [emerg] can name the export.
 */
char *
brix_conf_set_peers(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_brix_common_conf_t *c = conf;
    ngx_str_t                    *value = cf->args->elts;
    ngx_str_t                    *slot;
    ngx_uint_t                    i;

    (void) cmd;

    if (c->common.cache_peers != NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cache_peers: duplicate directive — list every ring "
            "member in one declaration");
        return NGX_CONF_ERROR;
    }
    c->common.cache_peers = ngx_array_create(cf->pool, cf->args->nelts - 1,
                                             sizeof(ngx_str_t));
    if (c->common.cache_peers == NULL) {
        return NGX_CONF_ERROR;
    }
    for (i = 1; i < cf->args->nelts; i++) {
        slot = ngx_array_push(c->common.cache_peers);
        if (slot == NULL) {
            return NGX_CONF_ERROR;
        }
        *slot = value[i];
    }
    return NGX_CONF_OK;
}

/*
 * brix_conf_set_backend_tx_endpoint — setter for
 * "brix_backend_token_exchange_endpoint <url>" (P90-70.8 slice of the phase-70
 * §6 invariant: trust config is validated at LOAD, not first use).  The
 * runtime exchange client (auth/token/exchange.c brix_tx_http_post) pins
 * libcurl to HTTPS-only — a subject token and the client secret ride every
 * request — so a non-https endpoint can never succeed; without this check it
 * would only surface as every EXCHANGE delegation failing (fail-closed deny)
 * at first use.  Reject it at nginx -t time instead: https:// scheme, a
 * non-empty host, and no whitespace/control bytes (the value is handed to
 * CURLOPT_URL verbatim).
 */
char *
brix_conf_set_backend_tx_endpoint(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    char       *rv;
    ngx_str_t  *ep;
    ngx_uint_t  i;

    rv = ngx_conf_set_str_slot(cf, cmd, conf);
    if (rv != NGX_CONF_OK) {
        return rv;
    }
    ep = (ngx_str_t *) ((char *) conf + cmd->offset);

    if (ep->len <= sizeof("https://") - 1
        || ngx_strncasecmp(ep->data, (u_char *) "https://", 8) != 0
        || ep->data[8] == '/') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_backend_token_exchange_endpoint: \"%V\" is not an https:// "
            "URL with a host — the exchange client is HTTPS-only (a subject "
            "token and the client secret ride every request), so this "
            "endpoint could never be reached", ep);
        return NGX_CONF_ERROR;
    }
    for (i = 0; i < ep->len; i++) {
        if (ep->data[i] <= ' ' || ep->data[i] == 0x7f) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "brix_backend_token_exchange_endpoint: whitespace or control "
                "byte at offset %ui", i);
            return NGX_CONF_ERROR;
        }
    }
    return NGX_CONF_OK;
}
