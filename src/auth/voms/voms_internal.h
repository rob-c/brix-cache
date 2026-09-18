#ifndef BRIX_VOMS_INTERNAL_H
#define BRIX_VOMS_INTERNAL_H

/*
 * voms_internal.h — the module side of native VOMS attribute-certificate support
 *
 * WHAT: The nginx-facing wrappers around the shared engine (shared/voms/):
 *       a per-worker trust-store cache for the VOMS server chain, the
 *       extraction entry points declared in ngx_brix_module.h / voms_http.h,
 *       and the collector that renders verified entries into the flat VO and
 *       FQAN views the identity layer consumes.
 * WHY:  The project carries no dependency on libvomsapi any more: every AC is
 *       decoded and verified in plain C over OpenSSL by shared/voms/voms_ac.h.
 * HOW:  extract.c builds a brix_voms_trust_t (store from trust.c, the
 *       configured vomsdir) and calls brix_voms_retrieve; collect.c walks the
 *       entries whose verdict is BRIX_VOMS_OK.
 */

#include "core/ngx_brix_module.h"
#include "auth/voms/voms_io.h"
#include "voms/voms_ac.h"
#include <openssl/x509.h>

/* A notBefore up to this far in the future is accepted (clock skew between
 * the VOMS server and this host); notAfter is strict. */
#define BRIX_VOMS_SKEW_SECONDS 300

/*
 * The X509_STORE that verifies VOMS server certificate chains for one CA
 * directory: the one brix_voms_warm built at configuration time (inherited by
 * the workers through the module's CA-store cache), or built on first use.
 * Returns an owned reference (X509_STORE_free when done); NULL when the
 * directory cannot be loaded (the caller then rejects the AC).
 */
X509_STORE *brix_voms_trust_store(ngx_log_t *log, const ngx_str_t *cert_dir);

/* Render the verified entries of `res` into the caller's views. */
ngx_int_t brix_collect_voms_vos(const brix_voms_result_t *res,
    const brix_voms_out_t *out);

#endif /* BRIX_VOMS_INTERNAL_H */
