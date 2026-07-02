/*
 * token_cache.h — cross-worker JWT validation cache.
 *
 * Bearer tokens are re-presented on every stateless HTTP request and across
 * many TCP connections / worker processes, so the RSA/ECDSA signature
 * verification (the most expensive single hot-path operation) repeats
 * needlessly.  This cache keys verified claims on the SHA-256 fingerprint of
 * the raw token bytes and serves them until the token's own `exp` (capped at
 * five minutes), letting repeated presentations skip EVP_DigestVerify.
 *
 * Only successfully verified claims are ever stored; failures are never
 * cached.  Revocation cannot be detected once cached — the standard tradeoff
 * for stateless JWT validation, bounded here by the short TTL cap.
 */
#ifndef XROOTD_TOKEN_TOKEN_CACHE_H
#define XROOTD_TOKEN_TOKEN_CACHE_H

#include "core/shm/kv.h"
#include "token.h"

/*
 * xrootd_token_cache_lookup() — return 1 and populate *claims if the raw
 * token's fingerprint is cached and not yet expired; 0 otherwise.
 */
int xrootd_token_cache_lookup(xrootd_kv_t *kv, const char *token,
    size_t token_len, xrootd_token_claims_t *claims);

/*
 * xrootd_token_cache_store() — cache verified claims under the token
 * fingerprint with TTL = min(exp - now, 5 min).  No-op if already expired.
 */
void xrootd_token_cache_store(xrootd_kv_t *kv, const char *token,
    size_t token_len, const xrootd_token_claims_t *claims);

/*
 * xrootd_token_cache_directive() — setter for `xrootd_token_cache zone=<name>;`
 * Resolves the named KV zone and stores it in the conf field at cmd->offset
 * (an xrootd_kv_t * slot).  Valid in stream server and http location blocks.
 */
char *xrootd_token_cache_directive(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

#endif /* XROOTD_TOKEN_TOKEN_CACHE_H */
