#ifndef XROOTD_TPC_COMMON_CREDENTIAL_H
#define XROOTD_TPC_COMMON_CREDENTIAL_H

/* ---- Module: TPC Delegated Credential Model ----
 *
 * WHAT: Protocol-neutral representation of the credential a third-party copy
 *       carries to authenticate against the remote endpoint. Defines
 *       xrootd_tpc_credential_type_t (NONE / PROXY / TOKEN), the
 *       xrootd_tpc_credential_t value object (proxy_pem, bearer, identity,
 *       expires_at), and the parse/validate/type-name entry points implemented
 *       in credential.c.
 *
 * WHY: Both the stream (root://) and WebDAV (davs://) TPC paths must accept the
 *      same delegated-credential forms — a GSI proxy PEM or a WLCG bearer token
 *      — yet historically each transport parsed credentials its own way. A
 *      single typed model lets the shared TPC core normalise the credential
 *      once and reason about expiry uniformly.
 *
 * HOW: xrootd_tpc_credential_parse() sniffs the raw credential (honouring an
 *      optional caller hint, the "Bearer " prefix, or a "-----BEGIN" PEM
 *      marker) into a typed xrootd_tpc_credential_t; xrootd_tpc_credential_validate()
 *      rejects empty or expired credentials; xrootd_tpc_credential_type_name()
 *      maps the enum to a stable log/metric string.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include "core/types/identity.h"

typedef enum {
    XROOTD_TPC_CREDENTIAL_NONE  = 0,
    XROOTD_TPC_CREDENTIAL_PROXY = 1,
    XROOTD_TPC_CREDENTIAL_TOKEN = 2,
} xrootd_tpc_credential_type_t;

typedef struct {
    xrootd_tpc_credential_type_t  type;
    ngx_str_t                     proxy_pem;
    ngx_str_t                     bearer;
    xrootd_identity_t            *identity;
    time_t                        expires_at;
} xrootd_tpc_credential_t;

/* Sniff a raw credential into *cred (zeroed first), classifying it via the
 * caller hint or the "Bearer "/"-----BEGIN" markers after trimming surrounding
 * whitespace/CRLF; the "Bearer " prefix is stripped from tokens. Empty/NULL
 * input or the literal "none" yields type NONE. When pool is non-NULL the value
 * is copied NUL-terminated into it; when pool is NULL *cred aliases the caller's
 * bytes (borrowed, must outlive cred). Returns NGX_OK, NGX_DECLINED for an
 * unrecognised format, or NGX_ERROR on NULL cred / allocation failure. */
ngx_int_t xrootd_tpc_credential_parse(const ngx_str_t *raw_credential,
    xrootd_tpc_credential_type_t hint, xrootd_tpc_credential_t *cred,
    ngx_pool_t *pool, ngx_log_t *log);

/* Validate a parsed credential: PROXY/TOKEN must carry a non-empty body, and a
 * non-zero cred->expires_at must lie in the future relative to ngx_time(); NONE
 * always passes. Read-only. Returns NGX_OK, NGX_DECLINED if empty/expired/of an
 * unknown type, or NGX_ERROR on NULL cred. */
ngx_int_t xrootd_tpc_credential_validate(
    const xrootd_tpc_credential_t *cred, ngx_log_t *log);

/* Map a credential type to a stable lowercase log/metric string ("none",
 * "proxy", "token", or "unknown"). Returns a static literal; never NULL. */
const char *xrootd_tpc_credential_type_name(
    xrootd_tpc_credential_type_t type);

#endif /* XROOTD_TPC_COMMON_CREDENTIAL_H */
