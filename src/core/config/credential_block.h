#ifndef BRIX_CONFIG_CREDENTIAL_BLOCK_H
#define BRIX_CONFIG_CREDENTIAL_BLOCK_H

/*
 * credential_block.h — the reusable `brix_credential <name> { … }` config block
 * (phase-63 §14).
 *
 * WHAT: A named, declared-once identity a server uses to reach an UPSTREAM (a
 *       source backend, the cache fill / write-back flush, or — later — the
 *       proxy/TPC upstream). Parses into a small POD, interned by name, looked up
 *       by `credential=<name>` (or the sibling `brix_storage_credential <name>`)
 *       on the consuming directive.
 *
 * WHY:  Today the same X.509-proxy + CA + bearer-token vocabulary is spelled five
 *       different ways across the cache-origin, stream-proxy and WebDAV-proxy
 *       config families (§14.1). One block, referenced everywhere, replaces that
 *       fragmentation — "identity is a property of the source, not of each
 *       subsystem that reaches it".
 *
 * HOW:  `brix_conf_credential_block()` is an nginx block handler (the ngx_map /
 *       ngx_geo pattern): it records the name then re-enters ngx_conf_parse with a
 *       per-line handler that fills one field per nested directive. The result is
 *       interned in a small per-process table. `brix_credential_lookup()` finds a
 *       block by name; `brix_credential_bearer()` resolves its bearer token
 *       (inline `token`, else the contents of `token_file`). The X.509 fields are
 *       parsed and stored for C-3 (in-process GSI) but not yet consumed here.
 */

#include <ngx_config.h>
#include <ngx_core.h>

/* Parsed `brix_credential` block (§14.4 shape). Empty fields ⇒ unset. */
typedef struct {
    ngx_str_t   name;            /* the block's name (lookup key)                 */
    ngx_str_t   x509_proxy;      /* a ready VOMS/grid proxy PEM path  (C-3)       */
    ngx_str_t   x509_cert;       /* host cert PEM path                (C-3)       */
    ngx_str_t   x509_key;        /* host key PEM path                 (C-3)       */
    ngx_str_t   ca_dir;          /* CA dir to verify the upstream     (C-3)       */
    ngx_str_t   token;           /* inline bearer token                           */
    ngx_str_t   token_file;      /* path to a bearer token (WLCG / SciToken)      */
    ngx_flag_t  token_forward;   /* on = delegate the CLIENT's token (C-3)        */
    ngx_flag_t  tls;             /* roots:// / https to the upstream              */
    ngx_str_t   vo;              /* optional VOMS FQAN                (C-3)        */
    ngx_str_t   s3_access_key;   /* S3 SigV4 access-key id      (s3:// backend)   */
    ngx_str_t   s3_secret_key;   /* S3 SigV4 secret key         (s3:// backend)   */
    ngx_str_t   s3_region;       /* S3 SigV4 region scope       (s3:// backend)   */
    ngx_str_t   sss_keytab;      /* SSS shared-secret keytab    (root:// origin)  */
    void       *last_def_cycle;  /* ngx_cycle* of the config parse that last defined
                                  * this name — used ONLY to distinguish a benign
                                  * reload re-parse (different cycle) from a genuine
                                  * duplicate definition within one config (same
                                  * cycle), which silently last-wins and must warn. */
} brix_credential_t;

/* The `brix_credential <name> { … }` block directive handler (stream scope). */
char *brix_conf_credential_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

/* Find a declared credential by name (NUL-terminated `name`), or NULL. The
 * returned pointer is stable for the process lifetime (interned on the cf pool). */
const brix_credential_t *brix_credential_lookup(const char *name);

/* Resolve a credential's bearer token into `out` (NUL-terminated, truncated to
 * cap): the inline `token` if set, else the first line of `token_file`. Returns
 * NGX_OK with *out set (or "" when the credential carries no token), or NGX_ERROR
 * if token_file is set but unreadable. NULL cred ⇒ "" + NGX_OK (anonymous). */
ngx_int_t brix_credential_bearer(const brix_credential_t *cred, char *out,
    size_t cap, ngx_log_t *log);

#endif /* BRIX_CONFIG_CREDENTIAL_BLOCK_H */
