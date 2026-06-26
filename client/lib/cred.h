/* client/lib/cred.h
 *
 * cred.h — common credential acquisition for the client tools.
 *
 * WHAT: one store that discovers, loads, caches, and refreshes each credential
 *       kind (X.509 proxy, bearer token, Kerberos TGT, SSS keytab, S3 keys) and
 *       serves BOTH the root:// auth handshake (the lib/sec modules) and the HTTP/S3
 *       transports (webfile.c, s3.c) from a single source of truth.
 * WHY:  discovery/refresh logic is duplicated across sec_gsi.c/sec_token.c/
 *       sec_sss.c/sec_krb5.c/credrefresh.c, and the HTTP path acquires bearers
 *       separately from the root:// token module. One store removes the drift
 *       and lets --auto-refresh cover every kind uniformly.
 * HOW:  per-kind handlers (cred_x509.c etc.) implement available/acquire/refresh;
 *       the store caches the result with an expiry and re-acquires when a caller
 *       asks for a credential within min_remaining_s of expiry. ngx-free.
 */
#ifndef XRDC_CRED_H
#define XRDC_CRED_H

#include "xrdc.h"
#include <stdint.h>

typedef enum {
    XRDC_CRED_X509_PROXY = 0, /* GSI proxy PEM (root:// gsi + davs:// TLS client + http TPC) */
    XRDC_CRED_BEARER,         /* WLCG/OIDC bearer (root:// ztn + HTTP Authorization)          */
    XRDC_CRED_KRB5,           /* Kerberos TGT ccache                                          */
    XRDC_CRED_SSS,            /* shared-secret keytab                                          */
    XRDC_CRED_S3KEYS,         /* AWS access/secret for SigV4                                  */
    XRDC_CRED_KIND_COUNT
} xrdc_cred_kind;

/* A read-only snapshot a consumer uses. Strings are owned by the store and stay
 * valid until the next acquire of the SAME kind on the SAME store. */
typedef struct {
    xrdc_cred_kind kind;
    const char    *path;       /* proxy/keytab/ccache path, or NULL                 */
    const char    *token;      /* bearer string, or NULL                            */
    const char    *s3_access;  /* S3 access key, or NULL                            */
    const char    *s3_secret;  /* S3 secret key, or NULL                            */
    int64_t        not_after;  /* unix expiry; 0 = unknown/none                     */
} xrdc_cred_view;

/* Explicit overrides (from CLI flags); empty/NULL fields fall back to env/default
 * discovery — preserving today's per-protocol precedence exactly. */
typedef struct {
    const char *proxy_path;     /* --proxy   / $X509_USER_PROXY (else /tmp/x509up_u<uid>) */
    const char *bearer_literal; /* $BEARER_TOKEN                                          */
    const char *bearer_path;    /* $BEARER_TOKEN_FILE (else $XDG_RUNTIME_DIR/bt_u<uid>)   */
    const char *keytab_path;    /* $XrdSecSSSKT / $XrdSecsssKT / ~/.xrd/sss.keytab        */
    const char *ccache;         /* $KRB5CCNAME                                            */
    const char *s3_access;      /* --s3-access / $AWS_ACCESS_KEY_ID                       */
    const char *s3_secret;      /* --s3-secret / $AWS_SECRET_ACCESS_KEY                   */
    const char *oidc_account;   /* --oidc-account / $OIDC_ACCOUNT (bearer refresh)        */
    int         auto_refresh;   /* 1 = proactively re-acquire near expiry                 */
} xrdc_cred_config;

typedef struct xrdc_cred_store xrdc_cred_store;

xrdc_cred_store *xrdc_cred_store_new(const xrdc_cred_config *cfg);
void             xrdc_cred_store_free(xrdc_cred_store *s);

/* Acquire (discover+load, cached). If auto_refresh and the cached credential is
 * within min_remaining_s of expiry, re-acquire first. 0 + *view, or -1 (st) if no
 * usable credential of that kind exists. min_remaining_s <= 0 disables the check. */
int xrdc_cred_acquire(xrdc_cred_store *s, xrdc_cred_kind kind,
                      int min_remaining_s, xrdc_cred_view *view, xrdc_status *st);

/* Probe only (no load) — does a usable credential of this kind appear available?
 * Mirrors the sec-module have_creds() probe for auth pre-flight diagnostics. */
int xrdc_cred_available(xrdc_cred_store *s, xrdc_cred_kind kind);

/* Per-kind handler contract (implemented by cred_x509.c, cred_bearer.c, …). */
typedef struct {
    xrdc_cred_kind kind;
    int (*available)(const xrdc_cred_config *cfg);
    /* acquire() fills *out and *not_after on success (returns 0) or sets *st
     * and returns -1.  LIFETIME CONTRACT (applies to ALL handlers — B3-B6):
     * acquire() must write out->{path,token,s3_access,s3_secret} as pointers
     * to storage that remains valid until acquire() RETURNS — the store copies
     * (strdup) them immediately afterward.  Do NOT point them at acquire()'s
     * own stack locals; use static or otherwise non-stack storage. */
    int (*acquire)(const xrdc_cred_config *cfg, xrdc_cred_view *out,
                   int64_t *not_after, xrdc_status *st);
    int (*refresh)(const xrdc_cred_config *cfg, xrdc_status *st);  /* NULL = no refresh */
} xrdc_cred_handler;

/* Handler accessors (NULL when compiled out, e.g. krb5 without XROOTD_HAVE_KRB5). */
const xrdc_cred_handler *xrdc_cred_x509(void);
const xrdc_cred_handler *xrdc_cred_bearer(void);
const xrdc_cred_handler *xrdc_cred_krb5(void);
const xrdc_cred_handler *xrdc_cred_sss(void);
const xrdc_cred_handler *xrdc_cred_s3keys(void);

#endif /* XRDC_CRED_H */
