/*
 * brix_auth.h - auth / credential / proxy decls
 * Phase-38 umbrella split of brix.h; included via brix.h (relies on the
 * core types declared there first).  Do not include this directly.
 */
#ifndef XRDC_AUTH_H
#define XRDC_AUTH_H

/* ---- auth.c ---- */
/* Drive the kXR_auth/authmore loop for the server's "&P=..." security list. */
int  brix_authenticate(brix_conn *c, const char *seclist, const brix_opts *o,
                       brix_status *st);
/* §15 `xrdfs explain`: narrate the &P= list (c->sec_list), which protocol the
 * client would pick and why each other was skipped (no creds / not offered). */
void brix_auth_explain(brix_conn *c, const brix_opts *o, FILE *out);

/* ---- sec/sec_token.c ---- */
/* Discover a bearer token (BEARER_TOKEN / BEARER_TOKEN_FILE / $XDG_RUNTIME_DIR or
 * /tmp/bt_u<uid>); malloc'd string or NULL. Shared with credinfo.c. */
char *brix_token_discover(void);

/* ---- credinfo.c (§15.2 credential introspection) ---- */
/* Best-effort decoders for `explain`; each prints to `out` and never fails hard.
 * token: base64url-decode the JWT payload, show iss/sub/aud/scope/exp + EXPIRED
 * (no signature verify). gsi cert: subject/issuer/notAfter + VOMS FQANs + skew. */
void brix_token_explain(const char *jwt, FILE *out);
void brix_gsi_cert_explain(const char *proxy_path, FILE *out);

/* Machine-readable bearer-token facts (validity + WLCG scope), for the auth-suite
 * to predict whether the server should allow/deny an op. No signature verify. */
typedef struct {
    int  valid;       /* 1 = JWT payload parsed */
    long exp;         /* exp claim (epoch), 0 if absent */
    int  expired;     /* exp present and in the past (local clock) */
    int  has_scope;   /* a scope claim was present */
    int  has_read;    /* scope grants read  (storage.read / read:) */
    int  has_write;   /* scope grants write (storage.write/create/modify) */
} brix_token_meta;
void brix_token_meta_get(const char *jwt, brix_token_meta *m);

/* Phase 40 (c): client-side credential pre-flight / failure diagnostics.
 * brix_cred_diagnose inspects whatever credential is present locally (bearer
 * token via brix_token_discover, then GSI proxy at the default path) WITHOUT any
 * network call or signature verification, and prints a specific, actionable hint
 * to `out` (each line prefixed by `prefix`) when it finds a likely auth problem:
 * an expired/near-expiry token or proxy, or — when want_write is set — a token
 * that grants read scope only.  Returns 1 if a likely-fatal local problem was
 * found, else 0.  So the user sees "token expired 3m ago" instantly instead of a
 * bare "permission denied".
 * brix_cred_hint_for_status calls it (with an indented hint prefix) only when
 * `st` carries an auth/authz wire error (kXR_NotAuthorized / kXR_AuthFailed),
 * for one-line use at an app's error-reporting site. */
int  brix_cred_diagnose(int want_write, const char *prefix, FILE *out);
void brix_cred_hint_for_status(const brix_status *st, int want_write, FILE *out);

/* Phase 40 (b): proactively (re)acquire a stale credential before a transfer —
 * a bearer token via the local oidc-agent (`oidc-token <account>`; account from
 * arg or $OIDC_ACCOUNT) installed into $BEARER_TOKEN, and/or a GSI proxy via
 * brix_proxy_create when one is missing/expired/near-expiry and a user cert
 * exists. Best-effort and fail-soft: returns the count refreshed (0 = nothing to
 * do / no source). Opt-in from xrdcp --auto-refresh. (credrefresh.c) */
int  brix_cred_autorefresh(int want_write, const char *oidc_account,
                           int verbose, FILE *out);

/* ---- proxy.c (xrdgsiproxy: RFC-3820 X.509 proxy create/info/destroy) ---- */
/* If the session has a signing key and the server's security level requires it
 * for this opcode, send a kXR_sigver frame covering hdr24(+payload) and consume
 * its kXR_ok before the real request. No-op otherwise. 0 / -1. */
int  brix_sigver_maybe(brix_conn *c, const uint8_t *hdr24, const void *payload,
                       uint32_t plen, brix_status *st);

#endif /* XRDC_AUTH_H */
