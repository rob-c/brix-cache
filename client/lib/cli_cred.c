/*
 * client/lib/cli_cred.c — CLI-to-credential-store builder.
 *
 * WHAT: maps per-tool CLI values (proxy path, bearer token, S3 keys, OIDC
 *       account, auto-refresh flag) into an xrdc_cred_config and returns a
 *       live xrdc_cred_store.
 * WHY:  every connecting tool (xrdcp, xrdfs, xrootdfs) needs to perform this
 *       same mapping — NULL/empty field → fall back to env/default discovery —
 *       without duplicating the logic or pulling cred.h into every app.
 * HOW:  each field is only populated when the caller supplies a non-NULL,
 *       non-empty string, so empty string == "not set" and the per-handler
 *       env/default discovery path runs unchanged.  The function is a pure
 *       builder: it allocates nothing itself — xrdc_cred_store_new does — and
 *       it has no side effects beyond that allocation.
 */
#include "cred.h"
#include "xrdc.h"

#include <string.h>

/*
 * Credential-handler linkage anchor.
 *
 * xrdc_cred_store_new() discovers handlers through WEAK accessors (cred.c). A
 * weak *undefined* reference does NOT pull the defining object out of the static
 * libxrdc.a, so a statically-linked tool would otherwise build a store with NO
 * handlers — xrdc_cred_available() then always returns 0 and GSI/token/sss are
 * silently skipped (this was the cause of an "no usable auth protocol"
 * regression in xrdcp). Referencing the accessors STRONGLY here — from the one
 * TU every cred-store tool already links (xrdc_cli_cred_store_build) — forces
 * cred_x509.o / cred_bearer.o / cred_sss.o / cred_krb5.o / cred_s3.o into the
 * link so the store is actually populated. The accessors stay weak elsewhere,
 * so a tool that does NOT use the CLI cred store is unaffected.
 */
extern const xrdc_cred_handler *xrdc_cred_x509(void);
extern const xrdc_cred_handler *xrdc_cred_bearer(void);
extern const xrdc_cred_handler *xrdc_cred_sss(void);
extern const xrdc_cred_handler *xrdc_cred_krb5(void);
extern const xrdc_cred_handler *xrdc_cred_s3keys(void);

const xrdc_cred_handler *(*const xrdc_cli_cred_handler_anchor[])(void)
    __attribute__((used)) = {
    xrdc_cred_x509, xrdc_cred_bearer, xrdc_cred_sss,
    xrdc_cred_krb5, xrdc_cred_s3keys,
};

/*
 * xrdc_cli_cred_store_build — build a credential store from CLI/env values.
 *
 * WHAT: constructs an xrdc_cred_config from the caller's parsed CLI values and
 *       delegates to xrdc_cred_store_new.
 * WHY:  centralises the NULL/empty-guard logic so each tool front-end provides
 *       its parsed values without needing to know the config field names.
 * HOW:  each field is copied into the config only when the source string is
 *       non-NULL and non-empty; otherwise the field stays NULL so the per-kind
 *       handler falls back to its env/default discovery path.  auto_refresh is
 *       forwarded directly (it's an int flag, not a string).
 *
 * Returns a new store on success, or NULL on OOM (xrdc_cred_store_new failure).
 * The caller frees with xrdc_cred_store_free.
 */
struct xrdc_cred_store *
xrdc_cli_cred_store_build(const char *proxy,
                           const char *bearer,
                           const char *bearer_file,
                           const char *s3_access,
                           const char *s3_secret,
                           const char *oidc_account,
                           int         auto_refresh)
{
    xrdc_cred_config cfg;
    memset(&cfg, 0, sizeof(cfg));

    /* Only propagate non-NULL, non-empty strings so that an absent/empty CLI
     * flag leaves the field NULL — letting the per-kind handler discover the
     * credential from its env/default path instead. */
    if (proxy        != NULL && *proxy        != '\0') cfg.proxy_path     = proxy;
    if (bearer       != NULL && *bearer       != '\0') cfg.bearer_literal = bearer;
    if (bearer_file  != NULL && *bearer_file  != '\0') cfg.bearer_path    = bearer_file;
    if (s3_access    != NULL && *s3_access    != '\0') cfg.s3_access      = s3_access;
    if (s3_secret    != NULL && *s3_secret    != '\0') cfg.s3_secret      = s3_secret;
    if (oidc_account != NULL && *oidc_account != '\0') cfg.oidc_account   = oidc_account;
    cfg.auto_refresh = auto_refresh;

    return xrdc_cred_store_new(&cfg);
}
