/* client/lib/cred_x509.c
 *
 * WHAT: X.509 proxy credential handler for the unified credential store (cred.c).
 *       Implements brix_cred_x509() returning the XRDC_CRED_X509_PROXY handler
 *       with available / acquire / refresh operations.
 * WHY:  Proxy discovery (path resolution, readability probe, cert expiry) was
 *       duplicated across sec_gsi.c and credrefresh.c.  Centralising it here
 *       makes the store the single source of truth, so auto-refresh and auth
 *       pre-flight diagnostics share the same logic.
 * HOW:  Path resolution mirrors sec_gsi.c:proxy_path() exactly:
 *         cfg->proxy_path  (CLI --proxy override)
 *         > $X509_USER_PROXY  (environment)
 *         > /tmp/x509up_u<euid>  (default)
 *       available() probes with access(R_OK).  acquire() resolves the path,
 *       confirms readability, then best-effort parses the first PEM certificate's
 *       notAfter via OpenSSL to fill *not_after (0 on parse failure, which is
 *       acceptable for non-PEM stubs used in tests).  refresh() is a documented
 *       no-op for B3; full wiring to credrefresh.c is deferred to task C2 because
 *       brix_cred_autorefresh() takes (want_write, oidc_account, verbose, out)
 *       rather than (cfg, st), requiring a small adapter that is out of scope here.
 *
 * ngx-free.  No goto.  Functional/modular: one responsibility per function.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "cred.h"
#include "brix.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

/* path resolution */
/*
 * resolve_proxy_path — fill out[outsz] with the resolved X.509 proxy path.
 *
 * WHAT: implements the three-level precedence: cfg->proxy_path > $X509_USER_PROXY
 *       > /tmp/x509up_u<euid>.
 * WHY:  mirrors sec_gsi.c:proxy_path() exactly (sec_gsi.c:34-44); one canonical
 *       definition rather than two separate copies.
 * HOW:  three early-return snprintf branches; the result is always NUL-terminated
 *       (snprintf guarantees it within outsz).
 */
static void
resolve_proxy_path(const brix_cred_config *cfg, char *out, size_t outsz)
{
    const char *env;

    if (cfg != NULL && cfg->proxy_path != NULL && cfg->proxy_path[0] != '\0') {
        snprintf(out, outsz, "%s", cfg->proxy_path);
        return;
    }
    env = getenv("X509_USER_PROXY");
    if (env != NULL && env[0] != '\0') {
        snprintf(out, outsz, "%s", env);
        return;
    }
    snprintf(out, outsz, "/tmp/x509up_u%u", (unsigned)geteuid());
}

/* cert expiry parsing */
/*
 * parse_notafter — extract the first cert's notAfter from a PEM file as a
 * Unix timestamp.
 *
 * WHAT: opens path as a BIO, reads the first PEM certificate, converts its
 *       notAfter ASN1_TIME to seconds-since-epoch via ASN1_TIME_diff vs epoch.
 * WHY:  best-effort: the store records not_after so the expiry gate and the
 *       auto-refresh path can act before the proxy expires mid-transfer.
 * HOW:  BIO_new_file + PEM_read_bio_X509 + ASN1_TIME_diff(epoch, notAfter).
 *       Any failure returns -1; the caller maps -1 to not_after=0 (unknown/none)
 *       and still reports a successful acquire.
 *       ASN1_TIME_diff reports (days, seconds) relative to a base time; using
 *       the Unix epoch as the base gives seconds-since-epoch directly without
 *       timegm() (which is a GNU extension).
 */
static int
parse_notafter(const char *path, int64_t *result)
{
    BIO              *bio;
    X509             *cert;
    ASN1_TIME        *epoch;
    const ASN1_TIME  *na;
    int               day, sec;

    bio = BIO_new_file(path, "r");
    if (bio == NULL) {
        return -1;
    }
    cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (cert == NULL) {
        return -1;
    }

    na = X509_get0_notAfter(cert);
    if (na == NULL) {
        X509_free(cert);
        return -1;
    }

    /* Use Unix epoch (time 0) as the diff base so day*86400+sec gives
     * the absolute Unix timestamp directly. */
    epoch = ASN1_TIME_new();
    if (epoch == NULL) {
        X509_free(cert);
        return -1;
    }
    ASN1_TIME_set(epoch, (time_t)0);

    if (ASN1_TIME_diff(&day, &sec, epoch, na) != 1) {
        ASN1_TIME_free(epoch);
        X509_free(cert);
        return -1;
    }
    ASN1_TIME_free(epoch);
    X509_free(cert);

    *result = (int64_t)day * 86400 + (int64_t)sec;
    return 0;
}

/* handler callbacks */
/*
 * x509_available — 1 if the resolved proxy path exists and is readable.
 *
 * WHAT: fast probe used by auth pre-flight diagnostics and the cred store's
 *       brix_cred_available() API.  Does NOT load the cert.
 * WHY:  matches sec_gsi.c:gsi_have() semantics (access(R_OK) on resolved path).
 * HOW:  resolve path; access(path, R_OK).
 */
static int
x509_available(const brix_cred_config *cfg)
{
    char path[512];
    resolve_proxy_path(cfg, path, sizeof(path));
    return access(path, R_OK) == 0 ? 1 : 0;
}

/*
 * x509_acquire — resolve the proxy path, confirm readability, fill *out and
 * *not_after.
 *
 * WHAT: the store's acquire call; fills out->path and best-effort cert expiry.
 * WHY:  single canonical acquire path for the proxy credential.
 * HOW:  1) resolve path; 2) access(R_OK) → XRDC_ENOENT on failure;
 *       3) fill out; 4) parse_notafter (best-effort; 0 on parse failure).
 *       A non-PEM file (e.g. an empty test stub) returns not_after==0 but
 *       still returns 0 (success) — the proxy path itself is the credential.
 *
 * Lifetime of `path`: declared static so the buffer remains valid after this
 * function returns.  The caller (do_acquire → slot_store_view) strdup's
 * out->path immediately after acquire() returns — before any other acquire
 * call can overwrite the buffer.  The store is single-threaded per acquire,
 * so the single static buffer is safe for this window.
 */
static int
x509_acquire(const brix_cred_config *cfg, brix_cred_view *out,
             int64_t *not_after, brix_status *st)
{
    /* static: must outlive this return so slot_store_view can strdup it. */
    static char path[512];

    resolve_proxy_path(cfg, path, sizeof(path));

    if (access(path, R_OK) != 0) {
        brix_status_set(st, XRDC_ENOENT, 0,
                        "x509 proxy not found or not readable: %s", path);
        return -1;
    }

    out->kind  = XRDC_CRED_X509_PROXY;
    out->path  = path;   /* static buffer; store deep-copies via slot_store_view */
    out->token     = NULL;
    out->s3_access = NULL;
    out->s3_secret = NULL;

    /* Best-effort expiry: 0 is acceptable if the file is not a parseable PEM
     * (e.g. an empty test stub); the store treats 0 as "no expiry known". */
    if (parse_notafter(path, not_after) != 0) {
        *not_after = 0;
    }

    return 0;
}

/*
 * x509_refresh — documented no-op for task B3.
 *
 * WHAT: called by the store when auto_refresh is set and the proxy is near
 *       expiry; currently does nothing.
 * WHY:  credrefresh.c's brix_cred_autorefresh(want_write, oidc_account, verbose,
 *       out) does not match the (cfg, st) handler contract.  Adapting it (mapping
 *       cfg->oidc_account into the call and running the proxy regeneration path)
 *       is deferred to task C2, where the full auth suite validates the end-to-end
 *       refresh path.  Returning 0 is correct: the store treats a non-zero return
 *       as best-effort advisory only (it still re-acquires after refresh).
 * HOW:  no-op; suppress unused-parameter warnings.
 */
static int
x509_refresh(const brix_cred_config *cfg, brix_status *st)
{
    (void)cfg;
    (void)st;
    return 0;   /* no-op; C2 will wire brix_cred_autorefresh here */
}

/* handler accessor */
static const brix_cred_handler s_x509_handler = {
    .kind      = XRDC_CRED_X509_PROXY,
    .available = x509_available,
    .acquire   = x509_acquire,
    .refresh   = x509_refresh,
};

/*
 * brix_cred_x509 — return the static X.509 proxy handler.
 *
 * WHAT: strong definition that overrides the weak accessor in cred.c.
 * WHY:  weak/strong pattern lets lib and unit-test binaries link without every
 *       handler compiled in; this file provides the real X509 implementation.
 * HOW:  returns a pointer to the file-scoped static handler struct.
 */
const brix_cred_handler *
brix_cred_x509(void)
{
    return &s_x509_handler;
}
