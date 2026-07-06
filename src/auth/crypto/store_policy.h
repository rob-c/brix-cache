/*
 * store_policy.h — signing_policy table + X509_STORE ex_data binding.
 *
 * WHAT: Builds a per-CA-directory table of parsed signing_policy files and
 *       attaches it (with the operator's signing_policy + CRL modes) to an
 *       X509_STORE, so the shared verifier and every store-rebuild path
 *       inherit enforcement from a single place.
 * WHY:  The verifier (brix_gsi_verify_chain) must decide "may this CA sign
 *       this subject?" without threading extra parameters through every
 *       caller.  Binding the table to the store lets the decision travel with
 *       the trust material — including the stream CRL-reload rebuild and the
 *       WebDAV build-once path, which do not share a config object.
 * HOW:  ngx-free at its core (uses signing_policy.h + libc); the OpenSSL glue
 *       lives here.  Logging is via a caller-supplied callback so no ngx
 *       symbol is required.  The store owns the attached table and frees it.
 */
#ifndef BRIX_CRYPTO_STORE_POLICY_H
#define BRIX_CRYPTO_STORE_POLICY_H

#include "auth/crypto/signing_policy.h"

#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

/* CRL strictness, carried on the store alongside the signing_policy mode. */
#define BRIX_CRL_MODE_OFF     0   /* never set CRL verify flags */
#define BRIX_CRL_MODE_TRY     1   /* check where a CRL exists; missing = ok */
#define BRIX_CRL_MODE_REQUIRE 2   /* missing/expired/unverifiable CRL = reject */

typedef struct brix_sp_table_s brix_sp_table_t;

/* Logging callback: level is one of the BRIX_SP_LOG_* values below. */
#define BRIX_SP_LOG_WARN  1
#define BRIX_SP_LOG_INFO  2
typedef void (*brix_sp_log_fn)(void *log, int level, const char *msg);

/*
 * Scan cadir for <hash>.signing_policy files and compile them into a table.
 * A NULL cadir yields an empty (never-present) table.  A file that fails to
 * parse is recorded as a poisoned entry (its CA is rejected at check time)
 * and reported once via log_fn.  Caller owns the result unless it is handed
 * to brix_store_policy_attach() (which takes ownership).
 */
brix_sp_table_t *brix_sp_table_build(const char *cadir,
                                     void *log, brix_sp_log_fn log_fn);

void brix_sp_table_free(brix_sp_table_t *t);

/*
 * Decide whether ca may sign subject under mode.
 *   OFF     → always 1.
 *   ON      → 1 if no policy file is present for ca; else enforce.
 *   REQUIRE → a granting policy file must be present and allow the subject.
 * A present-but-malformed or wrong-CA file fails closed (returns 0) in ON and
 * REQUIRE.  Returns 1 to allow, 0 to deny.
 */
int brix_sp_table_check(const brix_sp_table_t *t, brix_sp_mode_t mode,
                        X509 *ca, X509 *subject);

/*
 * Attach table + modes to a store.  The store takes ownership of table and
 * frees it when the store is freed.  Returns 1 on success, 0 on failure
 * (in which case the caller retains ownership of table).
 */
int brix_store_policy_attach(X509_STORE *store, brix_sp_table_t *table,
                             brix_sp_mode_t sp_mode, int crl_mode);

/* Fetch what was attached, resolved from a verification context's store. */
brix_sp_table_t *brix_store_policy_table(X509_STORE_CTX *ctx);
brix_sp_mode_t   brix_store_policy_mode(X509_STORE_CTX *ctx);
int              brix_store_crl_mode(X509_STORE_CTX *ctx);

/*
 * Shared DN canonicaliser — OpenSSL oneline slash form into buf.  Used on
 * BOTH the policy side and the cert side so escaping can never diverge.
 * Returns buf (NUL-terminated), or an empty string on failure.
 */
char *brix_x509_oneline(X509_NAME *name, char *buf, size_t buflen);

#endif /* BRIX_CRYPTO_STORE_POLICY_H */
