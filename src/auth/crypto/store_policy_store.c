/*
 * store_policy_store.c — X509_STORE configuration (shared by production +
 * the C conformance oracle) and the ex_data glue that binds the compiled
 * signing_policy table + modes to a store.
 *
 * Split verbatim out of store_policy.c (see store_policy.h for the contract).
 * Depends only on OpenSSL + libc; no ngx symbols.
 */
#include "auth/crypto/store_policy.h"
#include "store_policy_internal.h"

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509v3.h>

#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

/* Attached to the X509_STORE as a single ex_data blob. */
typedef struct {
    brix_sp_table_t *table;
    brix_sp_mode_t   sp_mode;
    int              crl_mode;
} brix_store_policy_t;

/* -- store configuration (shared by production + oracle) ------------------ */

/*
 * WHAT: check_issued override accepting a name-matching issuer for an RFC 3820
 *       proxy subject even when its authorityKeyIdentifier does not match the
 *       issuer's subjectKeyIdentifier.
 * WHY:  xrdgsiproxy/voms-proxy-init copy the EEC's own AKID into the delegated
 *       proxy, so OpenSSL's default check_issued rejects the signing EEC as the
 *       proxy's issuer (AKID_SKID_MISMATCH) and reports "unable to get local
 *       issuer".  The reference XRootD chain selects issuers by subject name +
 *       signature; match that.
 * HOW:  defer to X509_check_issued; on the AKID objections, accept when the
 *       subject is a recognised proxy (EXFLAG_PROXY).  The RSA signature is
 *       still verified afterwards, so this relaxes selection, not trust.
 */
static int
brix_sp_proxy_check_issued(X509_STORE_CTX *ctx, X509 *subject, X509 *issuer)
{
    int rv;

    (void) ctx;

    rv = X509_check_issued(issuer, subject);
    if (rv == X509_V_OK) {
        return 1;
    }
    /*
     * The authorityKeyIdentifier is advisory (RFC 5280 §4.2.1.1): a mismatch
     * must not prevent selecting a name-matching issuer.  Accept the AKID/SKID
     * and AKID issuer-serial objections for ANY subject (not just proxies) —
     * the issuer's signature over the subject is still verified afterwards by
     * X509_verify_cert, so this relaxes issuer *selection*, never trust.  This
     * also covers delegated grid proxies whose copied AKID points at the CA.
     */
    if (rv == X509_V_ERR_AKID_SKID_MISMATCH
        || rv == X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH)
    {
        return 1;
    }
    return 0;
}

/* True when `crl` has a later lastUpdate than `than` (NULL `than` loses). */
static int
brix_crl_is_newer(X509_CRL *crl, X509_CRL *than)
{
    int day, sec;

    if (than == NULL) {
        return 1;
    }
    if (!ASN1_TIME_diff(&day, &sec, X509_CRL_get0_lastUpdate(than),
                        X509_CRL_get0_lastUpdate(crl)))
    {
        return 0;
    }
    return day > 0 || (day == 0 && sec > 0);
}

/*
 * WHAT: CRL selector making multi-CRL revocation FAIL-SAFE and deterministic.
 * WHY:  With several CRLs for one issuer in the trust dir (rollover overlap,
 *       base+delta published as <hash>.r0/.r1), OpenSSL's default get_crl
 *       picks a single "best" CRL by lastUpdate and, on exact ties, by load
 *       order — i.e. readdir order, which varies per filesystem.  The brix
 *       decision (clause corpus CRL-068/077/080) is conservative: if ANY CRL
 *       from the issuer lists the serial, the certificate is revoked.
 * HOW:  Collect the issuer-matching CRLs; return the first that lists the
 *       certificate's serial as revoked (a removeFromCRL entry in a full CRL
 *       is non-revoking: X509_CRL_get0_by_serial() == 2).  In "try" mode a
 *       full-CRL revocation is superseded by a delta CRL's removeFromCRL
 *       entry (decisions CRL-074/CRL-075).  Otherwise return
 *       the newest full CRL by lastUpdate, skipping delta CRLs — a delta
 *       returned as the sole CRL would fail on its critical DeltaCRLIndicator
 *       and turn a clean base+delta pair into a spurious reject.  Signature,
 *       validity-window and extension checks of the chosen CRL still happen
 *       in OpenSSL's check_crl().
 */
static int
brix_failsafe_get_crl(X509_STORE_CTX *ctx, X509_CRL **out, X509 *x)
{
    STACK_OF(X509_CRL) *crls;
    X509_CRL           *chosen = NULL;
    X509_CRL           *best = NULL;
    int                 i;

    crls = X509_STORE_CTX_get1_crls(ctx, X509_get_issuer_name(x));
    if (crls == NULL) {
        return 0;
    }

    for (i = 0; i < sk_X509_CRL_num(crls) && chosen == NULL; i++) {
        X509_CRL     *crl = sk_X509_CRL_value(crls, i);
        X509_REVOKED *rev;

        if (X509_CRL_get0_by_serial(crl, &rev, X509_get_serialNumber(x)) == 1) {
            chosen = crl;
        }
    }

    /*
     * Delta un-revocation (removeFromCRL in a delta CRL) is honored only in
     * "try" mode: a full-CRL revocation superseded by a delta's removeFromCRL
     * entry hands OpenSSL the delta, whose ==2 lookup is non-revoking
     * (decision CRL-074).  "require" stays fail-safe: the base revocation
     * stands regardless of any delta (decision CRL-075).
     */
    if (chosen != NULL
        && brix_store_crl_mode(ctx) != BRIX_CRL_MODE_REQUIRE
        && X509_CRL_get_ext_by_NID(chosen, NID_delta_crl, -1) < 0)
    {
        for (i = 0; i < sk_X509_CRL_num(crls); i++) {
            X509_CRL     *crl = sk_X509_CRL_value(crls, i);
            X509_REVOKED *rev;

            if (X509_CRL_get_ext_by_NID(crl, NID_delta_crl, -1) >= 0
                && X509_CRL_get0_by_serial(crl, &rev,
                                           X509_get_serialNumber(x)) == 2)
            {
                chosen = crl;
                break;
            }
        }
    }

    if (chosen == NULL) {
        for (i = 0; i < sk_X509_CRL_num(crls); i++) {
            X509_CRL *crl = sk_X509_CRL_value(crls, i);

            if (X509_CRL_get_ext_by_NID(crl, NID_delta_crl, -1) >= 0) {
                continue;
            }
            if (brix_crl_is_newer(crl, best)) {
                best = crl;
            }
        }
        chosen = best;
    }

    if (chosen == NULL) {
        sk_X509_CRL_pop_free(crls, X509_CRL_free);
        return 0;
    }

    X509_CRL_up_ref(chosen);
    *out = chosen;
    sk_X509_CRL_pop_free(crls, X509_CRL_free);
    return 1;
}

/*
 * WHAT: verify callback used only in BRIX_CRL_MODE_TRY.
 * WHY:  "try" checks revocation where a CRL exists but tolerates a CA that has
 *       none; a stale (expired) CRL stays fatal (staleness is evidence).
 * HOW:  downgrade only X509_V_ERR_UNABLE_TO_GET_CRL to success; every other
 *       verdict (CRL_HAS_EXPIRED, CERT_REVOKED, ...) stands.
 */
static int
brix_crl_try_verify_cb(int ok, X509_STORE_CTX *ctx)
{
    if (ok) {
        return 1;
    }
    if (X509_STORE_CTX_get_error(ctx) == X509_V_ERR_UNABLE_TO_GET_CRL) {
        return 1;
    }
    return 0;
}

int
brix_store_configure(X509_STORE *store, const char *cadir,
                     unsigned long extra_flags, int crl_count,
                     brix_sp_mode_t sp_mode, int crl_mode,
                     void *log, brix_sp_log_fn log_fn)
{
    brix_sp_table_t *table;

    if (store == NULL) {
        return -1;
    }

    if (extra_flags != 0) {
        X509_STORE_set_flags(store, extra_flags);
    }
    /* AKID is advisory: tolerate an AKID mismatch when selecting a name-matching
     * issuer on every store (webdav and GSI); the signature is still verified. */
    X509_STORE_set_check_issued(store, brix_sp_proxy_check_issued);

    if (crl_mode == BRIX_CRL_MODE_REQUIRE
        || (crl_mode == BRIX_CRL_MODE_TRY && crl_count > 0))
    {
        X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK
            | X509_V_FLAG_CRL_CHECK_ALL | X509_V_FLAG_USE_DELTAS);
        X509_STORE_set_get_crl(store, brix_failsafe_get_crl);
    }
    if (crl_mode == BRIX_CRL_MODE_TRY) {
        X509_STORE_set_verify_cb(store, brix_crl_try_verify_cb);
    }

    if (cadir == NULL && sp_mode == BRIX_SP_MODE_REQUIRE) {
        sp_log(log, log_fn, BRIX_SP_LOG_WARN,
               "signing_policy: \"require\" needs a hashed CA directory, not a "
               "bundle file");
        return -1;
    }

    table = brix_sp_table_build(cadir, log, log_fn);
    if (table == NULL) {
        return -1;
    }
    if (!brix_store_policy_attach(store, table, sp_mode, crl_mode)) {
        brix_sp_table_free(table);
        return -1;
    }
    return 0;
}

/* -- X509_STORE ex_data glue ---------------------------------------------- */

/*
 * ex_data free callback: released by OpenSSL when the store is freed, so the
 * attached blob (and the table it owns) never leaks across a store rebuild.
 */
static void
sp_ex_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx,
           long argl, void *argp)
{
    brix_store_policy_t *sp = ptr;

    (void) parent; (void) ad; (void) idx; (void) argl; (void) argp;

    if (sp == NULL) {
        return;
    }
    brix_sp_table_free(sp->table);
    free(sp);
}

static int
sp_store_ex_index(void)
{
    static int idx = -1;
    if (idx < 0) {
        idx = X509_STORE_get_ex_new_index(0, NULL, NULL, NULL, sp_ex_free);
    }
    return idx;
}

int
brix_store_policy_attach(X509_STORE *store, brix_sp_table_t *table,
                         brix_sp_mode_t sp_mode, int crl_mode)
{
    brix_store_policy_t *sp;
    int                  idx = sp_store_ex_index();

    if (store == NULL || idx < 0) {
        return 0;
    }
    sp = calloc(1, sizeof(*sp));
    if (sp == NULL) {
        return 0;
    }
    sp->table = table;
    sp->sp_mode = sp_mode;
    sp->crl_mode = crl_mode;

    if (!X509_STORE_set_ex_data(store, idx, sp)) {
        free(sp);
        return 0;
    }
    return 1;
}

static brix_store_policy_t *
sp_from_ctx(X509_STORE_CTX *ctx)
{
    X509_STORE *store;
    int         idx = sp_store_ex_index();

    if (ctx == NULL || idx < 0) {
        return NULL;
    }
    store = X509_STORE_CTX_get0_store(ctx);
    if (store == NULL) {
        return NULL;
    }
    return X509_STORE_get_ex_data(store, idx);
}

brix_sp_table_t *
brix_store_policy_table(X509_STORE_CTX *ctx)
{
    brix_store_policy_t *sp = sp_from_ctx(ctx);
    return sp ? sp->table : NULL;
}

brix_sp_mode_t
brix_store_policy_mode(X509_STORE_CTX *ctx)
{
    brix_store_policy_t *sp = sp_from_ctx(ctx);
    return sp ? sp->sp_mode : BRIX_SP_MODE_OFF;
}

int
brix_store_crl_mode(X509_STORE_CTX *ctx)
{
    brix_store_policy_t *sp = sp_from_ctx(ctx);
    return sp ? sp->crl_mode : BRIX_CRL_MODE_OFF;
}
