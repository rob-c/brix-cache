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
/*
 * WHAT: Find the first issuer CRL that actively revokes a certificate serial.
 * WHY:  Any matching full revocation must win over filesystem load order.
 * HOW:  Walk the collected issuer CRLs and accept lookup result one only.
 */
static X509_CRL *
brix_crl_find_revocation(STACK_OF(X509_CRL) *crls, X509 *cert)
{
    for (int i = 0; i < sk_X509_CRL_num(crls); i++) {
        X509_CRL     *crl = sk_X509_CRL_value(crls, i);
        X509_REVOKED *rev;

        if (X509_CRL_get0_by_serial(crl, &rev,
                                    X509_get_serialNumber(cert)) == 1)
            return crl;
    }
    return NULL;
}

/*
 * WHAT: Find a delta CRL carrying removeFromCRL for a certificate serial.
 * WHY:  Optional CRL mode honors a delta that supersedes a base revocation.
 * HOW:  Restrict the serial lookup-result-two search to delta CRLs.
 */
static X509_CRL *
brix_crl_find_removal(STACK_OF(X509_CRL) *crls, X509 *cert)
{
    for (int i = 0; i < sk_X509_CRL_num(crls); i++) {
        X509_CRL     *crl = sk_X509_CRL_value(crls, i);
        X509_REVOKED *rev;

        if (X509_CRL_get_ext_by_NID(crl, NID_delta_crl, -1) >= 0 &&
            X509_CRL_get0_by_serial(crl, &rev,
                                    X509_get_serialNumber(cert)) == 2)
            return crl;
    }
    return NULL;
}

/*
 * WHAT: Select the newest non-delta CRL for ordinary OpenSSL validation.
 * WHY:  Returning a lone delta would fail its critical DeltaCRLIndicator.
 * HOW:  Skip deltas and compare full-CRL lastUpdate values deterministically.
 */
static X509_CRL *
brix_crl_newest_full(STACK_OF(X509_CRL) *crls)
{
    X509_CRL *best = NULL;

    for (int i = 0; i < sk_X509_CRL_num(crls); i++) {
        X509_CRL *crl = sk_X509_CRL_value(crls, i);

        if (X509_CRL_get_ext_by_NID(crl, NID_delta_crl, -1) < 0 &&
            brix_crl_is_newer(crl, best))
            best = crl;
    }
    return best;
}

static int
brix_failsafe_get_crl(X509_STORE_CTX *ctx, X509_CRL **out, X509 *x)
{
    STACK_OF(X509_CRL) *crls;
    X509_CRL           *chosen;

    crls = X509_STORE_CTX_get1_crls(ctx, X509_get_issuer_name(x));
    if (crls == NULL)
        return 0;
    chosen = brix_crl_find_revocation(crls, x);
    if (chosen != NULL && brix_store_crl_mode(ctx) != BRIX_CRL_MODE_REQUIRE &&
        X509_CRL_get_ext_by_NID(chosen, NID_delta_crl, -1) < 0)
        chosen = brix_crl_find_removal(crls, x);
    if (chosen == NULL)
        chosen = brix_crl_newest_full(crls);

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
 * WHAT: a DIFFERENT_CRL_SCOPE verdict is a false positive iff the CRL that
 *       provoked it is the AUTHORITATIVE full CRL for the certificate — issued
 *       by the cert's exact issuer, carrying no IssuingDistributionPoint (so it
 *       covers every cert that issuer signed, all reasons), and NOT listing the
 *       cert's serial.  In that case revocation HAS been checked (the cert is
 *       provably absent from its issuer's full CRL) and the scope error is an
 *       artifact of brix_failsafe_get_crl handing OpenSSL a CRL without the
 *       scope score its own get_crl_sk would have attached (stock
 *       `openssl verify -crl_check_all` accepts the identical store).
 * WHY:  safe in BOTH try and require: a genuinely revoked cert is FOUND on this
 *       same full CRL, so it takes the CERT_REVOKED path, never this one.  A
 *       partial/delta/scoped CRL (has an IDP) is NOT authoritative and is left
 *       to fail, so real scope restrictions are still honoured.
 */
static int
brix_crl_scope_is_spurious(X509_STORE_CTX *ctx)
{
    X509               *cert = X509_STORE_CTX_get_current_cert(ctx);
    STACK_OF(X509_CRL) *crls;
    int                 i, spurious = 0;

    if (cert == NULL) {
        return 0;
    }
    /* Look CRLs up by the cert's issuer name directly rather than trusting
     * ctx->current_crl: the spurious codes include UNABLE_TO_GET_CRL, where
     * OpenSSL has cleared current_crl.  The cert's issuer is already
     * trust-validated (it is above this cert in the verified chain), so any
     * full CRL it signed is authoritative for revocation of this cert. */
    crls = X509_STORE_CTX_get1_crls(ctx, X509_get_issuer_name(cert));
    if (crls == NULL) {
        return 0;
    }
    for (i = 0; i < sk_X509_CRL_num(crls); i++) {
        X509_CRL     *crl = sk_X509_CRL_value(crls, i);
        X509_REVOKED *rev = NULL;

        /* A scoped/partial CRL (has an IDP) is NOT authoritative for the whole
         * cert population — its scope restriction is real; skip it. */
        if (X509_CRL_get_ext_by_NID(crl, NID_issuing_distribution_point, -1)
            >= 0) {
            continue;
        }
        /* ==1 revoked → NOT spurious, let it fail.  ==2 is a removeFromCRL
         * entry (listed but non-revoking) and ==0 is absent — both mean the
         * cert is not revoked by this full CRL, so the scope/path error is. */
        if (X509_CRL_get0_by_serial(crl, &rev,
                                    X509_get_serialNumber(cert)) == 1) {
            spurious = 0;
            break;
        }
        spurious = 1;   /* full CRL from the issuer, cert not revoked by it */
    }
    sk_X509_CRL_pop_free(crls, X509_CRL_free);
    return spurious;
}

/*
 * WHAT: CRL verify callback installed for BRIX_CRL_MODE_TRY and _REQUIRE.
 * WHY:  "try" checks revocation where a CRL exists but tolerates a CA that has
 *       none; a stale (expired) CRL stays fatal (staleness is evidence).  Both
 *       modes also tolerate the spurious DIFFERENT_CRL_SCOPE described above so
 *       a non-revoked cert under a full CRL is admitted (as stock OpenSSL does).
 * HOW:  downgrade UNABLE_TO_GET_CRL (try only) and provably-spurious
 *       DIFFERENT_CRL_SCOPE (both) to success; every other verdict
 *       (CRL_HAS_EXPIRED, CERT_REVOKED, ...) stands.
 */
static int
brix_crl_try_verify_cb(int ok, X509_STORE_CTX *ctx)
{
    int err;

    if (ok) {
        return 1;
    }
    err = X509_STORE_CTX_get_error(ctx);
    /* "try" tolerates a CA that publishes no CRL at all (genuine missing-CRL). */
    if (err == X509_V_ERR_UNABLE_TO_GET_CRL
        && brix_store_crl_mode(ctx) != BRIX_CRL_MODE_REQUIRE) {
        return 1;
    }
    /* All three are spurious artifacts of brix_failsafe_get_crl feeding OpenSSL
     * a CRL without the scope score its own get_crl_sk would attach, under
     * CRL_CHECK_ALL|USE_DELTAS: UNABLE_TO_GET_CRL / DIFFERENT_CRL_SCOPE /
     * CRL_PATH_VALIDATION_ERROR fire in sequence on the same cert where stock
     * `openssl verify -crl_check_all` accepts.  Tolerate them in BOTH modes
     * only when an authoritative full CRL from the cert's (already
     * trust-validated) issuer exists and does not list the cert — a genuinely
     * revoked cert is FOUND on that CRL and takes the CERT_REVOKED path. */
    if ((err == X509_V_ERR_UNABLE_TO_GET_CRL
         || err == X509_V_ERR_DIFFERENT_CRL_SCOPE
         || err == X509_V_ERR_CRL_PATH_VALIDATION_ERROR)
        && brix_crl_scope_is_spurious(ctx)) {
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
    if (crl_mode == BRIX_CRL_MODE_TRY
        || crl_mode == BRIX_CRL_MODE_REQUIRE) {
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
