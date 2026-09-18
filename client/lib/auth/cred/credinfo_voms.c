/*
 * credinfo_voms.c — VOMS attribute-certificate narration for `explain` (§15.2).
 *
 * WHAT: Renders the VOMS extension of a GSI proxy for the credential dump: one
 *       "VOMS:" line per FQAN, one summary line per VO (server URI, issuer,
 *       validity) and one verdict line per VO from the shared native verifier.
 * WHY:  credinfo.c used to byte-scan the DER for FQAN-looking strings — that
 *       could neither tell a forged AC from a genuine one nor say why a server
 *       would reject it. shared/voms/ is the single VOMS decoder/verifier for
 *       the nginx module and the native client, so the client's diagnostic now
 *       states exactly what the module will conclude about the same proxy.
 * HOW:  brix_voms_find_extension over the proxy leaf + chain, brix_voms_decode,
 *       then brix_voms_verify with a trust built from the environment
 *       (X509_CERT_DIR → X509_STORE, X509_VOMS_DIR → LSC directory). A missing
 *       trust directory downgrades to "unverified (no <dir>)" rather than a
 *       false failure. Fail-soft: every path prints a line and returns.
 */
#include "brix.h"
#include "voms/voms_ac.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#define VOMS_LINE        "      VOMS:  "
#define VOMS_SKEW_SECS   300   /* notBefore tolerance: the usual 5-minute clock allowance */
#define DEFAULT_CERT_DIR "/etc/grid-security/certificates"
#define DEFAULT_VOMS_DIR "/etc/grid-security/vomsdir"

/* Trust for one explain run: a usable store + vomsdir, or the directory whose
 * absence made verification impossible (then store is NULL). */
typedef struct {
    X509_STORE *store;
    const char *vomsdir;
    const char *missing_dir;
} credinfo_voms_trust_t;

/* ---- Environment directory with a grid-security default ----
 *
 * WHAT: returns getenv(var) when set and non-empty, else `fallback`.
 * WHY:  X509_CERT_DIR / X509_VOMS_DIR are the conventional overrides every
 *       grid tool honours; the defaults are the EGI/OSG install locations.
 * HOW:  1. getenv; 2. empty counts as unset.
 */
static const char *
voms_env_dir(const char *var, const char *fallback)
{
    const char *value = getenv(var);

    return (value != NULL && value[0] != '\0') ? value : fallback;
}

/* ---- Is `path` an existing directory? ----
 *
 * WHAT: 1 when stat succeeds and the inode is a directory, else 0.
 * WHY:  a host without grid trust material must read "unverified", never
 *       "NOT verified" — the AC may be perfectly good.
 * HOW:  1. stat; 2. S_ISDIR.
 */
static int
voms_dir_exists(const char *path)
{
    struct stat st;

    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

/* ---- Build the verification trust from the environment ----
 *
 * WHAT: fills *trust with an X509_STORE over X509_CERT_DIR and the
 *       X509_VOMS_DIR path, or records the first missing directory in
 *       trust->missing_dir (store NULL) so the caller reports "unverified".
 * WHY:  verification is only meaningful with both the CA bundle (signer chain)
 *       and the vomsdir (LSC binding); one without the other would produce a
 *       misleading verdict.
 * HOW:  1. resolve both directories; 2. require each to exist; 3. X509_STORE_new
 *       + X509_STORE_load_locations(NULL, cert_dir); 4. a store failure is
 *       reported as the cert dir being unusable.
 */
static void
voms_trust_open(credinfo_voms_trust_t *trust)
{
    const char *cert_dir = voms_env_dir("X509_CERT_DIR", DEFAULT_CERT_DIR);

    memset(trust, 0, sizeof(*trust));
    trust->vomsdir = voms_env_dir("X509_VOMS_DIR", DEFAULT_VOMS_DIR);
    if (!voms_dir_exists(cert_dir)) {
        trust->missing_dir = cert_dir;
        return;
    }
    if (!voms_dir_exists(trust->vomsdir)) {
        trust->missing_dir = trust->vomsdir;
        return;
    }
    trust->store = X509_STORE_new();
    if (trust->store == NULL
        || !X509_STORE_load_locations(trust->store, NULL, cert_dir)) {
        X509_STORE_free(trust->store);
        trust->store = NULL;
        trust->missing_dir = cert_dir;
    }
}

/* ---- Release the trust store ----
 *
 * WHAT: frees the X509_STORE (NULL-safe).
 * WHY:  the store is the only owned resource of a trust; one release point.
 * HOW:  1. X509_STORE_free.
 */
static void
voms_trust_close(credinfo_voms_trust_t *trust)
{
    X509_STORE_free(trust->store);
    trust->store = NULL;
}

/* ---- Format an epoch as ISO-8601 UTC ----
 *
 * WHAT: writes "YYYY-MM-DDTHH:MM:SSZ" into buf; "?" when the time is not
 *       representable.
 * WHY:  AC validity is what a server compares against its own clock; a fixed,
 *       zone-free rendering is comparable across hosts and in tests.
 * HOW:  1. gmtime_r; 2. strftime.
 */
static void
voms_fmt_time(time_t when, char *buf, size_t cap)
{
    struct tm utc;

    if (gmtime_r(&when, &utc) == NULL
        || strftime(buf, cap, "%Y-%m-%dT%H:%M:%SZ", &utc) == 0) {
        snprintf(buf, cap, "?");
    }
}

/* ---- Print one VO's decoded facts ----
 *
 * WHAT: one "VOMS:  <fqan>" line per FQAN, then the VO summary line
 *       (vo, server URI, issuer DN, validity window).
 * WHY:  the FQAN lines keep the prefix the existing diagnostics and tests
 *       match on; the summary is what an operator needs to check vomsdir.
 * HOW:  1. loop fqans; 2. format both validity bounds; 3. summary line.
 */
static void
voms_print_entry(const brix_voms_entry_t *entry, FILE *out)
{
    char not_before[32], not_after[32];
    int  i;

    for (i = 0; i < entry->nfqans; i++) {
        fprintf(out, VOMS_LINE "%s\n", entry->fqans[i]);
    }
    voms_fmt_time(entry->not_before, not_before, sizeof(not_before));
    voms_fmt_time(entry->not_after, not_after, sizeof(not_after));
    fprintf(out, VOMS_LINE "vo=%s server=%s issuer=%s valid %s..%s\n",
            entry->vo, entry->uri, entry->issuer_dn, not_before, not_after);
}

/* ---- Print one VO's verification verdict ----
 *
 * WHAT: "VOMS:  verified", "VOMS:  NOT verified: <reason>" or, when no trust
 *       directory was available, "VOMS:  unverified (no <dir>)".
 * WHY:  three distinct words for three distinct situations — a verified AC, a
 *       rejected AC, and a host that cannot judge — so nobody reads an absent
 *       CA bundle as a broken proxy.
 * HOW:  1. missing_dir wins; 2. else map the entry's verdict.
 */
static void
voms_print_verdict(const brix_voms_entry_t *entry,
                   const credinfo_voms_trust_t *trust, FILE *out)
{
    if (trust->missing_dir != NULL) {
        fprintf(out, VOMS_LINE "unverified (no %s)\n", trust->missing_dir);
        return;
    }
    if (entry->verdict == BRIX_VOMS_OK) {
        fprintf(out, VOMS_LINE "verified\n");
        return;
    }
    fprintf(out, VOMS_LINE "NOT verified: %s\n", brix_voms_strerror(entry->verdict));
}

/* ---- Verify (when trust exists) and print every decoded VO ----
 *
 * WHAT: runs brix_voms_verify over the result under `trust` when a store is
 *       available, then prints each entry's facts and verdict.
 * WHY:  verification is one call over all entries (each gets its own verdict);
 *       printing per entry afterwards keeps facts and verdict adjacent.
 * HOW:  1. build brix_voms_trust_t {store, vomsdir, now, skew}; 2. verify
 *       when store != NULL (the return value is per-entry in verdict, so it is
 *       not needed here); 3. print entry + verdict for each VO.
 */
static void
voms_verify_and_print(brix_voms_result_t *res, X509 *holder, STACK_OF(X509) *chain,
                      const credinfo_voms_trust_t *trust, FILE *out)
{
    brix_voms_trust_t lib_trust = { trust->store, trust->vomsdir, 0, VOMS_SKEW_SECS };
    int               i;

    if (trust->store != NULL) {
        (void) brix_voms_verify(res, holder, chain, &lib_trust);
    }
    for (i = 0; i < res->n; i++) {
        voms_print_entry(&res->entries[i], out);
        voms_print_verdict(&res->entries[i], trust, out);
    }
}

/* ---- Narrate the VOMS extension of a proxy ----
 *
 * WHAT: prints "VOMS:  none" when neither leaf nor chain carries the
 *       extension, "VOMS:  present (undecodable: <reason>)" when it will not
 *       decode, else the decoded FQANs, summary and verdict per VO.
 * WHY:  the entry point brix_gsi_cert_explain hands the proxy to; it owns the
 *       decode result and the trust for the duration of one print.
 * HOW:  1. brix_voms_find_extension; 2. brix_voms_decode; 3. voms_trust_open;
 *       4. voms_verify_and_print; 5. release trust and result.
 */
void
brix_credinfo_voms_explain(X509 *leaf, STACK_OF(X509) *chain, FILE *out)
{
    X509                  *holder = NULL;
    const unsigned char   *der = NULL;
    int                    len = 0;
    brix_voms_result_t    *res = NULL;
    brix_voms_status_t     rc;
    credinfo_voms_trust_t  trust;

    if (brix_voms_find_extension(leaf, chain, &holder, &der, &len) != BRIX_VOMS_OK) {
        fprintf(out, VOMS_LINE "none\n");
        return;
    }
    rc = brix_voms_decode(der, len, &res);
    if (rc != BRIX_VOMS_OK) {
        fprintf(out, VOMS_LINE "present (undecodable: %s)\n", brix_voms_strerror(rc));
        return;
    }
    voms_trust_open(&trust);
    voms_verify_and_print(res, holder, chain, &trust, out);
    voms_trust_close(&trust);
    brix_voms_result_free(res);
}
