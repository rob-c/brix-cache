/* client_trust.c — CVMFS whitelist, manifest, and root-catalog trust chain.
 * This implementation unit is included by client.c so it can use private fetch
 * helpers without exposing trust-chain staging as public client API. */
#ifndef __CLIENT_C_COMPILED__
#include "cvmfs/client/client.h"
#include "cvmfs/signature/verify.h"
#include "cvmfs/signature/whitelist.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>
#endif

/*
 * WHAT: Fetch and authenticate the repository whitelist.
 * WHY:  Repository identity and signing certificates derive from this anchor.
 * HOW:  Verify its master signature, wall-clock expiry, and exact repository name.
 */
static int load_whitelist(cvmfs_client_t *cl, long now,
                          cvmfs_whitelist_t *whitelist) {
    unsigned char wlbuf[65536]; size_t wln = 0;

    if (raw_fetch(cl, ".cvmfswhitelist", wlbuf, sizeof(wlbuf), &wln, now) != 0)
        return -3;
    if (cvmfs_whitelist_parse(wlbuf, wln, whitelist) != 0)
        return -4;
    if (cvmfs_verify_whitelist(whitelist, cl->master_pub,
                               cl->master_pub_len) != 0)
        return -5;
    /* Whitelist expiry is wall-clock time, while `now` is monotonic and only
     * suitable for TTL and refresh scheduling. */
    if (cvmfs_whitelist_expired(whitelist, (long) time(NULL)))
        return -6;
    if (whitelist->repo_name[0] == '\0' ||
        strcmp(whitelist->repo_name, cl->config.name) != 0)
        return -12;
    return 0;
}

/*
 * WHAT: Fetch and authenticate a staged manifest and its signing certificate.
 * WHY:  Catalog selection is trusted only after certificate allowlisting and signature.
 * HOW:  Parse the manifest, verify its CAS certificate fingerprint, then its body.
 */
static int load_manifest(cvmfs_client_t *cl, long now,
                         const cvmfs_whitelist_t *whitelist,
                         unsigned char *buffer, size_t capacity, size_t *length,
                         cvmfs_manifest_t *manifest) {
    unsigned char *certificate;
    size_t         certificate_len = 0;
    char           fingerprint[64];
    int            fingerprint_ok;
    int            signature_ok;

    if (raw_fetch(cl, ".cvmfspublished", buffer, capacity, length, now) != 0)
        return -3;
    if (cvmfs_manifest_parse(buffer, *length, manifest) != 0)
        return -7;
    /* Repository identity is bound by the whitelist N line. Stock publishers
     * may legitimately serve one signed manifest under more than one fqrn. */
    certificate = fetch_cas(cl, &manifest->certificate, 'X', 0,
                            &certificate_len, now);
    if (certificate == NULL)
        return -8;
    fingerprint_ok = cvmfs_cert_fingerprint(certificate, certificate_len,
                                             fingerprint,
                                             sizeof(fingerprint)) == 0 &&
                     cvmfs_whitelist_lists_fp(whitelist, fingerprint);
    signature_ok = fingerprint_ok &&
                   cvmfs_verify_manifest(manifest, certificate,
                                         certificate_len) == 0;
    free(certificate);
    return signature_ok ? 0 : -9;
}

/*
 * WHAT: Open the selected root catalog and validate its advertised revision.
 * WHY:  A pin selects immutable content while an unpinned mount rejects S drift.
 * HOW:  Open the chosen CAS hash, record pin drift, and compare catalog revision.
 */
static int load_root_catalog(cvmfs_client_t *cl, long now,
                             const cvmfs_manifest_t *manifest,
                             char *out_tmp, size_t out_tmp_size,
                             cvmfs_catalog_t **out_catalog) {
    const cvmfs_hash_t *wanted = cl->pin_set ? &cl->pin_root :
                                               &manifest->root_catalog;
    cvmfs_catalog_t    *catalog;
    char                revision[32];

    catalog = open_catalog_by_hash(cl, wanted, cl->catalog_tmp, out_tmp,
                                   out_tmp_size, now);
    if (catalog == NULL)
        return -10;
    if (cl->pin_set) {
        cl->pin_drift = !cvmfs_hash_eq(&cl->pin_root, &manifest->root_catalog);
        if (cl->pin_drift)
            cvmfs_hash_to_hex(&manifest->root_catalog, 0,
                              cl->pin_drift_hex, sizeof(cl->pin_drift_hex));
    }
    /* Pinning an older publish legitimately disagrees with the current S value.
     * Unpinned mounts require the content-addressed catalog revision to match. */
    if (!cl->pin_set && manifest->revision != 0 &&
        cvmfs_catalog_property(catalog, "revision", revision,
                               sizeof(revision)) == 1 &&
        atol(revision) != manifest->revision) {
        cvmfs_catalog_close(catalog);
        return -11;
    }
    *out_catalog = catalog;
    return 0;
}

/*
 * WHAT: Stage a complete verified trust chain and opened root catalog.
 * WHY:  Failed refreshes must never partly replace the metadata being served.
 * HOW:  Authenticate whitelist and manifest before opening the selected catalog.
 */
static int load_trust_and_catalog(cvmfs_client_t *cl, long now,
                                  unsigned char *mbuf, size_t mbuf_cap, size_t *mlen,
                                  cvmfs_manifest_t *m,
                                  char *out_tmp, size_t out_tmp_sz,
                                  cvmfs_catalog_t **out_cat) {
    cvmfs_whitelist_t whitelist;
    int               rc;

    rc = load_whitelist(cl, now, &whitelist);
    if (rc != 0)
        return rc;
    rc = load_manifest(cl, now, &whitelist, mbuf, mbuf_cap, mlen, m);
    if (rc != 0)
        return rc;
    return load_root_catalog(cl, now, m, out_tmp, out_tmp_sz, out_cat);
}
