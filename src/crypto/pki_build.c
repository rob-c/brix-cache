/*
 * pki_build.c — shared X509_STORE construction for CA/CRL verification.
 *
 * Centralises the X509_STORE build logic used by two independent protocols:
 *   - XRootD stream (GSI): src/gsi/config.c::xrootd_rebuild_gsi_store()
 *   - WebDAV HTTP:         src/webdav/auth_store.c::webdav_build_ca_store()
 *
 * Previously each protocol had its own inline CRL file/directory scanner
 * (~80 lines each, identical logic).  This file owns that logic once.
 */

#include "pki_build.h"

#include <openssl/pem.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>   /* EXFLAG_PROXY, X509_get_extension_flags */

#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

/*
 * WHAT: check_issued override that accepts a name-matching issuer for an
 *       RFC 3820 proxy subject even when the proxy's authorityKeyIdentifier
 *       does not match the issuer's subjectKeyIdentifier.
 *
 * WHY:  xrdgsiproxy / voms-proxy-init copy the end-entity certificate's own
 *       authorityKeyIdentifier into the delegated proxy, so the proxy's AKID
 *       points at the issuing CA rather than at the signing EEC.  OpenSSL's
 *       default check_issued then rejects the EEC as the proxy's issuer with
 *       X509_V_ERR_AKID_SKID_MISMATCH and X509_verify_cert reports "unable to
 *       get local issuer certificate" — even though the EEC really did sign the
 *       proxy.  This only bites once the EEC carries a subjectKeyIdentifier
 *       (every real IGTF/grid certificate does; OpenSSL 3.x also adds one by
 *       default), so real grid proxies fail while a SKID-less test cert passed.
 *       The reference XRootD server (XrdCryptosslX509Chain) selects issuers by
 *       subject name + signature and ignores the AKID hint, so those proxies
 *       authenticate there but not here.  Match that behaviour.
 *
 * HOW:  Defer to the default X509_check_issued.  On success, accept.  For a
 *       proxy subject whose only objection is an AKID/SKID (or AKID issuer-
 *       serial) mismatch, accept the name-matching issuer.  The proxy's RSA
 *       signature is still verified by X509_verify_cert afterwards, so this
 *       relaxes issuer *selection*, never signature trust; it is scoped to
 *       certificates OpenSSL has recognised as proxies (EXFLAG_PROXY, set only
 *       under X509_V_FLAG_ALLOW_PROXY_CERTS with a valid proxyCertInfo) and is
 *       installed only on stores built for proxy verification.
 */
static int
pki_proxy_check_issued(X509_STORE_CTX *ctx, X509 *subject, X509 *issuer)
{
    int rv;

    (void) ctx;

    rv = X509_check_issued(issuer, subject);
    if (rv == X509_V_OK) {
        return 1;
    }

    if ((X509_get_extension_flags(subject) & EXFLAG_PROXY)
        && (rv == X509_V_ERR_AKID_SKID_MISMATCH
            || rv == X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH))
    {
        return 1;
    }

    return 0;
}

/*
 * Load all PEM-encoded CRLs from a single file into the store.
 * Returns the number of CRLs added, or -1 if the file cannot be opened.
 */
static int
pki_load_crls_from_file(X509_STORE *store, const char *path, ngx_log_t *log)
{
    FILE      *fp;
    X509_CRL  *crl;
    int        count;

    fp = fopen(path, "r");
    if (fp == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                      "xrootd_pki: cannot open CRL file \"%s\"", path);
        return -1;
    }
    fcntl(fileno(fp), F_SETFD, FD_CLOEXEC);

    count = 0;
    while ((crl = PEM_read_X509_CRL(fp, NULL, NULL, NULL)) != NULL) {
        if (X509_STORE_add_crl(store, crl)) {
            count++;
        } else {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "xrootd_pki: failed to add CRL from \"%s\"", path);
        }
        X509_CRL_free(crl);
    }

    fclose(fp);
    return count;
}

/*
 * Load CRLs from a file or directory into the store.
 * Returns total CRLs added, or -1 on infrastructure failure (stat/opendir).
 * Directory scan matches *.pem and *.r0-*.r9 (grid CA CRL naming convention).
 */
static int
pki_load_crls(X509_STORE *store, const char *path, ngx_log_t *log)
{
    struct stat    st;
    DIR           *dir;
    struct dirent *ent;
    int            total;
    int            n;

    if (stat(path, &st) != 0) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                      "xrootd_pki: cannot stat CRL path \"%s\"", path);
        return -1;
    }

    if (S_ISREG(st.st_mode)) {
        return pki_load_crls_from_file(store, path, log);
    }

    if (!S_ISDIR(st.st_mode)) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "xrootd_pki: CRL path \"%s\" is neither a file nor a "
                      "directory", path);
        return -1;
    }

    dir = opendir(path);
    if (dir == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                      "xrootd_pki: cannot open CRL directory \"%s\"", path);
        return -1;
    }

    total = 0;
    while ((ent = readdir(dir)) != NULL) {
        const char *name = ent->d_name;
        size_t      nlen = strlen(name);
        char        fpath[PATH_MAX];
        int         match = 0;

        if (nlen > 4 && strcmp(name + nlen - 4, ".pem") == 0) {
            match = 1;
        }
        if (!match && nlen > 3 && name[nlen - 3] == '.'
            && name[nlen - 2] == 'r'
            && name[nlen - 1] >= '0' && name[nlen - 1] <= '9')
        {
            match = 1;
        }
        if (!match) {
            continue;
        }

        n = snprintf(fpath, sizeof(fpath), "%s/%s", path, name);
        if (n < 0 || (size_t) n >= sizeof(fpath)) {
            continue;
        }

        if (stat(fpath, &st) != 0 || !S_ISREG(st.st_mode)) {
            continue;
        }

        n = pki_load_crls_from_file(store, fpath, log);
        if (n > 0) {
            total += n;
        }
    }

    closedir(dir);
    return total;
}

X509_STORE *
xrootd_build_ca_store(ngx_log_t *log,
                       const char *cadir,
                       const char *cafile,
                       const char *crl_path,
                       unsigned long extra_flags,
                       int *crl_count_out)
{
    X509_STORE *store;

    if (crl_count_out != NULL) {
        *crl_count_out = 0;
    }

    store = X509_STORE_new();
    if (store == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "xrootd_pki: X509_STORE_new() failed");
        return NULL;
    }

    if (extra_flags != 0) {
        X509_STORE_set_flags(store, extra_flags);
    }

    /*
     * Proxy-verification stores (GSI): tolerate the AKID/SKID mismatch that
     * real xrdgsiproxy/voms-proxy-init delegated proxies carry so the signing
     * EEC is accepted as the proxy's issuer (see pki_proxy_check_issued).  Not
     * installed on plain client-certificate stores (webdav passes flags 0),
     * which keep OpenSSL's strict default issuer selection.
     */
    if (extra_flags & X509_V_FLAG_ALLOW_PROXY_CERTS) {
        X509_STORE_set_check_issued(store, pki_proxy_check_issued);
    }

    if (cadir != NULL) {
        if (!X509_STORE_load_path(store, cadir)) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "xrootd_pki: failed to load CA directory \"%s\"",
                          cadir);
        }
    }

    if (cafile != NULL) {
        if (!X509_STORE_load_file(store, cafile)) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "xrootd_pki: failed to load CA file \"%s\"", cafile);
        }
    }

    if (cadir == NULL && cafile == NULL) {
        X509_STORE_set_default_paths(store);
    }

    if (crl_path != NULL) {
        int crl_count = pki_load_crls(store, crl_path, log);
        if (crl_count < 0) {
            X509_STORE_free(store);
            return NULL;
        }

        if (crl_count > 0) {
            X509_STORE_set_flags(store,
                                 X509_V_FLAG_CRL_CHECK |
                                 X509_V_FLAG_CRL_CHECK_ALL |
                                 X509_V_FLAG_USE_DELTAS);
        }

        if (crl_count_out != NULL) {
            *crl_count_out = crl_count;
        }
    }

    return store;
}
