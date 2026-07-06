/*
 * pki_build.c — shared X509_STORE construction for CA/CRL verification.
 *
 * Centralises the X509_STORE build logic used by two independent protocols:
 *   - XRootD stream (GSI): src/gsi/config.c::brix_rebuild_gsi_store()
 *   - WebDAV HTTP:         src/webdav/auth_store.c::webdav_build_ca_store()
 *
 * Previously each protocol had its own inline CRL file/directory scanner
 * (~80 lines each, identical logic).  This file owns that logic once.
 */

#include "pki_build.h"
#include "auth/crypto/store_policy.h"

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
                      "brix_pki: cannot open CRL file \"%s\"", path);
        return -1;
    }
    fcntl(fileno(fp), F_SETFD, FD_CLOEXEC);

    count = 0;
    while ((crl = PEM_read_X509_CRL(fp, NULL, NULL, NULL)) != NULL) {
        if (X509_STORE_add_crl(store, crl)) {
            count++;
        } else {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "brix_pki: failed to add CRL from \"%s\"", path);
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
                      "brix_pki: cannot stat CRL path \"%s\"", path);
        return -1;
    }

    if (S_ISREG(st.st_mode)) {
        return pki_load_crls_from_file(store, path, log);
    }

    if (!S_ISDIR(st.st_mode)) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "brix_pki: CRL path \"%s\" is neither a file nor a "
                      "directory", path);
        return -1;
    }

    dir = opendir(path);
    if (dir == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                      "brix_pki: cannot open CRL directory \"%s\"", path);
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

/*
 * WHAT: bridge the ngx-free signing_policy loader's log callback to the nginx
 *       log.  WHY: signing_policy.c/store_policy.c carry no ngx symbol, so they
 *       emit via this shim.  HOW: map BRIX_SP_LOG_* to an ngx level and write.
 */
static void
brix_pki_sp_log(void *log, int level, const char *msg)
{
    ngx_uint_t lvl = (level == BRIX_SP_LOG_WARN) ? NGX_LOG_WARN : NGX_LOG_INFO;
    ngx_log_error(lvl, (ngx_log_t *) log, 0, "brix_pki: %s", msg);
}

X509_STORE *
brix_build_ca_store(ngx_log_t *log,
                       const char *cadir,
                       const char *cafile,
                       const char *crl_path,
                       unsigned long extra_flags,
                       int *crl_count_out,
                       brix_sp_mode_t sp_mode,
                       int crl_mode)
{
    X509_STORE *store;

    if (crl_count_out != NULL) {
        *crl_count_out = 0;
    }

    store = X509_STORE_new();
    if (store == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "brix_pki: X509_STORE_new() failed");
        return NULL;
    }

    if (cadir != NULL) {
        if (!X509_STORE_load_path(store, cadir)) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "brix_pki: failed to load CA directory \"%s\"",
                          cadir);
        }
    }

    if (cafile != NULL) {
        if (!X509_STORE_load_file(store, cafile)) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "brix_pki: failed to load CA file \"%s\"", cafile);
        }
    }

    if (cadir == NULL && cafile == NULL) {
        X509_STORE_set_default_paths(store);
    }

    {
        int crl_count = 0;

        if (crl_path != NULL) {
            crl_count = pki_load_crls(store, crl_path, log);
            if (crl_count < 0) {
                X509_STORE_free(store);
                return NULL;
            }
        }

        /*
         * All flag/callback/signing_policy setup is centralised in
         * brix_store_configure so the C conformance oracle configures a store
         * identically to this production path.
         */
        if (brix_store_configure(store, cadir, extra_flags, crl_count,
                                 sp_mode, crl_mode, log, brix_pki_sp_log) != 0)
        {
            X509_STORE_free(store);
            return NULL;
        }

        if (crl_count_out != NULL) {
            *crl_count_out = crl_count;
        }
    }

    return store;
}
