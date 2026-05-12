#include "../config/config.h"

/*
 * Load all PEM-encoded CRLs from a single file into the given X509_STORE.
 * Returns the number of CRLs added, or -1 on error opening the file.
 */
static int
xrootd_load_crls_from_file(X509_STORE *store, const char *path, ngx_log_t *log)
{
    FILE      *fp;
    X509_CRL  *crl;
    int        count = 0;

    fp = fopen(path, "r");
    if (fp == NULL) {
        ngx_log_error(NGX_LOG_WARN, log, ngx_errno,
                      "xrootd: cannot open CRL file \"%s\"", path);
        return -1;
    }

    while ((crl = PEM_read_X509_CRL(fp, NULL, NULL, NULL)) != NULL) {
        if (!X509_STORE_add_crl(store, crl)) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "xrootd: failed to add CRL entry from \"%s\"", path);
        } else {
            count++;
        }
        X509_CRL_free(crl);
    }

    fclose(fp);
    return count;
}

/*
 * Load CRLs from a path that is either a single PEM file or a directory
 * (scanning *.pem, *.r0, *.r1, ... *.r9 files, matching /etc/grid-security/certificates).
 * Returns the total number of CRLs loaded, or -1 on error.
 */
static int
xrootd_load_crls(X509_STORE *store, const char *path, ngx_log_t *log)
{
    struct stat     st;
    DIR            *dir;
    struct dirent  *ent;
    int             total = 0;
    int             n;

    if (stat(path, &st) != 0) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                      "xrootd: cannot stat CRL path \"%s\"", path);
        return -1;
    }

    /* Single file */
    if (S_ISREG(st.st_mode)) {
        return xrootd_load_crls_from_file(store, path, log);
    }

    /* Directory - scan for CRL files */
    if (!S_ISDIR(st.st_mode)) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "xrootd: CRL path \"%s\" is neither a file nor directory",
                      path);
        return -1;
    }

    dir = opendir(path);
    if (dir == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                      "xrootd: cannot open CRL directory \"%s\"", path);
        return -1;
    }

    while ((ent = readdir(dir)) != NULL) {
        const char *name = ent->d_name;
        size_t      nlen = strlen(name);
        char        fullpath[PATH_MAX];
        int         match = 0;

        /* Match *.pem */
        if (nlen > 4 && strcmp(name + nlen - 4, ".pem") == 0) {
            match = 1;
        }
        /* Match *.r0 through *.r9 (grid CA CRL naming convention) */
        if (nlen > 3 && name[nlen - 3] == '.' && name[nlen - 2] == 'r'
            && name[nlen - 1] >= '0' && name[nlen - 1] <= '9')
        {
            match = 1;
        }

        if (!match) {
            continue;
        }

        n = snprintf(fullpath, sizeof(fullpath), "%s/%s", path, name);
        if (n < 0 || (size_t) n >= sizeof(fullpath)) {
            continue;
        }

        /* Only load regular files, skip symlink targets that vanished etc. */
        if (stat(fullpath, &st) != 0 || !S_ISREG(st.st_mode)) {
            continue;
        }

        n = xrootd_load_crls_from_file(store, fullpath, log);
        if (n > 0) {
            total += n;
        }
    }

    closedir(dir);
    return total;
}

/*
 * Build (or rebuild) the X509_STORE used for GSI certificate verification.
 *
 * Loads the trusted CA from xcf->trusted_ca, then loads CRLs from xcf->crl
 * (which may be a single PEM file or a directory of *.pem / *.r0 files).
 *
 * On success the new store is atomically swapped into xcf->gsi_store and any
 * previous store is freed. On failure the old store is left in place so
 * existing connections are not disrupted.
 */
ngx_int_t
xrootd_rebuild_gsi_store(ngx_stream_xrootd_srv_conf_t *xcf, ngx_log_t *log)
{
    X509_STORE   *store;
    X509_STORE   *old_store;
    X509_LOOKUP  *lookup;

    store = X509_STORE_new();
    if (store == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "xrootd: X509_STORE_new() failed");
        return NGX_ERROR;
    }

    X509_STORE_set_flags(store, X509_V_FLAG_ALLOW_PROXY_CERTS);

    lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
    if (lookup == NULL) {
        X509_STORE_free(store);
        return NGX_ERROR;
    }

    if (!X509_LOOKUP_load_file(lookup,
                               (char *) xcf->trusted_ca.data,
                               X509_FILETYPE_PEM))
    {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "xrootd: cannot load trusted CA \"%s\"",
                      xcf->trusted_ca.data);
        X509_STORE_free(store);
        return NGX_ERROR;
    }

    /* Load CRLs if configured (file or directory) */
    if (xcf->crl.len > 0) {
        int crl_count = xrootd_load_crls(store, (char *) xcf->crl.data, log);
        if (crl_count < 0) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "xrootd: failed to load CRLs from \"%s\"",
                          xcf->crl.data);
            X509_STORE_free(store);
            return NGX_ERROR;
        }

        if (crl_count > 0) {
            /*
             * Enable CRL checking on the store. X509_V_FLAG_CRL_CHECK checks
             * the leaf issuer's CRL; _CHECK_ALL checks the entire chain.
             */
            X509_STORE_set_flags(store,
                                 X509_V_FLAG_CRL_CHECK |
                                 X509_V_FLAG_CRL_CHECK_ALL);
        }

        ngx_log_error(NGX_LOG_NOTICE, log, 0,
                      "xrootd: loaded %d CRL(s) from \"%s\"",
                      crl_count, xcf->crl.data);
    }

    /* Atomic swap */
    old_store = xcf->gsi_store;
    xcf->gsi_store = store;

    if (old_store != NULL) {
        X509_STORE_free(old_store);
    }

    return NGX_OK;
}

ngx_int_t
xrootd_configure_gsi(ngx_conf_t *cf, ngx_stream_xrootd_srv_conf_t *xcf)
{
    if (xcf->auth != XROOTD_AUTH_GSI && xcf->auth != XROOTD_AUTH_BOTH) {
        return NGX_OK;
    }

    /* GSI mode is only meaningful when all three trust inputs are present. */
    if (xcf->certificate.len == 0 || xcf->certificate_key.len == 0
        || xcf->trusted_ca.len == 0)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_auth gsi requires xrootd_certificate, "
            "xrootd_certificate_key and xrootd_trusted_ca");
        return NGX_ERROR;
    }

    if (xrootd_validate_path(cf, "xrootd_certificate", &xcf->certificate,
                             XROOTD_PATH_REGULAR_FILE, R_OK) != NGX_OK
        || xrootd_validate_path(cf, "xrootd_certificate_key",
                                &xcf->certificate_key,
                                XROOTD_PATH_REGULAR_FILE, R_OK) != NGX_OK
        || xrootd_validate_path(cf, "xrootd_trusted_ca", &xcf->trusted_ca,
                                XROOTD_PATH_REGULAR_FILE, R_OK) != NGX_OK
        || xrootd_validate_path(cf, "xrootd_crl", &xcf->crl,
                                XROOTD_PATH_FILE_OR_DIRECTORY, R_OK) != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* Load server certificate */
    {
        FILE *fp = fopen((char *) xcf->certificate.data, "r");
        if (fp == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                "xrootd: cannot open certificate \"%s\"",
                xcf->certificate.data);
            return NGX_ERROR;
        }
        xcf->gsi_cert = PEM_read_X509(fp, NULL, NULL, NULL);
        fclose(fp);
        if (xcf->gsi_cert == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd: cannot parse certificate \"%s\"",
                xcf->certificate.data);
            return NGX_ERROR;
        }
    }

    /* Cache the PEM serialization once; kXGS_cert sends it on every GSI login. */
    {
        BIO     *bio;
        BUF_MEM *bptr;

        bio = BIO_new(BIO_s_mem());
        if (bio == NULL) {
            return NGX_ERROR;
        }

        if (!PEM_write_bio_X509(bio, xcf->gsi_cert)) {
            BIO_free(bio);
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd: cannot serialize certificate \"%s\"",
                xcf->certificate.data);
            return NGX_ERROR;
        }

        BIO_get_mem_ptr(bio, &bptr);
        xcf->gsi_cert_pem = ngx_pnalloc(cf->pool, bptr->length);
        if (xcf->gsi_cert_pem == NULL) {
            BIO_free(bio);
            return NGX_ERROR;
        }

        ngx_memcpy(xcf->gsi_cert_pem, bptr->data, bptr->length);
        xcf->gsi_cert_pem_len = bptr->length;
        BIO_free(bio);
    }

    /* Load server private key */
    {
        FILE *fp = fopen((char *) xcf->certificate_key.data, "r");
        if (fp == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                "xrootd: cannot open private key \"%s\"",
                xcf->certificate_key.data);
            return NGX_ERROR;
        }
        xcf->gsi_key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
        fclose(fp);
        if (xcf->gsi_key == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd: cannot parse private key \"%s\"",
                xcf->certificate_key.data);
            return NGX_ERROR;
        }
    }

    /* Build trusted CA X509_STORE */
    if (xrootd_rebuild_gsi_store(xcf, cf->log) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Run a lightweight PKI/CRL consistency check and log any problems. */
    (void) xrootd_check_pki_consistency_stream(cf->log, xcf);

    /* Compute CA hash (for kXRS_issuer_hash in kXGS_init) */
    {
        FILE  *fp;
        X509  *ca;

        fp = fopen((char *) xcf->trusted_ca.data, "r");
        if (fp) {
            ca = PEM_read_X509(fp, NULL, NULL, NULL);
            fclose(fp);
            if (ca) {
                /*
                 * The protocol advertises the issuer hash during the GSI
                 * bootstrap so clients can confirm which CA the server wants.
                 */
                xcf->gsi_ca_hash = (uint32_t) X509_subject_name_hash(ca);
                X509_free(ca);
            }
        }
    }

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
        "xrootd: GSI auth configured - cert=%s ca_hash=%08xd",
        xcf->certificate.data, xcf->gsi_ca_hash);

    return NGX_OK;
}
