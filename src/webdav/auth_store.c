/*
 * auth_store.c - CA and CRL store construction for WebDAV x509 auth.
 */

#include "webdav.h"

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <dirent.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

X509_STORE *
webdav_build_ca_store(ngx_log_t *log,
                      ngx_http_xrootd_webdav_loc_conf_t *conf,
                      int *crl_count_out)
{
    X509_STORE *store;
    char        cadir_buf[PATH_MAX];
    char        cafile_buf[PATH_MAX];

    if (crl_count_out != NULL) {
        *crl_count_out = 0;
    }

    store = X509_STORE_new();
    if (store == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "xrootd_webdav: X509_STORE_new failed");
        return NULL;
    }

    if (conf->cadir.len > 0) {
        if (conf->cadir.len >= sizeof(cadir_buf)) {
            X509_STORE_free(store);
            return NULL;
        }
        ngx_memcpy(cadir_buf, conf->cadir.data, conf->cadir.len);
        cadir_buf[conf->cadir.len] = '\0';
        if (!X509_STORE_load_path(store, cadir_buf)) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "xrootd_webdav: failed to load CA directory \"%s\"",
                          cadir_buf);
        }
    }

    if (conf->cafile.len > 0) {
        if (conf->cafile.len >= sizeof(cafile_buf)) {
            X509_STORE_free(store);
            return NULL;
        }
        ngx_memcpy(cafile_buf, conf->cafile.data, conf->cafile.len);
        cafile_buf[conf->cafile.len] = '\0';
        if (!X509_STORE_load_file(store, cafile_buf)) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "xrootd_webdav: failed to load CA file \"%s\"",
                          cafile_buf);
        }
    }

    if (conf->cadir.len == 0 && conf->cafile.len == 0) {
        X509_STORE_set_default_paths(store);
    }

    if (conf->crl.len > 0) {
        char        crl_buf[PATH_MAX];
        struct stat crl_st;
        int         crl_count = 0;

        if (conf->crl.len >= sizeof(crl_buf)) {
            X509_STORE_free(store);
            return NULL;
        }
        ngx_memcpy(crl_buf, conf->crl.data, conf->crl.len);
        crl_buf[conf->crl.len] = '\0';

        if (stat(crl_buf, &crl_st) != 0) {
            ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                          "xrootd_webdav: cannot stat CRL path \"%s\"",
                          crl_buf);
            X509_STORE_free(store);
            return NULL;
        }

        if (S_ISREG(crl_st.st_mode)) {
            FILE     *fp;
            X509_CRL *crl_obj;

            fp = fopen(crl_buf, "r");
            if (fp == NULL) {
                ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                              "xrootd_webdav: cannot open CRL \"%s\"",
                              crl_buf);
                X509_STORE_free(store);
                return NULL;
            }

            while ((crl_obj = PEM_read_X509_CRL(fp, NULL, NULL, NULL))
                   != NULL)
            {
                if (!X509_STORE_add_crl(store, crl_obj)) {
                    ngx_log_error(NGX_LOG_WARN, log, 0,
                                  "xrootd_webdav: failed to add CRL from "
                                  "\"%s\"", crl_buf);
                }
                crl_count++;
                X509_CRL_free(crl_obj);
            }
            fclose(fp);
        } else if (S_ISDIR(crl_st.st_mode)) {
            DIR           *dir;
            struct dirent *ent;

            dir = opendir(crl_buf);
            if (dir == NULL) {
                ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                              "xrootd_webdav: cannot open CRL directory "
                              "\"%s\"", crl_buf);
                X509_STORE_free(store);
                return NULL;
            }

            while ((ent = readdir(dir)) != NULL) {
                const char *name = ent->d_name;
                size_t      nlen = strlen(name);
                char        fpath[PATH_MAX];
                int         match = 0;
                FILE       *fp;
                X509_CRL   *crl_obj;

                if (nlen > 4 && strcmp(name + nlen - 4, ".pem") == 0) {
                    match = 1;
                }
                if (nlen > 3 && name[nlen - 3] == '.'
                    && name[nlen - 2] == 'r'
                    && name[nlen - 1] >= '0' && name[nlen - 1] <= '9')
                {
                    match = 1;
                }
                if (!match) {
                    continue;
                }

                if (snprintf(fpath, sizeof(fpath), "%s/%s", crl_buf, name)
                    >= (int) sizeof(fpath))
                {
                    continue;
                }

                if (stat(fpath, &crl_st) != 0 || !S_ISREG(crl_st.st_mode)) {
                    continue;
                }

                fp = fopen(fpath, "r");
                if (fp == NULL) {
                    continue;
                }
                while ((crl_obj = PEM_read_X509_CRL(fp, NULL, NULL, NULL))
                       != NULL)
                {
                    if (X509_STORE_add_crl(store, crl_obj)) {
                        crl_count++;
                    }
                    X509_CRL_free(crl_obj);
                }
                fclose(fp);
            }
            closedir(dir);
        }

        if (crl_count > 0) {
            X509_STORE_set_flags(store,
                                 X509_V_FLAG_CRL_CHECK |
                                 X509_V_FLAG_CRL_CHECK_ALL);
        }

        if (crl_count_out != NULL) {
            *crl_count_out = crl_count;
        }
    }

    return store;
}
