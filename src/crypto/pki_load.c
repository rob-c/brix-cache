#include "pki_check.h"

#include <ngx_config.h>
#include <ngx_core.h>

#include <openssl/pem.h>

#include <dirent.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

/*
 * PEM certificate and CRL loaders used by startup consistency checks.
 */

static ngx_flag_t
xrootd_pki_crl_filename_matches(const char *name)
{
    size_t name_len;

    name_len = strlen(name);

    if (name_len > 4 && strcmp(name + name_len - 4, ".pem") == 0) {
        return 1;
    }

    /*
     * Grid CA distributions commonly publish CRLs as hash.r0/hash.r1 files in
     * addition to PEM bundles.  Accept only a single numeric suffix here; the
     * loader still stats the joined path before opening it.
     */
    if (name_len > 3 && name[name_len - 3] == '.'
        && name[name_len - 2] == 'r'
        && name[name_len - 1] >= '0' && name[name_len - 1] <= '9')
    {
        return 1;
    }

    return 0;
}


static ngx_int_t
xrootd_pki_join_child_path(char *dst, size_t dst_size, const char *directory,
    const char *filename)
{
    int written;

    written = snprintf(dst, dst_size, "%s/%s", directory, filename);
    if (written < 0 || (size_t) written >= dst_size) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_flag_t
xrootd_pki_is_regular_file(const char *path)
{
    struct stat file_stat;

    return stat(path, &file_stat) == 0 && S_ISREG(file_stat.st_mode);
}


static ngx_uint_t
xrootd_pki_load_certs_from_file(STACK_OF(X509) *certs, const char *path,
    ngx_log_t *log, ngx_flag_t log_open_error)
{
    FILE      *fp;
    X509      *cert;
    ngx_uint_t loaded;

    fp = fopen(path, "r");
    if (fp == NULL) {
        if (log_open_error) {
            ngx_log_error(NGX_LOG_WARN, log, ngx_errno,
                          "xrootd_pki_check: cannot open CA file \"%s\"",
                          path);
        }
        return 0;
    }

    loaded = 0;
    while ((cert = PEM_read_X509(fp, NULL, NULL, NULL)) != NULL) {
        if (sk_X509_push(certs, cert) <= 0) {
            X509_free(cert);
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "xrootd_pki_check: failed to append CA cert from \"%s\"",
                          path);
            break;
        }
        loaded++;
    }

    fclose(fp);
    return loaded;
}


static ngx_uint_t
xrootd_pki_load_crls_from_file(STACK_OF(X509_CRL) *crls, const char *path,
    ngx_log_t *log, ngx_flag_t log_open_error)
{
    FILE      *fp;
    X509_CRL  *crl;
    ngx_uint_t loaded;

    fp = fopen(path, "r");
    if (fp == NULL) {
        if (log_open_error) {
            ngx_log_error(NGX_LOG_WARN, log, ngx_errno,
                          "xrootd_pki_check: cannot open CRL file \"%s\"",
                          path);
        }
        return 0;
    }

    loaded = 0;
    while ((crl = PEM_read_X509_CRL(fp, NULL, NULL, NULL)) != NULL) {
        if (sk_X509_CRL_push(crls, crl) <= 0) {
            X509_CRL_free(crl);
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "xrootd_pki_check: failed to append CRL from \"%s\"",
                          path);
            break;
        }
        loaded++;
    }

    fclose(fp);
    return loaded;
}


STACK_OF(X509) *
xrootd_pki_load_certs_from_path(const char *path, ngx_log_t *log)
{
    struct stat     st;
    STACK_OF(X509) *stack;

    if (stat(path, &st) != 0) {
        ngx_log_error(NGX_LOG_WARN, log, ngx_errno,
                      "xrootd_pki_check: cannot stat CA path \"%s\"",
                      path);
        return NULL;
    }

    stack = sk_X509_new_null();
    if (stack == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "xrootd_pki_check: failed to allocate cert stack");
        return NULL;
    }

    if (S_ISREG(st.st_mode)) {
        (void) xrootd_pki_load_certs_from_file(stack, path, log, 1);

    } else if (S_ISDIR(st.st_mode)) {
        DIR           *directory;
        struct dirent *entry;

        directory = opendir(path);
        if (directory == NULL) {
            ngx_log_error(NGX_LOG_WARN, log, ngx_errno,
                          "xrootd_pki_check: cannot open CA dir \"%s\"",
                          path);
            sk_X509_free(stack);
            return NULL;
        }

        while ((entry = readdir(directory)) != NULL) {
            char child_path[PATH_MAX];

            if (entry->d_name[0] == '.') {
                continue;
            }

            if (xrootd_pki_join_child_path(child_path, sizeof(child_path),
                                           path, entry->d_name)
                != NGX_OK)
            {
                continue;
            }

            if (!xrootd_pki_is_regular_file(child_path)) {
                continue;
            }

            /*
             * Directory CA stores may include OpenSSL hash symlinks or helper
             * files.  Files that do not contain PEM certificates simply add
             * zero entries and are ignored.
             */
            (void) xrootd_pki_load_certs_from_file(stack, child_path, log, 0);
        }
        closedir(directory);
    }

    if (sk_X509_num(stack) == 0) {
        sk_X509_free(stack);
        return NULL;
    }

    return stack;
}


STACK_OF(X509_CRL) *
xrootd_pki_load_crls_from_path(const char *path, ngx_log_t *log)
{
    struct stat         st;
    STACK_OF(X509_CRL) *stack;

    if (stat(path, &st) != 0) {
        ngx_log_error(NGX_LOG_WARN, log, ngx_errno,
                      "xrootd_pki_check: cannot stat CRL path \"%s\"",
                      path);
        return NULL;
    }

    stack = sk_X509_CRL_new_null();
    if (stack == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "xrootd_pki_check: failed to allocate CRL stack");
        return NULL;
    }

    if (S_ISREG(st.st_mode)) {
        (void) xrootd_pki_load_crls_from_file(stack, path, log, 1);

    } else if (S_ISDIR(st.st_mode)) {
        DIR           *directory;
        struct dirent *entry;

        directory = opendir(path);
        if (directory == NULL) {
            ngx_log_error(NGX_LOG_WARN, log, ngx_errno,
                          "xrootd_pki_check: cannot open CRL dir \"%s\"",
                          path);
            sk_X509_CRL_free(stack);
            return NULL;
        }

        while ((entry = readdir(directory)) != NULL) {
            const char *filename;
            char        child_path[PATH_MAX];

            filename = entry->d_name;
            if (!xrootd_pki_crl_filename_matches(filename)) {
                continue;
            }

            if (xrootd_pki_join_child_path(child_path, sizeof(child_path),
                                           path, filename)
                != NGX_OK)
            {
                continue;
            }

            if (!xrootd_pki_is_regular_file(child_path)) {
                continue;
            }

            (void) xrootd_pki_load_crls_from_file(stack, child_path, log, 0);
        }
        closedir(directory);
    }

    if (sk_X509_CRL_num(stack) == 0) {
        sk_X509_CRL_free(stack);
        return NULL;
    }

    return stack;
}
