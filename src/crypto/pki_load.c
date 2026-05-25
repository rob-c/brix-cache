/* ------------------------------------------------------------------ */
/* Section: PEM Certificate and CRL Loaders                             */
/* ------------------------------------------------------------------ */
/*
 * WHAT: This file implements PEM certificate and CRL loaders used by startup consistency checks during nginx configuration phase. Loads X509 certificates and X509_CRL entries from either single-file or directory paths supporting Grid CA distribution formats (.pem bundles, hash.r0/hash.r1 files). All loaders use OpenSSL stack allocation (sk_X509_new_null) for certificate/CRL collection, stat() validation for path existence and type detection, and graceful error handling with WARN-level logging rather than fatal aborts. */

/* ------------------------------------------------------------------ */
/* Section: CRL Filename Matching                                       */
/* ------------------------------------------------------------------ */
/*
 * WHAT: xrootd_pki_crl_filename_matches() checks whether a filename looks like a Certificate Revocation List (CRL) — Grid CAs publish CRLs either as .pem bundles or as hash.r0/hash.r1 files. Returns 1 for both patterns (.pem suffix, dot-r-digit pattern); 0 otherwise used by directory loader to filter only valid CRL filenames during readdir iteration. */

/* ---- Function: xrootd_pki_crl_filename_matches() (static) ----
 *
 * WHAT: Checks whether a filename looks like a Certificate Revocation List (CRL) — Grid CAs publish CRLs either as .pem bundles or as hash.r0/hash.r1 files. Returns 1 for both patterns (.pem suffix, dot-r-digit pattern); 0 otherwise used by directory loader to filter only valid CRL filenames during readdir iteration ensuring stale helper files are not loaded into the CRL stack. */

/* ---- WHY: Grid CA distributions use multiple naming conventions for CRL files — .pem bundles contain PEM-encoded CRL entries; hash.r0/hash.r1 files follow OpenSSL's hash-based directory structure convention. Matching both patterns ensures all valid CRL files are collected regardless of CA distribution format without loading unrelated helper files or symlinks into the verification stack. ---- */
/* ---- HOW: Computes strlen(name). Checks suffix — if last 4 chars equal ".pem" returns 1. Also checks for hash.r0/hash.r1 pattern (last 3 chars: '.' + 'r' + digit '0'-'9') returns 1. Returns 0 for all other filenames. Used by directory loader to filter valid CRL entries during readdir iteration. */

/* ------------------------------------------------------------------ */
/* Section: Path Join Helper                                            */
/* ------------------------------------------------------------------ */
/*
 * WHAT: xrootd_pki_join_child_path() builds a full file path by combining directory name and filename using snprintf — validates output fits within dst_size bounds preventing buffer overflow when concatenating long paths. Returns NGX_OK on success; NGX_ERROR on truncation used by directory loader for constructing child file paths during readdir iteration. */

/* ---- Function: xrootd_pki_join_child_path() (static) ----
 *
 * WHAT: Builds a full file path by combining directory name and filename using snprintf — validates output fits within dst_size bounds preventing buffer overflow when concatenating long paths. Returns NGX_OK on success; NGX_ERROR on truncation used by directory loader for constructing child file paths during readdir iteration ensuring all constructed paths are safe for subsequent stat() and fopen() calls which would fail on truncated paths causing undefined behavior or security issues during PKI file discovery. */

/* ---- WHY: PATH_MAX bound validation prevents buffer overflow when combining potentially long directory names with filenames — snprintf output check ensures the concatenated path fits within dst before proceeding to stat() or fopen() which would fail on truncated paths causing undefined behavior or security issues during PKI file discovery. ---- */
/* ---- HOW: Calls snprintf(dst, dst_size, "%s/%s", directory, filename) to concatenate components. Checks return value — if negative (encoding error) or >= dst_size (truncation), returns NGX_ERROR. Otherwise returns NGX_OK confirming the full path safely fits within bounds. */

/* ------------------------------------------------------------------ */
/* Section: Regular File Check                                          */
/* ------------------------------------------------------------------ */
/*
 * WHAT: xrootd_pki_is_regular_file() checks whether a path points to a regular file (not a directory, symlink, etc.) using stat() and S_ISREG() — returns 1 if both conditions met (stat succeeds AND st_mode indicates regular file), 0 otherwise used by directory loader to skip non-regular entries during readdir iteration. */

/* ---- Function: xrootd_pki_is_regular_file() (static) ----
 *
 * WHAT: Checks whether a path points to a regular file (not a directory, symlink, etc.) using stat() and S_ISREG() — returns 1 if both conditions met (stat succeeds AND st_mode indicates regular file), 0 otherwise used by directory loader to skip non-regular entries during readdir iteration ensuring only actual certificate/CRL files are loaded into stacks rather than directories or special device files. */

/* ---- WHY: Regular file validation prevents loading non-file entries that would fail subsequent fopen() calls — symlinks, directories, and special device files should not be processed as PEM content sources. Skipping these entries avoids unnecessary stat() failures and potential security issues where unexpected filesystem objects could masquerade as certificate bundles. ---- */
/* ---- HOW: Calls stat(path, &file_stat) to retrieve filesystem metadata. Returns 1 only if stat succeeds (==0) AND st_mode indicates a regular file via S_ISREG(). Returns 0 for directories, symlinks, device files, or any stat failure. Used by directory loader to skip non-regular entries during readdir iteration. */

/* ------------------------------------------------------------------ */
/* Section: Single File PEM Loaders                                     */
/* ------------------------------------------------------------------ */
/*
 * WHAT: xrootd_pki_load_certs_from_file() reads PEM-format certificates from a single file and adds them to the cert stack — each certificate loaded one at a time until no more are found using PEM_read_X509() loop. Sets FD_CLOEXEC on file descriptor preventing fork-inherited file handle leaks. Returns count of successfully loaded certificates; 0 if file cannot be opened or loading fails mid-way. */

/* ---- Function: xrootd_pki_load_certs_from_file() (static) ----
 *
 * WHAT: Reads PEM-format certificates from a single file and adds them to the cert stack — each certificate loaded one at a time until no more are found using PEM_read_X509() loop. Sets FD_CLOEXEC on file descriptor preventing fork-inherited file handle leaks. Returns count of successfully loaded certificates; 0 if file cannot be opened or loading fails mid-way. Free failed certificate (X509_free) when stack push fails to prevent memory leaks. */

/* ---- WHY: Single-file PEM loading provides efficient batch certificate acquisition for CA bundles containing multiple certificates — loop continues until PEM_read_X509 returns NULL indicating end of file content. FD_CLOEXEC prevents fork-inherited file handle leaks ensuring child processes don't accidentally access parent's PKI files after nginx worker fork events. ---- */
/* ---- HOW: Opens the file with fopen(path, "r"). If open fails and log_open_error==1, logs a WARN-level error with ngx_errno. Sets FD_CLOEXEC on the file descriptor via fcntl(). Loops calling PEM_read_X509(fp) until NULL — each cert is pushed onto the stack; if push fails the cert is freed and loop breaks with an ERR-level log. Returns count of successfully loaded certificates. Closes file before returning. */

/* ------------------------------------------------------------------ */
/* Section: Single File CRL Loader                                      */
/* ------------------------------------------------------------------ */
/*
 * WHAT: xrootd_pki_load_crls_from_file() reads Certificate Revocation List (CRL) entries from a single file and adds them to the CRL stack — each CRL loaded one at a time until no more are found using PEM_read_X509_CRL() loop. Sets FD_CLOEXEC on file descriptor preventing fork-inherited file handle leaks. Returns count of successfully loaded CRLs; 0 if file cannot be opened or loading fails mid-way. */

/* ---- Function: xrootd_pki_load_crls_from_file() (static) ----
 *
 * WHAT: Reads Certificate Revocation List (CRL) entries from a single file and adds them to the CRL stack — each CRL loaded one at a time until no more are found using PEM_read_X509_CRL() loop. Sets FD_CLOEXEC on file descriptor preventing fork-inherited file handle leaks. Returns count of successfully loaded CRLs; 0 if file cannot be opened or loading fails mid-way. Free failed CRL (X509_CRL_free) when stack push fails to prevent memory leaks. */

/* ---- WHY: Single-file CRL loading provides efficient batch revocation list acquisition for bundles containing multiple CRL entries — loop continues until PEM_read_X509_CRL returns NULL indicating end of file content. FD_CLOEXEC prevents fork-inherited file handle leaks ensuring child processes don't accidentally access parent's PKI files after nginx worker fork events. ---- */
/* ---- HOW: Opens the file with fopen(path, "r"). If open fails and log_open_error==1, logs a WARN-level error with ngx_errno. Sets FD_CLOEXEC on the file descriptor via fcntl(). Loops calling PEM_read_X509_CRL(fp) until NULL — each CRL is pushed onto the stack; if push fails the CRL is freed and loop breaks with an ERR-level log. Returns count of successfully loaded CRLs. Closes file before returning. */

/* ------------------------------------------------------------------ */
/* Section: Path-Based Certificate Loader                               */
/* ------------------------------------------------------------------ */
/*
 * WHAT: xrootd_pki_load_certs_from_path() loads X509 certificates from either a single-file or directory path — stat() determines path type (file vs directory), then delegates to appropriate loader. File path: calls xrootd_pki_load_certs_from_file() with log_open_error=1; Directory path: opens DIR, iterates readdir entries skipping dot-prefix files, constructs child paths via join_child_path(), validates regular file status, loads each non-directory entry with log_open_error=0 (silent failures for helper files). Returns NULL if no certificates loaded or allocation failed. */

/* ---- Function: xrootd_pki_load_certs_from_path() ----
 *
 * WHAT: Loads X509 certificates from either a single-file or directory path — stat() determines path type (file vs directory), then delegates to appropriate loader. File path: calls xrootd_pki_load_certs_from_file() with log_open_error=1; Directory path: opens DIR, iterates readdir entries skipping dot-prefix files, constructs child paths via join_child_path(), validates regular file status, loads each non-directory entry with log_open_error=0 (silent failures for helper files). Returns NULL if no certificates loaded or allocation failed. Free stack on failure to prevent memory leaks. */
/* HOW: First calls stat() to determine path type — S_ISREG delegates to single-file loader; S_ISDIR opens directory and iterates readdir entries. Directory mode filters dot-prefix entries, joins child paths with PATH_MAX bounds check, validates regular file status before attempting PEM loading. Both modes allocate stack via sk_X509_new_null(), return NULL if empty or allocation failed (always frees on error). */

/* ---- WHY: Path-based certificate loading supports both single-bundle and directory-based CA distribution formats — stat() determines the appropriate loading strategy without requiring operator configuration choice. Directory mode handles OpenSSL hash symlinks and helper files gracefully by silently ignoring non-certificate entries while logging only actual PEM file open failures. Stack allocation ensures consistent memory management across both path types with cleanup on empty results. ---- */

/* ------------------------------------------------------------------ */
/* Section: Path-Based CRL Loader                                       */
/* ------------------------------------------------------------------ */
/*
 * WHAT: xrootd_pki_load_crls_from_path() loads X509_CRL entries from either a single-file or directory path — stat() determines path type (file vs directory), then delegates to appropriate loader. File path: calls xrootd_pki_load_crls_from_file() with log_open_error=1; Directory path: opens DIR, iterates readdir entries filtering only CRL filenames via xrootd_pki_crl_filename_matches(), constructs child paths via join_child_path(), validates regular file status, loads each matching entry with log_open_error=0 (silent failures for helper files). Returns NULL if no CRLs loaded or allocation failed. */

/* ---- Function: xrootd_pki_load_crls_from_path() ----
 *
 * WHAT: Loads X509_CRL entries from either a single-file or directory path — stat() determines path type (file vs directory), then delegates to appropriate loader. File path: calls xrootd_pki_load_crls_from_file() with log_open_error=1; Directory path: opens DIR, iterates readdir entries filtering only CRL filenames via xrootd_pki_crl_filename_matches(), constructs child paths via join_child_path(), validates regular file status, loads each matching entry with log_open_error=0 (silent failures for helper files). Returns NULL if no CRLs loaded or allocation failed. Free stack on failure to prevent memory leaks. */

/* ---- WHY: Path-based CRL loading supports both single-bundle and directory-based revocation list distribution formats — stat() determines the appropriate loading strategy without requiring operator configuration choice. Directory mode filters only valid CRL filenames (.pem, hash.r0/hash.r1 patterns) ensuring unrelated helper files or symlinks are not loaded into the verification stack. Stack allocation ensures consistent memory management across both path types with cleanup on empty results. ---- */

/*
 * PEM certificate and CRL loaders used by startup consistency checks.
 */

#include "pki_check.h"

#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

/*
 * Check whether a filename looks like a Certificate Revocation List (CRL).
 * Grid CAs publish CRLs either as .pem bundles or as hash.r0/hash.r1 files.
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

/*
 * Build a full file path by combining directory name and filename.
 */
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

/*
 * Check whether a path points to a regular file (not a directory, symlink, etc.).
 */
static ngx_flag_t
xrootd_pki_is_regular_file(const char *path)
{
    struct stat file_stat;

    return stat(path, &file_stat) == 0 && S_ISREG(file_stat.st_mode);
}

/*
 * Read PEM-format certificates from a single file and add them to the cert stack.
 * Each certificate in the file is loaded one at a time until no more are found.
 */
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
    fcntl(fileno(fp), F_SETFD, FD_CLOEXEC);

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

/*
 * Read Certificate Revocation List (CRL) entries from a single file and add them to the CRL stack.
 */
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
    fcntl(fileno(fp), F_SETFD, FD_CLOEXEC);

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
