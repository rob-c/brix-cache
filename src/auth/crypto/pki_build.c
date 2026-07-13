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

    (void) fclose(fp); /* phase74-fp: read-only stream, close failure cannot lose data */
    return count;
}

/*
 * WHAT: decide whether a directory entry name is a CRL file we should load.
 * WHY:  grid CA CRL directories mix CRLs with hash-link and metadata files; we
 *       load only *.pem and the *.r0-*.r9 grid CRL naming convention.  Isolating
 *       the predicate keeps the scan loop's branching (and CCN) contained here.
 * HOW:  suffix-test the name; return 1 on a match, 0 otherwise.
 */
static int
pki_crl_name_matches(const char *name)
{
    size_t nlen = strlen(name);

    if (nlen > 4 && strcmp(name + nlen - 4, ".pem") == 0) {
        return 1;
    }
    if (nlen > 3 && name[nlen - 3] == '.'
        && name[nlen - 2] == 'r'
        && name[nlen - 1] >= '0' && name[nlen - 1] <= '9')
    {
        return 1;
    }
    return 0;
}

/*
 * WHAT: load CRLs from one matched directory entry into the store.
 * WHY:  factors the per-entry path-join / regular-file guard / load out of the
 *       scan loop so the loop body is a single call and the loop's CCN drops.
 * HOW:  join dir+name, skip anything that is not a stat-able regular file, then
 *       delegate to pki_load_crls_from_file.  Returns CRLs added (>=0); a
 *       non-regular or over-long entry contributes 0 (silently skipped, exactly
 *       as before).
 */
static int
pki_load_crls_from_dirent(X509_STORE *store, const char *dir_path,
    const char *name, ngx_log_t *log)
{
    char        fpath[PATH_MAX];
    struct stat st;
    int         n;

    n = snprintf(fpath, sizeof(fpath), "%s/%s", dir_path, name);
    if (n < 0 || (size_t) n >= sizeof(fpath)) {
        return 0;
    }

    if (stat(fpath, &st) != 0 || !S_ISREG(st.st_mode)) {
        return 0;
    }

    n = pki_load_crls_from_file(store, fpath, log);
    return (n > 0) ? n : 0;
}

/*
 * WHAT: scan a CRL directory, loading every matching *.pem / *.r[0-9] CRL.
 * WHY:  separates the directory-iteration stage from the file-vs-directory
 *       dispatch so each function keeps one job and a low CCN.
 * HOW:  opendir + readdir loop; delegate matching to pki_crl_name_matches and
 *       per-entry loading to pki_load_crls_from_dirent.  Returns total CRLs
 *       added, or -1 if the directory cannot be opened.
 */
static int
pki_load_crls_from_dir(X509_STORE *store, const char *path, ngx_log_t *log)
{
    DIR           *dir;
    struct dirent *ent;
    int            total;

    dir = opendir(path);
    if (dir == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                      "brix_pki: cannot open CRL directory \"%s\"", path);
        return -1;
    }

    total = 0;
    while ((ent = readdir(dir)) != NULL) {
        if (!pki_crl_name_matches(ent->d_name)) {
            continue;
        }
        total += pki_load_crls_from_dirent(store, path, ent->d_name, log);
    }

    closedir(dir);
    return total;
}

/*
 * Load CRLs from a file or directory into the store.
 * Returns total CRLs added, or -1 on infrastructure failure (stat/opendir).
 * Directory scan matches *.pem and *.r0-*.r9 (grid CA CRL naming convention).
 */
static int
pki_load_crls(X509_STORE *store, const char *path, ngx_log_t *log)
{
    struct stat st;

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

    return pki_load_crls_from_dir(store, path, log);
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

/* ---- per-config-parse memo for the (expensive) CA/CRL store -------------- */

#define BRIX_CA_STORE_CACHE_MAX 16

typedef struct {
    char        key[768];       /* inputs fingerprint; empty = free slot       */
    X509_STORE *store;          /* cached (one ref held by the cache)          */
    int         crl_count;
} brix_ca_store_cache_ent_t;

static brix_ca_store_cache_ent_t brix_ca_store_cache[BRIX_CA_STORE_CACHE_MAX];

/*
 * WHAT: render the cache key (inputs fingerprint) for a store request.
 * WHY:  the key is INPUTS-ONLY (no scope/cycle) so a store built in the
 *       config-load process is reused by the master it forks into; isolating
 *       the format string keeps the one canonical spelling in one place.
 * HOW:  ngx_snprintf the CA/CRL paths + flags + modes into caller-owned buf.
 */
static void
brix_ca_store_cache_key(char *buf, size_t buflen, const char *cadir,
    const char *cafile, const char *crl_path, unsigned long extra_flags,
    brix_sp_mode_t sp_mode, int crl_mode)
{
    ngx_snprintf((u_char *) buf, buflen, "%s|%s|%s|%ul|%d|%d%Z",
        cadir ? cadir : "", cafile ? cafile : "", crl_path ? crl_path : "",
        extra_flags, (int) sp_mode, crl_mode);
}

/*
 * WHAT: probe the cache for an existing store matching @key.
 * WHY:  a hit skips the ~1s IGTF-CRL directory load; extracting the scan drops
 *       the branching (and CCN) out of the public entry point.
 * HOW:  linear scan of the fixed table.  On a hit: up_ref the store (caller owns
 *       the returned ref exactly as in the miss path), publish crl_count, log,
 *       and return it.  On a miss: record the first free slot via @free_slot_out
 *       and return NULL.
 */
static X509_STORE *
brix_ca_store_cache_get(const char *key, ngx_log_t *log, const char *cadir,
    const char *cafile, int *crl_count_out, int *free_slot_out)
{
    int i;

    *free_slot_out = -1;

    for (i = 0; i < BRIX_CA_STORE_CACHE_MAX; i++) {
        brix_ca_store_cache_ent_t *e = &brix_ca_store_cache[i];

        if (e->store != NULL && ngx_strcmp(e->key, key) == 0) {
            if (crl_count_out != NULL) { *crl_count_out = e->crl_count; }
            X509_STORE_up_ref(e->store);
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "brix_pki: reusing the CA/CRL store already built for \"%s\" "
                "(skipped a redundant CRL directory load)",
                cadir ? cadir : (cafile ? cafile : "(system)"));
            return e->store;
        }
        if (e->store == NULL && *free_slot_out < 0) { *free_slot_out = i; }
    }

    return NULL;
}

/*
 * WHAT: install a freshly built store into a free cache slot.
 * WHY:  the cache holds one reference; publishing it here keeps the ref/copy
 *       bookkeeping beside the lookup it mirrors.  A full table (slot < 0) is a
 *       no-op — the store is simply not memoised.
 * HOW:  up_ref for the cache's own ref, copy the key, record store + crl_count.
 */
static void
brix_ca_store_cache_put(int slot, const char *key, X509_STORE *store,
    int crl_count)
{
    brix_ca_store_cache_ent_t *e;

    if (slot < 0) {
        return;
    }

    e = &brix_ca_store_cache[slot];
    X509_STORE_up_ref(store);                 /* the cache holds one ref */
    ngx_cpystrn((u_char *) e->key, (u_char *) key, sizeof(e->key));
    e->store     = store;
    e->crl_count = crl_count;
}

/* Keyed by INPUTS ONLY (not by scope/cycle) so a store built in the config-load
 * process is reused by the daemonised master it forks into — collapsing the
 * duplicate ~1s IGTF-CRL load a dynamic module otherwise pays twice at startup.
 * `scope != NULL` enables caching; the per-worker CRL hot-reload timer passes
 * NULL to force a fresh rebuild from the current CRLs on disk.  A config change
 * to the CA/CRL paths yields a different key (rebuilds); a reload that only
 * rotates CRL *content* under the same dir is refreshed by that timer. */
X509_STORE *
brix_build_ca_store_cached(void *scope, ngx_log_t *log,
    const char *cadir, const char *cafile, const char *crl_path,
    unsigned long extra_flags, int *crl_count_out,
    brix_sp_mode_t sp_mode, int crl_mode)
{
    char        key[768];
    int         free_slot = -1;
    X509_STORE *store;
    int         crl_count = 0;

    if (scope == NULL) {                      /* caching disabled (CRL reload) */
        return brix_build_ca_store(log, cadir, cafile, crl_path, extra_flags,
                                     crl_count_out, sp_mode, crl_mode);
    }

    brix_ca_store_cache_key(key, sizeof(key), cadir, cafile, crl_path,
                            extra_flags, sp_mode, crl_mode);

    store = brix_ca_store_cache_get(key, log, cadir, cafile, crl_count_out,
                                    &free_slot);
    if (store != NULL) {
        return store;
    }

    store = brix_build_ca_store(log, cadir, cafile, crl_path, extra_flags,
                                 &crl_count, sp_mode, crl_mode);
    if (store == NULL) {
        return NULL;
    }
    if (crl_count_out != NULL) { *crl_count_out = crl_count; }

    brix_ca_store_cache_put(free_slot, key, store, crl_count);
    return store;
}
