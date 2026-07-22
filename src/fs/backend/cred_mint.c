/*
 * cred_mint.c — opt-in x509 credential minting (phase-2 T9). See cred_mint.h.
 *
 * WHAT: Implements brix_cred_mint(): cache-check an existing <key>.pem, and
 *       when it is missing/expired/within-refresh, generate a fresh EC P-256
 *       keypair + X509 signed by the operator's mint CA and write it
 *       atomically to <cred_dir>/<key>.pem.
 *
 * WHY:  See cred_mint.h for the full rationale and trust-model note. In
 *       short: gives bearer-only identities (S3 access keys, WLCG tokens
 *       with no matching pre-provisioned proxy) a per-user x509 origin
 *       identity without requiring the operator to pre-provision one file
 *       per user.
 *
 * HOW:  Four static helpers, each owning and freeing its own OpenSSL
 *       objects on every return path (no goto, mirrors the pxr_ctx/pxr_fail
 *       pattern in src/auth/gsi/proxy_req.c):
 *         mint_load_ca()       — PEM_read_bio_X509 + PEM_read_bio_PrivateKey.
 *         mint_cached_pem_ok() — parse an existing <key>.pem, compare notAfter
 *                                against now + refresh window.
 *         mint_build_cert()    — EVP_PKEY_Q_keygen(EC P-256), build+sign X509.
 *         mint_write_pem()     — serialize cert+key+CA cert, write via a
 *                                same-directory O_EXCL 0600 temp file + fsync
 *                                + rename (atomic, never a half-written file).
 */
#include "cred_mint.h"
#include "cred_mint_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#define MINT_PATH_MAX 1024

/* MINT_LOG, mint_ca_t, mint_material_t, and the mint_build_cert() prototype
 * live in cred_mint_internal.h — shared with cred_mint_cert.c, which owns the
 * EC-keygen + X509 build/sign half of the mint. */

/* ---- mint_load_ca ------------------------------------------------------
 * WHAT: Load the mint CA's certificate and private key from PEM files.
 * WHY:  Single place that owns the "bad CA material" failure mode so
 *       brix_cred_mint() never has to special-case it.
 * HOW:  fopen + PEM_read_X509 / PEM_read_PrivateKey; NULL on any failure,
 *       with partial allocations freed before returning. */
static int
mint_load_ca(const char *ca_cert_path, const char *ca_key_path,
    X509 **out_cert, EVP_PKEY **out_key, ngx_log_t *log)
{
    FILE     *f;
    X509     *cert = NULL;
    EVP_PKEY *key  = NULL;

    *out_cert = NULL;
    *out_key  = NULL;

    f = fopen(ca_cert_path, "r");
    if (f != NULL) {
        cert = PEM_read_X509(f, NULL, NULL, NULL);
        (void) fclose(f);   /* read-only stream — nothing buffered to lose */
    }
    if (cert == NULL) {
        MINT_LOG(NGX_LOG_ERR, log, 0,
            "brix: cred_mint: cannot load mint CA cert \"%s\"", ca_cert_path);
        return NGX_ERROR;
    }

    f = fopen(ca_key_path, "r");
    if (f != NULL) {
        key = PEM_read_PrivateKey(f, NULL, NULL, NULL);
        (void) fclose(f);   /* read-only stream — nothing buffered to lose */
    }
    if (key == NULL) {
        MINT_LOG(NGX_LOG_ERR, log, 0,
            "brix: cred_mint: cannot load mint CA key \"%s\"", ca_key_path);
        X509_free(cert);
        return NGX_ERROR;
    }

    *out_cert = cert;
    *out_key  = key;
    return NGX_OK;
}

/* ---- mint_cached_pem_ok -------------------------------------------------
 * WHAT: 1 iff <path> parses as an X509 whose notAfter is more than
 *       BRIX_CRED_MINT_REFRESH_WINDOW seconds in the future; 0 otherwise
 *       (absent, unparseable, expired, or within the refresh window).
 * WHY:  Avoids re-minting (and re-signing with the CA key) on every request
 *       once a valid proxy is cached; still re-mints proactively before the
 *       cached proxy would lapse mid-use.
 * HOW:  fopen + PEM_read_X509 (reads the FIRST PEM block — the leaf cert,
 *       matching ucred.c's ucred_check_pem convention) + X509_cmp_time
 *       against now + refresh window. */
static int
mint_cached_pem_ok(const char *path)
{
    FILE   *f;
    X509   *cert;
    time_t  cutoff;
    int     cmp;

    f = fopen(path, "r");
    if (f == NULL) {
        return 0;
    }
    cert = PEM_read_X509(f, NULL, NULL, NULL);
    (void) fclose(f);   /* read-only stream — nothing buffered to lose */
    if (cert == NULL) {
        return 0;
    }

    cutoff = time(NULL) + BRIX_CRED_MINT_REFRESH_WINDOW;
    cmp = X509_cmp_time(X509_get0_notAfter(cert), &cutoff);
    X509_free(cert);

    /* X509_cmp_time returns -1 if notAfter < cutoff (not enough life left),
     * 0 on a parse error (treat as not-ok), 1 if notAfter > cutoff (ok). */
    return (cmp > 0) ? 1 : 0;
}

/* ---- mint_serialize_pem --------------------------------------------------
 * WHAT: Serialize `cert` + `key` + `ca_cert` as concatenated PEM blocks (leaf
 *       cert, then private key, then the mint CA cert as the trust-chain tail)
 *       into a fresh mem BIO, returned on success. NULL on any failure, with
 *       the (partial) BIO freed.
 * WHY:  Owns the PEM-serialization failure mode so mint_write_pem() only has
 *       to deal with the file side; keeps the exact block ORDER (cert, key,
 *       CA) as the single point of truth — a reader relies on it.
 * HOW:  BIO_s_mem + PEM_write_bio_X509/PrivateKey/X509 + a non-empty check via
 *       BIO_get_mem_data. The caller owns the returned BIO and must BIO_free
 *       it (and reads its bytes via BIO_get_mem_data while it lives). */
static BIO *
mint_serialize_pem(X509 *cert, EVP_PKEY *key, X509 *ca_cert, ngx_log_t *log)
{
    BIO  *mem;
    char *data = NULL;

    mem = BIO_new(BIO_s_mem());
    if (mem == NULL
        || PEM_write_bio_X509(mem, cert) != 1
        || PEM_write_bio_PrivateKey(mem, key, NULL, NULL, 0, NULL, NULL) != 1
        || PEM_write_bio_X509(mem, ca_cert) != 1) {
        MINT_LOG(NGX_LOG_ERR, log, 0,
            "brix: cred_mint: PEM serialization failed");
        BIO_free(mem);
        return NULL;
    }
    if (BIO_get_mem_data(mem, &data) <= 0) {
        MINT_LOG(NGX_LOG_ERR, log, 0,
            "brix: cred_mint: empty PEM output");
        BIO_free(mem);
        return NULL;
    }

    return mem;
}

/* ---- mint_write_tmp ------------------------------------------------------
 * WHAT: Write `len` bytes of `data` to a freshly-created, O_EXCL, 0600,
 *       O_NOFOLLOW temp file at `tmp_path`, then fsync it. On any failure the
 *       temp file is unlinked before returning NGX_ERROR; on success the file
 *       persists (owned by the caller, which renames it into place).
 * WHY:  Isolates the durable-write failure ladder (open/write/fsync) so
 *       mint_write_pem() reads as serialize -> write-tmp -> rename.
 * HOW:  open(O_CREAT|O_EXCL|O_WRONLY|O_NOFOLLOW,0600), full-length write,
 *       fsync, close; unlink on the error paths. */
static int
mint_write_tmp(const char *tmp_path, const char *data, long len,
    ngx_log_t *log)
{
    int     fd;
    int     rc = NGX_ERROR;
    ssize_t w;

    fd = open(tmp_path, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW, 0600);
    if (fd < 0) {
        MINT_LOG(NGX_LOG_ERR, log, errno,
            "brix: cred_mint: cannot create temp file \"%s\"", tmp_path);
        return NGX_ERROR;
    }

    w = write(fd, data, (size_t) len);
    if (w < 0 || w != len) {
        MINT_LOG(NGX_LOG_ERR, log, errno,
            "brix: cred_mint: short/failed write to \"%s\"", tmp_path);
    } else if (fsync(fd) != 0) {
        MINT_LOG(NGX_LOG_ERR, log, errno,
            "brix: cred_mint: fsync failed on \"%s\"", tmp_path);
    } else {
        rc = NGX_OK;
    }
    close(fd);

    if (rc != NGX_OK) {
        unlink(tmp_path);
    }
    return rc;
}

/* ---- mint_build_paths ----------------------------------------------------
 * WHAT: Fill `final_path` (<dir>/<key_stem>.pem) and `tmp_path`
 *       (<dir>/.mint-<key_stem>.<pid>.tmp) — the PID keeps concurrent mints
 *       from colliding on the temp name. NGX_ERROR if either overflows its
 *       MINT_PATH_MAX buffer.
 * WHY:  Removes two length-check branches from mint_write_pem() and names the
 *       temp-file naming convention in one place.
 * HOW:  Bounded snprintf into caller-owned MINT_PATH_MAX buffers. */
static int
mint_build_paths(const char *dir, const char *key_stem,
    char final_path[MINT_PATH_MAX], char tmp_path[MINT_PATH_MAX],
    ngx_log_t *log)
{
    int n;

    n = snprintf(final_path, MINT_PATH_MAX, "%s/%s.pem", dir, key_stem);
    if (n < 0 || (size_t) n >= (size_t) MINT_PATH_MAX) {
        MINT_LOG(NGX_LOG_ERR, log, 0,
            "brix: cred_mint: credential path too long");
        return NGX_ERROR;
    }
    n = snprintf(tmp_path, MINT_PATH_MAX, "%s/.mint-%s.%d.tmp",
        dir, key_stem, (int) getpid());
    if (n < 0 || (size_t) n >= (size_t) MINT_PATH_MAX) {
        MINT_LOG(NGX_LOG_ERR, log, 0,
            "brix: cred_mint: temp credential path too long");
        return NGX_ERROR;
    }
    return NGX_OK;
}

/* ---- mint_write_pem -------------------------------------------------------
 * WHAT: Serialize mat->cert + mat->key + mat->ca_cert (leaf, then key, then
 *       the mint CA cert as the trust-chain tail) as concatenated PEM blocks
 *       and write them atomically to <dir>/<key_stem>.pem.
 * WHY:  A reader (brix_sd_ucred_resolve, or any other process racing this
 *       mint) must never observe a partially-written file; a crash between
 *       open() and the final bytes must not leave a corrupt .pem where a
 *       valid one previously existed.
 * HOW:  mint_build_paths -> mint_serialize_pem (in-memory) -> mint_write_tmp
 *       (same-directory O_EXCL 0600 temp + fsync) -> rename() over the final
 *       path (POSIX rename is atomic within one filesystem). The temp name
 *       embeds the PID so concurrent mints cannot collide.
 * vfs-seam-allow: svc-owned credential dir, not an export — this is the
 * shared per-user backend-credential cache directory (brix_storage_
 * credential_dir), not an fs/ export root; raw POSIX I/O here is the
 * existing Phase-1 seam convention (see ucred.c's O_NOFOLLOW token read). */
static int
mint_write_pem(const char *dir, const char *key_stem,
    const mint_material_t *mat, ngx_log_t *log)
{
    char  final_path[MINT_PATH_MAX];
    char  tmp_path[MINT_PATH_MAX];
    BIO  *mem = NULL;
    char *data = NULL;
    long  len = 0;

    if (mint_build_paths(dir, key_stem, final_path, tmp_path, log) != NGX_OK) {
        return NGX_ERROR;
    }

    mem = mint_serialize_pem(mat->cert, mat->key, mat->ca_cert, log);
    if (mem == NULL) {
        return NGX_ERROR;
    }
    len = BIO_get_mem_data(mem, &data);   /* aliases into mem; valid till free */

    if (mint_write_tmp(tmp_path, data, len, log) != NGX_OK) {
        BIO_free(mem);
        return NGX_ERROR;
    }
    BIO_free(mem);

    if (rename(tmp_path, final_path) != 0) {
        MINT_LOG(NGX_LOG_ERR, log, errno,
            "brix: cred_mint: rename \"%s\" -> \"%s\" failed",
            tmp_path, final_path);
        unlink(tmp_path);
        return NGX_ERROR;
    }

    return NGX_OK;
}

/* ---- mint_args_valid -----------------------------------------------------
 * WHAT: 1 iff every required brix_cred_mint() string argument is non-NULL and
 *       non-empty; 0 otherwise.
 * WHY:  Collapses the five-way validation ladder out of brix_cred_mint() so
 *       the public entry point stays under the CCN cap; the check itself is
 *       unchanged (same arguments, same "NULL or empty -> reject" rule).
 * HOW:  Short-circuit boolean over each argument's NULL/first-byte test. */
static int
mint_args_valid(const char *cred_dir, const char *ca_cert_path,
    const char *ca_key_path, const char *principal, const char *key)
{
    return cred_dir != NULL && cred_dir[0] != '\0'
        && ca_cert_path != NULL && ca_cert_path[0] != '\0'
        && ca_key_path != NULL && ca_key_path[0] != '\0'
        && principal != NULL && principal[0] != '\0'
        && key != NULL && key[0] != '\0';
}

/* ---- mint_generate -------------------------------------------------------
 * WHAT: Load the mint CA, build+sign a fresh proxy for `principal`, and write
 *       it atomically to <cred_dir>/<key>.pem. Assumes the cache-miss path
 *       (caller has already ruled out a still-valid cached PEM).
 * WHY:  Owns the full OpenSSL object lifecycle (CA cert/key + minted cert/key)
 *       and its exact free ordering — CA material and minted material are each
 *       freed on every return path — so brix_cred_mint() stays a thin
 *       cache-check + delegate + log wrapper under the CCN cap.
 * HOW:  mint_load_ca -> mint_build_cert -> mint_write_pem; frees the minted
 *       cert/key then the CA cert/key (order preserved from the original
 *       single-function form). `principal`, `key`, `ttl_secs` reach the log
 *       line and cert build; the CA-file paths reach only mint_load_ca. */
static ngx_int_t
mint_generate(const char *cred_dir, const char *ca_cert_path,
    const char *ca_key_path, const char *principal, const char *key,
    int ttl_secs, ngx_log_t *log)
{
    mint_ca_t       ca  = { NULL, NULL };
    mint_material_t mat = { NULL, NULL, NULL };
    ngx_int_t       rc;

    if (mint_load_ca(ca_cert_path, ca_key_path, &ca.cert, &ca.key, log)
        != NGX_OK) {
        return NGX_ERROR;
    }

    if (mint_build_cert(&ca, principal, ttl_secs, &mat, log) != NGX_OK) {
        X509_free(ca.cert);
        EVP_PKEY_free(ca.key);
        return NGX_ERROR;
    }
    mat.ca_cert = ca.cert;   /* trust-chain tail written into the PEM */

    rc = mint_write_pem(cred_dir, key, &mat, log) == NGX_OK
       ? NGX_OK : NGX_ERROR;

    if (rc == NGX_OK) {
        MINT_LOG(NGX_LOG_NOTICE, log, 0,
            "brix: cred_mint: minted proxy for principal=\"%s\" key=%s "
            "ttl=%ds", principal, key, ttl_secs);
    }

    X509_free(mat.cert);
    EVP_PKEY_free(mat.key);
    X509_free(ca.cert);
    EVP_PKEY_free(ca.key);
    return rc;
}

/*
 * brix_cred_mint — see cred_mint.h.
 */
ngx_int_t
brix_cred_mint(const char *cred_dir, const char *ca_cert_path,
    const char *ca_key_path, const char *principal, const char *key,
    int ttl_secs, ngx_log_t *log)
{
    char existing_path[MINT_PATH_MAX];
    int  n;

    if (!mint_args_valid(cred_dir, ca_cert_path, ca_key_path, principal,
            key)) {
        return NGX_ERROR;
    }

    n = snprintf(existing_path, sizeof(existing_path), "%s/%s.pem",
        cred_dir, key);
    if (n < 0 || (size_t) n >= sizeof(existing_path)) {
        MINT_LOG(NGX_LOG_ERR, log, 0,
            "brix: cred_mint: credential path too long for key \"%s\"", key);
        return NGX_ERROR;
    }

    /* Cache hit: an existing PEM with enough life left is reused verbatim —
     * no CA material is even loaded, so a steady-state deployment pays the
     * mint cost only once per refresh window per principal. */
    if (mint_cached_pem_ok(existing_path)) {
        return NGX_OK;
    }

    return mint_generate(cred_dir, ca_cert_path, ca_key_path, principal, key,
        ttl_secs, log);
}
