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

/* ---- MINT_LOG ---------------------------------------------------------
 * WHAT: ngx_log_error(), but tolerant of log==NULL (a no-op in that case).
 * WHY:  ngx_log_error() is a macro that dereferences `log` directly
 *       (`(log)->log_level >= level`) with no NULL guard of its own; callers
 *       of brix_cred_mint() in real request paths always carry ctx->log, but
 *       the standalone C unit test (tests/c/test_cred_mint.c) legitimately
 *       has no nginx log cycle available and passes NULL — guard every call
 *       site rather than change ngx_log_error's own contract. */
#define MINT_LOG(level, log, err, ...) \
    do { if ((log) != NULL) { ngx_log_error(level, log, err, __VA_ARGS__); } } while (0)

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

/* ---- mint_cn_char_ok -----------------------------------------------------
 * WHAT: 1 iff byte `c` is safe to copy verbatim into a CN RDN value: the
 *       ASCII alphanumerics plus the punctuation set [@._-/ =] (space and '='
 *       appear in DN-derived principals; '/' is a DN separator X509_NAME
 *       tolerates inside a single RDN value). Everything else — including
 *       control bytes and NUL — is rejected so mint_sanitize_cn maps it to '_'.
 * WHY:  Isolating the charset predicate keeps mint_sanitize_cn's loop trivial
 *       and makes the exact allow-list a single, testable, security-load-
 *       bearing point of truth (the set MUST stay identical byte-for-byte).
 * HOW:  Pure range/equality checks over the unsigned byte value. */
static int
mint_cn_char_ok(unsigned char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
        || (c >= '0' && c <= '9') || c == '@' || c == '.'
        || c == '_' || c == '-' || c == '/' || c == ' ' || c == '=';
}

/* ---- mint_sanitize_cn ----------------------------------------------------
 * WHAT: Copy `principal` into `out` (cap bytes) as a CN-safe string: any byte
 *       rejected by mint_cn_char_ok() is replaced with '_'. Truncates rather
 *       than overflows.
 * WHY:  The principal may be a DN, an S3 access key, or a JWT subject; RFC
 *       5280 does not forbid most of these characters in a CN, but control
 *       characters or an embedded NUL must never reach X509_NAME_add_entry.
 * HOW:  Single bounded pass; deterministic (same principal -> same CN). */
static void
mint_sanitize_cn(const char *principal, char *out, size_t cap)
{
    size_t i;
    size_t n = strlen(principal);

    if (n >= cap) {
        n = cap - 1;
    }
    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char) principal[i];
        out[i] = mint_cn_char_ok(c) ? (char) c : '_';
    }
    out[n] = '\0';
}

/* ---- mint_make_subject ---------------------------------------------------
 * WHAT: Build the minted-proxy subject X509_NAME "/O=brix-minted/CN=<cn>";
 *       NULL on any allocation/entry failure (freeing a partial name first).
 * WHY:  Owns the X509_NAME lifecycle in one place so mint_populate_cert()'s
 *       early-return ladder never has to special-case the subject build.
 * HOW:  X509_NAME_new + two X509_NAME_add_entry_by_txt calls; `cn` is already
 *       CN-sanitized by the caller (mint_sanitize_cn). */
static X509_NAME *
mint_make_subject(const char *cn, ngx_log_t *log)
{
    X509_NAME *subj = X509_NAME_new();

    if (subj == NULL
        || !X509_NAME_add_entry_by_txt(subj, "O", MBSTRING_ASC,
               (const unsigned char *) "brix-minted", -1, -1, 0)
        || !X509_NAME_add_entry_by_txt(subj, "CN", MBSTRING_ASC,
               (const unsigned char *) cn, -1, -1, 0)) {
        MINT_LOG(NGX_LOG_ERR, log, 0,
            "brix: cred_mint: cannot build proxy subject");
        X509_NAME_free(subj);
        return NULL;
    }
    return subj;
}

/* ---- mint_serial_from_rand -----------------------------------------------
 * WHAT: Pack 8 random bytes into a uint64 serial with the top bit cleared so
 *       the ASN1 INTEGER encoding is unambiguously positive.
 * WHY:  Keeps the bit-shuffle out of mint_populate_cert()'s boolean ladder
 *       and names the "coerce positive" invariant.
 * HOW:  Big-endian assembly of rnd[0..7]; rnd[0]'s top bit is masked off. */
static uint64_t
mint_serial_from_rand(const unsigned char rnd[8])
{
    return (((uint64_t) (rnd[0] & 0x7f)) << 56) | ((uint64_t) rnd[1] << 48)
         | ((uint64_t) rnd[2] << 40) | ((uint64_t) rnd[3] << 32)
         | ((uint64_t) rnd[4] << 24) | ((uint64_t) rnd[5] << 16)
         | ((uint64_t) rnd[6] << 8)  | (uint64_t) rnd[7];
}

/* ---- mint_cert_spec_t ----------------------------------------------------
 * WHAT: The immutable inputs mint_populate_cert() needs to set and sign one
 *       minted leaf certificate: its subject name, the mint CA cert (issuer
 *       source) and key (signer), the leaf's own public key, the ASN1 serial,
 *       and the validity window length in seconds.
 * WHY:  Bundling these related inputs keeps mint_populate_cert() at one job
 *       and ≤5 parameters without introducing any globals or changing what it
 *       does — purely a call-shape change.
 * HOW:  Plain aggregate, filled on the stack by mint_build_cert() and passed
 *       by const pointer; the helper mutates only the caller-owned `cert`. */
typedef struct {
    X509_NAME *subj;
    X509      *ca_cert;
    EVP_PKEY  *key;
    EVP_PKEY  *ca_key;
    uint64_t   serial;
    int        ttl_secs;
} mint_cert_spec_t;

/* ---- mint_ca_t / mint_material_t -----------------------------------------
 * WHAT: mint_ca_t bundles the loaded mint-CA cert+key (the signer);
 *       mint_material_t bundles the minted leaf cert+key plus the CA cert that
 *       forms the trust-chain tail written into the PEM.
 * WHY:  Groups the OpenSSL objects that always travel together so the mint
 *       helpers stay at ≤5 parameters without adding globals — the pointers
 *       and their free ordering are unchanged, only their call shape.
 * HOW:  Plain aggregates filled on the stack; ownership stays with the caller
 *       (each helper documents which objects it allocates or borrows). */
typedef struct {
    X509     *cert;
    EVP_PKEY *key;
} mint_ca_t;

typedef struct {
    X509     *cert;      /* minted leaf (owned) */
    EVP_PKEY *key;       /* minted leaf key (owned) */
    X509     *ca_cert;   /* borrowed: mint CA cert, PEM trust-chain tail */
} mint_material_t;

/* ---- mint_populate_cert --------------------------------------------------
 * WHAT: Populate and sign an already-allocated `cert` from `spec`: version 3,
 *       spec->serial, spec->subj, issuer = spec->ca_cert's subject, pubkey =
 *       spec->key, notBefore=now, notAfter=now+spec->ttl_secs,
 *       X509_sign(spec->ca_key, SHA-256). Returns NGX_OK/NGX_ERROR; frees
 *       nothing (caller owns cert).
 * WHY:  Splits the long field-setting boolean chain out of mint_build_cert()
 *       so each function stays under the CCN cap while preserving the exact
 *       single-expression short-circuit ordering (security-load-bearing).
 * HOW:  One boolean AND-chain; any failure logs and returns NGX_ERROR. */
static int
mint_populate_cert(X509 *cert, const mint_cert_spec_t *spec, ngx_log_t *log)
{
    if (X509_set_version(cert, 2L) != 1
        || ASN1_INTEGER_set_uint64(X509_get_serialNumber(cert),
               spec->serial) != 1
        || X509_set_subject_name(cert, spec->subj) != 1
        || X509_set_issuer_name(cert,
               X509_get_subject_name(spec->ca_cert)) != 1
        || X509_set_pubkey(cert, spec->key) != 1
        || X509_gmtime_adj(X509_getm_notBefore(cert), 0) == NULL
        || X509_gmtime_adj(X509_getm_notAfter(cert),
               (long) spec->ttl_secs) == NULL
        || X509_sign(cert, spec->ca_key, EVP_sha256()) <= 0) {
        MINT_LOG(NGX_LOG_ERR, log, 0,
            "brix: cred_mint: cannot build/sign minted proxy");
        return NGX_ERROR;
    }
    return NGX_OK;
}

/* ---- mint_build_cert -----------------------------------------------------
 * WHAT: Generate a fresh EC P-256 keypair and a signed X509 whose subject is
 *       "/O=brix-minted/CN=<sanitized principal>", issuer = the mint CA's
 *       subject, notBefore=now, notAfter=now+ttl_secs, signed by ca_key with
 *       SHA-256.
 * WHY:  Isolates the OpenSSL object lifecycle for the mint step so
 *       brix_cred_mint() stays a thin orchestrator; every early return here
 *       frees exactly what this call allocated.
 * HOW:  EVP_PKEY_Q_keygen(EC, P-256) -> X509_new -> mint_make_subject ->
 *       mint_populate_cert (which sets/signs every field). Serial is 8 random
 *       bytes coerced positive so it round-trips through ASN1_INTEGER. On
 *       success fills out->cert/out->key (leaves out->ca_cert untouched). */
static int
mint_build_cert(const mint_ca_t *ca, const char *principal, int ttl_secs,
    mint_material_t *out, ngx_log_t *log)
{
    EVP_PKEY   *key = NULL;
    X509       *cert = NULL;
    X509_NAME  *subj = NULL;
    unsigned char rnd[8];
    char        cn[256];
    int         ok;

    out->cert = NULL;
    out->key  = NULL;

    key = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
    if (key == NULL) {
        MINT_LOG(NGX_LOG_ERR, log, 0,
            "brix: cred_mint: EC P-256 key generation failed");
        return NGX_ERROR;
    }

    if (RAND_bytes(rnd, sizeof(rnd)) != 1) {
        MINT_LOG(NGX_LOG_ERR, log, 0, "brix: cred_mint: RNG failed");
        EVP_PKEY_free(key);
        return NGX_ERROR;
    }

    cert = X509_new();
    if (cert == NULL) {
        EVP_PKEY_free(key);
        return NGX_ERROR;
    }

    mint_sanitize_cn(principal, cn, sizeof(cn));
    subj = mint_make_subject(cn, log);
    if (subj == NULL) {
        X509_free(cert);
        EVP_PKEY_free(key);
        return NGX_ERROR;
    }

    mint_cert_spec_t spec = {
        .subj     = subj,
        .ca_cert  = ca->cert,
        .key      = key,
        .ca_key   = ca->key,
        .serial   = mint_serial_from_rand(rnd),
        .ttl_secs = ttl_secs,
    };
    ok = mint_populate_cert(cert, &spec, log) == NGX_OK;
    X509_NAME_free(subj);
    if (!ok) {
        X509_free(cert);
        EVP_PKEY_free(key);
        return NGX_ERROR;
    }

    out->cert = cert;
    out->key  = key;
    return NGX_OK;
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
