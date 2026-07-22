/*
 * cred_mint_cert.c — EC-keygen + X509 build/sign for opt-in x509 credential
 * minting (phase-2 T9). See cred_mint.h for the full rationale/trust-model and
 * cred_mint_internal.h for the shared macro/struct/prototype surface.
 *
 * WHAT: The certificate-construction half of brix_cred_mint(): sanitize the
 *       principal into a CN-safe string, build the minted-proxy subject,
 *       generate a fresh EC P-256 keypair, and populate + sign an X509 leaf
 *       with the mint CA. mint_build_cert() is the one entry point the
 *       orchestrator (cred_mint.c) calls; every other helper here is static.
 *
 * HOW:  mint_sanitize_cn (via mint_cn_char_ok) -> mint_make_subject ->
 *       EVP_PKEY_Q_keygen(EC P-256) -> mint_populate_cert (sets/signs every
 *       field). Each helper owns and frees its own OpenSSL objects on every
 *       return path (no goto; mirrors the pxr_ctx/pxr_fail pattern in
 *       src/auth/gsi/proxy_req.c).
 */
#include "cred_mint_internal.h"

#include <stdint.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

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
int
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
