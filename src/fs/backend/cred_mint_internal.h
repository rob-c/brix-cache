/*
 * cred_mint_internal.h — internal helpers shared between cred_mint.c and
 * cred_mint_cert.c.
 *
 * WHAT: The MINT_LOG NULL-tolerant log macro, the mint_ca_t / mint_material_t
 *       OpenSSL-object bundles, and the prototype for mint_build_cert() — the
 *       one EC-keygen + X509 build/sign entry point that crosses the
 *       cred_mint.c <-> cred_mint_cert.c split. Implementation detail of the
 *       cred_mint helper, NOT part of the public cred_mint.h surface.
 *
 * WHY:  Splitting the cert-minting lifecycle into cred_mint_cert.c keeps each
 *       translation unit under the file-size guard while preserving the
 *       verbatim mint logic. Only mint_build_cert() and the two object-bundle
 *       structs cross the split; the CN sanitiser, subject builder, serial
 *       packer and field-setter stay static in cred_mint_cert.c.
 *
 * HOW:  Prototypes + shared aggregates + one macro only; include cred_mint.h
 *       for the ngx types and the OpenSSL headers for the X509/EVP_PKEY
 *       struct members.
 */
#ifndef BRIX_FS_BACKEND_CRED_MINT_INTERNAL_H
#define BRIX_FS_BACKEND_CRED_MINT_INTERNAL_H

#include "cred_mint.h"

#include <openssl/evp.h>
#include <openssl/x509.h>

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

/* ---- mint_build_cert -----------------------------------------------------
 * Generate a fresh EC P-256 keypair and a signed X509 whose subject is
 * "/O=brix-minted/CN=<sanitized principal>", issuer = the mint CA's subject,
 * notBefore=now, notAfter=now+ttl_secs, signed by ca->key with SHA-256. On
 * success fills out->cert/out->key (leaves out->ca_cert untouched). Lives in
 * cred_mint_cert.c; called from mint_generate() in cred_mint.c. */
int mint_build_cert(const mint_ca_t *ca, const char *principal, int ttl_secs,
    mint_material_t *out, ngx_log_t *log);

#endif /* BRIX_FS_BACKEND_CRED_MINT_INTERNAL_H */
