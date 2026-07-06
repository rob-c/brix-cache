/*
 * signing_policy.h — Globus EACL signing_policy parser + subject matcher.
 *
 * WHAT: Parses a single <hash>.signing_policy file image into a compiled
 *       policy (per-CA cond_subjects glob lists) and answers "may this CA
 *       sign this subject DN?".
 * WHY:  WLCG/IGTF trust requires a CA sign only within its namespace; plain
 *       PKIX chain validation does not enforce this.  A trusted-but-misbehaving
 *       CA that signs outside its delegated namespace is accepted by OpenSSL
 *       but MUST be rejected under the WLCG trust model.
 * HOW:  ngx-free, caller-owned allocation, no globals.  Fail closed on any
 *       malformed input (the caller rejects the CA).  DN comparison is on the
 *       OpenSSL oneline slash form, case-insensitive.
 */
#ifndef BRIX_CRYPTO_SIGNING_POLICY_H
#define BRIX_CRYPTO_SIGNING_POLICY_H

#include <stddef.h>

typedef enum {
    BRIX_SP_MODE_OFF     = 0,   /* never consult signing_policy files */
    BRIX_SP_MODE_ON      = 1,   /* enforce when a policy file is present */
    BRIX_SP_MODE_REQUIRE = 2    /* every CA must have a granting policy file */
} brix_sp_mode_t;

typedef struct brix_sp_policy_s brix_sp_policy_t;

/*
 * Parse an EACL file image.  Returns NULL on malformed input, writing a
 * human-readable reason (including the offending line number) into errbuf.
 * Caller owns the result and frees it with brix_sp_free().
 */
brix_sp_policy_t *brix_sp_parse(const char *buf, size_t len,
                                char *errbuf, size_t errlen);

void brix_sp_free(brix_sp_policy_t *p);

/* 1 if some access_id_CA block names this CA DN (oneline slash form). */
int brix_sp_ca_dn_present(const brix_sp_policy_t *p, const char *ca_dn);

/*
 * 1 if subject_dn matches the cond_subjects globs of a granting block for
 * ca_dn.  Returns 0 (fail closed) when no granting block matches ca_dn.
 */
int brix_sp_subject_allowed(const brix_sp_policy_t *p,
                            const char *ca_dn, const char *subject_dn);

/* Globus glob: '*' matches any run including '/', '?' one char; case-insensitive. */
int brix_sp_glob_match(const char *pat, const char *str);

#endif /* BRIX_CRYPTO_SIGNING_POLICY_H */
