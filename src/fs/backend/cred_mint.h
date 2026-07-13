/*
 * cred_mint.h — opt-in x509 credential minting (phase-2 T9).
 *
 * WHAT: Declares brix_cred_mint(), which mints a short-lived x509 proxy for a
 *       principal that has no pre-provisioned credential under the shared
 *       credential dir, signs it with an operator-configured mint CA, and
 *       caches the PEM at <cred_dir>/<key>.pem so subsequent requests reuse
 *       it via the normal brix_sd_ucred_select()/_resolve() lookup.
 *
 * WHY:  S3 access keys (and other bearer-only identities) have no native
 *       x509 proxy, so a Phase-1 deployment can only give them per-user
 *       origin credentials by pre-provisioning a .pem out of band. Minting
 *       closes that gap for deployments that opt in by configuring a mint
 *       CA: the frontend becomes a proxy-issuing authority for identities it
 *       has already authenticated (WLCG token / S3 SigV4 / GSI-without-a-
 *       matching-proxy), and the minted proxy is presented to the origin
 *       exactly like a pre-provisioned Phase-1 credential.
 *
 *       TRUST MODEL (read before enabling): minting shifts trust from "the
 *       operator pre-provisioned this exact proxy" to "the origin trusts any
 *       proxy signed by the mint CA". The origin MUST be configured to trust
 *       the mint CA's issuing certificate for this to be meaningful — trust
 *       chain: mint CA cert -> minted proxy -> origin's CA bundle. A misplaced
 *       or overly-broad mint CA trust at the origin lets THIS FRONTEND mint a
 *       credential for any principal it has authenticated, so the mint CA
 *       key must be protected at least as strongly as any other frontend
 *       origin-facing secret. OFF unless brix_storage_credential_mint_ca is
 *       configured (then behavior is unchanged from Phase-1).
 *
 * HOW:  brix_cred_mint() loads the CA cert+key, reuses an existing cached
 *       PEM when it is still valid and outside the refresh window, otherwise
 *       generates a fresh EC P-256 keypair, builds an X509 whose subject
 *       encodes the principal, signs it with the CA key (SHA-256), and
 *       writes cert+key+CA-chain atomically (temp file in the same
 *       directory, O_EXCL 0600, fsync, rename) to <cred_dir>/<key>.pem.
 *       No goto: each helper (load_ca / gen_key / build_cert / write_pem)
 *       owns and frees its own OpenSSL objects on every return path.
 */
#ifndef BRIX_FS_BACKEND_CRED_MINT_H
#define BRIX_FS_BACKEND_CRED_MINT_H

#include <ngx_config.h>
#include <ngx_core.h>

/*
 * BRIX_CRED_MINT_REFRESH_WINDOW — seconds before notAfter at which a cached
 * minted PEM is treated as due for renewal rather than reused. Kept short
 * relative to realistic TTLs (default TTL is 3600s) so a cache hit is the
 * common case but a request never gets a credential expiring imminently.
 */
#define BRIX_CRED_MINT_REFRESH_WINDOW 300

/*
 * brix_cred_mint — mint (or reuse) a short-lived x509 proxy for `principal`.
 *
 * WHAT: Ensures <cred_dir>/<key>.pem exists and is valid for at least
 *       BRIX_CRED_MINT_REFRESH_WINDOW more seconds, minting a fresh one when
 *       it is missing, expired, unparseable, or inside the refresh window.
 *       Returns NGX_OK when the file is ready to be resolved by the caller
 *       (typically via brix_sd_ucred_resolve()), or NGX_ERROR on any failure
 *       (bad CA material, key generation failure, or write failure). Never
 *       leaves a partially-written file: the mint writes to a same-directory
 *       temp file and renames it into place only after a successful fsync.
 *
 * WHY:  Centralises the cache/refresh/mint decision so the VFS credential
 *       gate (vfs_cred.c) stays a thin caller: on ucred-select DECLINED with
 *       a mint CA configured, it calls this once and then re-resolves.
 *
 * HOW:  See cred_mint.c: mint_load_ca() loads ca_cert_path/ca_key_path;
 *       mint_cached_pem_ok() checks any existing <key>.pem's notAfter against
 *       the refresh window; mint_build_cert() generates a fresh EC P-256
 *       keypair and signs an X509 (subject CN = sanitized principal, issuer
 *       = CA subject, notBefore=now, notAfter=now+ttl_secs); mint_write_pem()
 *       serializes cert+key+CA-chain and writes it atomically.
 *
 * cred_dir:      directory that already holds (or will hold) <key>.pem —
 *                same directory brix_sd_ucred_select()/_resolve() read from.
 * ca_cert_path:  PEM file with the mint CA's certificate (issuer + trust
 *                anchor appended to the minted chain).
 * ca_key_path:   PEM file with the mint CA's private key (unencrypted;
 *                operator is responsible for filesystem permissions).
 * principal:     canonical principal string (see brix_sd_ucred_principal());
 *                encoded into the minted proxy's CN.
 * key:           the credential filename stem (see brix_sd_ucred_key()) —
 *                determines the output path <cred_dir>/<key>.pem.
 * ttl_secs:      lifetime of a freshly minted proxy, in seconds.
 * log:           nginx log for mint diagnostics ("minted"/failure reasons).
 */
ngx_int_t brix_cred_mint(const char *cred_dir, const char *ca_cert_path,
    const char *ca_key_path, const char *principal, const char *key,
    int ttl_secs, ngx_log_t *log);

#endif /* BRIX_FS_BACKEND_CRED_MINT_H */
