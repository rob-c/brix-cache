/* Authentication, credentials, and security-policy constants.
 *
 * Requires: include through core/types/tunables.h; sibling constants
 * and the caller-provided nginx/protocol/metrics types remain available
 * when dependent expressions and completion macros are expanded.
 */
#pragma once

/*
 * seccomp-BPF worker syscall filter (hyper-hardening-plan §D-3).
 *
 * A per-worker syscall allowlist installed at the tail of init_process, after
 * every setup syscall has run, so only the steady-state serving set must be
 * enumerated.  Mode enum (stored in ngx_stream_brix_srv_conf_t.seccomp, set via
 * an ngx_conf_enum_t slot; the strictest value across enabled server blocks wins
 * for the process):
 *   OFF     = no filter installed (default — strictly opt-in).
 *   AUDIT   = filter loaded with a log-only default action: allowlisted syscalls
 *             run silently, everything else is ALLOWED but logged to the kernel
 *             audit log (SECCOMP … audit records).  Converges the set risk-free.
 *   ENFORCE = allowlisted syscalls run; the named-dangerous set (execve/execveat/
 *             ptrace/process_vm_*) is KILLED; any other non-allowlisted syscall
 *             fails EPERM (fail-safe: a missed entry degrades one call, it does
 *             not crash the worker).
 *
 * Requires a build with libseccomp (config sets -DBRIX_HAVE_SECCOMP); without it
 * AUDIT/ENFORCE fail closed at init (the worker refuses to run rather than serve
 * unfiltered while the operator believes it is filtered).
 */
#define BRIX_SECCOMP_OFF                    0
#define BRIX_SECCOMP_AUDIT                  1
#define BRIX_SECCOMP_ENFORCE                2

/*
 * Phase 33 — GSI ephemeral DH key pool (src/gsi/keypool.c).
 *
 * Per-worker warm pool of pre-generated ffdhe2048 keys so kXGC_certreq never runs
 * keygen on the nginx event thread under a concurrent handshake burst.  The target
 * warm count (SIZE_DEFAULT, runtime-tunable via brix_gsi_keypool_size) is the
 * refill ceiling, sized to cover a worst-case concurrent-handshake burst; when the
 * pool falls to half the target an off-thread refill of REFILL_BATCH keys is
 * scheduled.  Each key is ~1-2 KB → target keys ≈ 100-130 KB per worker.
 *
 * SEED_DEFAULT keys are generated synchronously at worker start (brix_gsi_
 * keypool_seed); the remainder up to the target fills OFF the event thread so boot
 * is not blocked on ~target keygens (was the dominant per-worker startup cost). CAP
 * bounds the static ring so the target directive cannot be set unboundedly high.
 */
#define BRIX_GSI_KEYPOOL_CAP           256   /* static ring capacity (ceiling) */
#define BRIX_GSI_KEYPOOL_SIZE_DEFAULT  64    /* default warm/refill target     */
#define BRIX_GSI_KEYPOOL_SEED_DEFAULT  4     /* default synchronous boot seed  */
#define BRIX_GSI_KEYPOOL_REFILL_BATCH  32

/*
 * Clock-skew tolerance for JWT nbf/exp validation.
 * Even with NTP, production systems commonly drift 1–5 seconds.  The WLCG
 * Token Profile recommends that servers accept a small grace window so that
 * freshly-issued tokens are not rejected by a server whose clock lags slightly.
 * 30 seconds is generous enough for any reasonable NTP configuration.
 */
#define BRIX_TOKEN_CLOCK_SKEW_SECS  30

/*
 * Maximum base64url-encoded input size (bytes).
 * JWT tokens with claims typically 2-4 KB encoded; 8 KB provides 2x headroom.
 * Prevents buffer overflow on malformed or malicious oversized inputs.
 * Decoded output will be ~6 KB (base64 expands by 4/3).
 */
#define BRIX_B64_DECODE_MAX                  8192

/*
 * Maximum JWKS (JSON Web Key Set) file size (bytes).
 * Typical JWKS with 10-20 keys is 5-15 KB; 64 KB allows for large key sets.
 * Prevents DoS via oversized JWKS files (memory exhaustion, parse time).
 * If more than 20 keys needed, consider key rotation or multiple JWKS endpoints.
 */
#define BRIX_JWKS_FILE_MAX                   65536

/*
 * Maximum bearer token size (bytes).
 * WLCG SciTokens typically 2-4 KB; 4 KB accommodates future extensions.
 * Prevents unbounded allocation from malicious oversized token claims.
 */
#define BRIX_BEARER_TOKEN_MAX                  4096

/*
 * Maximum macaroon path caveats.
 * Prevents path traversal attack via excessive caveat chains.
 * 8 allows reasonable delegation depth while bounding verification cost.
 */
#define BRIX_MACAROON_PATH_CAVEATS_MAX         8

/*
 * ES256 (ECDSA P-256) signature component size (bytes).
 * IEEE P1363 format: raw r||s, each component is 32 bytes.
 * Total signature size is 64 bytes (BRIX_ES256_SIG_COMPONENT * 2).
 * Used for JWT ES256 signature validation in brix_token_verify_es256().
 */
#define BRIX_ES256_SIG_COMPONENT               32

/*
 * ES256 (ECDSA P-256) total signature size (bytes).
 * IEEE P1363 format: r (32 bytes) || s (32 bytes) = 64 bytes total.
 * Used for signature length validation before BN_bin2bn conversion.
 */
#define BRIX_ES256_SIG_SIZE                    64

/* ---- Authentication mode constants ---- */
#define BRIX_AUTH_NONE   0   /* no authentication required (anonymous) */
#define BRIX_AUTH_GSI    1   /* GSI/x509 authentication required       */
#define BRIX_AUTH_TOKEN  2   /* Bearer token (JWT/WLCG) authentication */
#define BRIX_AUTH_BOTH   3   /* Accept either GSI or token auth        */
#define BRIX_AUTH_SSS    4   /* XRootD Simple Shared Secret auth       */
#define BRIX_AUTH_UNIX   5   /* XRootD unix auth (self-asserted local) */
#define BRIX_AUTH_KRB5   6   /* XRootD Kerberos 5 auth                 */
#define BRIX_AUTH_HOST   7   /* XRootD host auth (reverse-DNS allowlist) */
#define BRIX_AUTH_PWD    8   /* XRootD pwd auth (XrdSecpwd password, opt-in) */

/*
 * Auth gate cache key buffer size (bytes).
 * Sized to hold: "aop" + IP (64) + "/" + resolved + "/" + reqpath + "/" +
 * DN + "/" + VO + "/" + scope + padding.
 * PATH_MAX + PATH_MAX covers worst-case path + resolved hostname.
 * 512 + 512 covers DN + VO list (typical: <100 bytes each).
 * 1024 covers scope claims (JWT/WLCG tokens can be large).
 */
#define BRIX_AUTH_GATE_KEY_BUF_SIZE            4096

/*
 * Auth audit buffer size (bytes).
 * Buffer for audit log formatting during authentication decisions.
 * Holds timestamp, identity, operation, path, and decision details.
 * 2 KB provides headroom for long DN/VO strings.
 */
#define BRIX_AUTH_AUDIT_BUF_SIZE               2048

/*
 * DN (Distinguished Name) buffer size (bytes).
 * X.509 certificate subject/issuer DN maximum length.
 * Typical DN: 100-300 bytes; 1024 provides 3-10x headroom.
 * Used in GSI/Kerberos authentication flows.
 */
#define BRIX_AUTH_DN_BUF_SIZE                  1024

/*
 * VO (Virtual Organization) list buffer size (bytes).
 * Holds comma-separated VO list from VOMS proxy.
 * Typical: 1-5 VOs at 20-50 bytes each; 512 provides 2-5x headroom.
 */
#define BRIX_AUTH_VO_BUF_SIZE                  512

/*
 * Auth cache key hash buffer size (bytes).
 * Temporary buffer for SHA-256 hash computation during cache key generation.
 * Must accommodate all key components before hashing.
 */
#define BRIX_AUTH_CACHE_KEY_BUF_SIZE           (3 + 64 + 1 + PATH_MAX + PATH_MAX + 512 + 512 + 1024 + 8)

/*
 * ACC GID cache lifetime default (seconds).
 * Default TTL for group membership cache entries.
 * 43200 seconds = 12 hours (balances freshness vs. lookup overhead).
 */
#define BRIX_ACC_GIDLIFETIME_DEFAULT           43200

/*
 * ACC audit buffer sizes (bytes).
 * Buffers for audit logging in access control decisions.
 * 256 bytes for identity/host, 1024 bytes for path.
 */
#define BRIX_ACC_AUDIT_ID_BUF_SIZE             256
#define BRIX_ACC_AUDIT_HOST_BUF_SIZE           256
#define BRIX_ACC_AUDIT_PATH_BUF_SIZE           1024

/*
 * IDMAP denylist buffer sizes (bytes).
 * Buffers for user/group denylist file parsing.
 * 1024 bytes per line handles typical entries with comments.
 */
#define BRIX_IDMAP_DENYLIST_LINE_BUF_SIZE      1024

/*
 * Auth cache TTL multiplier (milliseconds per second).
 * Converts configured TTL (seconds) to nginx timer units (milliseconds).
 * Standard conversion factor: 1 second = 1000 milliseconds.
 */
#define BRIX_AUTH_CACHE_TTL_MS_PER_SEC         1000

/*
 * Token buffer sizes for JWT/Macaroon processing.
 *
 * BRIX_TOKEN_SUB_BUF_SIZE: 512 bytes for subject claims
 * BRIX_TOKEN_ISS_BUF_SIZE: 512 bytes for issuer claims
 * BRIX_TOKEN_SCOPE_BUF_SIZE: 1024 bytes for scope claims
 * BRIX_TOKEN_GROUPS_BUF_SIZE: 512 bytes for groups claims
 * BRIX_TOKEN_HDR_JSON_BUF_SIZE: 2048 bytes for JWT header JSON
 * BRIX_TOKEN_MACAROON_SCOPE_BUF_SIZE: 1024 bytes for Macaroon scope
 * BRIX_TOKEN_MACAROON_PATH_CAV_BUF_SIZE: 1024 bytes for Macaroon path caveat
 * BRIX_TOKEN_FP_BUF_SIZE: 32 bytes for SHA-256 fingerprint
 * BRIX_TOKEN_AUD_BUF_SIZE: 512 bytes for audience claim
 * BRIX_TOKEN_ERR_BUF_SIZE: 256 bytes for token error messages
 * BRIX_TOKEN_INI_LINE_BUF_SIZE: 1024 bytes for INI file line parsing
 * BRIX_TOKEN_ISSUER_BUF_SIZE: 128 bytes for issuer registry buffer
 * BRIX_TOKEN_SIG_B64_BUF_SIZE: 128 bytes for base64-encoded signature
 */
#define BRIX_TOKEN_SUB_BUF_SIZE                512
#define BRIX_TOKEN_ISS_BUF_SIZE                512
#define BRIX_TOKEN_SCOPE_BUF_SIZE              1024
#define BRIX_TOKEN_GROUPS_BUF_SIZE             512
#define BRIX_TOKEN_HDR_JSON_BUF_SIZE           2048
#define BRIX_TOKEN_MACAROON_SCOPE_BUF_SIZE     1024
#define BRIX_TOKEN_MACAROON_PATH_CAV_BUF_SIZE  1024
#define BRIX_TOKEN_FP_BUF_SIZE                 32
#define BRIX_TOKEN_AUD_BUF_SIZE                512
#define BRIX_TOKEN_ERR_BUF_SIZE                256
#define BRIX_TOKEN_INI_LINE_BUF_SIZE           1024
#define BRIX_TOKEN_ISSUER_BUF_SIZE             128
#define BRIX_TOKEN_SIG_B64_BUF_SIZE            128

/*
 * Maximum auth database file size (bytes).
 * Prevents unbounded memory allocation when parsing authdb files.
 * 1 MB allows for thousands of entries while bounding resource usage.
 */
#define BRIX_AUTHDB_MAX_FILE_SIZE              1048576

/*
 * GSI certificate response buffer size (bytes).
 * Buffer for building certificate response messages in GSI handshake.
 * Must accommodate certificate chain + DH public key + signatures.
 * 16 KB handles typical certificate chains with room for growth.
 */
#define BRIX_GSI_CERT_RESP_BUF_SIZE            16384

/*
 * GSI signature buffer size (bytes).
 * Buffer for RSA/ECDSA signatures during GSI handshake.
 * RSA-4096 signature = 512 bytes; 1024 provides 2x headroom.
 */
#define BRIX_GSI_SIG_BUF_SIZE                  1024

/*
 * GSI RSA public exponent (65537 = 0x10001).
 * Standard RSA exponent providing good security/performance balance.
 * Used for key generation in proxy certificate requests.
 */
#define BRIX_GSI_RSA_EXPONENT                  65537

/*
 * GSI DH public key buffer size (bytes).
 * Buffer for Diffie-Hellman public key exchange.
 * ffdhe2048 = 256 bytes; 4096 provides 16x headroom for future groups.
 */
#define BRIX_GSI_DH_PUB_BUF_SIZE               4096

/*
 * OCSP (Online Certificate Status Protocol) constants.
 *
 * BRIX_OCSP_MAX_RESPONSE_BYTES: Maximum OCSP response size (64 KB)
 * BRIX_OCSP_NONCE_SIZE: OCSP nonce size in bytes (16 bytes per RFC 6960)
 */
#define BRIX_OCSP_MAX_RESPONSE_BYTES           (64 * 1024)
#define BRIX_OCSP_NONCE_SIZE                   16

/*
 * Crypto key strength minimums per IGTF security policy.
 * BRIX_CRYPTO_RSA_MIN_BITS: Minimum RSA key size (2048 bits)
 * BRIX_CRYPTO_DSA_MIN_BITS: Minimum DSA key size (2048 bits)
 * BRIX_CRYPTO_EC_MIN_BITS: Minimum EC key size (256 bits for P-256)
 */
#define BRIX_CRYPTO_RSA_MIN_BITS               2048
#define BRIX_CRYPTO_DSA_MIN_BITS               2048
#define BRIX_CRYPTO_EC_MIN_BITS                256

/*
 * PWD authentication constants.
 * BRIX_PWD_PATH_BUF_SIZE: Buffer for password file path (1024 bytes)
 * BRIX_PWD_PBKDF2_ITERATIONS: PBKDF2-HMAC-SHA1 iterations (10000)
 * BRIX_PWD_HASH_OUTPUT_SIZE: PBKDF2 output size in bytes (24)
 */
#define BRIX_PWD_PATH_BUF_SIZE                 1024
#define BRIX_PWD_PBKDF2_ITERATIONS             10000
#define BRIX_PWD_HASH_OUTPUT_SIZE              24

/*
 * Kerberos authentication constants.
 * BRIX_KRB5_CNAME_BUF_SIZE: Buffer for Kerberos client name (1024 bytes)
 */
#define BRIX_KRB5_CNAME_BUF_SIZE               1024

/*
 * GSI proxy delegation signed request tag buffer size (bytes).
 * Holds signed delegation request during proxy delegation handshake.
 * 1024 bytes handles typical proxy certification requests.
 */
#define BRIX_GSI_DELEGATION_TAG_BUF_SIZE       1024

/*
 * Maximum Bearer token size (bytes).
 * JWT/WLCG tokens typically 500-2000 bytes; 4096 provides 2-8x headroom.
 * Enforced during token extraction from Authorization header.
 */
#define BRIX_BEARER_TOKEN_MAX                  4096

/*
 * JWKS (JSON Web Key Set) file size maximum (bytes).
 * JWKS files contain public keys for token verification.
 * Typical: 2-10 KB; 64 KB allows for large key rotations.
 */
#define BRIX_JWKS_FILE_MAX                     65536

/*
 * Base64 URL decode buffer maximum (bytes).
 * Temporary buffer for base64url decoding of JWT components.
 * 8 KB handles large JWT claims sets.
 */
#define BRIX_B64_DECODE_MAX                    8192

/* ---- GSI signed-DH policy (phase-48; brix_gsi_signed_dh directive) ---- */
#define BRIX_GSI_SDH_OFF      0  /* always unsigned DH (default, universal)  */
#define BRIX_GSI_SDH_AUTO     1  /* signed DH for clients advertising >=10400 */
#define BRIX_GSI_SDH_REQUIRE  2  /* signed DH only; reject <10400 clients     */

/* XrdSecgsi version at/after which the RSA-signed-DH wire variant applies
 * (XrdSecgsiVersDHsigned in the reference implementation). */
#define BRIX_GSI_VERS_DHSIGNED 10400

/*
 * SSS configuration line buffer size (bytes).
 * Used for parsing SSS keytab configuration files.
 * 4096 bytes handles typical keytab entries with headroom.
 */
#define BRIX_SSS_CONFIG_LINE_BUF_SIZE          4096

/*
 * GSSAPI read buffer size (bytes).
 * Used for GSSAPI token exchange and context establishment.
 * 16384 bytes (16 KB) handles typical GSSAPI tokens with headroom.
 */
#define BRIX_GSSAPI_READ_BUF_SIZE              16384

/*
 * Impersonation broker maximum concurrent connections.
 * Limits simultaneous broker client connections to prevent resource exhaustion.
 * 1024 connections provides headroom for high-concurrency workloads.
 */
#define BRIX_IMP_BROKER_MAXCONN                1024

/*
 * Impersonation broker socket path buffer size (bytes).
 * Accommodates Unix domain socket paths for broker communication.
 * 256 bytes handles typical socket paths with headroom.
 */
#define BRIX_IMP_SOCK_PATH_BUF_SIZE            256

/*
 * Impersonation broker root path buffer size (bytes).
 * Buffer for broker root directory path construction.
 * 1024 bytes handles deep directory structures.
 */
#define BRIX_IMP_ROOT_PATH_BUF_SIZE            1024

/*
 * GSI proxy certificate RSA key minimum bits.
 * RFC 3828 and XRootD security policy require 2048-bit minimum for proxy certs.
 * Used in EVP_PKEY_CTX_set_rsa_keygen_bits() for proxy key generation.
 * Larger keys (3072, 4096) supported but 2048 balances security/performance.
 */
#define BRIX_GSI_PROXY_KEY_BITS          2048

/*
 * RSA public exponent for key generation.
 * 65537 (0x10001) is the standard RSA public exponent per PKCS#1 v2.1.
 * Chosen for efficient encryption operations while maintaining security.
 * Used in EVP_PKEY_CTX_set_rsa_keygen_pubexp() for proxy key generation.
 */
#define BRIX_RSA_PUBLIC_EXPONENT         65537

/*
 * GSI buffer sizes for DN/EEC parsing.
 * BRIX_GSI_DN_BUF_SIZE: 1024 bytes for Distinguished Name strings
 * BRIX_GSI_EEC_BUF_SIZE: 1024 bytes for EEC (End Entity Certificate) strings
 */
#define BRIX_GSI_DN_BUF_SIZE                 1024
#define BRIX_GSI_EEC_BUF_SIZE                1024

/*
 * GSI DH (Diffie-Hellman) key sizes.
 * BRIX_GSI_DH_FFDHE2048: 2048-bit finite field DH group (ffdhe2048)
 * BRIX_GSI_DH_FFDHE3072: 3072-bit finite field DH group (ffdhe3072)
 * BRIX_GSI_DH_FIXED_SIZE: Fixed 3072-bit DH params size in bytes
 */
#define BRIX_GSI_DH_FFDHE2048_BITS           2048
#define BRIX_GSI_DH_FFDHE3072_BITS           3072
#define BRIX_GSI_DH_FIXED_SIZE               3072

/*
 * GSI serial number buffer size.
 * Buffer for certificate serial number formatting (8 bytes hex + null terminator).
 */
#define BRIX_GSI_SERIAL_BUF_SIZE             17

/*
 * GSI time conversion constants.
 * BRIX_GSI_SECS_PER_DAY: Seconds per day (86400) for proxy lifetime calculations
 */
#define BRIX_GSI_SECS_PER_DAY                86400

/* ---- SSS constants ---- */
#define BRIX_SSS_KEY_MAX   128
#define BRIX_SSS_NAME_MAX  192

/*
 * OIDC agent socket default path.
 * Default location for oidc-agent Unix socket.
 * Used when no explicit socket path is configured.
 */
#define BRIX_OIDC_AGENT_SOCKET_PATH  "/run/user/1000/oidc/oidc_agent.sock"

/*
 * Credential staging directory mode.
 * Mode for credential staging directories.
 * 0700 = owner rwx only (private tmpfs directory).
 */
#define BRIX_CRED_STAGE_DIR_MODE  0700

/*
 * Minimum RSA/DSA key size (bits).
 * IGTF floor for acceptable public key strength.
 */
#define BRIX_MIN_RSA_KEY_BITS  2048

/*
 * Minimum DSA key size (bits).
 * IGTF floor for acceptable DSA key strength.
 */
#define BRIX_MIN_DSA_KEY_BITS  2048

/*
 * GSI certificate request message code.
 * kXGC_certreq = 1000 in XRootD GSI protocol.
 */
#define BRIX_GSI_CERTREQ_CODE  1000

/*
 * GSI certificate response message code.
 * kXGS_cert = 2001 in XRootD GSI protocol.
 */
#define BRIX_GSI_CERT_CODE  2001

/*
 * GSI signed-DH minimum client version.
 * Clients >= 10400 support signed DH handshake.
 */
#define BRIX_GSI_SIGNED_DH_MIN_VERSION  10400

/*
 * GSI authmore response code.
 * kXR_authmore = 4002 in XRootD protocol.
 */
#define BRIX_GSI_AUTHMORE_CODE  4002

/*
 * Authentication and credential constants.
 */
#define BRIX_AUTH_ATTEMPTS_MAX      10      /* Maximum authentication attempts */
#define BRIX_AUTH_SKEW_SECS         30      /* Token clock skew tolerance */
#define BRIX_AUTH_TOKEN_MAX         65536   /* Maximum token size */
#define BRIX_AUTH_CERT_MODE         0600    /* Certificate file permissions */

/*
 * Guard and security constants.
 */
#define BRIX_GUARD_TEST_IP_BUF      64      /* Guard test IP buffer */
#define BRIX_GUARD_TEST_PROTO_BUF   32      /* Guard test protocol buffer */
#define BRIX_GUARD_TEST_SIGNAL_BUF  64      /* Guard test signal buffer */
#define BRIX_GUARD_TEST_PATH_BUF    256     /* Guard test path buffer */
