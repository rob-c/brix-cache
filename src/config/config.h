#ifndef XROOTD_CONFIG_INTERNAL_H
#define XROOTD_CONFIG_INTERNAL_H

#include "../ngx_xrootd_module.h"

/* Filesystem object kind checked by xrootd_validate_path. */

/* ---- xrootd_path_kind_t — filesystem object kind for path validation ----
 *
 * WHAT: Enumerates the three kinds of filesystem objects that xrootd_validate_path checks:
 *       regular file, directory, or either. Used during postconfiguration to validate
 *       configured paths (xrootd_root, cache directories) against actual filesystem state.
 *
 * WHY: Postconfiguration validation catches misconfigured paths early — nginx -t fails
 *      with emerg errors before any traffic is accepted. Each kind maps to a specific
 *      stat check and errno translation so the error message accurately describes what
 *      was wrong (e.g., path exists but is a directory when a file was expected). */
typedef enum {
    XROOTD_PATH_REGULAR_FILE,      /* path must be an existing regular file */
    XROOTD_PATH_DIRECTORY,         /* path must be an existing directory */
    XROOTD_PATH_FILE_OR_DIRECTORY  /* path must exist; either kind is acceptable */
} xrootd_path_kind_t;

/*
 * xrootd_validate_path — check that a configured path exists, is of the right
 * kind, and is accessible with access_mode (e.g. R_OK).
 *
 * Emits NGX_LOG_EMERG and returns NGX_ERROR on any failure; used during
 * postconfiguration to catch misconfigured paths early.
 */
ngx_int_t xrootd_validate_path(ngx_conf_t *cf, const char *label,
    const ngx_str_t *path, xrootd_path_kind_t kind, int access_mode);

/*
 * xrootd_copy_conf_string — duplicate a C string from an ngx_str_t source
 * into a NUL-terminated ngx_str_t using ngx_pnalloc from cf->pool.
 *
 * Returns NGX_CONF_ERROR on OOM; otherwise the cfg error string returned by
 * the directive setter.  dst->data and dst->len are set on success.
 */
char *xrootd_copy_conf_string(ngx_conf_t *cf, const ngx_str_t *src,
    ngx_str_t *dst);

/* ---- xrootd_config_prepare_server — validate and prepare each server block ----
 *
 * WHAT: Validates root/cache/access-log paths, merges config defaults, prepares TLS and auth
 *       subsystems for a single stream server block. Called during postconfiguration pass.
 *       Returns NGX_OK on success, NGX_ERROR on any validation failure.
 *
 * WHY: Each server block must have valid root path, optional cache directory, and access log
 *      before accepting traffic. This function centralizes per-server validation so that
 *      nginx -t catches configuration errors (missing directories, invalid paths) early.
 */

/* ---- xrootd_configure_gsi — load GSI CA store and configure authentication subsystem ----
 *
 * WHAT: Loads host certificate/key pair, reads CA directory for proxy cert verification,
 *       optionally loads CRL files. Returns NGX_OK on success, NGX_ERROR on failure.
 *
 * WHY: GSI/x509 proxy certificate authentication requires a trusted CA store to verify
 *      intermediate certificates in the proxy chain. Host cert/key enables TLS termination.
 */

/* ---- xrootd_configure_tls — resolve certificate/key and prepare SSL_CTX ----
 *
 * WHAT: Loads xrootd_tls_certificate/xrootd_tls_certificate_key, creates and configures
 *       an SSL_CTX for TLS termination on root:// connections (kXR_wantTLS upgrade).
 *       Returns NGX_OK on success, NGX_ERROR on failure.
 *
 * WHY: In-protocol XRootD TLS upgrade requires a pre-built SSL_CTX that clients can
 *      switch to after handshake. The certificate/key pair must be valid grid PKI certs.
 */

/* ---- xrootd_configure_token_auth — load JWKS keys for bearer-token authentication ----
 *
 * WHAT: Loads JSON Web Key Set (JWKS) file from configured path, parses public keys for
 *       JWT signature verification. Returns NGX_OK on success, NGX_ERROR on failure.
 *
 * WHY: WLCG/SciToken bearer tokens are signed with RSA/ECDSA keys published in JWKS format.
 *      The server loads these keys once at startup to verify token signatures without
 *      network calls per request. Token scope enforcement is applied per-path after verification.
 */

/* ---- xrootd_token_jwks_schedule_refresh — start periodic JWKS refresh timer ----
 *
 * WHAT: Schedules a per-worker mtime-poll timer that watches the JWKS file for changes
 *       and reloads keys when modified. Called from init_process callback.
 *
 * WHY: JWKS keys rotate periodically (key rotation, new signing keys). The server must
 *      detect and load updated keys without restart — mtime polling avoids unnecessary
 *      HTTP fetches while catching file changes promptly. Each worker polls independently.
 */

/* ---- xrootd_configure_sss_auth — load SSS key file and validate format ----
 *
 * WHAT: Loads shared-secret (SSS) authentication key from configured file path, validates
 *       key length and hex format. Returns NGX_OK on success, NGX_ERROR on failure.
 *
 * WHY: SSS provides HMAC-based authentication for internal cluster communication where
 *      GSI certs are unavailable. Key file must contain valid hex-encoded bytes with
 *      minimum length requirements for adequate entropy.
 */

/* ---- xrootd_config_finalize_policy — validate VO ACL rules and group-ownership policies ----
 *
 * WHAT: Parses configured VO (Virtual Organization) ACL rules, validates group ownership
 *       policies, applies path-based access restrictions. Returns NGX_OK on success.
 *
 * WHY: HEP sites organize storage by VO (ATLAS, CMS, ALICE, LHCb). ACL rules grant or deny
 *      access per-path based on client's VOMS attributes and group membership.
 */

/* ---- xrootd_configure_metrics — create/attach shared-memory metrics zone ----
 *
 * WHAT: Creates or attaches to a shared-memory zone for Prometheus metrics counters using
 *       ngx_shm_zone_init. Returns NGX_OK on success, NGX_ERROR on failure.
 *
 * WHY: All workers share one metrics zone so counters are globally consistent across the
 *      nginx instance. Prometheus scrapes read this shared memory — low-cardinality labels
 *      prevent label explosion at scale.
 */

/* ---- xrootd_configure_session_registry — create/attach shared-memory session registry ----
 *
 * WHAT: Creates or attaches to a shared-memory zone for tracking active XRootD sessions.
 *       Returns NGX_OK on success, NGX_ERROR on failure.
 *
 * WHY: Session registry tracks authenticated connections for manager mode (CMS heartbeat),
 *      locate responses, and session cleanup. Shared memory allows all workers to query
 *      the same session state without inter-worker communication.
 */

/* ---- xrootd_srv_configure_registry — create/attach shared-memory server registry zone ----
 *
 * WHAT: Creates or attaches to a shared-memory zone for dynamic server registration in
 *       manager mode, with configurable slot count. Returns NGX_OK on success.
 *
 * WHY: Manager mode requires all storage nodes to register their location and capabilities
 *      in a shared registry so kXR_locate can return accurate redirect responses to clients.
 */

/* ---- xrootd_pending_configure — create/attach shared-memory pending-locate table zone ----
 *
 * WHAT: Creates or attaches to a shared-memory zone for tracking pending locate requests
 *       that require server registry lookup before completion.
 *
 * WHY: kXR_locate responses depend on the current server registry state. Pending entries
 *      hold requests until registry is populated, then resolve them with accurate redirects.
 */

/* Called from postconfiguration to validate and prepare each server block. */
ngx_int_t xrootd_config_prepare_server(ngx_conf_t *cf,
    ngx_stream_xrootd_srv_conf_t *xcf);

/* Load GSI CA store and configure the GSI authentication subsystem. */
ngx_int_t xrootd_configure_gsi(ngx_conf_t *cf,
    ngx_stream_xrootd_srv_conf_t *xcf);

/* Resolve xrootd_tls_certificate/key and prepare the SSL_CTX. */
ngx_int_t xrootd_configure_tls(ngx_conf_t *cf,
    ngx_stream_xrootd_srv_conf_t *xcf);

/* Load JWKS keys for bearer-token (WLCG/SciToken) authentication. */
ngx_int_t xrootd_configure_token_auth(ngx_conf_t *cf,
    ngx_stream_xrootd_srv_conf_t *xcf);

/* Start per-worker mtime-poll JWKS refresh timer (call from init_process). */
void xrootd_token_jwks_schedule_refresh(ngx_cycle_t *cycle,
    ngx_stream_xrootd_srv_conf_t *conf);

/* Load the SSS key file and validate key length/format. */
ngx_int_t xrootd_configure_sss_auth(ngx_conf_t *cf,
    ngx_stream_xrootd_srv_conf_t *xcf);

/* Validate and prepare Kerberos 5 service principal/keytab state. */
ngx_int_t xrootd_configure_krb5_auth(ngx_conf_t *cf,
    ngx_stream_xrootd_srv_conf_t *xcf);

/* Validate and apply VO ACL rules and group-ownership policies. */
ngx_int_t xrootd_config_finalize_policy(ngx_conf_t *cf,
    ngx_stream_xrootd_srv_conf_t *xcf);

/* Create or attach to the shared-memory metrics zone. */
ngx_int_t xrootd_configure_metrics(ngx_conf_t *cf,
    ngx_stream_core_main_conf_t *cmcf);

/* Create or attach to the shared-memory session registry zone. */
ngx_int_t xrootd_configure_session_registry(ngx_conf_t *cf);

/* Create or attach to the shared-memory server registry zone. */
ngx_int_t xrootd_srv_configure_registry(ngx_conf_t *cf, ngx_uint_t slots);

/* Create or attach to the shared-memory pending-locate table zone. */
ngx_int_t xrootd_pending_configure(ngx_conf_t *cf);

/* Create or attach to the live transfer monitor shared-memory zone. */
ngx_int_t xrootd_configure_dashboard(ngx_conf_t *cf);

/* Create or attach to the unified TPC transfer registry zone. */
ngx_int_t xrootd_tpc_registry_configure(ngx_conf_t *cf);

/* Resolve thread-pool names to concrete pool objects for all server blocks. */
ngx_int_t xrootd_configure_thread_pools(ngx_conf_t *cf,
    ngx_stream_core_main_conf_t *cmcf);

#endif /* XROOTD_CONFIG_INTERNAL_H */
