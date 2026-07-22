/*
 * shared_conf_types.h — ngx_http_brix_shared_conf_t definition.
 *
 * The shared config preamble struct, split out of shared_conf.h so both files
 * stay under the per-file line ceiling. Included at the exact original position
 * of the struct by shared_conf.h; every consumer sees the type transitively.
 */

#ifndef NGX_HTTP_BRIX_SHARED_CONF_TYPES_H
#define NGX_HTTP_BRIX_SHARED_CONF_TYPES_H

#include <ngx_thread_pool.h>

#include <regex.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "observability/pmark/pmark.h"

/*
 * ngx_http_brix_shared_conf_t — Common fields embedded at the top of every
 * protocol location/server config struct (stream, WebDAV, S3).
 *
 * WHAT: A shared preamble that holds enable flags, root path, write permission,
 * and thread pool name — fields present in all three protocol configs. Each
 * protocol struct embeds this struct as its first member so offsetof() offsets
 * into the protocol-specific tail remain valid after merge.
 *
 * WHY: Stream, WebDAV, and S3 each duplicate enable + root + allow_write in
 * their own structs and their create/merge functions (~90 total ngx_conf_merge_*
 * calls). Consolidating these shared fields into one struct reduces merge
 * boilerplate to ~30 protocol-specific calls plus a single preamble merge.
 *
 * HOW: Protocol structs declare this as their first member (no padding needed
 * because it starts with ngx_flag_t which aligns naturally). The create function
 * sets all shared fields to NGX_CONF_UNSET; the merge function uses standard
 * nginx merge macros on each field before calling protocol-specific merge logic.
 */

typedef struct {
    ngx_flag_t          enable;             /* on/off toggle for protocol          */
    ngx_str_t           root;               /* filesystem export root path         */
    char                root_canon[PATH_MAX]; /* canonicalized/confined root        */
    ngx_str_t           storage_backend;    /* SD backend name: "" / "posix" = the
                                             * default POSIX tree; "pblock" = the
                                             * block-based backend rooted at root.  */
    size_t              pblock_block_size;  /* pblock stripe size for new files
                                             * (bytes); 0 = backend default (64 MiB) */
    ngx_flag_t          storage_staging;    /* write-back: a remote (root://) backend
                                             * stages uploads to the LOCAL export and
                                             * promotes them on commit, vs streaming
                                             * straight through (Mode A). off = Mode A */
    ngx_str_t           storage_credential; /* [brix_storage_credential <name>] —
                                             * the brix_credential block (§14) the
                                             * source backend authenticates with;
                                             * "" = anonymous. Today threads a bearer
                                             * token into sd_http. */
    ngx_str_t           storage_credential_dir; /* [brix_storage_credential_dir
                                             * <dir>] — directory of per-identity
                                             * x509 proxy PEMs for a remote
                                             * backend (phase-1 per-user backend
                                             * credentials). Defaults to the
                                             * tmpfs BRIX_CREDENTIAL_DIR_DEFAULT
                                             * (/dev/shm/brix-creds, created 0700
                                             * at config time); explicit "" =
                                             * feature off.                      */
    ngx_uint_t          storage_credential_fallback; /* [brix_storage_credential_
                                             * fallback allow|deny] — 0 allow the
                                             * static service credential when the
                                             * identity has no per-user file
                                             * (default); 1 deny (fail EACCES).  */
    ngx_str_t           storage_credential_mint_ca_cert; /* [brix_storage_
                                             * credential_mint_ca <cert> <key>]
                                             * — phase-2 T9 opt-in minting: PEM
                                             * cert of the CA the frontend signs
                                             * minted proxies with. "" = minting
                                             * off (Phase-1 behavior only). The
                                             * ORIGIN must be configured to trust
                                             * this CA — see cred_mint.h.       */
    ngx_str_t           storage_credential_mint_ca_key;  /* PEM private key
                                             * paired with mint_ca_cert above;
                                             * set together by the same
                                             * directive.                       */
    ngx_uint_t          storage_credential_mint_ttl; /* [brix_storage_credential_
                                             * mint_ttl <secs>] — lifetime of a
                                             * freshly minted proxy; default
                                             * 3600. Ignored when minting is
                                             * off.                             */
    ngx_uint_t          backend_delegation; /* [brix_backend_delegation
                                             * select|passthrough|exchange|
                                             * delegate|mint|auto] (phase-70 §4)
                                             * — the backend-leg credential
                                             * strategy; enum → BRIX_CRED_*.
                                             * Default 0 (SELECT).              */
    ngx_array_t        *backend_token_aud;  /* [brix_backend_token_audience_ok
                                             * <aud>...] (phase-70 §5.4) —
                                             * ngx_str_t[] backend audiences a
                                             * bearer may be forwarded to; NULL
                                             * = none configured.               */
    ngx_str_t           backend_tx_endpoint;   /* [brix_backend_token_exchange_
                                             * endpoint <url>] (phase-70 §5.4) —
                                             * RFC 8693 token endpoint. ""
                                             * = EXCHANGE falls back to verbatim
                                             * bearer passthrough.              */
    ngx_str_t           backend_tx_client_id;  /* [brix_backend_token_exchange_
                                             * client_id <id>] — OAuth2 client id
                                             * for the exchange (HTTP Basic).   */
    ngx_str_t           backend_tx_client_secret; /* [brix_backend_token_exchange_
                                             * client_secret <secret>] — paired
                                             * client secret; NEVER logged.     */
    ngx_str_t           backend_sts_endpoint;  /* [brix_backend_s3_sts_endpoint
                                             * <url>] (phase-70 §5.5) — STS base
                                             * URL for S3 credential EXCHANGE;
                                             * "" = STS off.                    */
    ngx_str_t           backend_sts_role;   /* [brix_backend_s3_sts_role <arn>]
                                             * — role ARN to AssumeRole into; ""
                                             * selects GetSessionToken.         */
    ngx_flag_t          backend_krb5_forwardable; /* [brix_backend_krb5_
                                             * forwardable on|off] (phase-70
                                             * §5.7) — allow GSSAPI credential
                                             * forwarding to the origin. Default
                                             * off.                             */
    ngx_flag_t          backend_passthrough_persist; /* [brix_backend_passthrough_
                                             * persist on|off] (phase-70 §5.1) —
                                             * permit spilling a captured full
                                             * proxy into the async stage
                                             * journal owner dir. Default off.  */
    void               *storage_instance;   /* resolved brix_sd_instance_t* for a
                                             * non-POSIX backend, built per worker at
                                             * init_process. Runtime only — never
                                             * merged. NULL ⇒ default POSIX path.    */
    /* ---- phase-64 composable tier grammar (additive over storage_backend) ----
     * Raw directive values parsed + registered at finalisation (the legacy cache
     * directives that share a name — brix_cache, _verify, _slice, _dirty_max_age
     * — are NOT re-used here; the new cache tier uses the non-colliding names and
     * sensible defaults until the P2 legacy-removal big-bang). */
    ngx_str_t           cache_store;        /* brix_cache_store URL ("" = none)   */
    ngx_array_t        *cache_store_args;   /* its credential=/block_size= tokens    */
    ngx_str_t           cache_cold_store;   /* brix_cache_cold_store URL ("" = none)
                                             * — phase-85 F7 cold tier: eviction
                                             * victims demote here; a miss promotes
                                             * (verified) from here before origin. */
    ngx_array_t        *cache_cold_store_args;
    ngx_array_t        *cache_peers;        /* brix_cache_peers tokens (ngx_str_t[])
                                             * — phase-85 F8 sibling mesh: the
                                             * ring member list, one "host:port"
                                             * per sibling with this node's own
                                             * slot written "self=host:port".
                                             * NULL = no mesh.                    */
    ngx_flag_t          stage_enable;       /* brix_stage on|off                  */
    ngx_str_t           stage_store;        /* brix_stage_store URL               */
    ngx_array_t        *stage_store_args;
    ngx_uint_t          stage_flush_async;  /* brix_stage_flush: 0 sync, 1 async   */
    ngx_flag_t          backend_async;      /* brix_backend_async on|off: route     */
                                            /* namespace mutations through the      */
                                            /* durable coalescing queue (park until */
                                            /* the batch flushes)                   */
    ngx_uint_t          backend_async_batch; /* brix_backend_async_batch: size flush */
    ngx_msec_t          backend_async_wait; /* brix_backend_async_wait: time flush   */
    off_t               cache_max_object;   /* brix_cache_max_object (0 = no cap)  */
    ngx_uint_t          cache_evict_at;     /* brix_cache_evict_at  (percent)      */
    ngx_uint_t          cache_evict_to;     /* brix_cache_evict_to  (percent)      */
    ngx_uint_t          cache_meta_mode;    /* brix_cache_meta  (0 auto..3 sidecar)*/
    ngx_uint_t          cache_verify_mode;  /* brix_cache_verify_mode_e for the
                                             * composed cache tier (phase-68);
                                             * 0/UNSET = off. Registered today by
                                             * the cvmfs protocol only.           */
    ngx_str_t           cache_quarantine_dir; /* verify-mismatch evidence dir;
                                             * "" = unlink the failed part.       */
    ngx_str_t           cache_cvmfs_master_key; /* phase-85 F1: path to the repo
                                             * master public key PEM (may hold
                                             * several concatenated keys). "" =
                                             * no manifest signature verify.     */
    time_t              cache_manifest_ttl; /* phase-68 cvmfs: TTL stamped on
                                             * MANIFEST-class cache fills (secs;
                                             * 0 = no expiry stamping).           */
    time_t              cache_offline_ttl;  /* phase-85 F10 cvmfs: through a
                                             * total origin outage keep serving
                                             * the last verified manifest this
                                             * long past its fill; extends the
                                             * 10x-TTL stale window (0 = off).   */
    time_t              cache_client_hold;  /* phase-68 T20: keep retrying a
                                             * failing fill this long while a
                                             * client waits, then 504+Retry-After
                                             * on a kept-alive conn. 0 = today's
                                             * single-pass fill.                  */
    time_t              cache_fill_max_life; /* T20: detached-fill retry budget
                                             * once every client has gone.       */
    ngx_uint_t          cache_batch_cinfo;  /* brix_cache_batch_cinfo (0 off/1 on/2 auto) */
    size_t              cache_index_cache;  /* brix_cache_index_cache (L1 entries) */
    size_t              cache_slice_size;   /* brix_cache_slice_size (0 = whole-file) */
    /* Read-cache admission (deny/allow prefix + include regex).  The directives
     * live on the stream srv conf (they are stream-only and share the matcher
     * with write-through); the protocol finaliser bridges the already-merged
     * pointers here so the protocol-agnostic tier registration can build the
     * composable sd_cache policy from them — read-fill parity with write-through
     * and the legacy cache_origin admit (brix_cache_admit).  NULL when unset. */
    ngx_array_t        *cache_deny_prefixes;  /* brix_wt_prefix_entry_t[] — blacklist */
    ngx_array_t        *cache_allow_prefixes; /* brix_wt_prefix_entry_t[] — whitelist */
    regex_t            *cache_include_re;      /* compiled include filter, or NULL     */
    ngx_flag_t          allow_write;        /* write permission flag               */
    ngx_flag_t          verify_write;       /* brix_verify_write: fold a self-computed
                                             * read-back CRC check into whole-object
                                             * writes routed through brix_vfs_writer
                                             * (root:// staged, WebDAV/S3 PUT). Off by
                                             * default; never applies to partial/
                                             * ranged (REST/Content-Range) writes.  */
    ngx_flag_t          require_pgwrite;    /* brix_require_pgwrite on|off: refuse a
                                             * cleartext kXR_write / kXR_writev that
                                             * carries data on a writable root:// file
                                             * handle (kXR_Unsupported), forcing clients
                                             * onto the per-page-CRC32c kXR_pgwrite path
                                             * so a hostile-network bit-flip is caught
                                             * on the wire (plain write has no CRC).
                                             * Off by default (plain write is the stock
                                             * upload op); SSI accumulation and
                                             * zero-length no-ops are exempt.          */
    ngx_flag_t          read_only;          /* hard read-only switch: when on, the
                                             * finaliser forces allow_write off so
                                             * EVERY write op is rejected at the
                                             * protocol edge (root:// require_write,
                                             * WebDAV/S3 method gate, write-open)
                                             * before the VFS - and before token
                                             * scope, so a write token cannot bypass
                                             * it. Overrides allow_write on.        */
    ngx_flag_t          compress;           /* phase-42: outbound GET compression
                                             * (Accept-Encoding negotiated). Off by
                                             * default; bypasses sendfile when used. */
    ngx_flag_t          strict_security;    /* [brix_strict_security on|off] (E-1)
                                             * — refuse valid-but-dangerous configs
                                             * at nginx -t instead of only warning:
                                             * anonymous S3 (no SigV4/token verify),
                                             * WebDAV writes without auth, anonymous
                                             * dashboard, etc. Off by default (warn
                                             * only); see brix_shared_security_gate. */
    ngx_str_t           access_log;         /* HTTP-plane brix_access_log path.
                                             * Empty/off disables sesslog emission
                                             * for HTTP protocols. Stream keeps its
                                             * legacy srv_conf access_log owner. */
    ngx_open_file_t    *access_log_file;    /* nginx-managed HTTP log handle. */
    ngx_flag_t          session_log;        /* brix_session_log on|off; controls
                                             * correlated SESS lifecycle records.
                                             * Default ON wherever an access-log fd
                                             * exists. */
    ngx_flag_t          ktls;               /* [brix_ktls on|off] SSL_OP_ENABLE_KTLS
                                             * on this server's TLS context so HTTPS
                                             * GET sendfiles over kernel-TLS (and PUT
                                             * decrypts in-kernel). Default ON:
                                             * transparent no-op when the negotiated
                                             * cipher/kernel cannot offload. See
                                             * docs/.../ktls.md.                     */
    ngx_flag_t          cache_store_endpoint; /* [brix_cache_store_endpoint on|off]
                                             * default OFF. Marks this location as a
                                             * trusted remote cache-STORE surface (a
                                             * cache node's origin-facing endpoint),
                                             * where internal sidecar names (.cinfo /
                                             * .meta / stage markers) are legitimate
                                             * request targets and so must be allowed
                                             * for both read and create. Every normal
                                             * client location leaves it OFF, keeping
                                             * the reserved-name 404 guard in force
                                             * (default-deny). Read at the WebDAV/S3
                                             * path resolver and forwarded to
                                             * brix_http_resolve_path_ex().           */
    ngx_str_t           thread_pool_name;   /* async I/O thread pool name          */
    ngx_thread_pool_t  *thread_pool;        /* resolved pool handle (runtime only) */
    int                 rootfd;             /* O_PATH fd on root_canon for openat2
                                             * RESOLVE_BENEATH confinement; -1 until
                                             * opened per worker at init_process.
                                             * Runtime only — never merged.        */
    brix_pmark_conf_t pmark;              /* SciTags packet-marking config — see
                                             * src/pmark/pmark.h. Shared by every
                                             * protocol; init/merge below.          */
    ngx_uint_t        seccomp;            /* brix_seccomp mode (off/audit/enforce)
                                             * for HTTP (WebDAV/S3/cvmfs) servers;
                                             * a record only — the effective mode is
                                             * the process-global brix_seccomp_worker_mode
                                             * (strictest across ALL brix servers,
                                             * incl. stream), 0=OFF via pcalloc.     */
} ngx_http_brix_shared_conf_t;

#endif /* NGX_HTTP_BRIX_SHARED_CONF_TYPES_H */
