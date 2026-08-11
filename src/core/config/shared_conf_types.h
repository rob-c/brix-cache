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
#include "auth/authz/acc/acc.h"   /* brix_acc_http_t (phase-101 W2: in the preamble) */
#include "core/shm/rate_limit.h"  /* brix_rate_limit_conf_t + brix_kv_t (phase-105 W1) */
#include "net/mirror/mirror.h"    /* brix_mirror_conf_t (phase-105 W2) */

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
    time_t              storage_credential_mint_ttl; /* sec_slot (W7): accepts nginx
                                                       * time units. [brix_storage_credential_
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
    void               *backend_tx_cache;   /* per-worker RFC-8693 minted-token
                                             * cache (brix_tx_cache_t*), lazily
                                             * created by the cred gate via the
                                             * slot handed to
                                             * brix_vfs_deleg_set_exchange()
                                             * (P90-70.9). Not a directive; not
                                             * merged — each conf owns its own. */
    ngx_str_t           backend_sts_endpoint;  /* [brix_backend_s3_sts_endpoint
                                             * <url>] (phase-70 §5.5) — STS base
                                             * URL for S3 credential EXCHANGE;
                                             * "" = STS off.                    */
    ngx_str_t           backend_sts_role;   /* [brix_backend_s3_sts_role <arn>]
                                             * — role ARN to AssumeRole into; ""
                                             * selects GetSessionToken.         */
    ngx_str_t           backend_sts_access_key; /* [brix_backend_s3_sts_access_key
                                             * <id>] (phase-70 §5.5) — node S3
                                             * SERVICE access-key id that SigV4-
                                             * signs the STS AssumeRole request. */
    ngx_str_t           backend_sts_secret_key; /* [brix_backend_s3_sts_secret_key
                                             * <secret>] — paired service secret;
                                             * NEVER logged. STS is armed only
                                             * when endpoint+ak+sk are all set. */
    ngx_str_t           backend_sts_region; /* [brix_backend_s3_sts_region
                                             * <region>] — SigV4 region for the
                                             * "sts" service; "" → us-east-1.    */
    ngx_int_t           backend_sts_ttl;    /* [brix_backend_s3_sts_ttl <secs>]
                                             * — requested temp-cred lifetime;
                                             * clamped 900..43200 by the STS
                                             * client. UNSET → 3600.             */
    ngx_uint_t          backend_sts_flavor; /* [brix_backend_s3_sts_flavor
                                             * aws|minio] (phase-70 §5.5) — STS
                                             * wire dialect: aws=GET/presigned,
                                             * minio=POST/form/header-auth.
                                             * UNSET → aws (0).                  */
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
    ngx_str_t           backend_sss_keytab; /* [brix_backend_sss_keytab <path>]
                                             * (phase-70 §5.6 / P90-70.3) — SSS
                                             * keytab the delegation gate signs
                                             * identity-injection credentials
                                             * with (assert the CALLER to the
                                             * origin, never the keytab's own
                                             * principal). Load-validated. "" =
                                             * injection off.                   */
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
    ngx_str_t           cache_root;         /* [brix_cache_root <path>] (phase-101 W8):
                                             * legacy read-through cache root; was the
                                             * webdav+s3 twins brix_{webdav,s3}_cache_
                                             * root. "" = disabled. The stream plane's
                                             * fd-based cache (brix_cache_export) is a
                                             * separate mechanism, left as-is. */
    char                cache_root_canon[PATH_MAX]; /* realpath of cache_root; "" =
                                             * disabled. Derived per-protocol at merge
                                             * (after adopt), not adopted. */
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
    ngx_flag_t          cache_global_cas;   /* phase-87 G13: hardlink-dedup
                                             * cvmfs-cas-verified CAS objects
                                             * across repos in the local posix
                                             * cache store (default off).        */
    ngx_flag_t          cache_only_if_cached; /* brix_cache_only_if_cached (audit
                                             * §4.4, upstream pfc.onlyifcached):
                                             * serve only what is already cached
                                             * — a read MISS returns ENOENT
                                             * instead of filling from the
                                             * origin, so the client fails over
                                             * to another replica rather than
                                             * making this node pull the object.
                                             * Writes always pass through
                                             * (default off).                    */
    ngx_flag_t          cache_passthrough;  /* phase-92 brix_cache_passthrough:
                                             * store-then-evict an admission-
                                             * declined remote object so the
                                             * coalesced HTTP waiters are served
                                             * a transient hit, then it is
                                             * evicted (default off).            */
    off_t               cache_passthrough_max; /* brix_cache_passthrough_max: the
                                             * spool cap for a passthrough fill;
                                             * 0 = fall back to cache_max_object. */
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
    time_t              cache_uvkeep;       /* brix_cache_uvkeep (audit §4.3,
                                             * pfc.uvkeep): age out a never-
                                             * verified cache entry past this
                                             * many secs from its fill so the
                                             * next open revalidates (0 = off). */
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
    ngx_int_t           cache_prefetch;     /* brix_cache_prefetch: max in-flight
                                             * background block-prefetch jobs per
                                             * worker (0 = off)                    */
    size_t              cache_prefetch_window; /* brix_cache_prefetch_window: max
                                             * bytes one WILLNEED hint may queue
                                             * for background fill                 */
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
    ngx_flag_t          data_substreams;    /* brix_data_substreams on|off (root://):
                                             * accept kXR_bind so a client may open
                                             * secondary data connections (parallel
                                             * reads).  ON by default.  When OFF, bind
                                             * is refused with kXR_Unsupported, so a
                                             * client falls back to sending every
                                             * request (and its data) inline on the
                                             * primary connection (pathid 0) — the
                                             * correct, spec-endorsed fallback.  BriX
                                             * does not yet service a cross-connection
                                             * WRITE data-path, so a deployment fronting
                                             * clients that stream write payloads on a
                                             * substream (e.g. go-hep WithSubStreams)
                                             * turns this off to force the streaming
                                             * inline write path.                       */
    ngx_flag_t          read_only;          /* hard read-only switch: when on, the
                                             * finaliser forces allow_write off so
                                             * EVERY write op is rejected at the
                                             * protocol edge (root:// require_write,
                                             * WebDAV/S3 method gate, write-open)
                                             * before the VFS - and before token
                                             * scope, so a write token cannot bypass
                                             * it. Overrides allow_write on.        */
    ngx_flag_t          read_only_public;   /* [brix_read_only_public on|off] — the
                                             * public-gateway posture: implies
                                             * read_only (the finaliser turns it on),
                                             * and additionally refuses the kXR_query
                                             * infotypes that describe the SERVER
                                             * rather than a path the client may
                                             * already read (QStats, Qspace, Qconfig,
                                             * QFSinfo, Qvisa). Listing, stat, read,
                                             * checksum and per-path xattr are
                                             * untouched, so an anonymous client can
                                             * still browse and stream data.        */
    ngx_flag_t          compress;           /* phase-42: outbound GET compression
                                             * (Accept-Encoding negotiated). Off by
                                             * default; bypasses sendfile when used. */
    ngx_uint_t          tls_require;        /* [brix_tls_require <caps...>] —
                                             * BRIX_TLSREQ_* capability mask
                                             * (vfs_secgate.h): ops exercising a
                                             * masked capability are refused on
                                             * cleartext transports. 0 = off. */
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
                                             * decrypts in-kernel). Default OFF
                                             * (phase-33 P5: opt-in, HW-offload-only;
                                             * software kTLS regresses). No-op when
                                             * the cipher/kernel cannot offload. See
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
    brix_acc_http_t   acc;                /* XrdAcc engine settings + per-worker
                                             * state (phase-101 W2): promoted from the
                                             * webdav/s3 loc-confs so brix_authdb* /
                                             * brix_acc_* register ONCE on the common
                                             * module and every HTTP protocol (incl.
                                             * cvmfs) inherits via adopt. The tables/
                                             * timer tail is per-worker, NEVER merged. */
    ngx_flag_t        zip_access;         /* [brix_zip_access on|off] (phase-101 W4):
                                             * serve a member of a stored ZIP via a
                                             * ?zip=member query. Was brix_webdav_zip_
                                             * access / brix_s3_zip_access. */
    size_t            zip_cd_max_bytes;   /* [brix_zip_cd_max_bytes] central-directory
                                             * scan cap; was the webdav/s3 twins. */
    ngx_str_t         pwd_file;           /* [brix_pwd_file <file>] (phase-101 W4):
                                             * HTTP basic-auth password db; was
                                             * brix_webdav_pwd_file. Bare on the stream
                                             * plane already. "" = off. */
    ngx_flag_t        upload_resume;      /* [brix_upload_resume on|off] (phase-101
                                             * W4): resumable Content-Range PUT;
                                             * was brix_webdav_upload_resume. Default
                                             * ON (applied in the shared merge). */
    ngx_str_t         token_macaroon_secret;     /* [brix_macaroon_secret <hex>]
                                             * (phase-101 W4): was
                                             * brix_webdav_macaroon_secret. */
    ngx_str_t         token_macaroon_secret_old; /* [brix_macaroon_secret_old <hex>]
                                             * grace-period rotation key. */
    ngx_str_t         upload_stage_dir;    /* [brix_stage_dir <path>] (phase-101 W4):
                                             * optional fast-cache staging device;
                                             * was brix_webdav_stage_dir. The derived
                                             * *_canon buffer stays protocol-local. */
    ngx_str_t         crl;                 /* [brix_crl <dir>] (phase-101 W4): CRL PEM
                                             * directory; was brix_webdav_crl. */
    ngx_uint_t        signing_policy_mode; /* [brix_signing_policy] BRIX_SP_MODE_*;
                                             * was brix_webdav_signing_policy. */
    ngx_uint_t        crl_mode;            /* [brix_crl_mode] BRIX_CRL_MODE_*;
                                             * was brix_webdav_crl_mode. */
    ngx_str_t         vomsdir;             /* [brix_vomsdir <dir>] (phase-101 W4):
                                             * VOMS *.lsc trust dir; was
                                             * brix_webdav_vomsdir. */
    ngx_str_t         voms_cert_dir;       /* [brix_voms_cert_dir <dir>]: VOMS CA dir;
                                             * was brix_webdav_voms_cert_dir. */
    ngx_array_t      *vo_rules;            /* brix_vo_rule_t[] from [brix_require_vo
                                             * <path> <vo>] (phase-101 W4): per-path VO
                                             * ACL; was the webdav-local brix_webdav_
                                             * require_vo. Honored on webdav/root/gridftp
                                             * (VOMS); parsed-but-inert on s3 (SigV4). */
    ngx_array_t      *authdb_rules;        /* brix_authdb_rule_t[] from [brix_authdb
                                             * <file>] (phase-101 W5.2): native u/g/p/h
                                             * READ ACL; moved here from the webdav-local
                                             * field so brix_authdb registers once on
                                             * http_common (all HTTP planes) into the shared
                                             * preamble.  ENFORCED in the webdav AND s3 access
                                             * phases (+ root:// on stream) — each deep-copies
                                             * this and finalizes the copy against its own
                                             * root (brix_authdb_rules_finalize_copy) so a
                                             * sibling plane's finalize can't mis-resolve it.
                                             * cvmfs is NOT gated: its read-through/CAS path
                                             * model has no local realpath to match. */
    ngx_array_t      *protbind;            /* brix_protbind_rule_t[] from [brix_protbind
                                             * <tpl> none|[only] <proto>...] (phase-101
                                             * W4): per-host credential-source binding
                                             * (XRootD sec.protbind); was brix_webdav_
                                             * protbind. NULL = no rules; shared engine
                                             * in src/auth/protbind/. */
    /* HTTP-TPC SSRF + source-allowlist policy (phase-101 W4): were brix_webdav_
     * tpc_{allow_local,allow_private,source_guard,source_allow,require_source_size};
     * bare brix_tpc_* on the stream plane already. Honored by the webdav curl-COPY
     * engine; the native (root) TPC reads its own stream-conf copies. */
    ngx_flag_t        tpc_allow_local;     /* 0: reject loopback+link-local targets */
    ngx_flag_t        tpc_allow_private;   /* default 1: allow RFC-1918/ULA targets */
    ngx_flag_t        tpc_source_guard;    /* 0: off; on = pull only from an
                                             * authority on tpc_source_allow */
    ngx_array_t      *tpc_source_allow;    /* ngx_str_t[]: exact host or leading-'.'
                                             * domain suffix (NULL = none) */
    ngx_flag_t        tpc_require_source_size; /* 0: pull a length-less source anyway;
                                                 * on = refuse it as unverifiable */
    ngx_str_t         tpc_verify_checksum; /* [brix_tpc_verify_checksum on|off|<alg>]
                                             * (phase-101 W4): unified post-copy TPC
                                             * integrity. Normalized at parse: "" =
                                             * off; a canonical checksum alg name
                                             * otherwise ("on" => "adler32", the
                                             * XRootD/WLCG default). The native
                                             * (root) TPC reads it as a boolean gate
                                             * (kXR_Qcksum negotiates its own alg);
                                             * the webdav curl-COPY uses the alg for
                                             * Want-Digest + recompute. Was the flag
                                             * brix_tpc_verify_checksum (stream) and
                                             * the <alg> brix_webdav_tpc_verify_
                                             * checksum (webdav) — now one grammar. */
    ngx_str_t         token_jwks;          /* [brix_token_jwks <file>] (phase-101 W4):
                                             * JWKS pubkey file; collapsed webdav+s3
                                             * twins. Per-worker jwks_keys[] stays
                                             * protocol-local. */
    ngx_str_t         token_issuer;        /* [brix_token_issuer] required "iss". */
    ngx_str_t         token_audience;      /* [brix_token_audience] required "aud". */
    time_t            token_clock_skew;    /* [brix_token_clock_skew] exp/nbf grace;
                                             * sec_slot since phase-105 W8 (suffixes
                                             * legal; the 300s security clamp in the
                                             * shared merge still rejects loudly).
                                             * Unified default 30 (was 30 on webdav,
                                             * 60 on s3 — stricter wins). */
    ngx_str_t         token_config;        /* [brix_token_config <scitokens.cfg>]
                                             * (phase-101 W4): multi-issuer registry
                                             * file; overrides the single-issuer
                                             * jwks/issuer/audience when set. Was the
                                             * webdav-local brix_webdav_token_config;
                                             * bare on the stream plane already. The
                                             * built token_registry stays protocol-
                                             * local. */
    /* OIDC token introspection / revocation (phase-105 W4.1 — were the
     * brix_webdav_token_introspect_* quad; 101 Table 1 planned the bare
     * names). Consulted by the GLOBAL introspection access handler
     * (webdav/introspect.c) for any brix request carrying a Bearer token —
     * the verdict cache (brix_webdav_revoke_cache) stays webdav-scoped. */
    ngx_str_t         introspect_url;      /* [brix_token_introspect_url] display/doc */
    ngx_str_t         introspect_loc;      /* [brix_token_introspect_loc] internal URI
                                             * that proxy_passes to the IdP; enables
                                             * the check ("" = off) */
    time_t            introspect_ttl;      /* [brix_token_introspect_ttl] verdict TTL;
                                             * sec_slot since the move (was num) */
    ngx_flag_t        introspect_fail_open; /* [brix_token_introspect_fail_open] */
    ngx_str_t         trusted_ca;         /* [brix_trusted_ca <file>] (phase-105 W2):
                                             * auth-layer verify-source CA bundle for
                                             * the GSI/VOMS chain (101-W6 role name).
                                             * Consumed by webdav cert-auth today;
                                             * scope documented in directives.md. */
    ngx_str_t         trusted_ca_dir;     /* [brix_trusted_ca_dir <dir>] verify-source
                                             * CA directory — file/dir forms of ONE
                                             * source; distinct from client_ca_store
                                             * (front-leg SSL_CTX) and backend_ca_dir
                                             * (proxy back leg) — the 101-W6 four-
                                             * mechanism distinction holds. */
    ngx_uint_t        verify_depth;       /* [brix_verify_depth <n>] (phase-105 W3.5):
                                             * cap on the accepted client proxy-chain
                                             * depth in the auth path (VOMS proxies +
                                             * delegation re-verify). One spelling with
                                             * the stream plane; per-plane defaults
                                             * KEEP (HTTP 10; stream 0=unlimited). */
    ngx_str_t         tcp_congestion;     /* [brix_tcp_congestion <alg>] (phase-105
                                             * W2): sender-side congestion alg applied
                                             * by the SHARED file-serve path — one
                                             * site covers webdav GET, S3 GetObject
                                             * and cvmfs; was webdav-owned while the
                                             * engine was already cross-protocol. */
    brix_mirror_conf_t mirror;            /* [brix_mirror_url/_methods/_sample/
                                             * _strip_auth/_writes/_log_diverge/
                                             * _timeout/_token] (phase-105 W2):
                                             * traffic-mirror SETTINGS — were
                                             * webdav-owned; the engine plumbing
                                             * (upstream conf, TLS ctx, request ctx)
                                             * stays on the webdav conf, which the
                                             * globally-registered phase handlers
                                             * fetch (documented residual, same
                                             * shape as ratelimit_http.c). The
                                             * stream plane keeps its own flat
                                             * copy. */
    ngx_flag_t        delegation_endpoint; /* [brix_delegation_endpoint on|off]
                                             * (phase-105 W2): opt-in GSI proxy-upload
                                             * delegation well-known endpoint. Consumed
                                             * by the webdav dispatch today (HTTP-TPC
                                             * delegation is a webdav COPY mechanism);
                                             * documented webdav-scoped in
                                             * directives.md. Was webdav-owned. */
    ngx_str_t         client_ca_store;    /* [brix_client_ca_store <dir>] (phase-105
                                             * W2): hashed CA dir loaded into the
                                             * SERVER SSL_CTX client-verify store at
                                             * postconfiguration — the listener ctx is
                                             * shared by every protocol on the server,
                                             * so behavior was already server-wide;
                                             * only ownership moved. Hook stays in
                                             * webdav postconfig (documented residual). */
    time_t            max_delay;          /* [brix_max_delay <time>] (phase-105 W3):
                                             * the xrootd maxdelay analog — CAP on the
                                             * client wait/Retry-After seconds a
                                             * response may advertise. Was
                                             * brix_webdav_maxdelay; the stream plane
                                             * spells it brix_max_delay already (its
                                             * flat field + default 60 stay per-plane;
                                             * HTTP default 0 = off). */
    brix_kv_t        *token_cache_kv;     /* [brix_token_cache zone=] (phase-105 W1):
                                             * verified-token KV cache; was the
                                             * webdav-local field, so the bare name
                                             * parsed-but-was-inert on s3/cvmfs
                                             * (first-module-wins routed it to
                                             * webdav's conf). NULL = off. */
    brix_rate_limit_conf_t rate_limit;    /* [brix_rate_limit zone= rate= burst=
                                             * key=dn|ip] (phase-105 W1): token-
                                             * bucket admission; engine in
                                             * core/shm/rate_limit.c. kv==NULL = off
                                             * (the UNSET sentinel — zeroed init). */
    ngx_array_t      *rl_rules;           /* brix_rl_rule_t[] from [brix_rate_limit_
                                             * rule / brix_bandwidth_limit /
                                             * brix_concurrency_limit] (phase-105
                                             * W1): traffic-shaping rules, engine in
                                             * net/ratelimit/. NULL = none; inherited
                                             * WHOLE at merge (like vo_rules) — was
                                             * location-exact on webdav, so server-
                                             * scope rules are new capability. */
    ngx_uint_t        seccomp;            /* brix_seccomp mode (off/audit/enforce)
                                             * for HTTP (WebDAV/S3/cvmfs) servers;
                                             * a record only — the effective mode is
                                             * the process-global brix_seccomp_worker_mode
                                             * (strictest across ALL brix servers,
                                             * incl. stream), 0=OFF via pcalloc.     */
} ngx_http_brix_shared_conf_t;

/* phase-105 W8: the preamble is plane-neutral (embedded by the stream srv
 * conf, stream_common, and gridftp as well as every HTTP protocol conf) —
 * new code should use this alias; existing uses are NOT swept (a rename
 * sweep is deliberately out of scope, same call phase-101 made). */
typedef ngx_http_brix_shared_conf_t  brix_shared_conf_t;

#endif /* NGX_HTTP_BRIX_SHARED_CONF_TYPES_H */
