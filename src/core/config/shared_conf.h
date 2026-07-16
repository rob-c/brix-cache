/*
 * shared_conf.h — Shared config preamble struct for nginx-xrootd protocols.
 */

#ifndef NGX_HTTP_BRIX_SHARED_CONF_H
#define NGX_HTTP_BRIX_SHARED_CONF_H

#include <ngx_thread_pool.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "observability/pmark/pmark.h"

/* Default per-user credential store: a RAM-backed (tmpfs) directory, so
 * delegated private keys never persist across a reboot, never land in
 * backups/snapshots, and leave no blocks on real disk. /dev/shm is mounted
 * on effectively every Linux system, so no operator setup is required —
 * the directory itself is created 0700 at config time (see
 * brix_shared_credential_dir_ensure below). Opt out with an explicit
 * `brix_storage_credential_dir "";`. */
#define BRIX_CREDENTIAL_DIR_DEFAULT  "/dev/shm/brix-creds"

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
    ngx_flag_t          stage_enable;       /* brix_stage on|off                  */
    ngx_str_t           stage_store;        /* brix_stage_store URL               */
    ngx_array_t        *stage_store_args;
    ngx_uint_t          stage_flush_async;  /* brix_stage_flush: 0 sync, 1 async   */
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
    time_t              cache_manifest_ttl; /* phase-68 cvmfs: TTL stamped on
                                             * MANIFEST-class cache fills (secs;
                                             * 0 = no expiry stamping).           */
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
    ngx_flag_t          allow_write;        /* write permission flag               */
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
    ngx_str_t           thread_pool_name;   /* async I/O thread pool name          */
    ngx_thread_pool_t  *thread_pool;        /* resolved pool handle (runtime only) */
    int                 rootfd;             /* O_PATH fd on root_canon for openat2
                                             * RESOLVE_BENEATH confinement; -1 until
                                             * opened per worker at init_process.
                                             * Runtime only — never merged.        */
    brix_pmark_conf_t pmark;              /* SciTags packet-marking config — see
                                             * src/pmark/pmark.h. Shared by every
                                             * protocol; init/merge below.          */
} ngx_http_brix_shared_conf_t;

/*
 * ngx_http_brix_shared_create_loc_conf() — Allocates and initializes a shared
 * preamble struct with NGX_CONF_UNSET sentinel values. Called by each protocol's
 * create_loc_conf function to set the shared fields before returning its own
 * full config struct.
 *
 * WHY: nginx merge macros detect NGX_CONF_UNSET to know which value is unset;
 * every protocol must initialize shared fields this way so parent→child merge
 * works correctly regardless of whether enable/root/allow_write appear in main,
 * server, or location blocks.
 */
static inline void
ngx_http_brix_shared_init(ngx_http_brix_shared_conf_t *conf)
{
    conf->enable             = NGX_CONF_UNSET;
    conf->allow_write        = NGX_CONF_UNSET;
    conf->read_only          = NGX_CONF_UNSET;
    conf->compress           = NGX_CONF_UNSET;
    conf->access_log.len     = 0;
    conf->access_log.data    = NULL;
    conf->access_log_file    = NULL;
    conf->session_log        = NGX_CONF_UNSET;
    conf->ktls               = NGX_CONF_UNSET;
    conf->storage_staging    = NGX_CONF_UNSET;
    conf->cache_verify_mode  = NGX_CONF_UNSET_UINT;
    conf->thread_pool_name.len  = 0;
    conf->thread_pool_name.data = NULL;
    conf->thread_pool        = NULL;
    conf->storage_backend.len   = 0;
    conf->storage_backend.data  = NULL;
    conf->storage_credential.len  = 0;
    conf->storage_credential.data = NULL;
    conf->storage_credential_dir.len   = 0;
    conf->storage_credential_dir.data  = NULL;
    conf->storage_credential_fallback  = NGX_CONF_UNSET_UINT;
    conf->storage_credential_mint_ca_cert.len   = 0;
    conf->storage_credential_mint_ca_cert.data  = NULL;
    conf->storage_credential_mint_ca_key.len    = 0;
    conf->storage_credential_mint_ca_key.data   = NULL;
    conf->storage_credential_mint_ttl  = NGX_CONF_UNSET_UINT;
    conf->backend_delegation = NGX_CONF_UNSET_UINT;
    conf->backend_token_aud  = NGX_CONF_UNSET_PTR;
    conf->backend_tx_endpoint.len       = 0;
    conf->backend_tx_endpoint.data      = NULL;
    conf->backend_tx_client_id.len      = 0;
    conf->backend_tx_client_id.data     = NULL;
    conf->backend_tx_client_secret.len  = 0;
    conf->backend_tx_client_secret.data = NULL;
    conf->backend_sts_endpoint.len      = 0;
    conf->backend_sts_endpoint.data     = NULL;
    conf->backend_sts_role.len          = 0;
    conf->backend_sts_role.data         = NULL;
    conf->backend_krb5_forwardable      = NGX_CONF_UNSET;
    conf->backend_passthrough_persist   = NGX_CONF_UNSET;
    conf->pblock_block_size  = NGX_CONF_UNSET_SIZE;
    conf->storage_instance   = NULL;   /* built per worker at init_process */
    conf->cache_store.len    = 0;
    conf->cache_store.data   = NULL;
    conf->cache_store_args   = NULL;
    conf->stage_enable       = NGX_CONF_UNSET;
    conf->stage_store.len    = 0;
    conf->stage_store.data   = NULL;
    conf->stage_store_args   = NULL;
    conf->stage_flush_async  = NGX_CONF_UNSET_UINT;
    conf->cache_max_object   = NGX_CONF_UNSET;
    conf->cache_evict_at     = NGX_CONF_UNSET_UINT;
    conf->cache_evict_to     = NGX_CONF_UNSET_UINT;
    conf->cache_meta_mode    = NGX_CONF_UNSET_UINT;
    conf->cache_batch_cinfo  = NGX_CONF_UNSET_UINT;
    conf->cache_index_cache  = NGX_CONF_UNSET_SIZE;
    conf->cache_slice_size   = NGX_CONF_UNSET_SIZE;
    conf->rootfd             = -1;   /* opened per worker at init_process */
    /* root_canon zeroed by ngx_pcalloc — no explicit memset needed */
    brix_pmark_conf_init(&conf->pmark);
}

/*
 * brix_shared_apply_read_only() — enforce the hard read-only switch. When
 * common->read_only is on, force allow_write off so EVERY existing write gate
 * (root:// brix_dispatch_require_write, the WebDAV/S3 write-method gate, the
 * write-open gate) rejects writes at the protocol edge - before the VFS, and
 * before token scope (allow_write is checked first), so a write-scoped token
 * cannot bypass it. ngx_http_brix_shared_merge() applies it after the
 * allow_write/read_only merges so no protocol can forget the enforcement;
 * callers with later allow_write-dependent validations (e.g. WebDAV's
 * "writes need auth" check) simply run them after the shared merge.
 */
static inline void
brix_shared_apply_read_only(ngx_http_brix_shared_conf_t *common,
    ngx_log_t *log)
{
    if (common->read_only != 1) {
        return;
    }
    if (common->allow_write == 1 && log != NULL) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "brix: read_only on - the export is read-only; all write "
            "operations are rejected at the protocol edge (overrides allow_write)");
    }
    common->allow_write = 0;
}

/*
 * brix_shared_credential_dir_ensure() — Config-time guarantee for
 * brix_storage_credential_dir: create the directory 0700 (chown'd to the
 * worker user when the master runs as root) if it is missing, and shout —
 * NGX_LOG_WARN at parse time — when it cannot be created, is not a
 * directory, is group/other-accessible, or is owned by a user the workers
 * do not run as.
 *
 * WHY: The store holds delegated PRIVATE KEYS, and the default lives on
 * tmpfs (/dev/shm) precisely so nothing persists across reboots or lands in
 * backups — but /dev/shm is world-writable (1777), so the entire security
 * boundary is this directory's 0700 mode + ownership, which must therefore
 * be enforced here rather than left to operator setup. A broken or
 * foreign-owned path must NOT kill startup (the store may be unused, and
 * fallback=allow keeps requests on the service credential), but the admin
 * must be told that credential delegation will not work until it is fixed.
 *
 * HOW: stat(); on ENOENT mkdir(0700) + chown to ccf->user when euid==0
 * (mirroring ngx_create_paths). Every failure and every unsafe pre-existing
 * state warns via ngx_conf_log_error and returns — never fatal. Called from
 * every shared merge (per server/location), so a broken path is shouted per
 * context; the healthy path prints nothing and costs one stat().
 */
static inline void
brix_shared_credential_dir_ensure(ngx_conf_t *cf, const ngx_str_t *dir)
{
    struct stat       st;
    const char       *path;
    uid_t             want_uid;
    ngx_core_conf_t  *ccf;

    if (dir == NULL || dir->len == 0) {
        return;                 /* explicit "" = per-user store disabled */
    }

    path = (const char *) dir->data;    /* conf tokens are NUL-terminated */
    ccf  = (ngx_core_conf_t *)
               ngx_get_conf(cf->cycle->conf_ctx, ngx_core_module);
    want_uid = (geteuid() == 0
                && ccf != NULL
                && ccf->user != (ngx_uid_t) NGX_CONF_UNSET_UINT)
             ? (uid_t) ccf->user : geteuid();

    if (stat(path, &st) != 0) {
        if (errno != ENOENT) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, errno,
                "brix: credential store \"%s\" is not accessible — "
                "credential delegation will not work until "
                "brix_storage_credential_dir is fixed", path);
            return;
        }

        if (mkdir(path, 0700) != 0 && errno != EEXIST) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, errno,
                "brix: cannot create credential store \"%s\" — "
                "credential delegation will not work until "
                "brix_storage_credential_dir is fixed", path);
            return;
        }

        if (stat(path, &st) != 0) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, errno,
                "brix: credential store \"%s\" vanished after create — "
                "credential delegation will not work", path);
            return;
        }

        /* The master parses config as root but the workers write the store
         * as the `user` directive's uid — hand the fresh directory to them,
         * exactly as ngx_create_paths does for the temp paths. */
        if (geteuid() == 0 && st.st_uid != want_uid
            && chown(path, want_uid,
                     (ccf != NULL) ? (gid_t) ccf->group : (gid_t) -1) != 0)
        {
            ngx_conf_log_error(NGX_LOG_WARN, cf, errno,
                "brix: cannot chown credential store \"%s\" to the worker "
                "user — credential delegation will not work", path);
        }
        return;
    }

    if (!S_ISDIR(st.st_mode)) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
            "brix: credential store \"%s\" is not a directory — "
            "credential delegation will not work until "
            "brix_storage_credential_dir is fixed", path);
        return;
    }

    if ((st.st_mode & 0077) != 0) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
            "brix: credential store \"%s\" is group/other-accessible "
            "(mode %04uo) — delegated private keys may be exposed; "
            "chmod 0700", path, (ngx_uint_t) (st.st_mode & 07777));
    }

    if (st.st_uid != want_uid) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
            "brix: credential store \"%s\" is owned by uid %ud but the "
            "workers run as uid %ud — credential delegation will not work "
            "until ownership or brix_storage_credential_dir is fixed",
            path, (ngx_uint_t) st.st_uid, (ngx_uint_t) want_uid);
    }
}

/*
 * ngx_http_brix_shared_merge() — Merges shared preamble fields from parent to
 * child using standard nginx merge macros. Called at the top of each protocol's
 * merge_loc_conf function before protocol-specific merge logic runs.
 *
 * WHY: This is the SINGLE audit point for common.* config inheritance — every
 * HTTP protocol (WebDAV, S3, cvmfs) calls it instead of hand-merging the same
 * ~20 fields (which drifted per protocol and dropped the read-only enforcement
 * in cvmfs). Defaults: enable=0, allow_write=0, compress=0, ktls=1,
 * thread_pool_name="", storage_credential_dir=BRIX_CREDENTIAL_DIR_DEFAULT
 * (tmpfs store, ensured 0700 by brix_shared_credential_dir_ensure above),
 * tier grammar defaults as before.
 *
 * HOW: root_default parameterizes the one deliberate per-protocol difference
 * (WebDAV exports default to "/", S3/cvmfs to ""). Ends by applying the hard
 * read-only switch (see brix_shared_apply_read_only above) and merging pmark;
 * returns NGX_CONF_OK or NGX_CONF_ERROR (pmark merge failure).
 */
static inline char *
ngx_http_brix_shared_merge(ngx_conf_t *cf,
                             ngx_http_brix_shared_conf_t *prev,
                             ngx_http_brix_shared_conf_t *conf,
                             const char *root_default)
{
    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    /* root_default is a runtime const char* parameter, not a string literal;
     * ngx_conf_merge_str_value computes sizeof(default)-1, which yields the
     * pointer width (7 on 64-bit) rather than the actual string length — the
     * empty-string default used by s3/cvmfs became {len:7,data:""}, so the
     * pure-cache-node root.len==0 → "/" fallback never fired.  Hand-roll. */
    if (conf->root.data == NULL) {
        if (prev->root.data != NULL) {
            conf->root = prev->root;
        } else {
            conf->root.data = (u_char *) root_default;
            conf->root.len = ngx_strlen(root_default);
        }
    }
    ngx_conf_merge_value(conf->allow_write, prev->allow_write, 0);
    ngx_conf_merge_value(conf->read_only, prev->read_only, 0);
    ngx_conf_merge_value(conf->compress, prev->compress, 0);
    ngx_conf_merge_str_value(conf->access_log, prev->access_log, "");
    if (conf->access_log.len > 0
        && ngx_strcmp(conf->access_log.data, (u_char *) "off") != 0)
    {
        conf->access_log_file = ngx_conf_open_file(cf->cycle,
                                                   &conf->access_log);
        if (conf->access_log_file == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "brix: cannot register HTTP access log \"%V\"",
                &conf->access_log);
            return NGX_CONF_ERROR;
        }
    } else {
        conf->access_log_file = NULL;
    }
    ngx_conf_merge_value(conf->session_log, prev->session_log, 1);
    ngx_conf_merge_value(conf->ktls, prev->ktls, 1);   /* default ON (offload-gated) */
    ngx_conf_merge_value(conf->storage_staging, prev->storage_staging, 0);
    ngx_conf_merge_str_value(conf->thread_pool_name, prev->thread_pool_name, "");
    ngx_conf_merge_str_value(conf->storage_backend, prev->storage_backend, "");
    ngx_conf_merge_str_value(conf->storage_credential, prev->storage_credential,
                             "");
    /* Defaults to a RAM-backed (tmpfs) store so delegated keys never touch
     * real disk; behaviour-neutral for non-delegated deployments because a
     * lookup miss with fallback=allow (the default) lands on the service
     * credential exactly like an unset dir. `""` opts out entirely. */
    ngx_conf_merge_str_value(conf->storage_credential_dir,
                             prev->storage_credential_dir,
                             BRIX_CREDENTIAL_DIR_DEFAULT);
    brix_shared_credential_dir_ensure(cf, &conf->storage_credential_dir);
    ngx_conf_merge_uint_value(conf->storage_credential_fallback,
                              prev->storage_credential_fallback, 0);
    ngx_conf_merge_str_value(conf->storage_credential_mint_ca_cert,
                             prev->storage_credential_mint_ca_cert, "");
    ngx_conf_merge_str_value(conf->storage_credential_mint_ca_key,
                             prev->storage_credential_mint_ca_key, "");
    ngx_conf_merge_uint_value(conf->storage_credential_mint_ttl,
                              prev->storage_credential_mint_ttl, 3600);
    ngx_conf_merge_uint_value(conf->backend_delegation,
                              prev->backend_delegation, 0);  /* SELECT */
    ngx_conf_merge_ptr_value(conf->backend_token_aud,
                             prev->backend_token_aud, NULL);
    ngx_conf_merge_str_value(conf->backend_tx_endpoint,
                             prev->backend_tx_endpoint, "");
    ngx_conf_merge_str_value(conf->backend_tx_client_id,
                             prev->backend_tx_client_id, "");
    ngx_conf_merge_str_value(conf->backend_tx_client_secret,
                             prev->backend_tx_client_secret, "");
    ngx_conf_merge_str_value(conf->backend_sts_endpoint,
                             prev->backend_sts_endpoint, "");
    ngx_conf_merge_str_value(conf->backend_sts_role,
                             prev->backend_sts_role, "");
    ngx_conf_merge_value(conf->backend_krb5_forwardable,
                         prev->backend_krb5_forwardable, 0);
    ngx_conf_merge_value(conf->backend_passthrough_persist,
                         prev->backend_passthrough_persist, 0);
    ngx_conf_merge_size_value(conf->pblock_block_size, prev->pblock_block_size,
                              0);

    /* phase-64 tier grammar */
    ngx_conf_merge_str_value(conf->cache_store, prev->cache_store, "");
    if (conf->cache_store_args == NULL) {
        conf->cache_store_args = prev->cache_store_args;
    }
    ngx_conf_merge_value(conf->stage_enable, prev->stage_enable, 0);
    ngx_conf_merge_str_value(conf->stage_store, prev->stage_store, "");
    if (conf->stage_store_args == NULL) {
        conf->stage_store_args = prev->stage_store_args;
    }
    ngx_conf_merge_uint_value(conf->stage_flush_async, prev->stage_flush_async, 0);
    ngx_conf_merge_off_value(conf->cache_max_object, prev->cache_max_object, 0);
    ngx_conf_merge_uint_value(conf->cache_evict_at, prev->cache_evict_at, 90);
    ngx_conf_merge_uint_value(conf->cache_evict_to, prev->cache_evict_to, 80);
    ngx_conf_merge_uint_value(conf->cache_meta_mode, prev->cache_meta_mode, 0);
    ngx_conf_merge_uint_value(conf->cache_batch_cinfo, prev->cache_batch_cinfo, 2);
    ngx_conf_merge_size_value(conf->cache_index_cache, prev->cache_index_cache, 0);
    ngx_conf_merge_size_value(conf->cache_slice_size, prev->cache_slice_size, 0);
    /* 0 == BRIX_CACHE_VERIFY_OFF (fs/cache/verify.h; not included here — it
     * drags stream-typed cache internals into every HTTP module conf). */
    ngx_conf_merge_uint_value(conf->cache_verify_mode, prev->cache_verify_mode,
                              0);

    /* Hard read-only: force allow_write off HERE so no protocol merge can
     * forget the enforcement (it must win before token-scope checks). */
    brix_shared_apply_read_only(conf, cf->log);

    return brix_pmark_conf_merge(cf, &prev->pmark, &conf->pmark);
}

static inline ngx_fd_t
brix_http_shared_access_log_fd(const ngx_http_brix_shared_conf_t *conf)
{
    if (conf == NULL || conf->access_log_file == NULL) {
        return NGX_INVALID_FILE;
    }

    return conf->access_log_file->fd;
}

/*
 * brix_tier_register_stores() — register the export's phase-64 composable
 * cache/stage tiers from the common preamble onto the backend registry (which
 * composes the sd_cache / sd_stage decorators per worker). Shared by all three
 * protocol finalisers (§4.4): each calls it with its &conf->common after the
 * storage backend + root_canon are set. Returns NGX_OK, or NGX_ERROR after an
 * [emerg] for an operator error (unknown scheme, bad path, stage-without-store).
 * Defined in config/runtime_server.c.
 */
ngx_int_t brix_tier_register_stores(ngx_conf_t *cf,
    ngx_http_brix_shared_conf_t *common);

/* Rewrite a "posix:<path>" / "pblock://<path>" storage_backend into the export root
 * (common->root) — the composable replacement for brix_root. No-op otherwise.
 * Call BEFORE the export-root prep. Defined in config/runtime_server.c. */
void brix_storage_backend_posix_root(ngx_http_brix_shared_conf_t *common);

/* 1 iff the storage backend is remote (root://, http(s)://, s3://, tape://, ceph):
 * the local root_canon is a namespace anchor only and must not require W_OK. */
int brix_storage_backend_is_remote(const ngx_http_brix_shared_conf_t *common);

/*
 * brix_conf_set_store_slot() — directive setter for a tier store-URL directive
 * (brix_{,webdav_,s3_}{cache,stage}_store). Stores arg[1] (the store URL) into
 * the ngx_str_t at cmd->offset, and any trailing "credential=<n>" / "block_size=<n>"
 * tokens (args[2..]) into the ngx_array_t* whose field offset is carried in
 * cmd->post. The finaliser passes that array to brix_tier_parse_store. Use with
 * NGX_CONF_TAKE1234. Defined in config/runtime_server.c.
 */
char *brix_conf_set_store_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

#endif /* NGX_HTTP_BRIX_SHARED_CONF_H */
