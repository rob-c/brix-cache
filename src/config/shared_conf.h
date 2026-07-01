/*
 * shared_conf.h — Shared config preamble struct for nginx-xrootd protocols.
 */

#ifndef _NGX_HTTP_XROOTD_SHARED_CONF_H
#define _NGX_HTTP_XROOTD_SHARED_CONF_H

#include <ngx_thread_pool.h>

#include "../pmark/pmark.h"

/*
 * ngx_http_xrootd_shared_conf_t — Common fields embedded at the top of every
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
    ngx_str_t           storage_credential; /* [xrootd_storage_credential <name>] —
                                             * the xrootd_credential block (§14) the
                                             * source backend authenticates with;
                                             * "" = anonymous. Today threads a bearer
                                             * token into sd_http. */
    void               *storage_instance;   /* resolved xrootd_sd_instance_t* for a
                                             * non-POSIX backend, built per worker at
                                             * init_process. Runtime only — never
                                             * merged. NULL ⇒ default POSIX path.    */
    /* ---- phase-64 composable tier grammar (additive over storage_backend) ----
     * Raw directive values parsed + registered at finalisation (the legacy cache
     * directives that share a name — xrootd_cache, _verify, _slice, _dirty_max_age
     * — are NOT re-used here; the new cache tier uses the non-colliding names and
     * sensible defaults until the P2 legacy-removal big-bang). */
    ngx_str_t           cache_store;        /* xrootd_cache_store URL ("" = none)   */
    ngx_array_t        *cache_store_args;   /* its credential=/block_size= tokens    */
    ngx_flag_t          stage_enable;       /* xrootd_stage on|off                  */
    ngx_str_t           stage_store;        /* xrootd_stage_store URL               */
    ngx_array_t        *stage_store_args;
    ngx_uint_t          stage_flush_async;  /* xrootd_stage_flush: 0 sync, 1 async   */
    off_t               cache_max_object;   /* xrootd_cache_max_object (0 = no cap)  */
    ngx_uint_t          cache_evict_at;     /* xrootd_cache_evict_at  (percent)      */
    ngx_uint_t          cache_evict_to;     /* xrootd_cache_evict_to  (percent)      */
    ngx_uint_t          cache_meta_mode;    /* xrootd_cache_meta  (0 auto..3 sidecar)*/
    ngx_uint_t          cache_batch_cinfo;  /* xrootd_cache_batch_cinfo (0 off/1 on/2 auto) */
    size_t              cache_index_cache;  /* xrootd_cache_index_cache (L1 entries) */
    size_t              cache_slice_size;   /* xrootd_cache_slice_size (0 = whole-file) */
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
    ngx_str_t           thread_pool_name;   /* async I/O thread pool name          */
    ngx_thread_pool_t  *thread_pool;        /* resolved pool handle (runtime only) */
    int                 rootfd;             /* O_PATH fd on root_canon for openat2
                                             * RESOLVE_BENEATH confinement; -1 until
                                             * opened per worker at init_process.
                                             * Runtime only — never merged.        */
    xrootd_pmark_conf_t pmark;              /* SciTags packet-marking config — see
                                             * src/pmark/pmark.h. Shared by every
                                             * protocol; init/merge below.          */
} ngx_http_xrootd_shared_conf_t;

/*
 * ngx_http_xrootd_shared_create_loc_conf() — Allocates and initializes a shared
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
ngx_http_xrootd_shared_init(ngx_http_xrootd_shared_conf_t *conf)
{
    conf->enable             = NGX_CONF_UNSET;
    conf->allow_write        = NGX_CONF_UNSET;
    conf->read_only          = NGX_CONF_UNSET;
    conf->thread_pool_name.len  = 0;
    conf->thread_pool_name.data = NULL;
    conf->thread_pool        = NULL;
    conf->storage_backend.len   = 0;
    conf->storage_backend.data  = NULL;
    conf->storage_credential.len  = 0;
    conf->storage_credential.data = NULL;
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
    xrootd_pmark_conf_init(&conf->pmark);
}

/*
 * ngx_http_xrootd_shared_merge() — Merges shared preamble fields from parent to
 * child using standard nginx merge macros. Called at the top of each protocol's
 * merge_loc_conf function before protocol-specific merge logic runs.
 *
 * WHY: Consolidates ~30 individual merge calls (10 per protocol) into one helper,
 * reducing boilerplate and ensuring shared fields always use consistent defaults
 * regardless of which protocol is active. Defaults: enable=0, allow_write=0,
 * root="", thread_pool_name="".
 */
static inline char *
ngx_http_xrootd_shared_merge(ngx_conf_t *cf,
                             ngx_http_xrootd_shared_conf_t *prev,
                             ngx_http_xrootd_shared_conf_t *conf)
{
    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_str_value(conf->root, prev->root, "");
    ngx_conf_merge_value(conf->allow_write, prev->allow_write, 0);
    ngx_conf_merge_value(conf->read_only, prev->read_only, 0);
    ngx_conf_merge_str_value(conf->thread_pool_name, prev->thread_pool_name, "");
    ngx_conf_merge_str_value(conf->storage_backend, prev->storage_backend, "");
    ngx_conf_merge_str_value(conf->storage_credential, prev->storage_credential,
                             "");
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

    return xrootd_pmark_conf_merge(cf, &prev->pmark, &conf->pmark);
}

/*
 * xrootd_shared_apply_read_only() — enforce the hard read-only switch. When
 * common->read_only is on, force allow_write off so EVERY existing write gate
 * (root:// xrootd_dispatch_require_write, the WebDAV/S3 write-method gate, the
 * write-open gate) rejects writes at the protocol edge - before the VFS, and
 * before token scope (allow_write is checked first), so a write-scoped token
 * cannot bypass it. Call from each protocol finaliser BEFORE the allow_write-
 * dependent validations (e.g. WebDAV's "writes need auth" check).
 */
static inline void
xrootd_shared_apply_read_only(ngx_http_xrootd_shared_conf_t *common,
    ngx_log_t *log)
{
    if (common->read_only != 1) {
        return;
    }
    if (common->allow_write == 1 && log != NULL) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "xrootd: read_only on - the export is read-only; all write "
            "operations are rejected at the protocol edge (overrides allow_write)");
    }
    common->allow_write = 0;
}

/*
 * xrootd_tier_register_stores() — register the export's phase-64 composable
 * cache/stage tiers from the common preamble onto the backend registry (which
 * composes the sd_cache / sd_stage decorators per worker). Shared by all three
 * protocol finalisers (§4.4): each calls it with its &conf->common after the
 * storage backend + root_canon are set. Returns NGX_OK, or NGX_ERROR after an
 * [emerg] for an operator error (unknown scheme, bad path, stage-without-store).
 * Defined in config/runtime_server.c.
 */
ngx_int_t xrootd_tier_register_stores(ngx_conf_t *cf,
    ngx_http_xrootd_shared_conf_t *common);

/* Rewrite a "posix:<path>" / "pblock://<path>" storage_backend into the export root
 * (common->root) — the composable replacement for xrootd_root. No-op otherwise.
 * Call BEFORE the export-root prep. Defined in config/runtime_server.c. */
void xrootd_storage_backend_posix_root(ngx_http_xrootd_shared_conf_t *common);

/* 1 iff the storage backend is remote (root://, http(s)://, s3://, tape://, ceph):
 * the local root_canon is a namespace anchor only and must not require W_OK. */
int xrootd_storage_backend_is_remote(const ngx_http_xrootd_shared_conf_t *common);

/*
 * xrootd_conf_set_store_slot() — directive setter for a tier store-URL directive
 * (xrootd_{,webdav_,s3_}{cache,stage}_store). Stores arg[1] (the store URL) into
 * the ngx_str_t at cmd->offset, and any trailing "credential=<n>" / "block_size=<n>"
 * tokens (args[2..]) into the ngx_array_t* whose field offset is carried in
 * cmd->post. The finaliser passes that array to xrootd_tier_parse_store. Use with
 * NGX_CONF_TAKE1234. Defined in config/runtime_server.c.
 */
char *xrootd_conf_set_store_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

#endif /* _NGX_HTTP_XROOTD_SHARED_CONF_H */
