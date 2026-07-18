/*
 * module.c — nginx directive table, config lifecycle, and HTTP module context for the S3 endpoint.
 *
 * WHAT: Three responsibilities in one file:
 *   1. Config lifecycle (ngx_http_s3_create_loc_conf / ngx_http_s3_merge_loc_conf):
 *      Allocates ngx_http_s3_loc_conf_t with NGX_CONF_UNSET defaults, merges main→srv→loc
 *      config using ngx_conf_merge_value/ngx_conf_merge_str_value macros, and when enable=1
 *      calls brix_prepare_export_root() to canonicalize the root path into conf->common.root_canon.
 *   2. Post-config handler install (ngx_http_s3_set):
 *      The content of the "brix_s3" directive — parses a flag, then installs
 *      ngx_http_s3_handler as the location's request handler via clcf->handler.
 *   3. Directive table (ngx_http_s3_commands[] + ngx_module_t):
 *      Declares all S3 config directives with their type, parsing function, conf offset,
 *      and nginx module registration struct.
 *
 * WHY: The S3 endpoint shares the same nginx location-config model as WebDAV but has its own
 *      set of directives (brix_s3, brix_s3_root, brix_s3_bucket, etc.) and a distinct
 *      loc_conf structure. This file owns the full config lifecycle — allocation, merge, root
 *      canonicalization, and handler installation — so that every location block with
 *      "brix_s3 on" gets properly initialized before accepting traffic. The brix_prepare_export_root()
 *      call ensures conf->common.root_canon is valid (no path escapes) at config-time, preventing runtime failures.
 *
 * HOW:
 *   ngx_http_s3_create_loc_conf(): ngx_pcalloc(sizeof(ngx_http_s3_loc_conf_t)) — sets enable,
 *     allow_write, allow_unsigned_session_token, max_keys to NGX_CONF_UNSET (merge macros detect unset).
 *   ngx_http_s3_merge_loc_conf(): parent→child merge using ngx_conf_merge_value for flags/ints,
 *     ngx_conf_merge_str_value for strings. Defaults: enable=0, allow_write=0, allow_unsigned_session_token=0,
 *     max_keys=1000, root="", bucket="", access_key="", secret_key="", region="us-east-1". When conf->common.enable is true,
 *     calls brix_prepare_export_root() with directive_name="brix_export", allow_write from config,
 *     required=0 (root not mandatory), canon_size=sizeof(conf->common.root_canon). Returns NGX_CONF_ERROR on failure.
 *   ngx_http_s3_set(): parses the "brix_s3" flag via ngx_conf_set_flag_slot(), then retrieves the
 *     core location conf and sets clcf->handler = ngx_http_s3_handler — this is what routes all S3 requests.
 *   Directive table: 8 directives (brix_s3, brix_s3_root, brix_s3_bucket, brix_s3_access_key,
 *     brix_s3_secret_key, brix_s3_region, brix_s3_allow_write, brix_s3_allow_unsigned_session_token,
 *     brix_s3_max_keys) — each with NGX_HTTP_LOC_CONF type, appropriate parsing function (flag_slot, str_slot,
 *     num_slot), and offsetof() into ngx_http_s3_loc_conf_t. Ends with ngx_null_command.
 */

#include "s3.h"
#include "auth/authz/acc/acc.h"            /* XrdAcc engine directives + enum tables */
#include "auth/token/token.h"              /* brix_jwks_load, brix_jwks_register_cleanup */
#include "core/config/root_prepare.h"
#include "core/config/http_rootfd.h"
#include "core/compat/tmp_path.h"          /* SP4 orphan direct-write temp reaper */
#include "core/config/credential_block.h"   /* §14 brix_credential lookup/bearer */
#include "core/config/http_common.h"        /* unified brix_* directive adoption */
#include "core/config/export_guard.h"       /* brix_assert_dir_outside_export (hard guard) */
#include "fs/vfs/vfs_backend_registry.h"   /* per-export backend registration */
#include "core/compat/alloc_guard.h"
#include "module_internal.h"               /* s3_merge_* helpers (module_merge.c) */

static ngx_int_t ngx_http_s3_postconfiguration(ngx_conf_t *cf);

/*
 * Config lifecycle
 * */

static void *
ngx_http_s3_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_s3_loc_conf_t *c;

    BRIX_PCALLOC_OR_RETURN(c, cf->pool, sizeof(*c), NULL);

    ngx_http_brix_shared_init(&c->common);
    c->allow_unsigned_session_token = NGX_CONF_UNSET;
    c->verify_chunk_signatures      = NGX_CONF_UNSET;
    c->list_cache                   = NGX_CONF_UNSET;
    c->list_cache_ttl               = NGX_CONF_UNSET_MSEC;
    c->max_keys    = NGX_CONF_UNSET;
    c->mpu_max_age = NGX_CONF_UNSET;
    c->zip_access  = NGX_CONF_UNSET;
    c->zip_cd_max_bytes = NGX_CONF_UNSET_SIZE;
    brix_acc_http_init_conf(&c->acc);   /* XrdAcc engine (off by default) */

    /* WLCG bearer-token auth — off by default; str fields zeroed by pcalloc. */
    c->token_enable     = NGX_CONF_UNSET;
    c->token_clock_skew = NGX_CONF_UNSET;

    return c;
}

/*
 * ngx_http_s3_merge_loc_conf() — S3 location merge orchestrator.
 *
 * WHAT: Runs the per-concern merge helpers in their required order: preamble
 *   (adopt + shared common merge) → scalars → token (merge + JWKS load) →
 *   export (enabled-only export/backend/tier build).
 *
 * WHY: The concerns have a strict order — the adopt/shared merge must seed
 *   conf->common before the protocol scalar/token merges read it, and the
 *   export build depends on every earlier merge being settled. Expressing the
 *   orchestrator as a flat call sequence keeps that ordering visible in one
 *   place while each concern stays under the complexity gate. Merge order +
 *   defaults are byte-frozen (nginx -t).
 *
 * HOW: Each fallible step returns NGX_CONF_OK/ERROR; the orchestrator
 *   early-returns NGX_CONF_ERROR on the first failure. The scalar merge cannot
 *   fail. The export step runs only for S3-enabled locations.
 */
static char *
ngx_http_s3_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_s3_loc_conf_t *prev = parent;
    ngx_http_s3_loc_conf_t *conf = child;

    if (s3_merge_preamble(cf, prev, conf) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }
    s3_merge_scalars(prev, conf);
    if (s3_merge_token(cf, prev, conf) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }
    if (conf->common.enable) {
        if (s3_merge_export(cf, conf) != NGX_CONF_OK) {
            return NGX_CONF_ERROR;
        }
        /* E-1: an S3 export with neither a SigV4 access key nor WLCG token auth
         * accepts every request unauthenticated. Warn always; refuse strict. */
        if (!conf->token_enable && conf->access_key.len == 0
            && brix_shared_security_gate(cf, conf->common.strict_security,
                   "S3 export accepts unauthenticated requests "
                   "(no brix_s3_access_key and brix_s3_token off)",
                   "brix_s3_access_key/brix_s3_secret_key or brix_s3_token")
               != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}

/*
 * Post-config: install content handler
 * */

static ngx_int_t
ngx_http_s3_postconfiguration(ngx_conf_t *cf)
{
    ngx_http_core_main_conf_t  *cmcf;
    ngx_http_core_srv_conf_t  **cscfp;
    ngx_http_s3_loc_conf_t     *scf;
    static ngx_str_t            default_pool_name = ngx_string("default");
    ngx_str_t                  *pool_name;
    ngx_uint_t                  s;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    cscfp = cmcf->servers.elts;

    for (s = 0; s < cmcf->servers.nelts; s++) {
        ngx_http_conf_ctx_t *ctx = cscfp[s]->ctx;

        scf = ctx->loc_conf[ngx_http_brix_s3_module.ctx_index];
        if (scf == NULL || !scf->common.enable) {
            continue;
        }

        pool_name = (scf->common.thread_pool_name.len > 0)
                    ? &scf->common.thread_pool_name
                    : &default_pool_name;

        scf->common.thread_pool = ngx_thread_pool_get(cf->cycle, pool_name);
        if (scf->common.thread_pool == NULL) {
            ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                "brix_s3: thread pool \"%V\" not found - "
                "async PUT I/O disabled (add a thread_pool directive)",
                pool_name);
        }
        /* kTLS for S3 https servers is enabled centrally in the WebDAV
         * postconfiguration server loop (every server carries a server-level
         * webdav loc-conf whose common.ktls flag drives SSL_OP_ENABLE_KTLS). */
    }

    return NGX_OK;
}

static ngx_http_module_t ngx_http_s3_module_ctx = {
    NULL,                          /* preconfiguration        */
    ngx_http_s3_postconfiguration, /* postconfiguration       */
    NULL,                          /* create main conf        */
    NULL,                          /* init main conf          */
    NULL,                          /* create server conf      */
    NULL,                          /* merge server conf       */
    ngx_http_s3_create_loc_conf,   /* create location conf    */
    ngx_http_s3_merge_loc_conf,    /* merge location conf     */
};

static char *
ngx_http_s3_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;
    char                      *rv;

    rv = ngx_conf_set_flag_slot(cf, cmd, conf);
    if (rv != NGX_CONF_OK) {
        return rv;
    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_s3_handler;

    return NGX_CONF_OK;
}

/*
 * Directives
 * */

static ngx_command_t ngx_http_s3_commands[] = {

    { ngx_string("brix_s3"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_http_s3_set,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, common.enable),
      NULL },

    /* The XrdAcc directives (brix_authdb / _format / _audit) are registered by
     * the WebDAV module with shared setters that populate the S3 loc-conf too,
     * so they are intentionally NOT redeclared here (a duplicate would conflict). */

    /* Export root, storage backend/credential, outbound compression and the
     * composable tier grammar (brix_export, brix_storage_backend,
     * brix_storage_credential, brix_compress, brix_cache_*, brix_stage*) are
     * owned by the shared ngx_http_brix_common_module; this protocol adopts
     * them via brix_http_common_adopt(). */

    { ngx_string("brix_s3_bucket"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, bucket),
      NULL },

    { ngx_string("brix_s3_cache_root"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, cache_root),
      NULL },

    { ngx_string("brix_s3_access_key"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, access_key),
      NULL },

    { ngx_string("brix_s3_secret_key"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, secret_key),
      NULL },

    { ngx_string("brix_s3_region"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, region),
      NULL },

    /* brix_allow_write / brix_read_only are owned by ngx_http_brix_common_module. */

    { ngx_string("brix_s3_allow_unsigned_session_token"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, allow_unsigned_session_token),
      NULL },

    { ngx_string("brix_s3_verify_chunk_signatures"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, verify_chunk_signatures),
      NULL },

    { ngx_string("brix_s3_list_cache"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, list_cache),
      NULL },

    /* ZIP member access over S3 GetObject (phase-57 W2). Opt-in, off default. */
    { ngx_string("brix_s3_zip_access"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, zip_access),
      NULL },

    { ngx_string("brix_s3_zip_cd_max_bytes"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, zip_cd_max_bytes),
      NULL },

    { ngx_string("brix_s3_list_cache_ttl"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, list_cache_ttl),
      NULL },

    { ngx_string("brix_s3_max_keys"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, max_keys),
      NULL },

    /* Phase 39 (WS8): incomplete-multipart reaper idle age in seconds (0=off). */
    { ngx_string("brix_s3_mpu_max_age"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, mpu_max_age),
      NULL },

    /* brix_thread_pool is owned by ngx_http_brix_common_module. */

    /* SciTags packet marking (src/pmark/) — see phase-34 doc */    { ngx_string("brix_pmark"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, common.pmark.enable), NULL },
    { ngx_string("brix_pmark_firefly"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, common.pmark.firefly), NULL },
    { ngx_string("brix_pmark_flowlabel"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, common.pmark.flowlabel), NULL },
    { ngx_string("brix_pmark_scitag_cgi"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, common.pmark.scitag_cgi), NULL },
    { ngx_string("brix_pmark_firefly_origin"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, common.pmark.firefly_origin), NULL },
    { ngx_string("brix_pmark_http_plain"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, common.pmark.http_plain), NULL },
    { ngx_string("brix_pmark_echo"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, common.pmark.echo), NULL },
    { ngx_string("brix_pmark_appname"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, common.pmark.appname), NULL },
    { ngx_string("brix_pmark_defsfile"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, common.pmark.defsfile), NULL },
    { ngx_string("brix_pmark_domain"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, brix_pmark_set_domain,
      NGX_HTTP_LOC_CONF_OFFSET, 0, NULL },
    { ngx_string("brix_pmark_firefly_dest"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, brix_pmark_set_firefly_dest,
      NGX_HTTP_LOC_CONF_OFFSET, 0, NULL },
    { ngx_string("brix_pmark_map_experiment"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE23, brix_pmark_set_map_experiment,
      NGX_HTTP_LOC_CONF_OFFSET, 0, NULL },
    { ngx_string("brix_pmark_map_activity"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE3 | NGX_CONF_TAKE4,
      brix_pmark_set_map_activity,
      NGX_HTTP_LOC_CONF_OFFSET, 0, NULL },

    /* WLCG bearer-token authentication (off by default).
     * brix_s3_token on — enable enforcing JWT mode; requires brix_s3_token_jwks.
     * brix_s3_token_jwks — path to a JWKS JSON file with RSA/EC public keys.
     * brix_s3_token_issuer — expected "iss" claim value.
     * brix_s3_token_audience — expected "aud" claim value.
     * brix_s3_token_clock_skew — grace period in seconds for exp/nbf (default 60). */
    { ngx_string("brix_s3_token"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, token_enable),
      NULL },

    { ngx_string("brix_s3_token_jwks"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, token_jwks),
      NULL },

    { ngx_string("brix_s3_token_issuer"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, token_issuer),
      NULL },

    { ngx_string("brix_s3_token_audience"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, token_audience),
      NULL },

    { ngx_string("brix_s3_token_clock_skew"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, token_clock_skew),
      NULL },

    ngx_null_command
};

ngx_module_t ngx_http_brix_s3_module = {
    NGX_MODULE_V1,
    &ngx_http_s3_module_ctx,    /* module context     */
    ngx_http_s3_commands,       /* module directives  */
    NGX_HTTP_MODULE,            /* module type        */
    NULL,                       /* init master        */
    NULL,                       /* init module        */
    NULL,                       /* init process       */
    NULL,                       /* init thread        */
    NULL,                       /* exit thread        */
    NULL,                       /* exit process       */
    NULL,                       /* exit master        */
    NGX_MODULE_V1_PADDING
};
