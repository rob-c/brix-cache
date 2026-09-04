/* stream_common.c — ngx_stream_brix_common_module (phase-101 W3, variant A).
 *
 * The stream-plane analogue of ngx_http_brix_common_module: it owns the bare
 * storage/x509 directive names once, so the root and gridftp stream modules can
 * both adopt them instead of each registering its own (prefixed) copy.  See
 * stream_common.h for the design and docs/refactor/phase-101-config-surface-
 * unification.md (W3) for the migration.
 *
 * Stage 1 (this commit) is the inert scaffold: the module registers NO
 * directives, so behaviour is byte-identical to before — it only establishes
 * the module + the adopt entry point.  Stage 2 MOVEs the storage bare names
 * here from the root module and wires root/gridftp to adopt.
 */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include "core/config/stream_common.h"
#include "core/ngx_brix_module.h"   /* brix_vo_rules_append */
#include "fs/path/path.h"           /* brix_vo_rule_t */

/* Defined in http_common.c.  It operates purely on the plane-neutral preamble
 * type (ngx_http_brix_shared_conf_t), so a single definition serves both
 * planes — the static build links one binary and the dynamic build combines
 * every brix module into one .so (see ./config).  Forward-declared here rather
 * than including http_common.h so this stream TU need not pull in ngx_http.h. */
void brix_shared_adopt_unified(ngx_http_brix_shared_conf_t *dst,
                               const ngx_http_brix_shared_conf_t *src);

static void *brix_stream_common_create_srv_conf(ngx_conf_t *cf);
static char *brix_stream_common_merge_srv_conf(ngx_conf_t *cf,
                                               void *parent, void *child);

/* brix_require_vo owner setter: parse into THIS module's vo_rules (root and
 * gridftp deep-copy from here at merge). */
static char *
brix_stream_common_set_require_vo(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_brix_common_conf_t *c = conf;

    (void) cmd;
    return brix_vo_rules_append(cf, cf->args->elts, &c->common.vo_rules);
}

static ngx_command_t  brix_stream_common_commands[] = {
    /* phase-101 W3 (variant A): the storage bare names, MOVED here from the root
     * stream module (module.c / directives_tpc.h) so root:// and gridftp share
     * one owner.  Same stock slots + preamble fields as before — only the owning
     * module and the container struct change (offset into the common conf's
     * embedded preamble).  root and gridftp adopt these at merge. */
    { ngx_string("brix_export"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_common_conf_t, common.root),
      NULL },

    { ngx_string("brix_storage_backend"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_common_conf_t, common.storage_backend),
      NULL },

    /* phase-108 A.4: name-translation override (see the http twin). Validated at
     * nginx -t by brix_vfs_backend_config_n2n at merge. */
    { ngx_string("brix_n2n_scheme"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_common_conf_t, common.n2n_scheme),
      NULL },

    { ngx_string("brix_n2n_pool"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_common_conf_t, common.n2n_pool),
      NULL },

    { ngx_string("brix_n2n_prefix"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_common_conf_t, common.n2n_prefix),
      NULL },

    { ngx_string("brix_storage_credential"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_common_conf_t, common.storage_credential),
      NULL },

    { ngx_string("brix_allow_write"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_common_conf_t, common.allow_write),
      NULL },

    { ngx_string("brix_durable_commit"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_common_conf_t, common.durable_commit),
      NULL },

    { ngx_string("brix_verify_write"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_common_conf_t, common.verify_write),
      NULL },

    /* Shared x509 and VOMS trust material for every stream protocol. */
    { ngx_string("brix_certificate"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_common_conf_t, common.certificate),
      NULL },

    { ngx_string("brix_certificate_key"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_common_conf_t, common.certificate_key),
      NULL },

    { ngx_string("brix_trusted_ca"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_common_conf_t, common.trusted_ca),
      NULL },

    { ngx_string("brix_vomsdir"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_common_conf_t, common.vomsdir),
      NULL },

    { ngx_string("brix_voms_cert_dir"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_common_conf_t, common.voms_cert_dir),
      NULL },

    /* phase-101 W3 stage 3b: brix_require_vo VO-ACL, MOVED here from the root
     * stream module.  Parsed into this module's vo_rules; root and gridftp
     * deep-copy + finalize their own copy against their own export root. */
    { ngx_string("brix_require_vo"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE2,
      brix_stream_common_set_require_vo,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    ngx_null_command
};

static ngx_stream_module_t  brix_stream_common_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */
    NULL,                                  /* create main conf */
    NULL,                                  /* init main conf */
    brix_stream_common_create_srv_conf,    /* create srv conf */
    brix_stream_common_merge_srv_conf      /* merge srv conf */
};

ngx_module_t  ngx_stream_brix_common_module = {
    NGX_MODULE_V1,
    &brix_stream_common_module_ctx,
    brix_stream_common_commands,
    NGX_STREAM_MODULE,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NGX_MODULE_V1_PADDING
};

/*
 * create_srv_conf — allocate the common module's srv conf and seed its embedded
 * preamble with UNSET sentinels so parent->child inheritance can tell "not
 * configured" from an explicit value (mirror of the HTTP common module).
 */
static void *
brix_stream_common_create_srv_conf(ngx_conf_t *cf)
{
    ngx_stream_brix_common_conf_t  *c;

    c = ngx_pcalloc(cf->pool, sizeof(*c));
    if (c == NULL) {
        return NULL;
    }
    ngx_http_brix_shared_init(&c->common);
    return c;
}

/*
 * merge_srv_conf — inheritance-only fold (stream{} main -> server) that applies
 * NO defaults; each stream protocol picks its own defaults after adopting.
 * Because brix_stream_common_adopt() reads the server srv conf directly (values
 * set at parse time), correctness does not depend on whether this fold has run
 * before root/gridftp adopt.
 */
static char *
brix_stream_common_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_stream_brix_common_conf_t  *prev = parent;
    ngx_stream_brix_common_conf_t  *conf = child;

    (void) cf;
    brix_shared_adopt_unified(&conf->common, &prev->common);
    return NGX_CONF_OK;
}

void
brix_stream_common_adopt(ngx_conf_t *cf, brix_shared_conf_t *dst)
{
    ngx_stream_brix_common_conf_t  *scf;

    /* During merge_srv_conf nginx sets cf->ctx to the current server's stream
     * ctx (ngx_stream.c), so this returns THIS server's stream_common srv conf,
     * whose directive fields were populated at parse time.
     * brix_shared_adopt_unified only fills still-UNSET dst slots. */
    scf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_brix_common_module);
    if (scf != NULL) {
        brix_shared_adopt_unified(dst, &scf->common);
    }
}

ngx_int_t
brix_shared_clone_vo_rules(ngx_conf_t *cf, brix_shared_conf_t *conf)
{
    ngx_array_t                    *copy;
    brix_vo_rule_t                 *src, *r;
    ngx_uint_t                      i;

    if (conf->vo_rules == NULL || conf->vo_rules->nelts == 0) {
        return NGX_OK;
    }

    copy = ngx_array_create(cf->pool, conf->vo_rules->nelts,
                            sizeof(brix_vo_rule_t));
    if (copy == NULL) {
        return NGX_ERROR;
    }

    /* Shallow struct copy per rule: path/vo point into cf->pool (immutable), and
     * .resolved is empty on the common owner (it never finalizes), so each plane
     * finalizes this fresh array against its own root_canon. */
    src = conf->vo_rules->elts;
    for (i = 0; i < conf->vo_rules->nelts; i++) {
        r = ngx_array_push(copy);
        if (r == NULL) {
            return NGX_ERROR;
        }
        *r = src[i];
    }

    conf->vo_rules = copy;
    return NGX_OK;
}
