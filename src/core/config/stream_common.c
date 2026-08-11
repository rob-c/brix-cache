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
    return brix_vo_rules_append(cf, cf->args->elts, &c->vo_rules);
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

    { ngx_string("brix_verify_write"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_common_conf_t, common.verify_write),
      NULL },

    /* phase-101 W3 stage 3: the x509 GSI-trust strings, MOVED here from the root
     * stream module (directives_auth.h).  Stored in this module's own conf
     * fields (NOT the preamble); root and gridftp adopt them into their existing
     * per-protocol fields via brix_stream_common_adopt_gsi(), so the GSI SSL_CTX
     * / trust-store / VOMS readers stay byte-for-byte unchanged. */
    { ngx_string("brix_certificate"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_common_conf_t, certificate),
      NULL },

    { ngx_string("brix_certificate_key"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_common_conf_t, certificate_key),
      NULL },

    { ngx_string("brix_trusted_ca"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_common_conf_t, trusted_ca),
      NULL },

    { ngx_string("brix_vomsdir"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_common_conf_t, vomsdir),
      NULL },

    { ngx_string("brix_voms_cert_dir"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_common_conf_t, voms_cert_dir),
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
brix_stream_common_adopt(ngx_conf_t *cf, ngx_http_brix_shared_conf_t *dst)
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

/* Inherit-only string adopt: fill an unset (*dst empty) target from a set
 * source. NULL dst/empty source are no-ops. */
static void
adopt_str(ngx_str_t *dst, const ngx_str_t *src)
{
    if (dst != NULL && dst->len == 0 && src->len) {
        *dst = *src;
    }
}

void
brix_stream_common_adopt_gsi(ngx_conf_t *cf,
                             ngx_str_t *certificate,
                             ngx_str_t *certificate_key,
                             ngx_str_t *trusted_ca,
                             ngx_str_t *vomsdir,
                             ngx_str_t *voms_cert_dir)
{
    ngx_stream_brix_common_conf_t  *scf;

    scf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_brix_common_module);
    if (scf == NULL) {
        return;
    }

    adopt_str(certificate,     &scf->certificate);
    adopt_str(certificate_key, &scf->certificate_key);
    adopt_str(trusted_ca,      &scf->trusted_ca);
    adopt_str(vomsdir,         &scf->vomsdir);
    adopt_str(voms_cert_dir,   &scf->voms_cert_dir);
}

ngx_int_t
brix_stream_common_adopt_vo_rules(ngx_conf_t *cf, ngx_array_t **dst)
{
    ngx_stream_brix_common_conf_t  *scf;
    ngx_array_t                    *copy;
    brix_vo_rule_t                 *src, *r;
    ngx_uint_t                      i;

    scf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_brix_common_module);
    if (scf == NULL || scf->vo_rules == NULL || scf->vo_rules->nelts == 0) {
        return NGX_OK;                       /* nothing to adopt */
    }
    if (*dst != NULL && (*dst)->nelts > 0) {
        return NGX_OK;                       /* caller set its own — keep it */
    }

    copy = ngx_array_create(cf->pool, scf->vo_rules->nelts,
                            sizeof(brix_vo_rule_t));
    if (copy == NULL) {
        return NGX_ERROR;
    }

    /* Shallow struct copy per rule: path/vo point into cf->pool (immutable), and
     * .resolved is empty on the common owner (it never finalizes), so each plane
     * finalizes this fresh array against its own root_canon. */
    src = scf->vo_rules->elts;
    for (i = 0; i < scf->vo_rules->nelts; i++) {
        r = ngx_array_push(copy);
        if (r == NULL) {
            return NGX_ERROR;
        }
        *r = src[i];
    }

    *dst = copy;
    return NGX_OK;
}
