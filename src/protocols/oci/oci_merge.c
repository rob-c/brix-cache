/*
 * oci_merge.c — the OCI location merge: refusals first, then the export build.
 *
 * WHAT: ngx_http_brix_oci_merge_loc_conf() and its four helpers — scalar
 *       inheritance, the §0.6.3 config-load refusal matrix, the upstream
 *       descriptor built from `brix_oci_mirror`, and the export/backend/tier
 *       build the enabled surfaces share.
 * WHY:  a registry mirror is a cache whose upstream is named by ONE directive,
 *       so almost everything this file does is turning that one URL into the
 *       shapes the existing machinery already understands: a storage backend
 *       string for sd_http, an export root for the confinement fd, a verify
 *       mode for the fill. The part that is genuinely new is the refusal
 *       matrix: every combination below is one an operator can write and would
 *       otherwise get a silently WRONG deployment from (a "mirror" that
 *       accepts pushes, a push registry open to the world, a credential file
 *       every local user can read). Those are nginx -t failures on purpose.
 * HOW:  the order is load-bearing and matches the cvmfs merge it is modelled
 *       on: adopt the unified directives → merge our scalars → pre-seed the
 *       verify default while the sentinel is still readable → shared merge →
 *       refuse → build. A location with neither surface enabled returns after
 *       the shared merge having allocated nothing (J.2).
 */

#include "oci.h"
#include "oci_module_internal.h"

#include "auth/token/issuer_registry.h"    /* registry push authn (D4)         */
#include "core/compat/alloc_guard.h"
#include "core/config/http_common.h"       /* unified brix_* directive adoption */
#include "fs/cache/verify.h"
#include "oci/url.h"
#include "protocols/shared/merge_export.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

/* The token endpoint's credential is a secret in a file, and this is the
 * ONLY mode that keeps it one: 0600, or 0400. Anything a second local
 * account can read is refused rather than warned about — the same stance the
 * tree takes for every other key file. */
#define OCI_PWFILE_MODE_MASK  (S_IRWXG | S_IRWXO)

/* One line of a password file. Longer is a paste accident, not a password. */
#define OCI_PWFILE_LINE_MAX   256


/* Inherit every OCI scalar and pre-seed the verify default.
 *
 * The verify pre-seed must land BEFORE the shared merge: the sentinel is what
 * distinguishes "the operator said nothing" from "the operator said off", and
 * the shared merge collapses the former to the latter. An OCI cache key names
 * a sha256 digest for every immutable object, so the self-verifying mode is
 * the only default that makes a mirror trustworthy by construction. */
static char *
oci_merge_scalars(ngx_conf_t *cf, ngx_http_brix_oci_loc_conf_t *prev,
    ngx_http_brix_oci_loc_conf_t *conf)
{
    brix_http_common_adopt(cf, &conf->common);

    ngx_conf_merge_value(conf->mirror, prev->mirror, 0);
    ngx_conf_merge_str_value(conf->mirror_url, prev->mirror_url, "");
    ngx_conf_merge_str_value(conf->mirror_user, prev->mirror_user, "");
    ngx_conf_merge_str_value(conf->mirror_pwfile, prev->mirror_pwfile, "");
    ngx_conf_merge_str_value(conf->upstream_ns, prev->upstream_ns, "");
    ngx_conf_merge_str_value(conf->token_zone_name, prev->token_zone_name,
                             "oci_tokens");
    ngx_conf_merge_value(conf->token_zone_set, prev->token_zone_set, 0);
    ngx_conf_merge_sec_value(conf->manifest_ttl, prev->manifest_ttl, 60);
    ngx_conf_merge_value(conf->insecure, prev->insecure, 0);

    ngx_conf_merge_value(conf->registry, prev->registry, 0);
    ngx_conf_merge_value(conf->registry_anon, prev->registry_anon, 0);
    ngx_conf_merge_str_value(conf->registry_root, prev->registry_root, "");
    ngx_conf_merge_str_value(conf->token_issuers, prev->token_issuers, "");
    ngx_conf_merge_size_value(conf->max_blob, prev->max_blob, 0);
    ngx_conf_merge_sec_value(conf->upload_grace, prev->upload_grace,
                             24 * 60 * 60);
    ngx_conf_merge_msec_value(conf->gc_interval, prev->gc_interval, 0);
    ngx_conf_merge_sec_value(conf->gc_grace, prev->gc_grace,
                             BRIX_OCI_GC_GRACE_DEFAULT);
    if (conf->issuers == NULL) {
        conf->issuers = prev->issuers;
    }
    if (conf->auth_realms == NULL) {
        conf->auth_realms = prev->auth_realms;
    }
    if (conf->up == NULL) {
        conf->up = prev->up;
    }

    if ((conf->mirror || conf->registry)
        && conf->common.cache_verify_mode == NGX_CONF_UNSET_UINT)
    {
        conf->common.cache_verify_mode = BRIX_CACHE_VERIFY_OCI_DIGEST;
    }

    return ngx_http_brix_shared_merge(cf, &prev->common, &conf->common, "");
}


/* The §0.6.3 refusal matrix for the mirror surface. */
static char *
oci_reject_mirror(ngx_conf_t *cf, ngx_http_brix_oci_loc_conf_t *conf,
    const brix_oci_url_t *url)
{
    if (conf->common.allow_write == 1) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_allow_write on: an OCI pull-through mirror is read-only "
            "by construction; use brix_oci_registry for a push surface");
        return NGX_CONF_ERROR;
    }

    if (conf->common.stage_store.len > 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_stage_store: an OCI pull-through mirror never stages "
            "writes; remove it from this block");
        return NGX_CONF_ERROR;
    }

    if (!url->tls && !conf->insecure) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_oci_mirror \"%V\": a cleartext upstream would hand every "
            "pulled token to the network; use https, or brix_oci_mirror_"
            "insecure on for a test fixture", &conf->mirror_url);
        return NGX_CONF_ERROR;
    }

    if ((conf->mirror_user.len == 0) != (conf->mirror_pwfile.len == 0)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_oci_mirror_auth needs both a user and a password file");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


/* Does this server prove its clients at the TLS layer? Read straight off the
 * ssl module's server conf rather than inferred: `ssl_verify_client on` (and
 * `optional`, whose result the request path checks) means the peer carries a
 * certificate this server's CA chain accepted, which is an authenticated
 * context by any definition worth the name. */
static int
oci_ssl_verifies_client(ngx_conf_t *cf)
{
#if (NGX_HTTP_SSL)
    ngx_http_ssl_srv_conf_t *sslcf =
        ngx_http_conf_get_module_srv_conf(cf, ngx_http_ssl_module);

    return (sslcf != NULL && sslcf->verify != 0);
#else
    (void) cf;
    return 0;
#endif
}


/* The §0.6.3 refusal matrix for the surfaces as a pair, plus the registry's
 * one structural demand: a push endpoint must have said, in the config, who
 * is allowed to push. */
static char *
oci_reject_surfaces(ngx_conf_t *cf, ngx_http_brix_oci_loc_conf_t *conf)
{
    if (conf->mirror && conf->registry) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_oci_mirror and brix_oci_registry are different locations: "
            "one caches somebody else's registry, the other IS a registry");
        return NGX_CONF_ERROR;
    }

    /* A mirror's objects are cache entries: the cache tier is what decides
     * when they go, and a sweep that unlinked them behind its back would be
     * deleting another subsystem's bookkeeping. Only the mirror is refused
     * here and not every non-registry block: the directive inherits, so an
     * operator who sets it once at server level and enables the registry in
     * one location underneath is writing a correct config, and the outer
     * block's copy is simply inert. */
    if (conf->gc_interval > 0 && conf->mirror) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_oci_gc_interval: there is nothing for a registry sweep to "
            "collect on a pull-through mirror; the cache tier owns eviction "
            "there");
        return NGX_CONF_ERROR;
    }

    if (!conf->registry) {
        return NGX_CONF_OK;
    }

    /* A pass costs a full walk of the store. Below a second apart they
     * overlap into a busy loop over the disk rather than maintenance, and the
     * timer would spend the worker on nothing else. */
    if (conf->gc_interval > 0 && conf->gc_interval < BRIX_OCI_GC_MIN_INTERVAL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_oci_gc_interval: %M ms is a busy loop over the store, not "
            "maintenance; use %M ms or more", conf->gc_interval,
            (ngx_msec_t) BRIX_OCI_GC_MIN_INTERVAL);
        return NGX_CONF_ERROR;
    }

    /* An unauthenticated push registry is a supply-chain hole, so it can only
     * be reached through a directive that says so in as many words. TLS client
     * verification counts as the authenticated context: the peer is already
     * proven at the transport before a byte of the API is parsed. */
    if (conf->token_issuers.len == 0 && !conf->registry_anon
        && !oci_ssl_verifies_client(cf))
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_oci_registry on without an authenticated context: add "
            "brix_oci_token_issuers <scitokens.cfg>, enable ssl_verify_client, "
            "or state the intent with brix_oci_registry_allow_anonymous on");
        return NGX_CONF_ERROR;
    }

    /* One issuer table per configured file, built at load so a malformed
     * scitokens.cfg fails nginx -t instead of every push. */
    if (conf->token_issuers.len > 0 && conf->issuers == NULL) {
        if (brix_token_registry_build(cf,
                (const char *) conf->token_issuers.data,
                BRIX_AUTHZ_CAPABILITY, &conf->issuers) != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


/* Read the token-endpoint password and compose the "user:pass" pair the D1
 * dance base64s. The file is read ONCE, here, at config load: a per-request
 * read would put a secret on the hot path and a reload is the operator's
 * signal that the credential changed. */
static char *
oci_read_pwfile(ngx_conf_t *cf, ngx_http_brix_oci_loc_conf_t *conf,
    brix_oci_upstream_t *up)
{
    char         line[OCI_PWFILE_LINE_MAX];
    char        *path = (char *) conf->mirror_pwfile.data;
    struct stat  st;
    FILE        *f;
    size_t       n;

    f = fopen(path, "re");
    if (f == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
            "brix_oci_mirror_auth: cannot open password file \"%V\"",
            &conf->mirror_pwfile);
        return NGX_CONF_ERROR;
    }

    if (fstat(fileno(f), &st) != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
            "brix_oci_mirror_auth: cannot stat \"%V\"", &conf->mirror_pwfile);
        (void) fclose(f);
        return NGX_CONF_ERROR;
    }

    if (st.st_mode & OCI_PWFILE_MODE_MASK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_oci_mirror_auth: password file \"%V\" is mode %04o - "
            "group/world access must be removed (chmod 0600)",
            &conf->mirror_pwfile, (unsigned) (st.st_mode & 07777));
        (void) fclose(f);
        return NGX_CONF_ERROR;
    }

    if (fgets(line, sizeof(line), f) == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_oci_mirror_auth: password file \"%V\" is empty",
            &conf->mirror_pwfile);
        (void) fclose(f);
        return NGX_CONF_ERROR;
    }
    (void) fclose(f);

    n = strcspn(line, "\r\n");
    line[n] = '\0';
    if (n == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_oci_mirror_auth: password file \"%V\" first line is blank",
            &conf->mirror_pwfile);
        return NGX_CONF_ERROR;
    }

    if ((size_t) snprintf(up->basic, sizeof(up->basic), "%.*s:%s",
                          (int) conf->mirror_user.len, conf->mirror_user.data,
                          line)
        >= sizeof(up->basic))
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_oci_mirror_auth: user and password exceed %uz bytes",
            sizeof(up->basic));
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


/* Turn `brix_oci_mirror <base-url>` into the upstream descriptor the fill
 * thread reads and into the storage-backend string sd_http is configured
 * from. The two must agree byte-for-byte: the canonical cache key is an
 * absolute "/v2/..." path, so the backend base carries the scheme, authority
 * and any path prefix, and nothing else. */
static char *
oci_build_upstream(ngx_conf_t *cf, ngx_http_brix_oci_loc_conf_t *conf)
{
    brix_oci_upstream_t  *up;
    brix_oci_url_t        url;
    u_char               *backend;
    size_t                len;

    if (conf->mirror_url.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_oci_mirror requires an upstream base URL");
        return NGX_CONF_ERROR;
    }

    if (brix_oci_url_parse((const char *) conf->mirror_url.data,
                           conf->mirror_url.len, &url) != 0)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_oci_mirror \"%V\" is not an absolute http(s) URL with a "
            "plain host and path", &conf->mirror_url);
        return NGX_CONF_ERROR;
    }

    if (oci_reject_mirror(cf, conf, &url) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }

    BRIX_PCALLOC_OR_RETURN(up, cf->pool, sizeof(*up), NGX_CONF_ERROR);

    (void) ngx_cpystrn((u_char *) up->host, (u_char *) url.host,
                       sizeof(up->host));
    (void) ngx_cpystrn((u_char *) up->base_path, (u_char *) url.path,
                       sizeof(up->base_path));
    up->port     = url.port;
    up->tls      = url.tls;
    up->insecure = conf->insecure;
    if (conf->auth_realms != NULL) {
        /* Copied by value: the fill thread reads the allowlist on every
         * dance, and it reads it off the upstream it already holds. */
        up->realms = *conf->auth_realms;
    }

    len = (size_t) snprintf(up->base_url, sizeof(up->base_url),
                            "%s://%s%s%s:%d%s",
                            url.tls ? "https" : "http",
                            strchr(url.host, ':') ? "[" : "",
                            url.host,
                            strchr(url.host, ':') ? "]" : "",
                            url.port, url.path);
    if (len >= sizeof(up->base_url)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_oci_mirror \"%V\" is too long", &conf->mirror_url);
        return NGX_CONF_ERROR;
    }

    if (conf->mirror_pwfile.len > 0
        && oci_read_pwfile(cf, conf, up) != NGX_CONF_OK)
    {
        return NGX_CONF_ERROR;
    }

    /* The composable backend is the same http(s) driver a CVMFS Stratum-1
     * rides; the mirror's contribution is the base it points at. An explicit
     * brix_storage_backend in the same block is a second answer to a question
     * that already has one. */
    if (conf->common.storage_backend.len > 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_storage_backend and brix_oci_mirror both name the upstream "
            "for this location; brix_oci_mirror is the OCI spelling - "
            "configure exactly one");
        return NGX_CONF_ERROR;
    }

    backend = ngx_pnalloc(cf->pool, len + 1);
    if (backend == NULL) {
        return NGX_CONF_ERROR;
    }
    ngx_memcpy(backend, up->base_url, len + 1);
    conf->common.storage_backend.data = backend;
    conf->common.storage_backend.len  = len;

    conf->up = up;
    return NGX_CONF_OK;
}


/* Anchor the namespace, open the confinement fd, register the backend and
 * compose the cache tiers — the build order every brix HTTP protocol shares.
 * The mirror is a pure cache node: no local export tree, so the namespace
 * anchors at "/" and every object lives in the cache store. */
static char *
oci_merge_export(ngx_conf_t *cf, ngx_http_brix_oci_loc_conf_t *conf)
{
    if (conf->mirror) {
        conf->common.allow_write = 0;
    }

    brix_storage_backend_posix_root(&conf->common);

    if (conf->registry && conf->registry_root.len > 0) {
        conf->common.root = conf->registry_root;
    }
    if (brix_http_merge_export_anchor(cf, &conf->common,
                                      conf->mirror ? "brix_oci_mirror"
                                                   : "brix_oci_registry",
                                      conf->registry ? 1 : 0) != NGX_CONF_OK)
    {
        return NGX_CONF_ERROR;
    }

    /* MANIFEST-class entries get the tag freshness window stamped; every
     * digest-addressed object is immutable and ignores it (§D2.2). */
    conf->common.cache_manifest_ttl = conf->manifest_ttl;

    if (brix_tier_register_stores(cf, &conf->common) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


/* Resolve — or, for the documented `oci_tokens 1m` default, create — the SHM
 * zone the D1 dance caches bearers in. A mirror is expected to work from the
 * six directives §0.6.4 shows, so the absence of an explicit
 * brix_oci_token_zone is a default rather than an error; an explicit NAME that
 * was never declared still fails nginx -t, because that is a typo. */
static char *
oci_bind_token_zone(ngx_conf_t *cf, ngx_http_brix_oci_loc_conf_t *conf)
{
    brix_kv_t *kv = brix_kv_find(&conf->token_zone_name);

    if (kv != NULL) {
        conf->up->tokens = kv;
        return NGX_CONF_OK;
    }

    if (conf->token_zone_set) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_oci_mirror: token zone \"%V\" is not declared - add "
            "brix_oci_token_zone %V <size> to the http block",
            &conf->token_zone_name, &conf->token_zone_name);
        return NGX_CONF_ERROR;
    }

    BRIX_PCALLOC_OR_RETURN(kv, cf->pool, sizeof(*kv), NGX_CONF_ERROR);

    if (brix_kv_configure(cf, kv, &conf->token_zone_name,
                          BRIX_OCI_TOKEN_ZONE_DEFAULT_SIZE,
                          BRIX_OCI_TOKEN_KEYLEN, BRIX_OCI_TOKEN_MAX,
                          &ngx_http_brix_oci_module) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    conf->up->tokens = kv;
    return NGX_CONF_OK;
}


char *
ngx_http_brix_oci_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_brix_oci_loc_conf_t *prev = parent;
    ngx_http_brix_oci_loc_conf_t *conf = child;

    if (oci_merge_scalars(cf, prev, conf) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }

    if (!conf->mirror && !conf->registry) {
        return NGX_CONF_OK;                 /* surface off: nothing is built */
    }

    if (oci_reject_surfaces(cf, conf) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }

    if (conf->mirror && oci_build_upstream(cf, conf) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }

    if (oci_merge_export(cf, conf) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }

    /* Registered from the CANONICAL root, which is the only spelling the
     * store itself is built under — the raw directive string would hand the
     * sweep back the symlinks brix_prepare_export_root just removed. */
    if (conf->registry) {
        brix_oci_gc_register((const char *) conf->common.root_canon,
                             conf->gc_interval, conf->gc_grace);
    }

    if (conf->mirror && oci_bind_token_zone(cf, conf) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
