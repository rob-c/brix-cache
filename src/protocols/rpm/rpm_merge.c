/*
 * rpm_merge.c — the RPM location merge: refusals first, then the export build.
 *
 * WHAT: ngx_http_brix_rpm_merge_loc_conf() and its three helpers — scalar
 *       inheritance with the verify pre-seed, the config-load refusal matrix,
 *       and the export/backend/tier build.
 * WHY:  the whole mirror is named by ONE directive, so almost everything here
 *       is turning that one URL into shapes the existing machinery already
 *       understands: a storage-backend string for sd_http, an export root for
 *       the confinement fd, a verify mode for the fill, a manifest TTL for the
 *       mutable half of the repository. What is genuinely new is the refusal
 *       matrix. Each entry below is a config an operator can write and would
 *       otherwise get a silently WRONG deployment from — a "mirror" that
 *       accepts uploads, a cleartext upstream, two directives naming the same
 *       upstream differently, or a verify mode that quietly turns the
 *       self-addressing check off. They are nginx -t failures on purpose.
 * HOW:  the order is load-bearing and matches the OCI merge it is modelled on:
 *       adopt the unified directives → merge our scalars → pre-seed the verify
 *       default while the sentinel is still readable → shared merge → refuse →
 *       build. A location without brix_rpm_mirror returns after the shared
 *       merge having allocated nothing.
 */

#include "rpm.h"

#include "core/compat/alloc_guard.h"
#include "core/config/http_common.h"       /* unified brix_* directive adoption */
#include "fs/cache/verify.h"
#include "oci/url.h"                       /* the tree's http(s) URL grammar   */
#include "protocols/shared/merge_export.h"

#include <stdio.h>
#include <string.h>


/* Inherit every RPM scalar and pre-seed the verify default.
 *
 * The pre-seed must land BEFORE the shared merge: the sentinel is what
 * distinguishes "the operator said nothing" from "the operator said off", and
 * the shared merge collapses the former to the latter. Every metadata file a
 * createrepo repository publishes carries its own checksum in its name, so
 * the self-verifying mode is the only default that makes a mirror
 * trustworthy by construction. */
static char *
rpm_merge_scalars(ngx_conf_t *cf, ngx_http_brix_rpm_loc_conf_t *prev,
    ngx_http_brix_rpm_loc_conf_t *conf)
{
    brix_http_common_adopt(cf, &conf->common);

    ngx_conf_merge_value(conf->mirror, prev->mirror, 0);
    ngx_conf_merge_str_value(conf->mirror_url, prev->mirror_url, "");
    ngx_conf_merge_value(conf->insecure, prev->insecure, 0);
    ngx_conf_merge_value(conf->prefetch, prev->prefetch, 0);
    ngx_conf_merge_sec_value(conf->metadata_ttl, prev->metadata_ttl,
                             BRIX_RPM_METADATA_TTL_DEFAULT);

    if (conf->mirror && conf->common.cache_verify_mode == NGX_CONF_UNSET_UINT) {
        conf->common.cache_verify_mode = BRIX_CACHE_VERIFY_RPM_REPODATA;
    }

    return ngx_http_brix_shared_merge(cf, &prev->common, &conf->common, "");
}


/* The refusal matrix. */
static char *
rpm_reject(ngx_conf_t *cf, ngx_http_brix_rpm_loc_conf_t *conf,
    const brix_oci_url_t *url)
{
    if (conf->common.allow_write == 1) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_allow_write on: an RPM pull-through mirror is read-only by "
            "construction; publish a repository with brixrpm createrepo "
            "instead");
        return NGX_CONF_ERROR;
    }

    if (conf->common.stage_store.len > 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_stage_store: an RPM pull-through mirror never stages "
            "writes; remove it from this block");
        return NGX_CONF_ERROR;
    }

    if (!url->tls && !conf->insecure) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_rpm_mirror \"%V\": a cleartext upstream lets anyone on the "
            "path replace a package before this mirror ever hashes it; use "
            "https, or brix_rpm_mirror_insecure on for a test fixture",
            &conf->mirror_url);
        return NGX_CONF_ERROR;
    }

    /* The rpm-repodata verify is not a preference here, it is the reason this
     * plane exists: the classifier hands the cache tier a per-instance
     * personality, and every OTHER mode would tell the tier this cache is a
     * CVMFS or OCI one — which would then read RPM keys with the wrong
     * grammar and stamp the wrong freshness window on them. An operator who
     * wants no verification at all wants nginx's own proxy_cache, not this. */
    if (conf->common.cache_verify_mode != BRIX_CACHE_VERIFY_RPM_REPODATA) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cache_verify %s: a brix_rpm_mirror location must run the "
            "rpm-repodata verification - it is what checks each metadata file "
            "against the checksum its own name carries",
            brix_cache_verify_mode_str(conf->common.cache_verify_mode));
        return NGX_CONF_ERROR;
    }

    if (conf->common.storage_backend.len > 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_storage_backend and brix_rpm_mirror both name the upstream "
            "for this location; brix_rpm_mirror is the RPM spelling - "
            "configure exactly one");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


/* Turn `brix_rpm_mirror <base-url>` into the storage-backend string sd_http is
 * configured from. The cache key is the request URI verbatim (an absolute
 * repository path), so the backend base carries the scheme, authority and any
 * path prefix, and nothing else — exactly the composition the stock
 * `proxy_cache_key $uri; proxy_pass http://origin;` recipe performs. */
static char *
rpm_build_upstream(ngx_conf_t *cf, ngx_http_brix_rpm_loc_conf_t *conf)
{
    brix_oci_url_t   url;
    u_char          *backend;
    char             base[512];
    size_t           len;

    if (conf->mirror_url.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_rpm_mirror requires an upstream base URL");
        return NGX_CONF_ERROR;
    }

    if (brix_oci_url_parse((const char *) conf->mirror_url.data,
                           conf->mirror_url.len, &url) != 0)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_rpm_mirror \"%V\" is not an absolute http(s) URL with a "
            "plain host and path", &conf->mirror_url);
        return NGX_CONF_ERROR;
    }

    if (rpm_reject(cf, conf, &url) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }

    len = (size_t) snprintf(base, sizeof(base), "%s://%s%s%s:%d%s",
                            url.tls ? "https" : "http",
                            strchr(url.host, ':') ? "[" : "",
                            url.host,
                            strchr(url.host, ':') ? "]" : "",
                            url.port, url.path);
    if (len >= sizeof(base)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_rpm_mirror \"%V\" is too long", &conf->mirror_url);
        return NGX_CONF_ERROR;
    }

    backend = ngx_pnalloc(cf->pool, len + 1);
    if (backend == NULL) {
        return NGX_CONF_ERROR;
    }
    ngx_memcpy(backend, base, len + 1);
    conf->common.storage_backend.data = backend;
    conf->common.storage_backend.len  = len;

    return NGX_CONF_OK;
}


/* Anchor the namespace, open the confinement fd, register the backend and
 * compose the cache tiers — the build order every brix HTTP protocol shares.
 * A mirror is a pure cache node: no local export tree, so the namespace
 * anchors at "/" and every object lives in the cache store. */
static char *
rpm_merge_export(ngx_conf_t *cf, ngx_http_brix_rpm_loc_conf_t *conf)
{
    conf->common.allow_write = 0;

    brix_storage_backend_posix_root(&conf->common);

    if (brix_http_merge_export_anchor(cf, &conf->common, "brix_rpm_mirror", 0)
        != NGX_CONF_OK)
    {
        return NGX_CONF_ERROR;
    }

    /* The mutable half of a repository — repomd.xml and anything createrepo
     * did not name after its own checksum — expires on this window; every
     * digest-named metadata file and every package is immutable and ignores
     * it. Which is which is the classifier's answer, read back through the
     * instance's verify personality (sd_cache_is_manifest_key). */
    conf->common.cache_manifest_ttl = conf->metadata_ttl;

    if (brix_tier_register_stores(cf, &conf->common) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


char *
ngx_http_brix_rpm_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_brix_rpm_loc_conf_t *prev = parent;
    ngx_http_brix_rpm_loc_conf_t *conf = child;

    if (rpm_merge_scalars(cf, prev, conf) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }

    if (!conf->mirror) {
        return NGX_CONF_OK;                 /* surface off: nothing is built */
    }

    if (rpm_build_upstream(cf, conf) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }

    return rpm_merge_export(cf, conf);
}
