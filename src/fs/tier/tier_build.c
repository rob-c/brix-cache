/*
 * tier_build.c - turn a tier cfg into a bound SD instance, and compose the stack
 * (phase-64 section 5, Appendix C). See tier.h.
 *
 * xrootd_tier_build is the SINGLE driver-name dispatch in the whole storage plane:
 * it maps a parsed tier cfg onto the existing per-driver create function. A driver
 * not yet implemented as a tier (rados, tape) is a tracked "needs development"
 * (P1) - it logs a [warn] and returns NULL so the export is held inactive, never a
 * crash. xrootd_tier_build_stack composes cache(stage(backend)) via the sd_cache /
 * sd_stage decorators and enforces tape-requires-cache (P4/G8). The result is
 * memoised per worker; the VFS resolves to it blind (P3, G4/G5).
 */
#include "tier.h"

#include "fs/backend/xroot/sd_xroot.h"    /* xrootd_sd_xroot_create_origin   */
#include "fs/backend/http/sd_http.h"      /* xrootd_sd_http_create           */
#include "fs/backend/remote/sd_remote.h"  /* xrootd_sd_remote_create (s3)    */
#include "fs/backend/cache/sd_cache.h"    /* xrootd_sd_cache_create          */
#include "fs/backend/stage/sd_stage.h"    /* xrootd_sd_stage_create          */
#include "fs/backend/frm/sd_frm.h"        /* xrootd_sd_frm_create (tape)     */
#include "fs/backend/rados/sd_ceph.h"     /* xrootd_sd_ceph_conf_t (rados)   */
#include "fs/cache/origin/s3_transport.h"  /* xrootd_s3_origin_curl_transport */

#include <string.h>

/* Resolve a tier's §14 credential into NUL-terminated bearer / proxy / ca-dir
 * strings (empty when the tier is anonymous or the field is unset). */
static void
tier_resolve_creds(const xrootd_tier_cfg_t *t, char *bearer, size_t bcap,
    char *proxy, size_t pcap, char *cadir, size_t ccap, ngx_log_t *log)
{
    const xrootd_credential_t *c = t->credential;

    bearer[0] = '\0';
    proxy[0]  = '\0';
    cadir[0]  = '\0';
    if (c == NULL) {
        return;
    }
    (void) xrootd_credential_bearer(c, bearer, bcap, log);   /* "" when none */
    if (c->x509_proxy.len > 0 && c->x509_proxy.len < pcap) {
        ngx_memcpy(proxy, c->x509_proxy.data, c->x509_proxy.len);
        proxy[c->x509_proxy.len] = '\0';
    }
    if (c->ca_dir.len > 0 && c->ca_dir.len < ccap) {
        ngx_memcpy(cadir, c->ca_dir.data, c->ca_dir.len);
        cadir[c->ca_dir.len] = '\0';
    }
}

/* "needs development": a recognised driver that is not yet a tier in this build.
 * Marked possibly-unused: its only callers are the #else arms of the optional-
 * library driver branches (pblock/sqlite, rados/ceph), so a build with ALL those
 * libraries present (e.g. the ceph container) references it from no arm. */
static xrootd_sd_instance_t *tier_needs_dev(ngx_log_t *log, const char *driver,
    const char *sp) __attribute__((unused));

static xrootd_sd_instance_t *
tier_needs_dev(ngx_log_t *log, const char *driver, const char *sp)
{
    ngx_log_error(NGX_LOG_WARN, log, 0,
        "xrootd tier: the \"%s\" driver is not yet implemented as a storage tier "
        "(needs development - phase-64 %s); this export is inactive until then",
        driver, sp);
    return NULL;
}

/* ---- the single driver-name dispatch (Appendix C) ------------------------- */

xrootd_sd_instance_t *
xrootd_tier_build(const xrootd_tier_cfg_t *t, ngx_log_t *log)
{
    if (t == NULL || !t->configured) {
        return NULL;
    }

    if (ngx_strcmp(t->driver, "posix") == 0) {
        int err = 0;

        return xrootd_sd_instance_create(ngx_cycle->pool, log, "posix",
                                         (void *) t->path, &err);
    }

    if (ngx_strcmp(t->driver, "pblock") == 0) {
#if XROOTD_HAVE_SQLITE
        xrootd_sd_pblock_conf_t conf;
        int                     err = 0;

        ngx_memzero(&conf, sizeof(conf));
        conf.root            = t->path;
        conf.busy_timeout_ms = 5000;
        conf.block_size      = (int64_t) t->block_size;
        return xrootd_sd_instance_create(ngx_cycle->pool, log, "pblock", &conf,
                                         &err);
#else
        return tier_needs_dev(log, "pblock (needs libsqlite3)", "build");
#endif
    }

    if (ngx_strcmp(t->driver, "xroot") == 0) {
        char bearer[4096];
        char proxy[1024];
        char cadir[1024];

        tier_resolve_creds(t, bearer, sizeof(bearer), proxy, sizeof(proxy),
                           cadir, sizeof(cadir), log);
        return xrootd_sd_xroot_create_origin(t->host, t->port, t->tls,
            XROOTD_AF_AUTO,
            (bearer[0] != '\0') ? bearer : NULL,
            (proxy[0] != '\0') ? proxy : NULL,
            (cadir[0] != '\0') ? cadir : NULL, NULL /* sss_keytab */, log);
    }

    if (ngx_strcmp(t->driver, "http") == 0) {
        xrootd_sd_http_cfg_t cfg;
        char                 bearer[4096];
        char                 proxy[1024];
        char                 cadir[1024];

        tier_resolve_creds(t, bearer, sizeof(bearer), proxy, sizeof(proxy),
                           cadir, sizeof(cadir), log);
        ngx_memzero(&cfg, sizeof(cfg));
        cfg.host         = t->host;
        cfg.port         = t->port;
        cfg.tls          = t->tls;
        cfg.base_path    = t->path;
        cfg.transport    = &xrootd_s3_origin_curl_transport;
        cfg.timeout_ms   = 60000;
        cfg.bearer_token = (bearer[0] != '\0') ? bearer : NULL;
        return xrootd_sd_http_create(&cfg, log);
    }

    if (ngx_strcmp(t->driver, "s3") == 0) {
        xrootd_sd_remote_cfg_t cfg;
        const char            *bucket = t->path;

        /* The §14 credential block carries no S3 access/secret/region yet (that
         * representation is SP3, section 21); SP1 builds an anonymous/public S3
         * source - read works for public buckets. */
        ngx_memzero(&cfg, sizeof(cfg));
        cfg.scheme = XROOTD_SD_REMOTE_S3;
        ngx_cpystrn((u_char *) cfg.host, (u_char *) t->host, sizeof(cfg.host));
        cfg.port = t->port;
        cfg.tls  = t->tls;
        if (bucket[0] == '/') {
            bucket++;
        }
        ngx_cpystrn((u_char *) cfg.bucket, (u_char *) bucket, sizeof(cfg.bucket));
        cfg.timeout_ms = 60000;
        cfg.transport  = &xrootd_s3_origin_curl_transport;
        return xrootd_sd_remote_create(&cfg, log);
    }

    if (ngx_strcmp(t->driver, "rados") == 0
        || ngx_strcmp(t->driver, "ceph") == 0) {
#if XROOTD_HAVE_CEPH
        /* rados://POOL[/namespace] / ceph://POOL[/namespace] -> the ceph (librados)
         * driver; the path tail is the object key prefix. The cstore over it uses
         * XATTR cinfo mode (the cache state lives on the RADOS object). */
        xrootd_sd_ceph_conf_t conf;
        const char           *prefix = (t->path[0] == '/') ? t->path + 1 : t->path;
        int                   err = 0;

        ngx_memzero(&conf, sizeof(conf));
        conf.pool       = t->host;
        conf.conf_file  = NULL;          /* default /etc/ceph/ceph.conf */
        conf.key_prefix = (prefix[0] != '\0') ? prefix : NULL;
        return xrootd_sd_instance_create(ngx_cycle->pool, log, "ceph", &conf,
                                         &err);
#else
        return tier_needs_dev(log, "rados (needs librados at build time)", "SP3");
#endif
    }
    if (ngx_strcmp(t->driver, "tape") == 0
        || ngx_strcmp(t->driver, "frm") == 0) {
        /* the tape://|frm:// authority host selects the MSS adapter ("" = stub); the
         * path is the adapter's MSS base (the stub's local tape dir). */
        return xrootd_sd_frm_create(t->host, t->path, log);
    }

    ngx_log_error(NGX_LOG_ERR, log, 0,
        "xrootd tier: unknown driver \"%s\"", t->driver);
    return NULL;   /* operator error - parse_store should have rejected it */
}

/* ---- compose the stack (cache outermost -> stage -> backend) -------------- */

xrootd_sd_instance_t *
xrootd_tier_build_stack(xrootd_tier_stack_t *s, ngx_log_t *log)
{
    xrootd_sd_instance_t *top;
    xrootd_sd_instance_t *store;

    if (s == NULL) {
        return NULL;
    }
    if (s->composed != NULL) {
        return s->composed;                 /* memoised in this worker */
    }

    top = xrootd_tier_build(&s->backend, log);
    if (top == NULL) {
        return NULL;
    }

    /* G8 (P4): a nearline (tape) backend cannot be served without a cache tier as
     * the recall target. The operator-facing [emerg] is raised at config time once
     * the tier config wiring lands (section 9.4); this is the build-time guard. */
    if (s->backend.nearline && !s->cache_store.configured) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "xrootd tier: a nearline (tape) backend requires xrootd_cache (the "
            "recall target) - export held inactive");
        return NULL;
    }

    if (s->stage_store.configured && s->stage.enabled) {
        store = xrootd_tier_build(&s->stage_store, log);
        if (store == NULL) {
            return NULL;
        }
        top = xrootd_sd_stage_create(top, store, &s->stage, NULL, log);
        if (top == NULL) {
            ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                "xrootd tier: stage decorator init failed");
            return NULL;
        }
    }

    if (s->cache_store.configured && s->cache.enabled) {
        const char *local_root;

        store = xrootd_tier_build(&s->cache_store, log);
        if (store == NULL) {
            return NULL;
        }
        /* LOCAL cinfo only for a posix cache store; a remote store keeps cinfo as
         * a store xattr (SP2), so pass NULL there. */
        local_root = (ngx_strcmp(s->cache_store.driver, "posix") == 0
                      && s->cache_store.path[0] != '\0')
                   ? s->cache_store.path : NULL;
        top = xrootd_sd_cache_create(top, store, &s->cache, local_root, log);
        if (top == NULL) {
            ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                "xrootd tier: cache decorator init failed");
            return NULL;
        }
    }

    s->composed = top;
    return top;
}
