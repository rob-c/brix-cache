/*
 * tier_build.c - turn a tier cfg into a bound SD instance, and compose the stack
 * (phase-64 section 5, Appendix C). See tier.h.
 *
 * brix_tier_build is the SINGLE driver-name dispatch in the whole storage plane:
 * it maps a parsed tier cfg onto the existing per-driver create function. A driver
 * not yet implemented as a tier (rados, tape) is a tracked "needs development"
 * (P1) - it logs a [warn] and returns NULL so the export is held inactive, never a
 * crash. brix_tier_build_stack composes cache(stage(backend)) via the sd_cache /
 * sd_stage decorators and enforces tape-requires-cache (P4/G8). The result is
 * memoised per worker; the VFS resolves to it blind (P3, G4/G5).
 */
#include "tier.h"

#include "fs/backend/xroot/sd_xroot.h"    /* brix_sd_xroot_create_origin   */
#include "fs/backend/http/sd_http.h"      /* brix_sd_http_create           */
#include "fs/backend/remote/sd_remote.h"  /* brix_sd_remote_create (s3)    */
#include "fs/backend/cache/sd_cache.h"    /* brix_sd_cache_create          */
#include "fs/backend/stage/sd_stage.h"    /* brix_sd_stage_create          */
#include "fs/backend/frm/sd_frm.h"        /* brix_sd_frm_create (tape)     */
#include "fs/backend/rados/sd_ceph.h"     /* brix_sd_ceph_conf_t (rados)   */
#include "fs/cache/origin/s3_transport.h"  /* brix_s3_origin_curl_transport */
#include "core/compat/cstr.h"              /* brix_str_cbuf                 */
#include "auth/impersonate/lifecycle.h"    /* brix_imp_worker_runtime_ids   */

#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* Resolve a tier's §14 credential into NUL-terminated bearer / proxy / key /
 * ca-dir strings (empty when the tier is anonymous or the field is unset).
 *
 * GSI: a combined x509_proxy (cert + key in one PEM) takes precedence and leaves
 * `key` empty (the key lives in the proxy).  Otherwise a separate cert + key pair
 * is used — `proxy` carries the cert chain, `key` the private key — so a plain
 * host cert/key authenticates a tier-composed remote origin (cache/stage over a
 * root:// backend) without hand-concatenating them.  Without this the cert/key
 * fields were silently dropped on the tier path and the origin login failed with
 * "no credential set". */
static void
tier_resolve_creds(const brix_tier_cfg_t *t, char *bearer, size_t bcap,
    char *proxy, size_t pcap, char *key, size_t kcap, char *cadir, size_t ccap,
    ngx_log_t *log)
{
    const brix_credential_t *c = t->credential;

    bearer[0] = '\0';
    proxy[0]  = '\0';
    key[0]    = '\0';
    cadir[0]  = '\0';
    if (c == NULL) {
        return;
    }
    (void) brix_credential_bearer(c, bearer, bcap, log);   /* "" when none */
    if (c->x509_proxy.len > 0) {
        (void) brix_str_cbuf(proxy, pcap, &c->x509_proxy);
    } else if (c->x509_cert.len > 0) {
        (void) brix_str_cbuf(proxy, pcap, &c->x509_cert);
        if (c->x509_key.len > 0) {
            (void) brix_str_cbuf(key, kcap, &c->x509_key);
        }
    }
    if (c->ca_dir.len > 0) {
        (void) brix_str_cbuf(cadir, ccap, &c->ca_dir);
    }
}

/* "needs development": a recognised driver that is not yet a tier in this build.
 * Marked possibly-unused: its only callers are the #else arms of the optional-
 * library driver branches (pblock/sqlite, rados/ceph), so a build with ALL those
 * libraries present (e.g. the ceph container) references it from no arm. */
static brix_sd_instance_t *tier_needs_dev(ngx_log_t *log, const char *driver,
    const char *sp) __attribute__((unused));

static brix_sd_instance_t *
tier_needs_dev(ngx_log_t *log, const char *driver, const char *sp)
{
    ngx_log_error(NGX_LOG_WARN, log, 0,
        "xrootd tier: the \"%s\" driver is not yet implemented as a storage tier "
        "(needs development - phase-64 %s); this export is inactive until then",
        driver, sp);
    return NULL;
}

/* ---- the single driver-name dispatch (Appendix C) ------------------------- */

/* WHAT: build a local posix backend from a tier cfg.
 * WHY:  the default storage driver — a plain directory root.
 * HOW:  hand the export path straight to the posix sd factory. */
static brix_sd_instance_t *
tier_build_posix(const brix_tier_cfg_t *t, ngx_log_t *log)
{
    int err = 0;

    return brix_sd_instance_create(log, "posix", (void *) t->path, &err);
}

/* WHAT: hand a pblock store's master-created state to the runtime worker ids.
 * WHY:  the config-time validation build (root master) CREATES the store root,
 *       data dir and catalog.db (+ WAL/SHM sidecars) root-owned; the always-on
 *       de-escalated worker (brix_worker_user/nobody) then EACCESes on every
 *       catalog write and block-dir mkdir — writes surface to clients as
 *       kXR_NotAuthorized. Same provisioning contract as the default credential
 *       store and stage spool (see brix_imp_worker_runtime_ids).
 * HOW:  master/config-time + euid 0 only. Resolve the post-de-escalation ids
 *       (a real unprivileged `user` account already owns nothing here — nginx
 *       only forks workers later — so the brix_worker_user/nobody resolution is
 *       the one that matters) and chown the fixed store layout; absent pieces
 *       (ENOENT) are fine, the worker creates them as itself. */
void
brix_tier_pblock_hand_to_worker(const char *root, ngx_log_t *log)
{
    static const char *tails[] = {
        "", "/data", "/catalog.db", "/catalog.db-wal", "/catalog.db-shm",
        "/catalog.db-journal",
    };
    uid_t      uid;
    gid_t      gid;
    ngx_uint_t i;
    char       path[PATH_MAX];

    if (root == NULL || geteuid() != 0
        || ngx_process == NGX_PROCESS_WORKER)
    {
        return;
    }
    if (brix_imp_worker_runtime_ids((ngx_uid_t) NGX_CONF_UNSET_UINT,
                                    (ngx_gid_t) NGX_CONF_UNSET_UINT,
                                    &uid, &gid) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_WARN, log, 0,
            "xrootd tier: cannot resolve the worker identity to own the "
            "pblock store \"%s\" — de-escalated workers may not be able to "
            "write it", root);
        return;
    }
    for (i = 0; i < sizeof(tails) / sizeof(tails[0]); i++) {
        (void) snprintf(path, sizeof(path), "%s%s", root, tails[i]);
        if (chown(path, uid, gid) != 0 && errno != ENOENT) {
            ngx_log_error(NGX_LOG_WARN, log, ngx_errno,
                "xrootd tier: chown(\"%s\") to the worker identity failed — "
                "de-escalated workers may not be able to write the pblock "
                "store", path);
        }
    }
}

/* WHAT: build a pblock (sqlite-backed block store) backend from a tier cfg.
 * WHY:  optional driver, present only when libsqlite3 is compiled in.
 * HOW:  populate the conf from the tier path/block_size; without the library
 *       report a tracked "needs development" so the export is held inactive. */
static brix_sd_instance_t *
tier_build_pblock(const brix_tier_cfg_t *t, ngx_log_t *log)
{
#if BRIX_HAVE_SQLITE
    brix_sd_pblock_conf_t conf;
    brix_sd_instance_t   *inst;
    int                     err = 0;

    ngx_memzero(&conf, sizeof(conf));
    conf.root            = t->path;
    conf.busy_timeout_ms = 5000;
    conf.block_size      = (int64_t) t->block_size;
    /* Enforce the off-root drop ONLY in a worker: pblock blobs/catalog.db must
     * never be owned by root. Cache/stage pblock tiers are also built once at
     * config time in the master (root) for validation — dropping THERE would
     * strip the master of the privilege it needs to open logs and fork workers,
     * so gate on ngx_process. The worker build (request-time) is what actually
     * creates the on-disk data; it drops to the `user <acct>;` account, or
     * "nobody" for a root worker (conf.unpriv_user left NULL). */
    conf.enforce_unprivileged = (ngx_process == NGX_PROCESS_WORKER);
    inst = brix_sd_instance_create(log, "pblock", &conf, &err);
    if (inst != NULL) {
        brix_tier_pblock_hand_to_worker(t->path, log);
    }
    return inst;
#else
    (void) t;
    return tier_needs_dev(log, "pblock (needs libsqlite3)", "build");
#endif
}

/* WHAT: build a root:// (xroot) remote-origin backend from a tier cfg.
 * WHY:  a tier composed over a remote xrootd origin (cache/stage source).
 * HOW:  resolve the §14 credential to NUL-terminated strings, then hand the
 *       host/port/tls plus optional bearer/x509/ca-dir to the xroot factory. */
static brix_sd_instance_t *
tier_build_xroot(const brix_tier_cfg_t *t, ngx_log_t *log)
{
    char bearer[4096];
    char proxy[1024];
    char key[1024];
    char cadir[1024];

    tier_resolve_creds(t, bearer, sizeof(bearer), proxy, sizeof(proxy),
                       key, sizeof(key), cadir, sizeof(cadir), log);
    brix_sd_xroot_origin_cfg_t cfg = {
        .host       = t->host,
        .port       = t->port,
        .tls        = t->tls,
        .af_policy  = BRIX_AF_AUTO,
        .bearer     = (bearer[0] != '\0') ? bearer : NULL,
        .x509_proxy = (proxy[0] != '\0') ? proxy : NULL,
        .x509_key   = (key[0] != '\0') ? key : NULL,
        .ca_dir     = (cadir[0] != '\0') ? cadir : NULL,
        .sss_keytab = NULL,
    };
    return brix_sd_xroot_create_origin(&cfg, log);
}

/* WHAT: build an http(s) remote-origin backend from a tier cfg.
 * WHY:  a tier composed over a plain HTTP origin (bearer-authenticated).
 * HOW:  resolve the credential (http uses bearer, not x509), then fill the
 *       http sd conf; the credential ca_dir verifies an https origin. */
static brix_sd_instance_t *
tier_build_http(const brix_tier_cfg_t *t, ngx_log_t *log)
{
    brix_sd_http_cfg_t cfg;
    char                 bearer[4096];
    char                 proxy[1024];
    char                 key[1024];    /* http auth uses bearer, not x509 */
    char                 cadir[1024];

    tier_resolve_creds(t, bearer, sizeof(bearer), proxy, sizeof(proxy),
                       key, sizeof(key), cadir, sizeof(cadir), log);
    ngx_memzero(&cfg, sizeof(cfg));
    cfg.host         = t->host;
    cfg.port         = t->port;
    cfg.tls          = t->tls;
    cfg.base_path    = t->path;
    cfg.transport    = &brix_s3_origin_curl_transport;
    cfg.timeout_ms   = BRIX_SD_HTTP_DEFAULT_TIMEOUT_MS;
    cfg.bearer_token = (bearer[0] != '\0') ? bearer : NULL;
    /* §14/C-3: verify the https origin against the credential's ca_dir (file
     * or hashed dir); "" system bundle (public-CA origin). */
    cfg.ca_path      = (cadir[0] != '\0') ? cadir : NULL;
    return brix_sd_http_create(&cfg, log);
}

/* WHAT: build an S3 remote-origin backend from a tier cfg.
 * WHY:  a tier sourced from a public/anonymous S3 bucket (SP1).
 * HOW:  copy host/port/tls and the leading-slash-stripped bucket into the
 *       remote conf; no access/secret yet (that representation is SP3). */
static brix_sd_instance_t *
tier_build_s3(const brix_tier_cfg_t *t, ngx_log_t *log)
{
    brix_sd_remote_cfg_t cfg;
    const char            *bucket = t->path;

    /* The §14 credential block carries no S3 access/secret/region yet (that
     * representation is SP3, section 21); SP1 builds an anonymous/public S3
     * source - read works for public buckets. */
    ngx_memzero(&cfg, sizeof(cfg));
    cfg.scheme = BRIX_SD_REMOTE_S3;
    ngx_cpystrn((u_char *) cfg.host, (u_char *) t->host, sizeof(cfg.host));
    cfg.port = t->port;
    cfg.tls  = t->tls;
    if (bucket[0] == '/') {
        bucket++;
    }
    ngx_cpystrn((u_char *) cfg.bucket, (u_char *) bucket, sizeof(cfg.bucket));
    cfg.timeout_ms = BRIX_SD_HTTP_DEFAULT_TIMEOUT_MS;
    cfg.transport  = &brix_s3_origin_curl_transport;
    return brix_sd_remote_create(&cfg, log);
}

/* WHAT: build a rados/ceph (librados) backend from a tier cfg.
 * WHY:  optional driver, present only when librados is compiled in.
 * HOW:  the authority host is the pool, the path tail the key prefix; without
 *       the library report a tracked "needs development" (export inactive). */
static brix_sd_instance_t *
tier_build_ceph(const brix_tier_cfg_t *t, ngx_log_t *log)
{
#if BRIX_HAVE_CEPH
    /* rados://POOL[/namespace] / ceph://POOL[/namespace] -> the ceph (librados)
     * driver; the path tail is the object key prefix. The cstore over it uses
     * XATTR cinfo mode (the cache state lives on the RADOS object). */
    brix_sd_ceph_conf_t conf;
    const char           *prefix = (t->path[0] == '/') ? t->path + 1 : t->path;
    int                   err = 0;

    ngx_memzero(&conf, sizeof(conf));
    conf.pool       = t->host;
    conf.conf_file  = NULL;          /* default /etc/ceph/ceph.conf */
    conf.key_prefix = (prefix[0] != '\0') ? prefix : NULL;
    return brix_sd_instance_create(log, "ceph", &conf, &err);
#else
    (void) t;
    return tier_needs_dev(log, "rados (needs librados at build time)", "SP3");
#endif
}

/* WHAT: build a tape/frm (nearline MSS) backend from a tier cfg.
 * WHY:  a nearline source recalled through the FRM adapter.
 * HOW:  the authority host selects the MSS adapter ("" = stub); the path is
 *       the adapter's MSS base. */
static brix_sd_instance_t *
tier_build_tape(const brix_tier_cfg_t *t, ngx_log_t *log)
{
    return brix_sd_frm_create(t->host, t->path, log);
}

brix_sd_instance_t *
brix_tier_build(const brix_tier_cfg_t *t, ngx_log_t *log)
{
    if (t == NULL || !t->configured) {
        return NULL;
    }

    if (ngx_strcmp(t->driver, "posix") == 0) {
        return tier_build_posix(t, log);
    }
    if (ngx_strcmp(t->driver, "pblock") == 0) {
        return tier_build_pblock(t, log);
    }
    if (ngx_strcmp(t->driver, "xroot") == 0) {
        return tier_build_xroot(t, log);
    }
    if (ngx_strcmp(t->driver, "http") == 0) {
        return tier_build_http(t, log);
    }
    if (ngx_strcmp(t->driver, "s3") == 0) {
        return tier_build_s3(t, log);
    }
    if (ngx_strcmp(t->driver, "rados") == 0
        || ngx_strcmp(t->driver, "ceph") == 0) {
        return tier_build_ceph(t, log);
    }
    if (ngx_strcmp(t->driver, "tape") == 0
        || ngx_strcmp(t->driver, "frm") == 0) {
        return tier_build_tape(t, log);
    }

    ngx_log_error(NGX_LOG_ERR, log, 0,
        "xrootd tier: unknown driver \"%s\"", t->driver);
    return NULL;   /* operator error - parse_store should have rejected it */
}

/* ---- compose the stack (cache outermost -> stage -> backend) -------------- */

/* WHAT: wrap `top` in the stage decorator when a stage store is configured.
 * WHY:  isolates the stage-tier composition (its own store build + errors).
 * HOW:  no-op passthrough when stage is unconfigured/disabled; otherwise build
 *       the stage store and decorate. Returns the (possibly wrapped) instance,
 *       or NULL on failure (store build or decorator init). */
static brix_sd_instance_t *
tier_compose_stage(brix_tier_stack_t *s, brix_sd_instance_t *top,
    ngx_log_t *log)
{
    brix_sd_instance_t *store;

    if (!(s->stage_store.configured && s->stage.enabled)) {
        return top;
    }
    store = brix_tier_build(&s->stage_store, log);
    if (store == NULL) {
        return NULL;
    }
    top = brix_sd_stage_create(top, store, &s->stage, NULL, log);
    if (top == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
            "xrootd tier: stage decorator init failed");
        return NULL;
    }
    return top;
}

/* WHAT: wrap `top` in the cache decorator when a cache store is configured.
 * WHY:  isolates the cache-tier composition (its own store build + errors).
 * HOW:  no-op passthrough when cache is unconfigured/disabled; otherwise build
 *       the cache store and decorate. LOCAL cinfo only for a posix store; a
 *       remote store keeps cinfo as a store xattr (SP2), so pass NULL there.
 *       Returns the (possibly wrapped) instance, or NULL on failure. */
static brix_sd_instance_t *
tier_compose_cache(brix_tier_stack_t *s, brix_sd_instance_t *top,
    ngx_log_t *log)
{
    brix_sd_instance_t *store;
    const char          *local_root;

    if (!(s->cache_store.configured && s->cache.enabled)) {
        return top;
    }
    store = brix_tier_build(&s->cache_store, log);
    if (store == NULL) {
        return NULL;
    }
    local_root = (ngx_strcmp(s->cache_store.driver, "posix") == 0
                  && s->cache_store.path[0] != '\0')
               ? s->cache_store.path : NULL;
    top = brix_sd_cache_create(top, store, &s->cache, local_root, log);
    if (top == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
            "xrootd tier: cache decorator init failed");
        return NULL;
    }
    return top;
}

brix_sd_instance_t *
brix_tier_build_stack(brix_tier_stack_t *s, ngx_log_t *log)
{
    brix_sd_instance_t *top;

    if (s == NULL) {
        return NULL;
    }
    if (s->composed != NULL) {
        return s->composed;                 /* memoised in this worker */
    }

    top = brix_tier_build(&s->backend, log);
    if (top == NULL) {
        return NULL;
    }

    /* G8 (P4): a nearline (tape) backend cannot be served without a cache tier as
     * the recall target. The operator-facing [emerg] is raised at config time once
     * the tier config wiring lands (section 9.4); this is the build-time guard. */
    if (s->backend.nearline && !s->cache_store.configured) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "xrootd tier: a nearline (tape) backend requires brix_cache (the "
            "recall target) - export held inactive");
        return NULL;
    }

    top = tier_compose_stage(s, top, log);
    if (top == NULL) {
        return NULL;
    }
    top = tier_compose_cache(s, top, log);
    if (top == NULL) {
        return NULL;
    }

    s->composed = top;
    return top;
}
