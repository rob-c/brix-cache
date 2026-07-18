/*
 * runtime_server_backend.c — storage-backend root rewriting + phase-64
 * composable cache/stage tier registration. Split verbatim out of
 * runtime_server.c (mechanical file-size split); shared entry points are
 * declared in shared_conf.h (reached via config.h).
 */

#include "config.h"
#include "root_prepare.h"
#include "credential_block.h"             /* §14 brix_credential lookup/bearer */
#include "core/compat/staged_file.h"
#include "core/compat/tmp_path.h"          /* SP4 orphan direct-write temp reaper */
#include "fs/vfs/vfs_backend_registry.h"   /* per-export backend registration */
#include "fs/path/path.h"                 /* brix_mkdir_recursive (pblock:// init) */
#include "fs/tier/tier.h"              /* phase-64 tier parse + cache/stage register */
#include "fs/cache/cache_internal.h"   /* brix_cache_state_root (effective sidecar tree) */
#include "core/config/export_guard.h"  /* brix_assert_dir_outside_export (hard guard) */

#include <stdlib.h>                    /* strtol (F8 peer-ring port parse)   */
#include <string.h>                    /* strrchr                            */

/* brix_pblock_write_opts_sidecar — persist a pblock `?tail` query string as the
 * one-line <root>/pblock.opts sidecar the pblock driver parses at instance init
 * (Phase-83 static opts). Best-effort at config finalise: the root dir already
 * exists (mkdir ran first). Kept here (not in the sqlite-gated pblock driver) so
 * it links regardless of BRIX_HAVE_SQLITE. */
static void
brix_pblock_write_opts_sidecar(const char *root, const char *tail)
{
    char  path[4096];
    FILE *f;

    (void) snprintf(path, sizeof(path), "%s/pblock.opts", root);
    f = fopen(path, "we");
    if (f == NULL) {
        return;
    }
    (void) fputs(tail != NULL ? tail : "", f);
    (void) fputc('\n', f);
    (void) fclose(f);
}

/* Directive setter for a tier store-URL directive: arg[1] = the store URL (into the
 * ngx_str_t at cmd->offset); args[2..] = trailing credential=/block_size= params
 * (into the ngx_array_t* at the field offset carried in cmd->post). See header. */
char *
brix_conf_set_store_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char         *p = conf;
    ngx_str_t    *url  = (ngx_str_t *) (p + cmd->offset);
    ngx_array_t **args = (ngx_array_t **) (p + (uintptr_t) cmd->post);
    ngx_str_t    *value = cf->args->elts;
    ngx_uint_t    i;

    if (url->data != NULL) {
        return "is duplicate";
    }
    *url = value[1];                            /* the store URL token */

    if (cf->args->nelts > 2) {
        *args = ngx_array_create(cf->pool, cf->args->nelts - 2, sizeof(ngx_str_t));
        if (*args == NULL) {
            return NGX_CONF_ERROR;
        }
        for (i = 2; i < cf->args->nelts; i++) {
            ngx_str_t *a = ngx_array_push(*args);

            if (a == NULL) {
                return NGX_CONF_ERROR;
            }
            *a = value[i];                      /* "credential=..." / "block_size=..." */
        }
    }
    return NGX_CONF_OK;
}

/* A LOCAL storage backend NAMES THE EXPORT TREE — the fully composable replacement
 * for brix_root. Rewrites common->root from the backend URL and anchors root_canon
 * there. No-op for a remote/non-local backend (root://, tape://, http://, a cache
 * origin, or none). Shared by all three protocol finalisers; called BEFORE the
 * export-root prep. Two forms:
 *   posix:<path>      → root = <path>; CLEAR the backend (default POSIX driver).
 *   pblock://<path>   → root = /<path> (one leading '/' guaranteed: "pblock://x"→
 *                       "/x", "pblock:///abs"→"//abs"→/abs); KEEP the "pblock"
 *                       driver; create the block-store directory on init if needed. */
void
brix_storage_backend_posix_root(ngx_http_brix_shared_conf_t *common)
{
    ngx_str_t *sb = &common->storage_backend;

    if (sb->len > sizeof("posix:") - 1
        && ngx_strncmp(sb->data, "posix:", sizeof("posix:") - 1) == 0)
    {
        u_char *p    = sb->data + (sizeof("posix:") - 1);
        size_t  plen = sb->len  - (sizeof("posix:") - 1);

        /* Accept both posix:<path> and posix://<path>: collapse leading "//" runs to
         * one '/' so the root is a single canonical path (a stray double slash
         * propagates into common->root and breaks raw prefix-strip path uses).
         * "posix://abs" with an absolute path yields "///abs" → "/abs". */
        while (plen >= 2 && p[0] == '/' && p[1] == '/') {
            p++;
            plen--;
        }
        common->root.data = p;
        common->root.len  = plen;
        sb->len           = 0;                       /* default POSIX driver */
        return;
    }

    if (sb->len > sizeof("pblock://") - 1
        && ngx_strncmp(sb->data, "pblock://", sizeof("pblock://") - 1) == 0)
    {
        size_t base = sizeof("pblock://") - 1;       /* past "pblock://" */

        /* Yield EXACTLY one leading '/': "pblock:///abs" already has it (offset
         * `base`); "pblock://rel" gains it by keeping the prior '/' (offset base-1).
         * A double slash would break the write-through's prefix-strip path derivation. */
        if (sb->data[base] == '/') {
            common->root.data = sb->data + base;
            common->root.len  = sb->len  - base;
        } else {
            common->root.data = sb->data + base - 1;
            common->root.len  = sb->len  - base + 1;
        }
        sb->len = sizeof("pblock") - 1;              /* the bare "pblock" driver */

        /* Phase-83 static opts: a `?tail` query string on the root
         * (pblock:///srv/x?lab=1&caps=-sendfile) selects the lab gate + caps/mem
         * knobs. Strip it BEFORE mkdir/root_canon (which would otherwise create a
         * literal '?' directory / canonicalise it away) by NUL-terminating the
         * root at '?', then stash the tail as the <root>/pblock.opts sidecar the
         * driver reads at init. No tail ⇒ no sidecar ⇒ lab OFF (production path). */
        {
            u_char *q = memchr(common->root.data, '?', common->root.len);

            if (q != NULL) {
                const char *tail = (const char *) (q + 1);

                *q = '\0';                           /* truncate root at '?' */
                common->root.len = (size_t) (q - common->root.data);
                (void) brix_mkdir_recursive((const char *) common->root.data,
                                            0755);
                brix_pblock_write_opts_sidecar(
                    (const char *) common->root.data, tail);
            } else {
                (void) brix_mkdir_recursive((const char *) common->root.data,
                                            0755);
            }
        }
    }
}

/* 1 iff the storage backend is REMOTE (the export's bytes live off-box: a root://
 * origin, http(s)://, s3://, tape://, ceph). For such an export the LOCAL root_canon
 * is only a namespace anchor — never written — so its export-root prep must not
 * demand W_OK (a pure remote-backed node defaults root_canon to "/", which is not
 * writable). Local backends (posix/pblock, or none) return 0 and keep the W_OK
 * check. Called after brix_storage_backend_posix_root (posix:/pblock:// already
 * rewritten away). */
int
brix_storage_backend_is_remote(const ngx_http_brix_shared_conf_t *common)
{
    static const char *const schemes[] = {
        "root://", "roots://", "http://", "https://", "s3://",
        "tape://", "frm://", "rados://", "ceph:", "cephfsro:", NULL
    };
    const ngx_str_t *sb = &common->storage_backend;
    int               i;

    for (i = 0; schemes[i] != NULL; i++) {
        size_t n = ngx_strlen(schemes[i]);

        if (sb->len >= n && ngx_strncmp(sb->data, schemes[i], n) == 0) {
            return 1;
        }
    }
    return 0;
}

/* Load the CVMFS repo master public key PEM named by `path` into the cache
 * policy (phase-85 F1). Config-time, cf->pool-owned (cycle lifetime — workers
 * inherit the pointer through the registered policy copy). The file may hold
 * several concatenated PEM keys (CVMFS key rotation); content is validated by
 * the OpenSSL PEM parser at verify time, here only shape-checked. [emerg] on
 * any failure — a verifying proxy with an unloadable trust anchor must not
 * start. */
static ngx_int_t
brix_tier_load_master_key(ngx_conf_t *cf, const ngx_str_t *path,
    brix_cache_policy_t *pol)
{
    char       pathz[1024];
    u_char    *buf;
    ssize_t    n;
    off_t      size;
    ngx_fd_t   fd;
    ngx_file_info_t  fi;

    if (path->len >= sizeof(pathz)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cvmfs_verify_manifest: key path too long");
        return NGX_ERROR;
    }
    ngx_cpystrn((u_char *) pathz, path->data, path->len + 1);

    fd = open(pathz, O_RDONLY | O_CLOEXEC);   /* vfs-seam-allow: config-domain trust-anchor PEM (not export storage) */
    if (fd == -1) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
            "brix_cvmfs_verify_manifest: cannot open \"%s\"", pathz);
        return NGX_ERROR;
    }
    if (ngx_fd_info(fd, &fi) == -1
        || (size = ngx_file_size(&fi)) <= 0 || size > 65536)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cvmfs_verify_manifest: \"%s\" is empty, unreadable "
            "or larger than 64KB", pathz);
        (void) close(fd);
        return NGX_ERROR;
    }
    buf = ngx_palloc(cf->pool, (size_t) size + 1);
    if (buf == NULL) {
        (void) close(fd);
        return NGX_ERROR;
    }
    n = read(fd, buf, (size_t) size);   /* vfs-seam-allow: config-domain trust-anchor PEM (not export storage) */
    (void) close(fd);
    if (n != (ssize_t) size) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
            "brix_cvmfs_verify_manifest: short read on \"%s\"", pathz);
        return NGX_ERROR;
    }
    buf[size] = '\0';
    if (ngx_strstr(buf, "BEGIN PUBLIC KEY") == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cvmfs_verify_manifest: \"%s\" holds no PEM public key",
            pathz);
        return NGX_ERROR;
    }
    pol->cvmfs_master_pub     = buf;
    pol->cvmfs_master_pub_len = (size_t) size;
    return NGX_OK;
}

/* Parse + validate the brix_cache_peers ring (phase-85 F8) and record it on
 * the backend registry. Each member token is "host:port"; this node's own slot
 * is "self=host:port" (the mesh needs every node to carry the IDENTICAL list so
 * rendezvous ownership agrees, so self is marked, never omitted). Operator
 * errors — malformed authority, no/duplicate self, fewer than 2 members, more
 * than 16 — are [emerg], failing nginx -t. */
static ngx_int_t
brix_tier_register_cache_peers(ngx_conf_t *cf,
    ngx_http_brix_shared_conf_t *common)
{
    char        hosts[16][256];
    int         ports[16];
    int         self = -1;
    ngx_str_t  *tok = common->cache_peers->elts;
    ngx_uint_t  i;

    if (common->cache_peers->nelts < 2) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cache_peers: a mesh needs at least 2 ring members "
            "(self=host:port plus one sibling)");
        return NGX_ERROR;
    }
    if (common->cache_peers->nelts > 16) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cache_peers: at most 16 ring members supported");
        return NGX_ERROR;
    }

    for (i = 0; i < common->cache_peers->nelts; i++) {
        char       buf[300];
        char      *auth = buf;
        char      *colon;
        long       port;

        if (tok[i].len >= sizeof(buf)) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "brix_cache_peers: member \"%V\" is too long", &tok[i]);
            return NGX_ERROR;
        }
        ngx_memcpy(buf, tok[i].data, tok[i].len);
        buf[tok[i].len] = '\0';

        if (ngx_strncmp(auth, "self=", sizeof("self=") - 1) == 0) {
            if (self >= 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "brix_cache_peers: more than one self= member");
                return NGX_ERROR;
            }
            self = (int) i;
            auth += sizeof("self=") - 1;
        }
        colon = strrchr(auth, ':');
        if (colon == NULL || colon == auth || colon[1] == '\0') {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "brix_cache_peers: member \"%V\" is not host:port", &tok[i]);
            return NGX_ERROR;
        }
        port = strtol(colon + 1, NULL, 10);
        if (port < 1 || port > 65535) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "brix_cache_peers: member \"%V\" has an invalid port",
                &tok[i]);
            return NGX_ERROR;
        }
        *colon = '\0';
        if (ngx_strlen(auth) >= sizeof(hosts[0])) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "brix_cache_peers: member \"%V\" host is too long", &tok[i]);
            return NGX_ERROR;
        }
        ngx_cpystrn((u_char *) hosts[i], (u_char *) auth, sizeof(hosts[i]));
        ports[i] = (int) port;
    }

    if (self < 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cache_peers: mark this node's own ring slot with "
            "self=host:port");
        return NGX_ERROR;
    }

    brix_vfs_backend_config_cache_peers(common->root_canon,
        (const char (*)[256]) hosts, ports,
        (int) common->cache_peers->nelts, self);
    return NGX_OK;
}

/* Parse the cache_store URL and record its tier cfg + read-through policy on the
 * backend registry. Split out of brix_tier_register_stores so each function's
 * branching stays within the readability gate. Operator errors are [emerg]. */
static ngx_int_t
brix_tier_register_cache_store(ngx_conf_t *cf,
    ngx_http_brix_shared_conf_t *common)
{
    char                err[256];
    brix_tier_cfg_t     cfg;
    brix_cache_policy_t pol;
    brix_tier_parse_t   tp = { cf, &cfg, err, sizeof(err) };

    if (brix_tier_parse_store(&tp, &common->cache_store,
            common->cache_store_args, BRIX_TIER_CACHE) != NGX_OK)
    {
        return NGX_ERROR;                      /* [emerg] already logged */
    }
    ngx_memzero(&pol, sizeof(pol));
    pol.enabled       = 1;
    pol.max_file_size = common->cache_max_object;
    /* Read-fill admission (bridged from the srv conf at finalisation): deny/allow
     * prefixes + include regex gate the composable sd_cache fill for parity with
     * write-through and the legacy cache_origin admit. NULL => no filter. */
    pol.deny_prefixes  = common->cache_deny_prefixes;
    pol.allow_prefixes = common->cache_allow_prefixes;
    pol.include_regex  = common->cache_include_re;
    pol.evict_at      = common->cache_evict_at;
    pol.evict_to      = common->cache_evict_to;
    pol.meta_mode     = (int) common->cache_meta_mode;
    pol.batch_cinfo   = (common->cache_batch_cinfo == 2)
                      ? -1 : (int) common->cache_batch_cinfo;
    pol.l1_entries    = common->cache_index_cache;
    pol.slice_size    = common->cache_slice_size;
    /* phase-68: digest verification on fill (cvmfs-cas today). The verify
     * runs on the staged temp BEFORE commit, which needs the store's
     * staged_path — a local posix store; reject other stores loudly. */
    pol.verify = (common->cache_verify_mode == NGX_CONF_UNSET_UINT)
               ? BRIX_CACHE_VERIFY_OFF
               : (brix_cache_verify_mode_e) common->cache_verify_mode;
    if (pol.verify == BRIX_CACHE_VERIFY_CVMFS_CAS
        && ngx_strcmp(cfg.driver, "posix") != 0)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cache_verify cvmfs-cas requires a local posix "
            "cache store (got \"%s\")", cfg.driver);
        return NGX_ERROR;
    }
    pol.cvmfs_manifest_ttl = common->cache_manifest_ttl;
    pol.cvmfs_offline_ttl  = common->cache_offline_ttl;
    /* phase-85 F1: brix_cvmfs_verify_manifest — load the repo master public
     * key(s) once at config time; the fill spine verifies every MANIFEST-class
     * fill's signature chain against it before publish. Same posix-store
     * constraint as cvmfs-cas (the verify reads the staged part path). */
    if (common->cache_cvmfs_master_key.len > 0) {
        if (ngx_strcmp(cfg.driver, "posix") != 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "brix_cvmfs_verify_manifest requires a local posix "
                "cache store (got \"%s\")", cfg.driver);
            return NGX_ERROR;
        }
        if (brix_tier_load_master_key(cf, &common->cache_cvmfs_master_key,
                                        &pol) != NGX_OK)
        {
            return NGX_ERROR;              /* [emerg] already logged */
        }
    }
    if (common->cache_quarantine_dir.len > 0) {
        ngx_cpystrn((u_char *) pol.quarantine_dir,
                    common->cache_quarantine_dir.data,
                    ngx_min(common->cache_quarantine_dir.len + 1,
                            sizeof(pol.quarantine_dir)));
    }
    brix_vfs_backend_config_cache_store(common->root_canon, &cfg, &pol);

    /* Phase-85 F7: the optional cold tier under the cache — its own store URL,
     * governed by the hot cache's policy (no separate knobs). */
    if (common->cache_cold_store.len > 0) {
        brix_tier_cfg_t   ccfg;
        brix_tier_parse_t ctp = { cf, &ccfg, err, sizeof(err) };

        if (brix_tier_parse_store(&ctp, &common->cache_cold_store,
                common->cache_cold_store_args, BRIX_TIER_CACHE) != NGX_OK)
        {
            return NGX_ERROR;                  /* [emerg] already logged */
        }
        brix_vfs_backend_config_cache_cold_store(common->root_canon, &ccfg);
    }

    /* Phase-85 F8: the sibling-mesh ring under the cache tier. */
    if (common->cache_peers != NULL
        && brix_tier_register_cache_peers(cf, common) != NGX_OK)
    {
        return NGX_ERROR;                      /* [emerg] already logged */
    }
    return NGX_OK;
}

/* Register the export's phase-64 composable cache/stage tiers (additive over the
 * storage backend). Parses the cache_store / stage_store URLs (operator errors are
 * [emerg], failing nginx -t) and records the tier cfg + policy on the backend
 * registry, which composes the sd_cache / sd_stage decorators per worker. Shared by
 * all three protocol finalisers (§4.4) - it reads only the common preamble. */
ngx_int_t
brix_tier_register_stores(ngx_conf_t *cf, ngx_http_brix_shared_conf_t *common)
{
    char                           err[256];

    /* G8 (P4/§9.4): a nearline (tape) backend is unservable without a cache tier
     * as the recall target - reject at config time. "frm://" is the tape:// alias. */
    {
        const ngx_str_t *sb = &common->storage_backend;
        int is_nearline =
            (sb->len > sizeof("tape://") - 1
             && ngx_strncmp(sb->data, "tape://", sizeof("tape://") - 1) == 0)
            || (sb->len > sizeof("frm://") - 1
                && ngx_strncmp(sb->data, "frm://", sizeof("frm://") - 1) == 0);

        if (is_nearline && common->cache_store.len == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "brix: a \"tape://\"/\"frm://\" backend is nearline and requires "
                "brix_cache_store (the recall target); add a cache tier");
            return NGX_ERROR;
        }
    }

    /* Phase-85 F7: a cold tier is meaningless without the hot cache it sits
     * under — reject at config time rather than silently ignoring it. */
    if (common->cache_cold_store.len > 0 && common->cache_store.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cache_cold_store requires brix_cache_store (the hot tier)");
        return NGX_ERROR;
    }

    /* Phase-85 F8: the sibling mesh fills INTO the cache tier — meaningless
     * without one. */
    if (common->cache_peers != NULL && common->cache_store.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cache_peers requires brix_cache_store (the mesh fills "
            "the cache tier)");
        return NGX_ERROR;
    }

    if (common->cache_store.len > 0
        && brix_tier_register_cache_store(cf, common) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (common->stage_enable == 1) {
        brix_tier_cfg_t     cfg;
        brix_stage_policy_t spol;
        brix_tier_parse_t   tp = { cf, &cfg, err, sizeof(err) };

        if (common->stage_store.len == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "brix_stage on requires brix_stage_store");
            return NGX_ERROR;
        }
        if (brix_tier_parse_store(&tp, &common->stage_store,
                common->stage_store_args, BRIX_TIER_STAGE) != NGX_OK)
        {
            return NGX_ERROR;
        }
        ngx_memzero(&spol, sizeof(spol));
        spol.enabled    = 1;
        spol.flush_mode = common->stage_flush_async ? BRIX_WT_MODE_ASYNC
                                                     : BRIX_WT_MODE_SYNC;
        brix_vfs_backend_config_stage_store(common->root_canon, &cfg, &spol);
    }

    return NGX_OK;
}
