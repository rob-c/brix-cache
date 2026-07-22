/*
 * runtime_server_backend_cache.c — phase-64/85 read-through cache-tier
 * registration: cache_store parse + policy fill, the CVMFS master-key load
 * (F1) and the sibling-mesh ring (F8). Split verbatim out of
 * runtime_server_backend.c (mechanical file-size split); the single entry
 * point crossing back into brix_tier_register_stores() is declared in
 * runtime_server_backend_internal.h.
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
#include "runtime_server_backend_internal.h"

#include <stdlib.h>                    /* strtol (F8 peer-ring port parse)   */
#include <string.h>                    /* strrchr                            */

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

/* Fill the read-through cache policy from the merged srv-conf knobs. Split out
 * of brix_tier_register_cache_store so each function's branching stays within
 * the readability gate — pure knob-to-policy plumbing, no validation here. */
static void
brix_tier_fill_cache_policy(ngx_http_brix_shared_conf_t *common,
    brix_cache_policy_t *polp)
{
    brix_cache_policy_t pol;

    ngx_memzero(&pol, sizeof(pol));
    pol.enabled       = 1;
    pol.max_file_size = common->cache_max_object;
    /* Read-fill admission (bridged from the srv conf at finalisation): deny/allow
     * prefixes + include regex gate the composable sd_cache fill for parity with
     * write-through and the legacy cache_origin admit. NULL => no filter. */
    pol.deny_prefixes  = common->cache_deny_prefixes;
    pol.allow_prefixes = common->cache_allow_prefixes;
    pol.include_regex  = common->cache_include_re;
    /* Documented defaults (90/80) applied here: the merge keeps the pair UNSET
     * so the stream reaper merge can detect an explicit setting. */
    pol.evict_at      = (common->cache_evict_at == NGX_CONF_UNSET_UINT)
                      ? 90 : common->cache_evict_at;
    pol.evict_to      = (common->cache_evict_to == NGX_CONF_UNSET_UINT)
                      ? 80 : common->cache_evict_to;
    pol.meta_mode     = (int) common->cache_meta_mode;
    pol.batch_cinfo   = (common->cache_batch_cinfo == 2)
                      ? -1 : (int) common->cache_batch_cinfo;
    pol.l1_entries    = common->cache_index_cache;
    pol.slice_size    = common->cache_slice_size;
    /* phase-68 digest-verification mode — the posix-store constraint it
     * carries is validated by the caller against the parsed store driver. */
    pol.verify = (common->cache_verify_mode == NGX_CONF_UNSET_UINT)
               ? BRIX_CACHE_VERIFY_OFF
               : (brix_cache_verify_mode_e) common->cache_verify_mode;
    pol.cvmfs_manifest_ttl = common->cache_manifest_ttl;
    pol.cvmfs_offline_ttl  = common->cache_offline_ttl;
    if (common->cache_quarantine_dir.len > 0) {
        ngx_cpystrn((u_char *) pol.quarantine_dir,
                    common->cache_quarantine_dir.data,
                    ngx_min(common->cache_quarantine_dir.len + 1,
                            sizeof(pol.quarantine_dir)));
    }
    *polp = pol;
}

/* Parse the cache_store URL and record its tier cfg + read-through policy on the
 * backend registry. Split out of brix_tier_register_stores so each function's
 * branching stays within the readability gate. Operator errors are [emerg]. */
ngx_int_t
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
    brix_tier_fill_cache_policy(common, &pol);
    /* phase-68: digest verification on fill (cvmfs-cas today). The verify
     * runs on the staged temp BEFORE commit, which needs the store's
     * staged_path — a local posix store; reject other stores loudly. */
    if (pol.verify == BRIX_CACHE_VERIFY_CVMFS_CAS
        && ngx_strcmp(cfg.driver, "posix") != 0)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cache_verify cvmfs-cas requires a local posix "
            "cache store (got \"%s\")", cfg.driver);
        return NGX_ERROR;
    }
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
