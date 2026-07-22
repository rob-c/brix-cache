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
#include "runtime_server_backend_internal.h"

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

/* 1 iff the storage backend is a WHOLE-OBJECT remote gateway (WebDAV or S3:
 * an upload replaces the entire object, so the remote driver cannot honour
 * random-offset writes and rejects them at the cap). root://, rados and ceph
 * remotes are byte-addressable and never need a stage tier for random writes;
 * tape:// / frm:// are nearline and already require a cache tier instead. */
static int
brix_storage_backend_is_whole_object(const ngx_http_brix_shared_conf_t *common)
{
    static const char *const schemes[] = { "http://", "https://", "s3://",
                                           NULL };
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

    /* Zero-config gateway staging: a whole-object remote backend (WebDAV/S3)
     * rejects random-offset writes at the cap, so a WRITABLE export with no
     * stage tier configured at all gets a brix-managed default store under
     * /tmp/staging (loud [warn] banner; opt out with "brix_stage off"). An
     * explicit "brix_stage off" merges to 0, not UNSET, and skips this. */
    if (common->stage_enable == NGX_CONF_UNSET
        && common->stage_store.len == 0
        && common->allow_write == 1
        && brix_storage_backend_is_whole_object(common))
    {
        brix_tier_default_stage_store(cf, common);
    }

    /* PrivateTmp posture check: any stage/cache store under a systemd-private
     * /tmp (including the default just provisioned) is wiped on restart. */
    brix_tier_warn_private_tmp(cf, common);

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
