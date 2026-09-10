/*
 * vfs_backend_store_params.c - stamp the trailing params of a
 * `brix_storage_backend` line onto the export's registry entry (phase-115).
 *
 * WHAT: one config-time call, made straight after brix_vfs_backend_config_str
 * has registered the URL, that parses the line's trailing params through the
 * tier vocabulary (verify_pages, mode=, prot=, credential=, block_size=) and
 * copies the ones the live backend path honours onto brix_vfs_backend_entry_t.
 *
 * WHY it exists at all: BriX has two store-config paths.  The tier composer
 * (brix_cache_store / brix_cache_cold_store / brix_stage_store) parses its
 * params and builds through brix_tier_build; the LIVE backend path parses only
 * the URL, into the VFS backend registry, and builds through brix_vbr_build_*.
 * No backend is ever built through the tier composer, so a param parsed only
 * into a brix_tier_cfg_t is a promise nothing keeps — which is exactly how
 * W4.3's `verify_pages` shipped unreachable (the directive was TAKE1, so
 * nginx -t refused the token for arity before any parser saw it).  This file
 * is the one seam that carries a store-line param across to the path that
 * actually builds the driver.
 *
 * HOW: parse into a scratch brix_tier_cfg_t (never retained — the tier cfg is
 * the parser's vocabulary, not this path's storage), then copy the three fields
 * the registry declares onto the entry.  A line with no params returns before
 * the URL is even looked at, so every configuration that works today is
 * bit-identical through here.
 */
#include "vfs_backend_registry.h"
#include "vfs_backend_internal.h"
#include "vfs_backend_config_internal.h" /* VFS_BE_STR */
#include "fs/tier/tier.h"

#include <string.h>

/* 2.0 F5: a forward:// export is configured by its params alone — the URL
 * names no origin, so the permit list is the one thing deciding which origins
 * the export may reach.  An empty list is refused rather than defaulted: a
 * forwarding proxy with no permit is an open relay to any host a client
 * names. */
static ngx_int_t
vfs_store_params_check_forward(ngx_conf_t *cf,
    const brix_vfs_backend_entry_t *e)
{
    /* A forward:// entry always carries at least one allowed protocol
     * (vfs_parse_forward_origin refuses an empty list), so the flags are
     * the entry's own identity — no driver-name branch (invariant 12). */
    if (e == NULL
        || !(e->origin_fwd_allow_root || e->origin_fwd_allow_roots))
    {
        return NGX_OK;
    }
    if (e->origin_fwd_permit[0] == '\0') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_storage_backend forward:// needs at least one "
            "permit=<host|.suffix> (an empty permit list would relay to any "
            "origin a client names)");
        return NGX_ERROR;
    }
    return NGX_OK;
}

ngx_int_t
brix_vfs_backend_store_params(ngx_conf_t *cf, const char *root_canon,
    ngx_str_t *url, ngx_array_t *args)
{
    brix_tier_cfg_t           tier;
    char                      err[256];
    brix_tier_parse_t         p = { cf, &tier, err, sizeof(err) };
    brix_vfs_backend_entry_t *e;

    /* A local export (no backend URL) has no registry entry: the params are
     * still validated below, so a typo is an operator error either way, but
     * there is no remote link for them to describe. */
    e = (root_canon != NULL && root_canon[0] != '\0')
        ? brix_vfs_backend_entry_find(root_canon) : NULL;

    if (args == NULL || args->nelts == 0) {
        /* no params: nothing to parse or stamp — unless the backend is one
         * that only its params can configure */
        return vfs_store_params_check_forward(cf, e);
    }

    err[0] = '\0';
    if (brix_tier_parse_backend_params(&p, url, args) != NGX_OK) {
        return NGX_ERROR;           /* the parser already emitted the [emerg] */
    }
    if (e == NULL) {
        return NGX_OK;
    }
    e->origin_verify_pages = (int) tier.verify_pages;
    e->origin_ftp_mode_e   = tier.ftp_mode_e ? 1 : 0;
    e->origin_ftp_prot_p   = tier.ftp_prot_p ? 1 : 0;
    e->origin_ftp_streams  = (int) tier.ftp_streams;
    VFS_BE_STR(e, origin_fwd_permit, tier.fwd_permit);
    return vfs_store_params_check_forward(cf, e);
}
