/*
 * n2n_stage.c — the ctx→cfg adapter for the name-translation stage. See the
 * header. The wrappers add no translation logic; they bind ctx->n2n (or a static
 * IDENTITY cfg when it is NULL) to the pure translators and map their 0/-1+errno
 * result onto NGX_OK/NGX_ERROR.
 */

#include "n2n_stage.h"

#include "fs/vfs/vfs_internal.h" /* ctx fields + canonical export-root strip */
#include "fs/path/site_n2n.h"    /* brix_n2n_lfn2pfn / brix_n2n_pfn2lfn */

#include <errno.h>

/* The translation an export with no configured n2n resolves to: pfn == the
 * canonicalized lfn. One static const so a NULL ctx->n2n costs no per-call
 * construction. */
static const brix_n2n_cfg_t brix_n2n_identity_cfg = { BRIX_N2N_IDENTITY, "", "" };

ngx_int_t
brix_path_lfn_to_pfn(const brix_vfs_ctx_t *ctx, const char *lfn,
    char *pfn, size_t cap)
{
    const brix_n2n_cfg_t *cfg;

    if (ctx == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    cfg = (ctx->n2n != NULL) ? ctx->n2n : &brix_n2n_identity_cfg;
    return (brix_n2n_lfn2pfn(cfg, lfn, pfn, cap) == 0) ? NGX_OK : NGX_ERROR;
}

ngx_int_t
brix_path_pfn_to_lfn(const brix_vfs_ctx_t *ctx, const char *pfn,
    char *lfn, size_t cap)
{
    const brix_n2n_cfg_t *cfg;

    if (ctx == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    cfg = (ctx->n2n != NULL) ? ctx->n2n : &brix_n2n_identity_cfg;
    return (brix_n2n_pfn2lfn(cfg, pfn, lfn, cap) == 0) ? NGX_OK : NGX_ERROR;
}

/* brix_path_resolved_to_pfn -- translate one confined VFS path for a driver.
 *
 * WHAT: Strips the export root from `resolved_path`, then translates that LFN
 *       through the ctx-bound N2N configuration into `pfn`. Returns NGX_OK or
 *       NGX_ERROR with errno set by the translator.
 * WHY:  Confinement is defined over the logical export path, while storage
 *       drivers address physical keys. One adapter fixes the security-relevant
 *       ordering and prevents callers from accidentally prefixing root_canon.
 * HOW:  Validate the inputs, derive the export-relative LFN with the existing
 *       VFS helper, then delegate all composition to brix_path_lfn_to_pfn(). */
ngx_int_t
brix_path_resolved_to_pfn(const brix_vfs_ctx_t *ctx,
    const char *resolved_path, char *pfn, size_t cap)
{
    const char *lfn;

    if (ctx == NULL || resolved_path == NULL || pfn == NULL || cap == 0) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    lfn = brix_vfs_export_relative(ctx, resolved_path);
    return brix_path_lfn_to_pfn(ctx, lfn, pfn, cap);
}

ngx_int_t
brix_path_export_to_pfn(const char *root_canon, const brix_n2n_cfg_t *cfg,
    const char *path, char *pfn, size_t cap)
{
    const char *lfn;

    if (path == NULL || pfn == NULL || cap == 0) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    lfn = brix_vfs_export_relative_root(path, root_canon);
    cfg = (cfg != NULL) ? cfg : &brix_n2n_identity_cfg;
    return (brix_n2n_lfn2pfn(cfg, lfn, pfn, cap) == 0)
        ? NGX_OK : NGX_ERROR;
}
