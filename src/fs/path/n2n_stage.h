#ifndef BRIX_PATH_N2N_STAGE_H
#define BRIX_PATH_N2N_STAGE_H

/*
 * n2n_stage.h — the ctx-carried logical↔physical name-translation stage
 * (phase-108 A.4).
 *
 * WHAT: Two thin wrappers that bind an export's resolved brix_n2n_cfg_t (carried
 *       on the VFS ctx as ctx->n2n) to the pure translators in site_n2n.c —
 *       brix_n2n_lfn2pfn() / brix_n2n_pfn2lfn(). LFN→PFN is what a backend keys
 *       storage by; PFN→LFN renders a physical listing back in logical terms.
 * WHY:  The pure translators are cfg-in / string-out and know nothing of a
 *       request. This is the single seam that reads the per-export cfg off the
 *       ctx, so every plane composes one name the same way and a NULL cfg means
 *       IDENTITY by construction rather than by each caller remembering to.
 * HOW:  ctx->n2n (NULL ⇒ a static IDENTITY cfg) is handed straight to the pure
 *       function. The wrappers add NO translation logic — they are the ctx→cfg
 *       adapter and nothing more; canonicalization and ".." rejection remain the
 *       pure canonicalizer's job. SECURITY: an LFN reaches here only AFTER
 *       resolve_path() has confined it (INVARIANT #4); the wrappers do not
 *       confine, they translate a name already proven in-export.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include "fs/path/site_n2n.h"

/* Forward decl only: the wrappers take the VFS ctx but stay stream-includable
 * without dragging the full vfs.h into every path-layer TU (same idiom as
 * vfs_policy.h). The .c includes vfs.h for the concrete ctx->n2n field. */
typedef struct brix_vfs_ctx_s brix_vfs_ctx_t;

/* LFN → physical name, using ctx->n2n (NULL ⇒ IDENTITY). Canonicalizes and
 * rejects ".." via the pure translator. NGX_OK, or NGX_ERROR with errno set
 * (EINVAL on a NULL ctx or a ".." component, ENAMETOOLONG on overflow). */
ngx_int_t brix_path_lfn_to_pfn(const brix_vfs_ctx_t *ctx, const char *lfn,
    char *pfn, size_t cap);

/* Physical name → LFN (reverse; renders a listing logically), using ctx->n2n
 * (NULL ⇒ IDENTITY). NGX_OK, or NGX_ERROR (EINVAL on a NULL ctx, or the pfn is
 * not under the configured pool/prefix, or overflow). */
ngx_int_t brix_path_pfn_to_lfn(const brix_vfs_ctx_t *ctx, const char *pfn,
    char *lfn, size_t cap);

/* Convert an already-confined absolute/export-relative VFS path into the
 * physical key passed to a non-POSIX storage driver. The export-root strip is
 * deliberately inside this helper so callers cannot translate the host path
 * prefix. NGX_OK, or NGX_ERROR with errno from the pure translator. */
ngx_int_t brix_path_resolved_to_pfn(const brix_vfs_ctx_t *ctx,
    const char *resolved_path, char *pfn, size_t cap);

/* Pool-less twin for delayed export work. `path` may be export-relative or an
 * already-confined absolute path; root_canon is stripped before translation.
 * A NULL cfg selects IDENTITY. */
ngx_int_t brix_path_export_to_pfn(const char *root_canon,
    const brix_n2n_cfg_t *cfg, const char *path, char *pfn, size_t cap);

#endif /* BRIX_PATH_N2N_STAGE_H */
