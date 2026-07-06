/*
 * export_guard.h — config-time assertion that service trees holding internal
 * metadata sidecars never live inside a client-visible export namespace.
 *
 * WHAT: brix_assert_dir_outside_export(cf, label, export_canon, dir) fails the
 *   config (NGX_ERROR + emerg log) when `dir` is at or beneath `export_canon`.
 *   A cache/state/stage tree nested under an export would place .cinfo/.meta
 *   sidecars and upload temps (.xrd-tmp./.xrdresume./.commit) directly in the
 *   namespace clients browse.
 *
 * WHY: the runtime name filter (brix_is_internal_name) hides those artifacts at
 *   every client checkpoint, but the STRUCTURAL guarantee is that the service
 *   trees are simply not in the export at all. This is a hard check — a
 *   misconfiguration is a deploy-blocking error, not a warning — so an operator
 *   cannot ship a topology that depends on the runtime filter as its only line
 *   of defence. Both paths are canonicalized (realpath, when the dir exists)
 *   before the at-or-beneath test so a symlinked or "."/".."-laden dir cannot
 *   sneak inside.
 *
 * HOW: realpath the tree (fall back to the given string when it is not yet
 *   created — operators configure absolute paths, and a lexical prefix match
 *   still catches the dangerous /export/... nesting), then reuse
 *   brix_beneath_strip_root() (non-NULL == inside the root). No-op on empty input.
 */
#ifndef BRIX_CORE_CONFIG_EXPORT_GUARD_H
#define BRIX_CORE_CONFIG_EXPORT_GUARD_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <stdlib.h>
#include <limits.h>
#include "fs/path/beneath.h"

static inline ngx_int_t
brix_assert_dir_outside_export(ngx_conf_t *cf, const char *label,
    const char *export_canon, const char *dir)
{
    char        canon[PATH_MAX];
    const char *cmp;

    if (export_canon == NULL || export_canon[0] == '\0'
        || dir == NULL || dir[0] == '\0')
    {
        return NGX_OK;
    }

    /* A pure cache node advertises export "/" (the whole namespace maps to a
     * remote origin); every local path is trivially "beneath /", so the guard
     * would reject an otherwise-valid topology. Such a node has no local export
     * tree to leak into and relies on the runtime name filter — skip it. */
    if (export_canon[0] == '/' && export_canon[1] == '\0') {
        return NGX_OK;
    }

    cmp = (realpath(dir, canon) != NULL) ? canon : dir;

    if (brix_beneath_strip_root(export_canon, cmp) != NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix: %s \"%s\" is at or beneath export root \"%s\" — internal "
            "metadata sidecars (.cinfo/.meta, upload temps) would be exposed in "
            "the client namespace; configure it outside every brix_export root",
            label, cmp, export_canon);
        return NGX_ERROR;
    }
    return NGX_OK;
}

#endif /* BRIX_CORE_CONFIG_EXPORT_GUARD_H */
