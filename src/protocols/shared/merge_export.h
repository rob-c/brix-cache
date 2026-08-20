#ifndef BRIX_MERGE_EXPORT_H
#define BRIX_MERGE_EXPORT_H

/*
 * merge_export.h — the export-anchor sequence every HTTP protocol merge runs.
 *
 * WHAT: One helper, brix_http_merge_export_anchor(), that turns a location's
 *       configured export root into the three things the read/write planes
 *       below it need: a canonical path (root_canon), the persistent O_PATH
 *       confinement fd every openat2(RESOLVE_BENEATH) anchors on, and a
 *       registered VFS storage backend for whatever brix_storage_backend named.
 *
 * WHY:  CVMFS, OCI and RPM each ran the identical four steps in their own
 *       merge, in the identical order, with the identical error handling — and
 *       the order is not incidental: the rootfd must be opened on the
 *       CANONICAL path (opening it on the configured one would anchor
 *       confinement on a symlink the operator could later repoint), and the
 *       backend must be registered against that same canonical root or a
 *       remote backend's namespace and the local confinement boundary describe
 *       different trees. A fourth plane copying the sequence would eventually
 *       copy it in the wrong order; there is now nothing to copy.
 *
 * HOW:  Defaults an unset root to "/" (the pure-cache-node anchor: the location
 *       serves the "/" namespace and fills from its backend into the cache
 *       store), then brix_prepare_export_root → brix_http_open_rootfd →
 *       brix_vfs_backend_config_str. Every failure is already reported by the
 *       step that failed, so the caller just propagates NGX_CONF_ERROR.
 *
 * NOT in scope, deliberately: the per-plane freshness stamps
 * (cache_manifest_ttl and friends) and brix_tier_register_stores. Those come
 * AFTER, and what each plane stamps between them is exactly what makes it that
 * plane — folding them in would take a policy decision away from the protocol
 * that owns it.
 */

#include "core/config/shared_conf.h"

char *brix_http_merge_export_anchor(ngx_conf_t *cf,
    ngx_http_brix_shared_conf_t *common, const char *directive_name,
    ngx_flag_t allow_write);

#endif /* BRIX_MERGE_EXPORT_H */
