/*
 * src/config/conf_helpers.h - Configuration merge helper macros.
 *
 * WHAT: Provides convenient wrapper macros for nginx's ngx_conf_merge_*
 *       family of functions. Reduces boilerplate in merge_*_conf() functions.
 *
 * WHY: Configuration merging (main → server → location hierarchy) uses
 *      repetitive patterns of ngx_conf_merge_* calls. The pattern repeats
 *      93 times across 14+ modules. Wrapping with simple macros reduces
 *      code duplication and improves readability.
 *
 * HOW: Each macro takes field name and default value, then expands to the
 *      corresponding ngx_conf_merge_* call. Works with standard nginx
 *      configuration structure patterns.
 */

#ifndef XROOTD_CONF_HELPERS_H
#define XROOTD_CONF_HELPERS_H

#include <nginx.h>
#include <ngx_core.h>
#include <ngx_http.h>

/* ---- MERGE_VALUE(field, default) ----
 *
 * Merge a simple integer/flag field from parent to child config.
 * Uses ngx_conf_merge_value().
 *
 * USAGE:
 *   MERGE_VALUE(enable, 0);  // Expands to:
 *   // ngx_conf_merge_value(conf->enable, prev->enable, 0);
 *
 * PRECONDITIONS:
 *   - 'conf' and 'prev' must be defined in scope
 *   - field must be a simple scalar (int, ngx_flag_t, etc.)
 */
#define MERGE_VALUE(field, default)                                  \
    ngx_conf_merge_value(conf->field, prev->field, (default))

/* ---- MERGE_UINT_VALUE(field, default) ----
 *
 * Merge an unsigned integer field from parent to child config.
 * Uses ngx_conf_merge_uint_value().
 *
 * USAGE:
 *   MERGE_UINT_VALUE(port, 1094);
 */
#define MERGE_UINT_VALUE(field, default)                             \
    ngx_conf_merge_uint_value(conf->field, prev->field, (default))

/* ---- MERGE_STR_VALUE(field, default) ----
 *
 * Merge a string field from parent to child config.
 * Uses ngx_conf_merge_str_value().
 *
 * USAGE:
 *   MERGE_STR_VALUE(path, "/var/xrootd");
 */
#define MERGE_STR_VALUE(field, default)                              \
    ngx_conf_merge_str_value(conf->field, prev->field, (default))

/* ---- MERGE_MSEC_VALUE(field, default) ----
 *
 * Merge a millisecond timeout field from parent to child config.
 * Uses ngx_conf_merge_msec_value(). Default is in milliseconds.
 *
 * USAGE:
 *   MERGE_MSEC_VALUE(timeout, 30000);  // 30 seconds
 */
#define MERGE_MSEC_VALUE(field, default)                             \
    ngx_conf_merge_msec_value(conf->field, prev->field, (default))

/* ---- MERGE_SEC_VALUE(field, default) ----
 *
 * Merge a second-based timeout field from parent to child config.
 * Uses ngx_conf_merge_sec_value(). Default is in seconds.
 *
 * USAGE:
 *   MERGE_SEC_VALUE(ttl, 3600);  // 1 hour
 */
#define MERGE_SEC_VALUE(field, default)                              \
    ngx_conf_merge_sec_value(conf->field, prev->field, (default))

/* ---- MERGE_PTR_VALUE(field) ----
 *
 * Merge a pointer field from parent to child config (inherits if child is NULL).
 * Uses direct assignment without ngx_conf_merge_ptr_value (which is not standard).
 *
 * USAGE:
 *   if (conf->handler == NULL) {
 *       MERGE_PTR_VALUE(handler);
 *   }
 */
#define MERGE_PTR_VALUE(field)                                       \
    if (conf->field == NULL) { conf->field = prev->field; }

/* ---- MERGE_ARRAY_VALUE(field) ----
 *
 * Merge an ngx_array_t pointer field from parent to child config.
 * Inherits parent array if child is NULL.
 *
 * USAGE:
 *   if (conf->acl_rules == NULL) {
 *       MERGE_ARRAY_VALUE(acl_rules);
 *   }
 */
#define MERGE_ARRAY_VALUE(field)                                     \
    if (conf->field == NULL) { conf->field = prev->field; }

/* ---- MERGE_TABLE_VALUE(field) ----
 *
 * Merge an ngx_hash_t pointer field from parent to child config.
 * Inherits parent hash table if child is NULL.
 *
 * USAGE:
 *   if (conf->map == NULL) {
 *       MERGE_TABLE_VALUE(map);
 *   }
 */
#define MERGE_TABLE_VALUE(field)                                     \
    if (conf->field.buckets == NULL) { conf->field = prev->field; }

/* ---- MERGE_OFF_VALUE(field, default) ----
 *
 * Merge an off_t (file offset/size) field from parent to child config.
 * Uses ngx_conf_merge_off_value(). Default is a size value in bytes.
 *
 * USAGE:
 *   MERGE_OFF_VALUE(cache_size, 1073741824);  // 1GB
 */
#define MERGE_OFF_VALUE(field, default)                              \
    ngx_conf_merge_off_value(conf->field, prev->field, (default))

/* ---- MERGE_BUFS_VALUE(field, default_num, default_size) ----
 *
 * Merge an ngx_bufs_t (buffer specification) field from parent to child.
 * Uses ngx_conf_merge_bufs_value(). Takes num buffers and size per buffer.
 *
 * USAGE:
 *   MERGE_BUFS_VALUE(buffer_spec, 4, 4096);  // 4 buffers of 4KB each
 */
#define MERGE_BUFS_VALUE(field, default_num, default_size)           \
    ngx_conf_merge_bufs_value(conf->field, prev->field,             \
                              (default_num), (default_size))

#endif /* XROOTD_CONF_HELPERS_H */
