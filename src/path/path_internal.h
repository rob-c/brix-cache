#pragma once

#include "../ngx_xrootd_module.h"

int xrootd_path_component_forbidden(const char *comp, size_t comp_len);
void xrootd_log_path_warning(ngx_log_t *log, const char *prefix,
    const char *path);
/* Confinement helpers used across resolve_confined_*.c fragments. */
int xrootd_path_within_root(const char *root_canon, const char *path_canon);
int xrootd_resolved_relative_to_root(ngx_log_t *log, const char *root_canon,
    const char *resolved, char *rel, size_t relsz);
int xrootd_get_canonical_root(ngx_log_t *log, const ngx_str_t *root,
    char *root_canon, size_t root_canon_sz);
ngx_int_t xrootd_finalize_path_rules(ngx_log_t *log, const ngx_str_t *root,
    ngx_array_t *rules, size_t element_size, size_t path_offset,
    size_t resolved_offset, size_t resolved_size);
