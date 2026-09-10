/*
 * space_group_conf.h — `brix_oss_space <group> <prefix> [quota=<size>|quota=-1]`
 *
 * WHAT: the per-server space-group table (phase-115 W3.3; the stock
 *       `oss.space` / `oss.cgroup` analog). A named group owns ONE
 *       export-relative path prefix and an optional byte quota. Longest-prefix
 *       lookup by logical path; lookup by name for the kXR_Qspace and
 *       kXR_open `oss.cgroup=` selectors.
 *
 * WHY:  stock sites account and cap storage per space group (one per VO or
 *       activity) and clients select a group at create time with
 *       `oss.cgroup=`. Before W3.3 a server had one group name
 *       (brix_oss_cgroup) and one quota (brix_oss_quota): the report could name
 *       a group but never distinguish two, and a quota could only be
 *       export-wide.
 *
 * HOW:  nginx-core types only (the table pointer lives in
 *       srv_conf_fields_auth.h). The setter validates the name with the same
 *       CGI-grammar rule brix_oss_cgroup uses (the name is emitted verbatim
 *       into the "&"-joined oss.* report), the prefix as an absolute,
 *       normalised, dot-segment-free path, and the quota as a non-negative size
 *       or the literal -1 (unlimited: accounting only). Duplicate names and
 *       duplicate prefixes fail the parse. The usage cache on each entry is
 *       per worker (copy-on-write after fork; never shared across workers).
 */
#ifndef BRIX_SPACE_GROUP_CONF_H
#define BRIX_SPACE_GROUP_CONF_H

#include <ngx_config.h>
#include <ngx_core.h>

typedef struct {
    ngx_str_t           name;        /* "&"-free group label (oss.cgroup) */
    ngx_str_t           prefix;      /* "/atlas": absolute, no trailing '/' */
    off_t               quota;       /* bytes; -1 = unlimited (accounting only) */
    ngx_msec_t          used_at;     /* per-worker usage cache: measured when */
    unsigned long long  used_bytes;  /* ... bytes under prefix + admitted writes */
    unsigned            used_valid:1;
} brix_oss_space_t;

/* 1 iff `name` can be emitted inside the "&"-joined oss.* report: non-empty
 * and free of '&' '=' ' ' and control bytes. Shared with brix_oss_cgroup. */
int brix_oss_space_name_ok(const ngx_str_t *name);

/* Directive setter (registered in directives_security.h); `conf` is the
 * ngx_stream_brix_srv_conf_t. The table is created on the first declaration. */
char *brix_conf_set_oss_space(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

/* Longest-prefix owner of the export-relative path logical[0..len), or NULL
 * when no group covers it (the export-wide default group applies). A prefix
 * matches at a component boundary only: "/atlas" owns "/atlas" and
 * "/atlas/x", never "/atlasdata". */
brix_oss_space_t *brix_oss_space_for_path(const ngx_array_t *spaces,
    const char *logical, size_t len);

/* The group called name[0..len), or NULL. */
brix_oss_space_t *brix_oss_space_by_name(const ngx_array_t *spaces,
    const u_char *name, size_t len);

#endif /* BRIX_SPACE_GROUP_CONF_H */
