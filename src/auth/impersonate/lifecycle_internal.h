/*
 * lifecycle_internal.h — shared state for the impersonation nginx-lifecycle glue.
 *
 * The lifecycle glue is split across three translation units that all read the
 * single process-global settings block:
 *   - lifecycle.c         config-directive parsing + validation
 *   - lifecycle_broker.c  master-side privileged-broker spawn + init_module
 *   - lifecycle_worker.c  worker cap-drop + client connect + per-request begin/end
 * This header names the settings struct and exports the one global they share so
 * the split stays behaviour-identical to the pre-split single file.
 */

#ifndef BRIX_IMPERSONATE_LIFECYCLE_INTERNAL_H
#define BRIX_IMPERSONATE_LIFECYCLE_INTERNAL_H

#include <ngx_config.h>
#include <ngx_core.h>

typedef struct {
    int        mode;                      /* BRIX_IMP_OFF/SINGLE/MAP */
    int        configured;                /* any directive parsed */
    ngx_str_t  socket;                    /* map: broker AF_UNIX path */
    ngx_str_t  export_root;               /* map: broker confinement root */
    ngx_str_t  gridmap;                   /* DN->user mapfile */
    ngx_str_t  default_user;              /* squash account ("" => deny) */
    ngx_str_t  single_user;               /* SINGLE: fixed account */
    ngx_str_t  broker_user;               /* MAP: non-root account the broker runs as */
    ngx_str_t  forbidden_users;           /* deny-list of target accounts ("" => default) */
    ngx_str_t  forbidden_groups;          /* deny-list of privileged groups ("" => default) */
    ngx_int_t  min_uid;                   /* reserved-uid floor */
    ngx_int_t  cache_ttl;                 /* resolution cache TTL */
} imp_settings_t;

extern imp_settings_t imp_settings;

#endif /* BRIX_IMPERSONATE_LIFECYCLE_INTERNAL_H */
