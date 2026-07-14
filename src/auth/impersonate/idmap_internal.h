/*
 * idmap_internal.h — private split contract between idmap.c, idmap_gridmap.c
 * and idmap_denylist.c after the file-size split.
 *
 * WHAT: Cross-declares the symbols that are DEFINED in one of the three idmap
 *       translation units but REFERENCED from another: the shared principal-size
 *       bound, the two mapping-policy globals set by idmap.c and read by the
 *       deny-list layer, and the handful of functions the core resolve/init
 *       pipeline calls into the grid-mapfile and deny-list clusters.
 * WHY:  idmap.c was 766 lines — over the 500-line file-size cap. The grid-mapfile
 *       parser/loader and the deny-list / forbidden-id machinery each form one
 *       cohesive concern and move to their own siblings; the cache, hash, policy
 *       install and the resolve entry points stay in idmap.c. Only the symbols
 *       that cross a boundary become non-static and are declared here.
 * HOW:  All three translation units include this header (after impersonate.h,
 *       which supplies the brix_idmap_* types). None of these symbols is exported
 *       beyond src/auth/impersonate/.
 */
#ifndef BRIX_IDMAP_INTERNAL_H
#define BRIX_IDMAP_INTERNAL_H

#include "impersonate.h"   /* brix_idmap_creds_t, brix_idmap_conf_t, uid_t */

#define IDMAP_PRINC_MAX    512          /* a GSI DN can be long */

/* Mapping policy installed by idmap_init_policy() in idmap.c and consulted by
 * the deny-list layer in idmap_denylist.c. */
extern uid_t  idmap_min_uid;
extern int    idmap_primary_only;

/* idmap_gridmap.c — grid-mapfile parse/load/lookup. */
ngx_int_t    idmap_gridmap_load(const char *path, ngx_log_t *log);
const char  *idmap_gridmap_lookup(const char *dn);

/* idmap_denylist.c — local-user resolution + forbidden-id / squash policy. */
int   idmap_resolve_user(const char *user, brix_idmap_creds_t *out);
int   idmap_creds_allowed(const brix_idmap_creds_t *cr);
void  idmap_init_denylists(const brix_idmap_conf_t *conf, ngx_log_t *log);

#endif /* BRIX_IDMAP_INTERNAL_H */
