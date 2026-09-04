#ifndef BRIX_VFS_AUTHZ_TYPES_H
#define BRIX_VFS_AUTHZ_TYPES_H

/*
 * vfs_authz_types.h — public value types for the VFS authorization backstop.
 *
 * WHAT: Declares the per-export rollout mode and borrowed authorization bundle
 *       carried by brix_vfs_ctx_t.
 * WHY:  These values belong to the public VFS context, while the evaluator API
 *       remains internal in vfs_authz.h. This keeps vfs.h focused and bounded.
 * HOW:  Rule pointers borrow finalized server configuration; `bound` separates
 *       an intentional allow-all export from a missed binder, and the rollout
 *       mode is carried per context instead of through a global.
 *
 * Requires: ngx_array_t and ngx_uint_t from ngx_core.h.
 */

typedef enum {
    BRIX_AUTHZ_BACKSTOP_OFF = 0,
    BRIX_AUTHZ_BACKSTOP_OBSERVE,
    BRIX_AUTHZ_BACKSTOP_ENFORCE
} brix_authz_backstop_mode_t;

typedef struct {
    ngx_array_t *authdb_rules;
    ngx_array_t *vo_rules;
    void        *acc_tables;
    void        *acc_entity;
    ngx_uint_t   acc_format;
    char         peer[256];
    brix_authz_backstop_mode_t mode;
    unsigned     bound:1;
} brix_vfs_authz_t;

struct brix_vfs_ctx_s;

/* Bind the finalized per-export rules and rollout mode to one initialized VFS
 * context. Pointers are borrowed; NULL vctx is a no-op. */
void brix_vfs_ctx_bind_authz(struct brix_vfs_ctx_s *vctx,
    ngx_array_t *authdb_rules, ngx_array_t *vo_rules,
    void *acc_tables, ngx_uint_t acc_format,
    const char *peer, brix_authz_backstop_mode_t mode);

void brix_vfs_ctx_bind_no_authz_rules(struct brix_vfs_ctx_s *vctx,
    brix_authz_backstop_mode_t mode);

#endif /* BRIX_VFS_AUTHZ_TYPES_H */
