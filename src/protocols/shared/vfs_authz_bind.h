#ifndef BRIX_PROTOCOLS_SHARED_VFS_AUTHZ_BIND_H
#define BRIX_PROTOCOLS_SHARED_VFS_AUTHZ_BIND_H

/* Bind one HTTP request's finalized authorization state to an initialized VFS
 * context. Rule arrays are explicit because S3 owns a root-finalized copy and
 * CVMFS deliberately does not consume the common native ACL. */
#include "core/config/shared_conf.h"
#include "fs/vfs/vfs.h"

void brix_http_vfs_bind_authz(ngx_http_request_t *r,
    const ngx_http_brix_shared_conf_t *common,
    ngx_array_t *authdb_rules, ngx_array_t *vo_rules,
    brix_vfs_ctx_t *vctx);

/* Explicitly bind an HTTP context whose protocol authorization model does not
 * use export path rules (CVMFS CAS, OCI/RPM service stores). It preserves the
 * configured rollout mode and records `no_rules`, never `unbound`. */
void brix_http_vfs_bind_no_rules(
    const ngx_http_brix_shared_conf_t *common, brix_vfs_ctx_t *vctx);

#endif /* BRIX_PROTOCOLS_SHARED_VFS_AUTHZ_BIND_H */
