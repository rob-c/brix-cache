/* object_scope.c — bind VFS identity and credentials for S3 object requests.
 * WHAT: Initialize the object request's typed storage and observation context.
 * WHY: GET, HEAD and DELETE must share the same policy and credential binding.
 * HOW: Build the VFS context, bind backend credentials/delegation, then monitoring.
 */
#include "s3.h"
#include "fs/vfs/vfs.h"
#include "core/http/http_variables.h"
#include "core/http/http_headers.h"
#include "object_internal.h"

void
s3_vfs_ctx(ngx_http_request_t *r, const char *fs_path,
    ngx_http_s3_loc_conf_t *cf, brix_vfs_ctx_t *vctx)
{
    ngx_http_s3_req_ctx_t *s3ctx;
    int                    is_tls = 0;

    s3ctx = ngx_http_get_module_ctx(r, ngx_http_brix_s3_module);

    is_tls = brix_http_request_is_tls(r);

    brix_vfs_ctx_init(vctx, r->pool, r->connection->log, BRIX_PROTO_S3,
        cf->common.root_canon, cf->common.cache_root_canon,
        brix_vfs_policy_from_write_enable(cf->common.allow_write),
        is_tls, (s3ctx != NULL) ? s3ctx->identity : NULL, fs_path);
    /* Mirror PUT's per-user backend credentials for inline and off-loop reads;
     * never fall back silently to a service credential. */
    brix_vfs_ctx_bind_backend_cred(vctx,
        &cf->common.storage_credential_dir,
        cf->common.storage_credential_fallback);
    brix_vfs_ctx_bind_backend_mint(vctx,
        &cf->common.storage_credential_mint_ca_cert,
        &cf->common.storage_credential_mint_ca_key,
        cf->common.storage_credential_mint_ttl);
    s3_vfs_bind_deleg(r, cf, vctx);
    /* S3 GET serve path (event loop; the off-loop fill/serve gates below read
     * this ctx). Bind the per-request I/O monitor so $brix_bytes_served /
     * $brix_backend_time / $brix_checksum report on the S3 download plane
     * exactly as they do on WebDAV. */
    brix_http_monitor_bind(r, vctx);
}
