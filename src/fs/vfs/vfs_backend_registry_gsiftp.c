/* Raw-source builder for an outbound GridFTP origin. */

#include "vfs_backend_internal.h"
#include "fs/backend/gsiftp/sd_gsiftp.h"

brix_sd_instance_t *
brix_vbr_build_gsiftp(brix_vfs_backend_entry_t *entry, ngx_log_t *log)
{
    brix_sd_gsiftp_cfg_t cfg = {
        .host = entry->origin_host,
        .port = entry->origin_port,
        .base_path = entry->origin_path,
        .require_gsi = entry->origin_tls,
        .x509_proxy = entry->origin_x509_proxy[0] != '\0'
            ? entry->origin_x509_proxy : NULL,
        .ca_dir = entry->origin_ca_dir[0] != '\0'
            ? entry->origin_ca_dir : NULL,
        .timeout_ms = 30000,
    };
    brix_sd_instance_t *inst = brix_sd_gsiftp_create(&cfg, log);

    if (inst == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
            "brix: GridFTP backend init failed for export \"%s\"",
            entry->root_canon);
    } else {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "brix: %s storage backend ready at \"%s\" (host=%s base=%s)",
            entry->origin_tls ? "gsiftp" : "ftp", entry->root_canon,
            entry->origin_host, entry->origin_path);
    }
    return inst;
}
