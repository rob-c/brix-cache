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
        .timeout_ms = BRIX_GSIFTP_BACKEND_TIMEOUT_MS,
        .dns = entry->dns,
        /* phase-115 W5.1: the store line's data-channel policy.  Both are
         * REQUESTS the session negotiates once and never relaxes — an origin
         * that refuses MODE E or PROT P fails the transfer rather than moving
         * the bytes under weaker terms than the operator asked for. */
        .mode = entry->origin_ftp_mode_e ? GFTP_DMODE_E : GFTP_DMODE_S,
        .prot = entry->origin_ftp_prot_p ? GFTP_DPROT_P : GFTP_DPROT_C,
        /* phase-115 W5.3: unlike its two neighbours this one DOES
         * degrade — see gftp_spas.h. */
        .streams = (unsigned) entry->origin_ftp_streams,
    };
    brix_sd_instance_t *inst = brix_sd_gsiftp_create(&cfg, log);

    if (inst == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
            "brix: GridFTP backend init failed for export \"%s\"",
            entry->root_canon);
    } else {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "brix: %s storage backend ready at \"%s\" (host=%s base=%s "
            "mode=%c prot=%c)",
            entry->origin_tls ? "gsiftp" : "ftp", entry->root_canon,
            entry->origin_host, entry->origin_path,
            entry->origin_ftp_mode_e ? 'E' : 'S',
            entry->origin_ftp_prot_p ? 'P' : 'C');
    }
    return inst;
}
