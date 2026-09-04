#ifndef BRIX_SD_GSIFTP_H
#define BRIX_SD_GSIFTP_H

/* Outbound ftp:// / gsiftp:// origin storage driver. */

#include "fs/backend/sd.h"

typedef struct {
    const char *host;
    int         port;
    const char *base_path;
    int         require_gsi;
    const char *x509_proxy;
    const char *ca_dir;
    int         timeout_ms;
} brix_sd_gsiftp_cfg_t;

brix_sd_instance_t *brix_sd_gsiftp_create(
    const brix_sd_gsiftp_cfg_t *cfg, ngx_log_t *log);
void brix_sd_gsiftp_destroy(brix_sd_instance_t *inst);

#endif /* BRIX_SD_GSIFTP_H */
